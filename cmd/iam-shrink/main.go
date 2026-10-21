package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/smford/iam-shrink/internal/mapper"
	"github.com/smford/iam-shrink/internal/render"
	"github.com/smford/iam-shrink/internal/runner"
)

var (
	version = "0.1.0"
)

func printUsage() {
	fmt.Fprintf(os.Stderr, `iam-shrink - Local-to-Least-Privilege AWS IAM Policy Generator

Usage:
  iam-shrink run [flags] -- <command> [args...]
  iam-shrink explain <service>:<api>
  iam-shrink export-mappings [flags]
  iam-shrink version

Commands:
  run              Run a command with AWS CSM telemetry and generate an IAM policy
  explain          Show IAM mapping, required ARNs, and dependencies for an SDK API
  export-mappings  Dump the embedded SDK-to-IAM mapping database to YAML
  version          Show version information

Flags for 'run':
  --format string           Output format: json, tf, cdk (default "json")
  --out string              Output file path (default: stdout)
  --include-failed          Include failed API calls (e.g. 403 AccessDenied) (default true)
  --group-by-service        Group IAM statements by AWS service prefix (default true)
  --strict-arns             Generate parameterized ARN placeholders instead of '*' (default false)
  --mappings string         Path to custom YAML file to extend or override mappings

Examples:
  iam-shrink run --format=tf -- go test ./...
  iam-shrink run --format=json -- python deploy_dryrun.py
  iam-shrink run --format=cdk --out=policy.ts -- npm test
  iam-shrink explain s3:ListObjectsV2
  iam-shrink export-mappings > custom_mappings.yaml
`)
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	subcommand := os.Args[1]

	switch subcommand {
	case "run":
		handleRun(os.Args[2:])
	case "explain":
		handleExplain(os.Args[2:])
	case "export-mappings":
		handleExportMappings(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Printf("iam-shrink version %s\n", version)
		os.Exit(0)
	case "help", "--help", "-h":
		printUsage()
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command %q\n\n", subcommand)
		printUsage()
		os.Exit(1)
	}
}

func handleRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var (
		formatStr      string
		outFile        string
		includeFailed  bool
		groupByService bool
		strictARNs     bool
		mappingsPath   string
	)

	fs.StringVar(&formatStr, "format", "json", "Output format: json, tf, cdk")
	fs.StringVar(&outFile, "out", "", "Output file path (default: stdout)")
	fs.BoolVar(&includeFailed, "include-failed", true, "Include failed API calls (e.g. 403 AccessDenied)")
	fs.BoolVar(&groupByService, "group-by-service", true, "Group statements by AWS service prefix")
	fs.BoolVar(&strictARNs, "strict-arns", false, "Generate parameterized ARN placeholders instead of '*'")
	fs.StringVar(&mappingsPath, "mappings", "", "Path to custom YAML mappings override file")

	// Split flags from command separated by "--"
	var flagArgs []string
	var cmdArgs []string

	dashIndex := -1
	for i, arg := range args {
		if arg == "--" {
			dashIndex = i
			break
		}
	}

	if dashIndex != -1 {
		flagArgs = args[:dashIndex]
		cmdArgs = args[dashIndex+1:]
	} else {
		// If no "--" was passed, parse until first non-flag arg
		if err := fs.Parse(args); err != nil {
			os.Exit(1)
		}
		cmdArgs = fs.Args()
		flagArgs = nil
	}

	if flagArgs != nil {
		if err := fs.Parse(flagArgs); err != nil {
			os.Exit(1)
		}
	}

	if len(cmdArgs) == 0 {
		fmt.Fprintf(os.Stderr, "Error: no command provided after '--'\n\n")
		printUsage()
		os.Exit(1)
	}

	format := render.FormatType(strings.ToLower(strings.TrimSpace(formatStr)))
	switch format {
	case render.FormatJSON, render.FormatTF, render.FormatCDK:
	default:
		fmt.Fprintf(os.Stderr, "Error: unsupported format %q (allowed: json, tf, cdk)\n", formatStr)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	opts := runner.Options{
		Command:        cmdArgs,
		Format:         format,
		OutputFile:     outFile,
		IncludeFailed:  includeFailed,
		GroupByService: groupByService,
		StrictARNs:     strictARNs,
		CustomMappings: mappingsPath,
		Stdout:         os.Stdout,
		Stderr:         os.Stderr,
	}

	res, err := runner.Run(ctx, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if res.ExitCode != 0 {
		os.Exit(res.ExitCode)
	}
}

func handleExplain(args []string) {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	mappingsPath := fs.String("mappings", "", "Path to custom mappings YAML file")

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	tail := fs.Args()
	if len(tail) == 0 {
		fmt.Fprintf(os.Stderr, "Error: explain requires '<service>:<api>' (e.g. 'iam-shrink explain s3:ListObjectsV2')\n")
		os.Exit(1)
	}

	query := tail[0]

	m, err := mapper.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing mapper: %v\n", err)
		os.Exit(1)
	}

	if *mappingsPath != "" {
		if err := m.LoadOverridesFile(*mappingsPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error loading overrides: %v\n", err)
			os.Exit(1)
		}
	}

	res, err := m.Explain(query)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Service:            %s (IAM Prefix: %s)\n", res.Service, res.ServicePrefix)
	fmt.Printf("SDK API:            %s\n", res.Api)
	fmt.Printf("IAM Actions:        %s\n", strings.Join(res.Actions, ", "))

	if len(res.ResourceARNs) > 0 {
		fmt.Printf("Resource ARNs:\n")
		for _, arn := range res.ResourceARNs {
			fmt.Printf("  - %s\n", arn)
		}
	} else {
		fmt.Printf("Resource ARNs:      *\n")
	}

	if len(res.DependentActions) > 0 {
		fmt.Printf("Dependent Actions:  %s\n", strings.Join(res.DependentActions, ", "))
	} else {
		fmt.Printf("Dependent Actions:  (none)\n")
	}

	if res.IsFallback {
		fmt.Printf("Fallback:           true (unmapped SDK method, inferred '<prefix>:<api>')\n")
	} else {
		fmt.Printf("Fallback:           false (canonical mapping)\n")
	}
}

func handleExportMappings(args []string) {
	fs := flag.NewFlagSet("export-mappings", flag.ContinueOnError)
	mappingsPath := fs.String("mappings", "", "Optional path to custom mappings YAML file to merge before export")

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	m, err := mapper.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing mapper: %v\n", err)
		os.Exit(1)
	}

	if *mappingsPath != "" {
		if err := m.LoadOverridesFile(*mappingsPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error loading overrides: %v\n", err)
			os.Exit(1)
		}
	}

	out, err := m.ExportYAML()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error exporting mappings: %v\n", err)
		os.Exit(1)
	}

	_, _ = os.Stdout.Write(out)
}
