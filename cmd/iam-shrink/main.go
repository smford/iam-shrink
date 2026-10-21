package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/smford/iam-shrink/internal/csm"
	"github.com/smford/iam-shrink/internal/diff"
	"github.com/smford/iam-shrink/internal/linter"
	"github.com/smford/iam-shrink/internal/mapper"
	"github.com/smford/iam-shrink/internal/proxy"
	"github.com/smford/iam-shrink/internal/render"
	"github.com/smford/iam-shrink/internal/runner"
	"github.com/smford/iam-shrink/internal/session"
)

var (
	version = "0.2.0"
)

func printUsage() {
	fmt.Fprintf(os.Stderr, `iam-shrink - Local-to-Least-Privilege AWS IAM Policy Generator

Usage:
  iam-shrink run [flags] -- <command> [args...]
  iam-shrink explain <service>:<api>
  iam-shrink export-mappings [flags]
  iam-shrink diff <existing-policy.json> [captured-policy.json]
  iam-shrink lint <policy.json>
  iam-shrink session <start|status|dump|stop> [flags]
  iam-shrink version

Commands:
  run              Run a command with AWS CSM telemetry and generate an IAM policy
  explain          Show IAM mapping, required ARNs, and dependencies for an SDK API
  export-mappings  Dump the embedded SDK-to-IAM mapping database to YAML
  diff             Compare an existing IAM policy against captured runtime permissions
  lint             Analyze an IAM policy for security risks and privilege escalation
  session          Manage a standalone background daemon session
  version          Show version information

Flags for 'run':
  --format string           Output format: json, tf, cdk, pulumi, cfn (default "json")
  --out string              Output file path (default: stdout)
  --include-failed          Include failed API calls (e.g. 403 AccessDenied) (default true)
  --group-by-service        Group IAM statements by AWS service prefix (default true)
  --split-by-access-level   Split statements by access level (Read/Write/List/Tagging/Permissions) (default false)
  --strict-arns             Generate parameterized ARN placeholders instead of '*' (default false)
  --emit-vars               Emit companion Terraform variable definitions (with --format=tf) (default false)
  --proxy                   Enable local HTTP/HTTPS interception proxy for exact resource extraction (default false)
  --lint                    Run security linter checks on generated policy (default false)
  --diff-against string     Compare generated policy against an existing policy JSON file
  --mappings string         Path to custom YAML file to extend or override mappings

Examples:
  iam-shrink run --format=tf --strict-arns --emit-vars -- go test ./...
  iam-shrink run --format=pulumi -- npm test
  iam-shrink run --format=cfn --out=policy.json -- python deploy_dryrun.py
  iam-shrink run --diff-against=existing_role.json -- go test ./...
  iam-shrink explain s3:ListObjectsV2
  iam-shrink lint my_policy.json
  iam-shrink session start
  iam-shrink session dump --format=tf
  iam-shrink session stop
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
	case "diff":
		handleDiff(os.Args[2:])
	case "lint":
		handleLint(os.Args[2:])
	case "session":
		handleSession(os.Args[2:])
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
		formatStr          string
		outFile            string
		includeFailed      bool
		groupByService     bool
		splitByAccessLevel bool
		strictARNs         bool
		emitVars           bool
		enableProxy        bool
		lintPolicy         bool
		diffAgainst        string
		mappingsPath       string
	)

	fs.StringVar(&formatStr, "format", "json", "Output format: json, tf, cdk, pulumi, cfn")
	fs.StringVar(&outFile, "out", "", "Output file path (default: stdout)")
	fs.BoolVar(&includeFailed, "include-failed", true, "Include failed API calls (e.g. 403 AccessDenied)")
	fs.BoolVar(&groupByService, "group-by-service", true, "Group statements by AWS service prefix")
	fs.BoolVar(&splitByAccessLevel, "split-by-access-level", false, "Split statements by access level")
	fs.BoolVar(&strictARNs, "strict-arns", false, "Generate parameterized ARN placeholders instead of '*'")
	fs.BoolVar(&emitVars, "emit-vars", false, "Emit companion Terraform variables (with --format=tf)")
	fs.BoolVar(&enableProxy, "proxy", false, "Enable HTTP/HTTPS proxy for exact resource extraction")
	fs.BoolVar(&lintPolicy, "lint", false, "Analyze generated policy for security risks")
	fs.StringVar(&diffAgainst, "diff-against", "", "Path to existing policy JSON to compare against")
	fs.StringVar(&mappingsPath, "mappings", "", "Path to custom YAML mappings override file")

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
	case render.FormatJSON, render.FormatTF, render.FormatCDK, render.FormatPulumi, render.FormatCFN:
	default:
		fmt.Fprintf(os.Stderr, "Error: unsupported format %q (allowed: json, tf, cdk, pulumi, cfn)\n", formatStr)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	opts := runner.Options{
		Command:            cmdArgs,
		Format:             format,
		OutputFile:         outFile,
		IncludeFailed:      includeFailed,
		GroupByService:     groupByService,
		SplitByAccessLevel: splitByAccessLevel,
		StrictARNs:         strictARNs,
		EmitVars:           emitVars,
		EnableProxy:        enableProxy,
		DiffAgainst:        diffAgainst,
		LintPolicy:         lintPolicy,
		CustomMappings:     mappingsPath,
		Stdout:             os.Stdout,
		Stderr:             os.Stderr,
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
	fmt.Printf("Access Level:       %s\n", res.AccessLevel)

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

func handleDiff(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: iam-shrink diff <existing-policy.json> [captured-policy.json]\n")
		os.Exit(1)
	}

	existingPath := args[0]
	existingActions, err := diff.ParseActionsFile(existingPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading existing policy %s: %v\n", existingPath, err)
		os.Exit(1)
	}

	var capturedActions []string
	if len(args) >= 2 {
		capturedPath := args[1]
		capturedActions, err = diff.ParseActionsFile(capturedPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading captured policy %s: %v\n", capturedPath, err)
			os.Exit(1)
		}
	} else {
		// Read captured policy from stdin
		stdinData, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
			os.Exit(1)
		}
		capturedActions, err = diff.ParseActions(stdinData)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing policy from stdin: %v\n", err)
			os.Exit(1)
		}
	}

	res := diff.Compare(existingActions, capturedActions)
	fmt.Print(res.Report())
}

func handleLint(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: iam-shrink lint <policy.json>\n")
		os.Exit(1)
	}

	path := args[0]
	issues, err := linter.LintFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error linting policy %s: %v\n", path, err)
		os.Exit(1)
	}

	fmt.Print(linter.FormatIssues(issues))
	if len(issues) > 0 && issues[0].Severity == linter.SeverityCritical {
		os.Exit(2)
	}
}

func handleSession(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: iam-shrink session <start|status|dump|stop> [flags]\n")
		os.Exit(1)
	}

	mgr, err := session.NewManager("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Session error: %v\n", err)
		os.Exit(1)
	}

	switch args[0] {
	case "start":
		handleSessionStart(mgr, args[1:])
	case "status":
		handleSessionStatus(mgr)
	case "dump":
		handleSessionDump(mgr, args[1:])
	case "stop":
		handleSessionStop(mgr, args[1:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown session action %q (allowed: start, status, dump, stop)\n", args[0])
		os.Exit(1)
	}
}

func handleSessionStart(mgr *session.Manager, args []string) {
	existing, err := mgr.LoadSession()
	if err == nil && existing != nil && mgr.IsRunning(existing) {
		fmt.Fprintf(os.Stderr, "Session is already active (PID: %d, Port: %d)\n", existing.PID, existing.CSMPort)
		os.Exit(1)
	}

	enableProxy := false
	for _, arg := range args {
		if arg == "--proxy" {
			enableProxy = true
		}
	}

	collector, err := csm.NewCollector()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create collector: %v\n", err)
		os.Exit(1)
	}
	collector.Start()

	home, _ := os.UserHomeDir()
	eventsFile := filepath.Join(home, ".iam-shrink", "events.jsonl")
	_ = os.Remove(eventsFile)

	var proxyPort int
	var proxySrv *proxy.ProxyServer
	if enableProxy {
		proxySrv, _ = proxy.NewProxyServer()
		if proxySrv != nil {
			proxyPort = proxySrv.Port()
			proxySrv.Start()
		}
	}

	state := session.SessionState{
		PID:        os.Getpid(),
		CSMPort:    collector.Port(),
		ProxyPort:  proxyPort,
		EventsFile: eventsFile,
		StartTime:  time.Now(),
	}

	if err := mgr.SaveSession(state); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to save session: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("iam-shrink background session started successfully!")
	fmt.Printf("Session PID: %d | CSM UDP Port: %d\n", os.Getpid(), collector.Port())
	fmt.Println("\nConfigure your shell or container with:")
	fmt.Printf("  export AWS_CSM_ENABLED=true\n")
	fmt.Printf("  export AWS_CSM_PORT=%d\n", collector.Port())
	fmt.Printf("  export AWS_CSM_HOST=127.0.0.1\n")
	if proxySrv != nil {
		for _, e := range proxySrv.Env() {
			fmt.Printf("  export %s\n", e)
		}
	}
	fmt.Println("\nTo inspect captured policy: iam-shrink session dump")
	fmt.Println("To end session:            iam-shrink session stop")

	// Run event recorder loop until SIGTERM/SIGINT
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	recorded := 0
	for {
		select {
		case <-sigCh:
			collector.StopAndDrain(200 * time.Millisecond)
			if proxySrv != nil {
				proxySrv.Stop()
			}
			return
		case <-ticker.C:
			all := collector.Events()
			if len(all) > recorded {
				for _, e := range all[recorded:] {
					_ = mgr.AppendEvent(eventsFile, e)
				}
				recorded = len(all)
			}
		}
	}
}

func handleSessionStatus(mgr *session.Manager) {
	state, err := mgr.LoadSession()
	if err != nil || state == nil {
		fmt.Println("No active iam-shrink session.")
		return
	}

	running := mgr.IsRunning(state)
	events, _ := mgr.ReadEvents(state.EventsFile)

	fmt.Printf("Session Status:  %s\n", map[bool]string{true: "ACTIVE", false: "STOPPED/ORPHANED"}[running])
	fmt.Printf("Session PID:     %d\n", state.PID)
	fmt.Printf("CSM Port:        %d\n", state.CSMPort)
	if state.ProxyPort > 0 {
		fmt.Printf("Proxy Port:      %d\n", state.ProxyPort)
	}
	fmt.Printf("Elapsed:         %s\n", time.Since(state.StartTime).Round(time.Second))
	fmt.Printf("Captured Events: %d\n", len(events))
}

func handleSessionDump(mgr *session.Manager, args []string) {
	state, err := mgr.LoadSession()
	if err != nil || state == nil {
		fmt.Fprintf(os.Stderr, "Error: no active or saved session found\n")
		os.Exit(1)
	}

	events, err := mgr.ReadEvents(state.EventsFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading session events: %v\n", err)
		os.Exit(1)
	}

	fs := flag.NewFlagSet("session dump", flag.ContinueOnError)
	formatStr := fs.String("format", "json", "Output format: json, tf, cdk, pulumi, cfn")
	strictARNs := fs.Bool("strict-arns", false, "Use strict ARNs")
	groupByService := fs.Bool("group-by-service", true, "Group statements by service")
	splitByAccess := fs.Bool("split-by-access-level", false, "Split statements by access level")

	_ = fs.Parse(args)

	m, err := mapper.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Initializing mapper: %v\n", err)
		os.Exit(1)
	}

	var actionItems []render.ActionItem
	seen := make(map[string]bool)
	for _, e := range events {
		k := fmt.Sprintf("%s:%s", e.Service, e.Api)
		if seen[k] {
			continue
		}
		seen[k] = true
		res := m.Resolve(e.Service, e.Api)
		for _, act := range res.Actions {
			actionItems = append(actionItems, render.ActionItem{
				Action:       act,
				Service:      res.ServicePrefix,
				ResourceARNs: res.ResourceARNs,
				AccessLevel:  res.AccessLevel,
				IsFallback:   res.IsFallback,
			})
		}
	}

	out, err := render.Render(actionItems, render.RenderOptions{
		Format:             render.FormatType(*formatStr),
		GroupByService:     *groupByService,
		SplitByAccessLevel: *splitByAccess,
		StrictARNs:         *strictARNs,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Rendering error: %v\n", err)
		os.Exit(1)
	}

	fmt.Print(out)
}

func handleSessionStop(mgr *session.Manager, args []string) {
	state, err := mgr.StopSession()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error stopping session: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Session (PID: %d) terminated.\n", state.PID)
}
