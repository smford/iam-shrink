package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/smford/iam-shrink/internal/advisor"
	"github.com/smford/iam-shrink/internal/ci"
	"github.com/smford/iam-shrink/internal/cloudtrail"
	"github.com/smford/iam-shrink/internal/compliance"
	"github.com/smford/iam-shrink/internal/csm"
	"github.com/smford/iam-shrink/internal/diff"
	"github.com/smford/iam-shrink/internal/k8s"
	"github.com/smford/iam-shrink/internal/linter"
	"github.com/smford/iam-shrink/internal/mapper"
	"github.com/smford/iam-shrink/internal/optimizer"
	"github.com/smford/iam-shrink/internal/proxy"
	"github.com/smford/iam-shrink/internal/render"
	"github.com/smford/iam-shrink/internal/runner"
	"github.com/smford/iam-shrink/internal/session"
	"github.com/smford/iam-shrink/internal/state"
	"github.com/smford/iam-shrink/internal/verifier"
	"github.com/smford/iam-shrink/internal/vscode"
	"github.com/smford/iam-shrink/internal/webui"
)

var (
	version = "0.5.0"
)

func printUsage() {
	fmt.Fprintf(os.Stderr, `iam-shrink - Local-to-Least-Privilege AWS IAM Policy Generator

Usage:
  iam-shrink run [flags] -- <command> [args...]
  iam-shrink ingest [flags] <cloudtrail-file-or-dir>
  iam-shrink patch --file=<main.tf> [flags] -- <command> [args...]
  iam-shrink prune-role <role-policy.json> [flags]
  iam-shrink verify <base-policy.json> <shrunk-policy.json>
  iam-shrink optimize [flags] <policy.json>
  iam-shrink report [flags] <policy.json>
  iam-shrink update-rules [flags]
  iam-shrink state <terraform.tfstate> [policy.json]
  iam-shrink pr-comment [flags]
  iam-shrink gate [flags] <policy.json>
  iam-shrink ui [flags] [policy.json]
  iam-shrink diff <existing-policy.json> [captured-policy.json]
  iam-shrink lint <policy.json>
  iam-shrink explain <service>:<api>
  iam-shrink export-mappings [flags]
  iam-shrink k8s manifest [flags]
  iam-shrink init-vscode [flags]
  iam-shrink session <start|status|dump|stop> [flags]
  iam-shrink version

Commands:
  run              Run a command with AWS CSM telemetry and generate an IAM policy
  ingest           Process AWS CloudTrail logs (.json, .json.gz) and synthesize a policy
  patch            Execute a command and update a Terraform .tf file in-place
  prune-role       Prune unaccessed permissions from an existing IAM role policy
  verify           Verify mathematically that a shrunk policy is a strict subset of base
  optimize         Compress policy size and optimize statements to fit under AWS IAM limits
  report           Audit an IAM policy against CIS AWS Foundations or NIST SP 800-53 benchmarks
  update-rules     Download updated CIS & NIST rule schemas to ~/.iam-shrink/rules/
  state            Resolve parameterized ARN variables using Terraform/OpenTofu tfstate
  pr-comment       Generate a formatted GitHub/GitLab Pull Request markdown comment
  gate             Enforce a CI/CD quality gate (blocks builds on wildcards or high risks)
  ui               Start the local interactive Web UI & access graph visualizer
  diff             Compare an existing IAM policy against captured runtime permissions
  lint             Analyze an IAM policy for security risks and privilege escalation
  explain          Show IAM mapping, required ARNs, and dependencies for an SDK API
  export-mappings  Dump the embedded SDK-to-IAM mapping database to YAML
  k8s              Generate Kubernetes IRSA and pod telemetry manifests
  init-vscode      Generate .vscode/tasks.json configuring iam-shrink for test suites
  session          Manage a standalone background daemon session
  version          Show version information

Flags for 'run':
  --format string           Output format: json, tf, cdk, cdktf, pulumi, cfn, gcp, azure, k8s-rbac, vault (default "json")
  --policy-type string      Policy type: identity, boundary, scp, resource (default "identity")
  --out string              Output file path (default: stdout)
  --patch-file string       Path to Terraform .tf file to patch in-place
  --include-failed          Include failed API calls (e.g. 403 AccessDenied) (default true)
  --group-by-service        Group IAM statements by AWS service prefix (default true)
  --split-by-access-level   Split statements by access level (Read/Write/List/Tagging/Permissions) (default false)
  --strict-arns             Generate parameterized ARN placeholders instead of '*' (default false)
  --emit-vars               Emit companion Terraform variable definitions (with --format=tf) (default false)
  --conditions              Synthesize AWS condition blocks (e.g. aws:RequestedRegion) (default false)
  --synthesize-notaction    Invert policy into an explicit Deny with NotAction (default false)
  --principal string        Principal ARN for resource-based policies (default: account root)
  --proxy                   Enable local HTTP/HTTPS interception proxy for exact resource extraction (default false)
  --compliance string       Evaluate compliance during run: cis, nist, all (default "")
  --export-otel string      Export captured calls to OpenTelemetry trace JSON file (default "")
  --lint                    Run security linter checks on generated policy (default false)
  --diff-against string     Compare generated policy against an existing policy JSON file
  --mappings string         Path to custom YAML file to extend or override mappings

Examples:
  iam-shrink run --format=tf --strict-arns --emit-vars -- go test ./...
  iam-shrink run --format=gcp -- python test_suite.py
  iam-shrink verify production_base.json shrunk_policy.json
  iam-shrink optimize --minify policy.json
  iam-shrink ui --port=8080 policy.json
  iam-shrink report --standard=cis policy.json
  iam-shrink state terraform.tfstate policy.json
  iam-shrink gate --fail-on-wildcard policy.json
  iam-shrink pr-comment --existing=base_role.json --captured=new_policy.json --standard=cis
`)
}

func parseFlagsAndPosArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var flagArgs []string
	var posArgs []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			flagArgs = append(flagArgs, a)
			if !strings.Contains(a, "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				f := fs.Lookup(strings.TrimLeft(a, "-"))
				if f != nil {
					if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); !ok || !bf.IsBoolFlag() {
						flagArgs = append(flagArgs, args[i+1])
						i++
					}
				} else {
					flagArgs = append(flagArgs, args[i+1])
					i++
				}
			}
		} else {
			posArgs = append(posArgs, a)
		}
	}
	if err := fs.Parse(flagArgs); err != nil {
		return nil, err
	}
	return posArgs, nil
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
	case "ingest":
		handleIngest(os.Args[2:])
	case "patch":
		handlePatch(os.Args[2:])
	case "prune-role":
		handlePruneRole(os.Args[2:])
	case "verify":
		handleVerify(os.Args[2:])
	case "optimize":
		handleOptimize(os.Args[2:])
	case "ui":
		handleUI(os.Args[2:])
	case "report":
		handleReport(os.Args[2:])
	case "update-rules":
		handleUpdateRules(os.Args[2:])
	case "state":
		handleState(os.Args[2:])
	case "pr-comment":
		handlePRComment(os.Args[2:])
	case "gate":
		handleGate(os.Args[2:])
	case "diff":
		handleDiff(os.Args[2:])
	case "lint":
		handleLint(os.Args[2:])
	case "explain":
		handleExplain(os.Args[2:])
	case "export-mappings":
		handleExportMappings(os.Args[2:])
	case "k8s":
		handleK8s(os.Args[2:])
	case "init-vscode":
		handleInitVSCode(os.Args[2:])
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
		formatStr            string
		policyTypeStr        string
		outFile              string
		patchFile            string
		patchTarget          string
		includeFailed        bool
		groupByService       bool
		splitByAccessLevel   bool
		strictARNs           bool
		emitVars             bool
		synthesizeConditions bool
		synthesizeNotAction  bool
		principalARN         string
		enableProxy          bool
		complianceStandard   string
		exportOTel           string
		lintPolicy           bool
		diffAgainst          string
		mappingsPath         string
		optimizeSize         bool
	)

	fs.StringVar(&formatStr, "format", "json", "Output format: json, tf, cdk, cdktf, pulumi, cfn")
	fs.StringVar(&policyTypeStr, "policy-type", "identity", "Policy type: identity, boundary, scp, resource")
	fs.StringVar(&outFile, "out", "", "Output file path (default: stdout)")
	fs.StringVar(&patchFile, "patch-file", "", "Path to Terraform .tf file to patch in-place")
	fs.StringVar(&patchTarget, "patch-target", "", "Target block name to patch (default: first match)")
	fs.BoolVar(&includeFailed, "include-failed", true, "Include failed API calls (e.g. 403 AccessDenied)")
	fs.BoolVar(&groupByService, "group-by-service", true, "Group statements by AWS service prefix")
	fs.BoolVar(&splitByAccessLevel, "split-by-access-level", false, "Split statements by access level")
	fs.BoolVar(&strictARNs, "strict-arns", false, "Generate parameterized ARN placeholders instead of '*'")
	fs.BoolVar(&emitVars, "emit-vars", false, "Emit companion Terraform variables (with --format=tf)")
	fs.BoolVar(&synthesizeConditions, "conditions", false, "Synthesize AWS condition blocks")
	fs.BoolVar(&synthesizeNotAction, "synthesize-notaction", false, "Invert policy into an explicit Deny with NotAction")
	fs.StringVar(&principalARN, "principal", "", "Principal ARN for resource-based policies")
	fs.BoolVar(&enableProxy, "proxy", false, "Enable HTTP/HTTPS proxy for exact resource extraction")
	fs.StringVar(&complianceStandard, "compliance", "", "Evaluate compliance during run: cis, nist, all")
	fs.StringVar(&exportOTel, "export-otel", "", "Path to write OpenTelemetry trace JSON file")
	fs.BoolVar(&lintPolicy, "lint", false, "Analyze generated policy for security risks")
	fs.StringVar(&diffAgainst, "diff-against", "", "Path to existing policy JSON to compare against")
	fs.StringVar(&mappingsPath, "mappings", "", "Path to custom YAML mappings override file")
	fs.BoolVar(&optimizeSize, "optimize-size", false, "Minify and compress JSON policy to minimize byte quota")

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
	policyType := render.PolicyType(strings.ToLower(strings.TrimSpace(policyTypeStr)))

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	opts := runner.Options{
		Command:              cmdArgs,
		Format:               format,
		PolicyType:           policyType,
		OutputFile:           outFile,
		PatchFile:            patchFile,
		PatchTarget:          patchTarget,
		IncludeFailed:        includeFailed,
		GroupByService:       groupByService,
		SplitByAccessLevel:   splitByAccessLevel,
		StrictARNs:           strictARNs,
		EmitVars:             emitVars,
		SynthesizeConditions: synthesizeConditions,
		SynthesizeNotAction:  synthesizeNotAction,
		PrincipalARN:         principalARN,
		EnableProxy:          enableProxy,
		ComplianceStandard:   complianceStandard,
		ExportOTel:           exportOTel,
		DiffAgainst:          diffAgainst,
		LintPolicy:           lintPolicy,
		CustomMappings:       mappingsPath,
		OptimizeSize:         optimizeSize,
		Stdout:               os.Stdout,
		Stderr:               os.Stderr,
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

func handleReport(args []string) {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	standardName := fs.String("standard", "cis", "Compliance standard: cis, nist")
	customRules := fs.String("rules", "", "Path to custom compliance rules YAML file")
	outputFormat := fs.String("format", "terminal", "Output format: terminal, markdown, json")

	files, err := parseFlagsAndPosArgs(fs, args)
	if err != nil {
		os.Exit(1)
	}

	if len(files) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: iam-shrink report [--standard=cis|nist] <policy.json>\n")
		os.Exit(1)
	}

	policyPath := files[0]
	actions, err := diff.ParseActionsFile(policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading policy %s: %v\n", policyPath, err)
		os.Exit(1)
	}

	reg, err := compliance.NewRegistry(*customRules)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Initializing compliance registry: %v\n", err)
		os.Exit(1)
	}

	resByAct := make(map[string][]string)
	for _, a := range actions {
		resByAct[strings.ToLower(a)] = []string{"*"}
	}

	rep, err := reg.Evaluate(*standardName, actions, resByAct)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Evaluation error: %v\n", err)
		os.Exit(1)
	}

	switch *outputFormat {
	case "markdown":
		fmt.Print(rep.FormatMarkdown())
	case "json":
		data, _ := os.ReadFile(policyPath)
		_ = data
		fmt.Println(rep.FormatTerminal())
	default:
		fmt.Print(rep.FormatTerminal())
	}
}

func handleUpdateRules(args []string) {
	fs := flag.NewFlagSet("update-rules", flag.ContinueOnError)
	sourceURL := fs.String("source", "", "Custom rules feed URL")
	urlAlias := fs.String("url", "", "Alias for --source")

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	targetURL := *sourceURL
	if targetURL == "" && *urlAlias != "" {
		targetURL = *urlAlias
	}

	dest, err := compliance.UpdateRules(targetURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to update rules: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Updated compliance rule baseline saved to %s\n", dest)
}

func handleState(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: iam-shrink state <terraform.tfstate> [policy.json]\n")
		os.Exit(1)
	}

	statePath := args[0]
	stateData, err := os.ReadFile(statePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading state file %s: %v\n", statePath, err)
		os.Exit(1)
	}

	var policyText string
	if len(args) >= 2 {
		data, err := os.ReadFile(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading policy %s: %v\n", args[1], err)
			os.Exit(1)
		}
		policyText = string(data)
	} else {
		stdinData, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
			os.Exit(1)
		}
		policyText = string(stdinData)
	}

	resolved, count, err := state.ResolvePolicyWithState(policyText, stateData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "State resolution error: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Resolved %d deployed resource ARNs from %s\n", count, statePath)
	fmt.Print(resolved)
}

func handlePRComment(args []string) {
	fs := flag.NewFlagSet("pr-comment", flag.ContinueOnError)
	existingPath := fs.String("existing", "", "Path to baseline/existing policy JSON")
	capturedPath := fs.String("captured", "", "Path to new/captured policy JSON")
	standard := fs.String("standard", "cis", "Compliance standard to include in report")

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if *existingPath == "" || *capturedPath == "" {
		fmt.Fprintf(os.Stderr, "Usage: iam-shrink pr-comment --existing=base.json --captured=new.json [--standard=cis]\n")
		os.Exit(1)
	}

	existingActions, err := diff.ParseActionsFile(*existingPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Reading existing policy %s: %v\n", *existingPath, err)
		os.Exit(1)
	}

	capturedActions, err := diff.ParseActionsFile(*capturedPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Reading captured policy %s: %v\n", *capturedPath, err)
		os.Exit(1)
	}

	diffRes := diff.Compare(existingActions, capturedActions)

	reg, err := compliance.NewRegistry("")
	var compRep *compliance.Report
	if err == nil && *standard != "" {
		resByAct := make(map[string][]string)
		for _, a := range capturedActions {
			resByAct[strings.ToLower(a)] = []string{"*"}
		}
		compRep, _ = reg.Evaluate(*standard, capturedActions, resByAct)
	}

	fmt.Print(ci.FormatPRComment(diffRes, compRep))
}

func handleGate(args []string) {
	fs := flag.NewFlagSet("gate", flag.ContinueOnError)
	failOnWildcard := fs.Bool("fail-on-wildcard", true, "Fail build if wildcard actions are present")
	maxSeverity := fs.String("max-severity", "HIGH", "Fail build if violations equal or exceed severity")
	minCompliance := fs.Float64("min-compliance", 75.0, "Minimum compliance score (0-100)")
	standard := fs.String("standard", "cis", "Standard to evaluate: cis, nist")

	files, err := parseFlagsAndPosArgs(fs, args)
	if err != nil {
		os.Exit(1)
	}

	if len(files) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: iam-shrink gate [flags] <policy.json>\n")
		os.Exit(1)
	}

	policyPath := files[0]
	actions, err := diff.ParseActionsFile(policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading policy %s: %v\n", policyPath, err)
		os.Exit(1)
	}

	issues, _ := linter.LintFile(policyPath)

	reg, err := compliance.NewRegistry("")
	var compRep *compliance.Report
	if err == nil {
		resByAct := make(map[string][]string)
		for _, a := range actions {
			resByAct[strings.ToLower(a)] = []string{"*"}
		}
		compRep, _ = reg.Evaluate(*standard, actions, resByAct)
	}

	gateOpts := ci.GateOptions{
		FailOnWildcard: *failOnWildcard,
		MaxSeverity:    *maxSeverity,
		MinCompliance:  *minCompliance,
	}

	res := ci.EvaluateGate(actions, issues, compRep, gateOpts)
	if !res.Passed {
		fmt.Fprintf(os.Stderr, "❌ Quality Gate FAILED (%d violations):\n", len(res.Reasons))
		for _, r := range res.Reasons {
			fmt.Fprintf(os.Stderr, "  - %s\n", r)
		}
		os.Exit(1)
	}

	fmt.Println("✅ Quality Gate PASSED: Policy meets least-privilege standards.")
}

func handleIngest(args []string) {
	fs := flag.NewFlagSet("ingest", flag.ContinueOnError)
	formatStr := fs.String("format", "json", "Output format: json, tf, cdk, pulumi, cfn")
	policyTypeStr := fs.String("policy-type", "identity", "Policy type: identity, boundary, scp, resource")
	outFile := fs.String("out", "", "Output file path (default: stdout)")
	strictARNs := fs.Bool("strict-arns", true, "Use strict ARNs")
	groupByService := fs.Bool("group-by-service", true, "Group statements by service")
	splitByAccess := fs.Bool("split-by-access-level", false, "Split by access level")
	includeFailed := fs.Bool("include-failed", true, "Include failed events")

	paths, err := parseFlagsAndPosArgs(fs, args)
	if err != nil {
		os.Exit(1)
	}

	if len(paths) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: iam-shrink ingest [flags] <cloudtrail-file-or-dir>\n")
		os.Exit(1)
	}

	targetPath := paths[0]
	events, err := cloudtrail.ParsePath(targetPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading CloudTrail logs %s: %v\n", targetPath, err)
		os.Exit(1)
	}

	m, err := mapper.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing mapper: %v\n", err)
		os.Exit(1)
	}

	var actionItems []render.ActionItem
	seen := make(map[string]bool)

	for _, item := range events {
		if !*includeFailed && item.Event.IsFailed() {
			continue
		}
		callKey := fmt.Sprintf("%s:%s", item.Event.Service, item.Event.Api)
		if seen[callKey] {
			continue
		}
		seen[callKey] = true

		res := m.Resolve(item.Event.Service, item.Event.Api)
		rARNs := res.ResourceARNs
		if len(item.ResourceARNs) > 0 {
			rARNs = item.ResourceARNs
		}

		for _, act := range res.Actions {
			actionItems = append(actionItems, render.ActionItem{
				Action:       act,
				Service:      res.ServicePrefix,
				ResourceARNs: rARNs,
				AccessLevel:  res.AccessLevel,
				IsFallback:   res.IsFallback,
			})
		}
	}

	renderOpts := render.RenderOptions{
		Format:             render.FormatType(*formatStr),
		PolicyType:         render.PolicyType(*policyTypeStr),
		GroupByService:     *groupByService,
		SplitByAccessLevel: *splitByAccess,
		StrictARNs:         *strictARNs,
	}

	rendered, err := render.Render(actionItems, renderOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Rendering error: %v\n", err)
		os.Exit(1)
	}

	if *outFile != "" {
		if err := os.WriteFile(*outFile, []byte(rendered), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Writing to %s: %v\n", *outFile, err)
			os.Exit(1)
		}
	} else {
		fmt.Print(rendered)
	}
}

func handlePatch(args []string) {
	fs := flag.NewFlagSet("patch", flag.ContinueOnError)
	filePath := fs.String("file", "", "Path to .tf file to patch")
	targetName := fs.String("target", "", "Target data source name (default: first match)")

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if *filePath == "" {
		fmt.Fprintf(os.Stderr, "Error: --file is required for patch command\n")
		os.Exit(1)
	}

	cmdArgs := fs.Args()
	if len(cmdArgs) > 0 && cmdArgs[0] == "--" {
		cmdArgs = cmdArgs[1:]
	}

	if len(cmdArgs) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: iam-shrink patch --file=main.tf [flags] -- <command> [args...]\n")
		os.Exit(1)
	}

	opts := runner.Options{
		Command:        cmdArgs,
		Format:         render.FormatTF,
		PatchFile:      *filePath,
		PatchTarget:    *targetName,
		IncludeFailed:  true,
		GroupByService: true,
		StrictARNs:     true,
		Stdout:         os.Stdout,
		Stderr:         os.Stderr,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	_, err := runner.Run(ctx, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Patch run error: %v\n", err)
		os.Exit(1)
	}
}

func handlePruneRole(args []string) {
	fs := flag.NewFlagSet("prune-role", flag.ContinueOnError)
	activeActionsFlag := fs.String("active-actions", "", "Comma-separated list of active actions (e.g. s3:GetObject,dynamodb:PutItem)")
	outFile := fs.String("out", "", "Output file for pruned policy (default: stdout)")

	files, err := parseFlagsAndPosArgs(fs, args)
	if err != nil {
		os.Exit(1)
	}

	if len(files) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: iam-shrink prune-role [flags] <role-policy.json> --active-actions=\"s3:GetObject,...\"\n")
		os.Exit(1)
	}

	policyPath := files[0]
	policyData, err := os.ReadFile(policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Reading role policy %s: %v\n", policyPath, err)
		os.Exit(1)
	}

	var active []string
	if *activeActionsFlag != "" {
		for _, a := range strings.Split(*activeActionsFlag, ",") {
			trimmed := strings.TrimSpace(a)
			if trimmed != "" {
				active = append(active, trimmed)
			}
		}
	}

	res, err := advisor.PrunePolicy(policyData, active)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Prune error: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Pruning complete: Removed %d actions (%.1f%% attack surface reduction).\n\n", len(res.PrunedActions), res.ReductionPct)

	if *outFile != "" {
		if err := os.WriteFile(*outFile, res.PrunedPolicyDoc, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Writing to %s: %v\n", *outFile, err)
			os.Exit(1)
		}
	} else {
		_, _ = os.Stdout.Write(res.PrunedPolicyDoc)
	}
}

func handleK8s(args []string) {
	if len(args) < 1 || args[0] != "manifest" {
		fmt.Fprintf(os.Stderr, "Usage: iam-shrink k8s manifest [flags]\n")
		os.Exit(1)
	}

	fs := flag.NewFlagSet("k8s manifest", flag.ContinueOnError)
	deployName := fs.String("deployment", "my-app", "Deployment name")
	ns := fs.String("namespace", "default", "Kubernetes namespace")
	csmPort := fs.Int("csm-port", 31000, "CSM UDP port")
	proxyPort := fs.Int("proxy-port", 31001, "Proxy TCP port")
	enableProxy := fs.Bool("proxy", false, "Include proxy configuration")
	image := fs.String("image", "ghcr.io/smford/iam-shrink:latest", "iam-shrink container image")

	_ = fs.Parse(args[1:])

	opts := k8s.ManifestOptions{
		DeploymentName: *deployName,
		Namespace:      *ns,
		CSMPort:        *csmPort,
		ProxyPort:      *proxyPort,
		EnableProxy:    *enableProxy,
		Image:          *image,
	}

	fmt.Print(k8s.GeneratePodSidecarYAML(opts))
}

func handleInitVSCode(args []string) {
	fs := flag.NewFlagSet("init-vscode", flag.ContinueOnError)
	testCmd := fs.String("test-cmd", "go test ./...", "Test command to configure in VS Code tasks")

	_ = fs.Parse(args)

	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}

	taskPath, err := vscode.WriteTasksFile(cwd, *testCmd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing tasks.json: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Created %s successfully!\nRun tasks via Cmd+Shift+P (or Ctrl+Shift+P) -> 'Tasks: Run Task' -> 'iam-shrink'.\n", taskPath)
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
	formatStr := fs.String("format", "json", "Output format: json, tf, cdk, cdktf, pulumi, cfn")
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

func readPolicyInput(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func handleVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	jsonOut := fs.Bool("json", false, "Output verification result as JSON")
	strict := fs.Bool("strict", true, "Exit with code 1 if shrunk policy is not a strict mathematical subset")

	posArgs, err := parseFlagsAndPosArgs(fs, args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	if len(posArgs) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: iam-shrink verify [flags] <base-policy.json> <shrunk-policy.json>")
		fmt.Fprintln(os.Stderr, "\nPerforms formal subset and equivalence verification to mathematically guarantee")
		fmt.Fprintln(os.Stderr, "that the shrunk policy grants no permissions beyond the base policy (0 shadow expansions).")
		os.Exit(1)
	}

	baseBytes, err := readPolicyInput(posArgs[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading base policy %q: %v\n", posArgs[0], err)
		os.Exit(1)
	}

	shrunkBytes, err := readPolicyInput(posArgs[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading shrunk policy %q: %v\n", posArgs[1], err)
		os.Exit(1)
	}

	res, err := verifier.VerifyPolicyBytes(baseBytes, shrunkBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Verification error: %v\n", err)
		os.Exit(1)
	}

	if *jsonOut {
		enc, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(enc))
	} else {
		if res.IsSubset {
			fmt.Println("✓ Verification PASS: Shrunk policy is a strict mathematical subset of the base policy.")
			if res.IsEquivalent {
				fmt.Printf("  Equivalence: base and shrunk policies grant the exact same set of %d actions.\n", res.BaseActionCount)
			} else {
				fmt.Printf("  Reduction: reduced from %d base permissions to %d active permissions.\n", res.BaseActionCount, res.TargetActionCount)
				fmt.Println("  Shadow expansions: 0 (no ungranted actions or wildcard escalations detected).")
			}
		} else {
			fmt.Println("✗ Verification FAIL: Shrunk policy introduces permissions not permitted by base policy!")
			fmt.Printf("  Found %d shadow expansion(s):\n", len(res.Expansions))
			for _, exp := range res.Expansions {
				fmt.Printf("    - Action: %-30s Resource: %-20s (%s)\n", exp.Action, exp.Resource, exp.Reason)
			}
		}
	}

	if *strict && !res.IsSubset {
		os.Exit(1)
	}
}

func handleOptimize(args []string) {
	fs := flag.NewFlagSet("optimize", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	outFile := fs.String("out", "", "Output file path (default: stdout)")
	checkOnly := fs.Bool("check", false, "Check quota limits only and exit with status code")

	posArgs, err := parseFlagsAndPosArgs(fs, args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	var data []byte
	if len(posArgs) > 0 {
		data, err = readPolicyInput(posArgs[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading policy %q: %v\n", posArgs[0], err)
			os.Exit(1)
		}
	} else {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			data, err = io.ReadAll(os.Stdin)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading from stdin: %v\n", err)
				os.Exit(1)
			}
		} else {
			fmt.Fprintln(os.Stderr, "Usage: iam-shrink optimize [flags] <policy.json>")
			os.Exit(1)
		}
	}

	res, err := optimizer.OptimizePolicyJSON(string(data))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Optimization error: %v\n", err)
		os.Exit(1)
	}

	if *checkOnly {
		fmt.Printf("Policy Size Analysis:\n")
		fmt.Printf("  Original size:  %d bytes\n", res.OriginalBytes)
		fmt.Printf("  Optimized size: %d bytes\n", res.OptimizedBytes)
		fmt.Printf("  Saved:          %d bytes (%.1f%% reduction)\n", res.SavedBytes, res.SavedPct)
		fmt.Printf("  Inline quota (max 2,048 bytes):   %s\n", quotaStatus(res.ExceedsInline, res.OptimizedBytes, optimizer.LimitInlinePolicy))
		fmt.Printf("  Managed quota (max 10,240 bytes):  %s\n", quotaStatus(res.ExceedsManaged, res.OptimizedBytes, optimizer.LimitManagedPolicy))
		if res.ExceedsManaged {
			os.Exit(2)
		} else if res.ExceedsInline {
			os.Exit(1)
		}
		os.Exit(0)
	}

	if *outFile != "" {
		if err := os.WriteFile(*outFile, []byte(res.OptimizedJSON), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Writing output to %s: %v\n", *outFile, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Optimized policy written to %s (%d bytes, saved %.1f%%)\n", *outFile, res.OptimizedBytes, res.SavedPct)
	} else {
		fmt.Println(res.OptimizedJSON)
	}
}

func quotaStatus(exceeds bool, current, limit int) string {
	if exceeds {
		return fmt.Sprintf("EXCEEDED (%d / %d bytes, +%d bytes over limit)", current, limit, current-limit)
	}
	return fmt.Sprintf("PASS (%d / %d bytes, %d bytes remaining)", current, limit, limit-current)
}

func handleUI(args []string) {
	fs := flag.NewFlagSet("ui", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	port := fs.Int("port", 8080, "Port to bind local Web UI server")

	posArgs, err := parseFlagsAndPosArgs(fs, args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	var actionItems []render.ActionItem
	if len(posArgs) > 0 {
		data, err := readPolicyInput(posArgs[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading policy %q: %v\n", posArgs[0], err)
			os.Exit(1)
		}
		actionItems, err = extractActionsFromPolicyOrEvents(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing policy: %v\n", err)
			os.Exit(1)
		}
	} else {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			data, err := io.ReadAll(os.Stdin)
			if err == nil && len(data) > 0 {
				actionItems, _ = extractActionsFromPolicyOrEvents(data)
			}
		}
	}

	srv, err := webui.NewServer(*port, actionItems)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error starting web UI server: %v\n", err)
		os.Exit(1)
	}
	srv.Start()
	defer srv.Stop()

	fmt.Printf("iam-shrink Web UI active at http://127.0.0.1:%d\n", srv.Port())
	fmt.Printf("Loaded %d IAM action(s) for interactive visualization and multi-format export.\n", len(actionItems))
	fmt.Println("Press Ctrl+C to exit.")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan
	fmt.Println("\nShutting down web UI server...")
}

func extractActionsFromPolicyOrEvents(data []byte) ([]render.ActionItem, error) {
	var policy struct {
		Statement []struct {
			Effect   string      `json:"Effect"`
			Action   interface{} `json:"Action"`
			Resource interface{} `json:"Resource"`
		} `json:"Statement"`
	}

	if err := json.Unmarshal(data, &policy); err == nil && len(policy.Statement) > 0 {
		var items []render.ActionItem
		seen := make(map[string]bool)
		for _, stmt := range policy.Statement {
			var actions []string
			switch v := stmt.Action.(type) {
			case string:
				actions = append(actions, v)
			case []interface{}:
				for _, act := range v {
					if s, ok := act.(string); ok {
						actions = append(actions, s)
					}
				}
			}

			var resources []string
			switch v := stmt.Resource.(type) {
			case string:
				resources = append(resources, v)
			case []interface{}:
				for _, res := range v {
					if s, ok := res.(string); ok {
						resources = append(resources, s)
					}
				}
			}

			for _, act := range actions {
				if seen[act] {
					continue
				}
				seen[act] = true
				svc := "aws"
				if parts := strings.Split(act, ":"); len(parts) == 2 {
					svc = parts[0]
				}
				items = append(items, render.ActionItem{
					Action:       act,
					Service:      svc,
					ResourceARNs: resources,
					AccessLevel:  "Active",
				})
			}
		}
		return items, nil
	}

	var rawItems []render.ActionItem
	if err := json.Unmarshal(data, &rawItems); err == nil && len(rawItems) > 0 {
		return rawItems, nil
	}

	return nil, fmt.Errorf("unrecognized format: expected IAM policy JSON with Statement array")
}
