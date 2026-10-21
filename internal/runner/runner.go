package runner

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/smford/iam-shrink/internal/compliance"
	"github.com/smford/iam-shrink/internal/csm"
	"github.com/smford/iam-shrink/internal/diff"
	"github.com/smford/iam-shrink/internal/linter"
	"github.com/smford/iam-shrink/internal/mapper"
	"github.com/smford/iam-shrink/internal/multicloud"
	"github.com/smford/iam-shrink/internal/optimizer"
	"github.com/smford/iam-shrink/internal/otel"
	"github.com/smford/iam-shrink/internal/patcher"
	"github.com/smford/iam-shrink/internal/proxy"
	"github.com/smford/iam-shrink/internal/render"
)

// Options configures the execution of a child command and policy generation.
type Options struct {
	Command              []string
	Format               render.FormatType
	PolicyType           render.PolicyType
	OutputFile           string
	PatchFile            string
	PatchTarget          string
	IncludeFailed        bool
	GroupByService       bool
	SplitByAccessLevel   bool
	StrictARNs           bool
	EmitVars             bool
	SynthesizeConditions bool
	SynthesizeNotAction  bool
	PrincipalARN         string
	EnableProxy          bool
	ComplianceStandard   string // "cis", "nist", "all"
	ExportOTel           string // Path to write OTel JSON traces
	DiffAgainst          string
	LintPolicy           bool
	CustomMappings       string // Path to optional YAML overrides
	OptimizeSize         bool   // Compress and minify output policy JSON
	Stdout               io.Writer
	Stderr               io.Writer
}

// Result holds the generated policy and child exit code.
type Result struct {
	Policy   string
	ExitCode int
	Events   []csm.Event
	Actions  []render.ActionItem
}

// Run executes the command under CSM monitoring and generates the least-privilege IAM policy.
func Run(ctx context.Context, opts Options) (*Result, error) {
	if len(opts.Command) == 0 {
		return nil, fmt.Errorf("no command provided to run")
	}

	stdoutWriter := opts.Stdout
	if stdoutWriter == nil {
		stdoutWriter = os.Stdout
	}
	stderrWriter := opts.Stderr
	if stderrWriter == nil {
		stderrWriter = os.Stderr
	}

	// 1. Initialize mapper
	m, err := mapper.New()
	if err != nil {
		return nil, fmt.Errorf("initializing mapper: %w", err)
	}
	if opts.CustomMappings != "" {
		if err := m.LoadOverridesFile(opts.CustomMappings); err != nil {
			return nil, fmt.Errorf("loading custom mappings %q: %w", opts.CustomMappings, err)
		}
	}

	// 2. Start CSM Collector
	collector, err := csm.NewCollector()
	if err != nil {
		return nil, fmt.Errorf("starting CSM collector: %w", err)
	}
	collector.Start()

	// 2b. Start Proxy if requested
	var proxySrv *proxy.ProxyServer
	if opts.EnableProxy {
		var pErr error
		proxySrv, pErr = proxy.NewProxyServer()
		if pErr != nil {
			collector.StopAndDrain(50 * time.Millisecond)
			return nil, fmt.Errorf("starting HTTP proxy: %w", pErr)
		}
		proxySrv.Start()
		defer proxySrv.Stop()
	}

	// 3. Prepare child process
	childCmd := exec.CommandContext(ctx, opts.Command[0], opts.Command[1:]...)

	// Inherit environment and inject CSM variables
	env := os.Environ()
	env = append(env,
		"AWS_CSM_ENABLED=true",
		fmt.Sprintf("AWS_CSM_PORT=%d", collector.Port()),
		"AWS_CSM_HOST=127.0.0.1",
	)
	if proxySrv != nil {
		env = append(env, proxySrv.Env()...)
	}
	childCmd.Env = env

	// Route child I/O
	// If outputting policy to stdout (OutputFile is empty), redirect child stdout to stderr
	// to prevent child logs from corrupting stdout JSON/HCL/CDK output.
	if opts.OutputFile == "" {
		childCmd.Stdout = stderrWriter
	} else {
		childCmd.Stdout = stdoutWriter
	}
	childCmd.Stderr = stderrWriter

	// 4. Start command and setup signal forwarding
	if err := childCmd.Start(); err != nil {
		collector.StopAndDrain(50 * time.Millisecond)
		return nil, fmt.Errorf("failed to start command %v: %w", opts.Command, err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	go func() {
		select {
		case sig, ok := <-sigCh:
			if ok && childCmd.Process != nil {
				_ = childCmd.Process.Signal(sig)
			}
		case <-ctx.Done():
			if childCmd.Process != nil {
				_ = childCmd.Process.Kill()
			}
		}
	}()

	// 5. Wait for child process to exit
	waitErr := childCmd.Wait()
	exitCode := 0
	if waitErr != nil {
		if exitErr, ok := waitErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}

	// 6. Drain trailing packets (200ms)
	collector.StopAndDrain(200 * time.Millisecond)

	// 7. Process collected events
	rawEvents := collector.Events()
	var actionItems []render.ActionItem

	var exactResources map[string][]string
	if proxySrv != nil {
		exactResources = proxySrv.Resources()
	}

	// Map (Service, Api) pairs
	seenCalls := make(map[string]bool)
	for _, evt := range rawEvents {
		if evt.Service == "" || evt.Api == "" {
			continue
		}

		if !opts.IncludeFailed && evt.IsFailed() {
			continue
		}

		callKey := fmt.Sprintf("%s:%s", evt.Service, evt.Api)
		if seenCalls[callKey] {
			continue
		}
		seenCalls[callKey] = true

		resolved := m.Resolve(evt.Service, evt.Api)

		// Check if proxy extracted exact ARNs for this API
		resourceARNs := resolved.ResourceARNs
		if exactResources != nil {
			proxyKey := strings.ToLower(evt.Service) + ":" + strings.ToLower(evt.Api)
			if exact, found := exactResources[proxyKey]; found && len(exact) > 0 {
				resourceARNs = exact
			}
		}

		for _, act := range resolved.Actions {
			actionItems = append(actionItems, render.ActionItem{
				Action:       act,
				Service:      resolved.ServicePrefix,
				ResourceARNs: resourceARNs,
				AccessLevel:  resolved.AccessLevel,
				IsFallback:   resolved.IsFallback,
				FallbackNote: fmt.Sprintf("unmapped fallback from SDK call %s:%s", evt.Service, evt.Api),
			})
		}
	}

	// 8. Render policy
	renderOpts := render.RenderOptions{
		Format:               opts.Format,
		PolicyType:           opts.PolicyType,
		GroupByService:       opts.GroupByService,
		SplitByAccessLevel:   opts.SplitByAccessLevel,
		StrictARNs:           opts.StrictARNs,
		EmitVars:             opts.EmitVars,
		SynthesizeConditions: opts.SynthesizeConditions,
		SynthesizeNotAction:  opts.SynthesizeNotAction,
		PrincipalARN:         opts.PrincipalARN,
	}

	var renderedPolicy string
	switch opts.Format {
	case render.FormatGCP:
		renderedPolicy, err = multicloud.RenderGCPIAMCustomRole(actionItems)
	case render.FormatAzure:
		renderedPolicy, err = multicloud.RenderAzureRBAC(actionItems)
	case render.FormatK8sRBAC:
		renderedPolicy = multicloud.RenderK8sRBAC(actionItems)
	case render.FormatVault:
		jsonPol, jErr := render.Render(actionItems, render.RenderOptions{Format: render.FormatJSON})
		if jErr != nil {
			return nil, fmt.Errorf("rendering vault policy: %w", jErr)
		}
		renderedPolicy = multicloud.RenderVaultSecretRole(jsonPol)
	default:
		renderedPolicy, err = render.Render(actionItems, renderOpts)
	}

	if err != nil {
		return nil, fmt.Errorf("rendering policy: %w", err)
	}

	if opts.OptimizeSize && (opts.Format == render.FormatJSON || opts.Format == "") {
		optRes, oErr := optimizer.OptimizePolicyJSON(renderedPolicy)
		if oErr == nil {
			renderedPolicy = optRes.OptimizedJSON
		}
	}

	// Optional OpenTelemetry Export
	if opts.ExportOTel != "" {
		if err := otel.ExportToFile(opts.ExportOTel, rawEvents); err != nil {
			_, _ = fmt.Fprintf(stderrWriter, "Warning: failed to export OTel traces to %s: %v\n", opts.ExportOTel, err)
		} else {
			_, _ = fmt.Fprintf(stderrWriter, "Exported OTel trace spans to %s\n", opts.ExportOTel)
		}
	}

	// Optional Compliance Check
	if opts.ComplianceStandard != "" {
		reg, err := compliance.NewRegistry("")
		if err == nil {
			var actNames []string
			resByAct := make(map[string][]string)
			for _, item := range actionItems {
				actNames = append(actNames, item.Action)
				resByAct[strings.ToLower(item.Action)] = item.ResourceARNs
			}
			stds := []string{opts.ComplianceStandard}
			if opts.ComplianceStandard == "all" {
				stds = []string{"cis", "nist"}
			}
			for _, s := range stds {
				report, err := reg.Evaluate(s, actNames, resByAct)
				if err == nil {
					_, _ = io.WriteString(stderrWriter, "\n"+report.FormatTerminal())
				}
			}
		}
	}

	// Optional Terraform in-place patching
	if opts.PatchFile != "" {
		patchHCL := renderedPolicy
		if opts.Format != render.FormatTF {
			// Generate TF format specifically for patching
			patchOpts := renderOpts
			patchOpts.Format = render.FormatTF
			patchHCL, _ = render.Render(actionItems, patchOpts)
		}
		if err := patcher.PatchTerraformFile(patcher.PatchOptions{
			FilePath:     opts.PatchFile,
			TargetName:   opts.PatchTarget,
			NewHCL:       patchHCL,
			CreateBackup: true,
		}); err != nil {
			return nil, fmt.Errorf("patching terraform file %s: %w", opts.PatchFile, err)
		}
		_, _ = fmt.Fprintf(stderrWriter, "Successfully patched %s (backup created at %s.bak)\n", opts.PatchFile, opts.PatchFile)
	}

	// Optional Linter
	if opts.LintPolicy {
		var stmtsInput []linter.StatementInput
		stmts := render.BuildStatements(actionItems, renderOpts)
		for _, s := range stmts {
			var acts []string
			for _, a := range s.Actions {
				acts = append(acts, a.Action)
			}
			stmtsInput = append(stmtsInput, linter.StatementInput{
				Sid:       s.Sid,
				Effect:    "Allow",
				Actions:   acts,
				Resources: s.ResourceARNs,
			})
		}
		issues := linter.LintStatements(stmtsInput)
		lintReport := linter.FormatIssues(issues)
		_, _ = io.WriteString(stderrWriter, "\n"+lintReport)
	}

	// Optional Diff against existing policy
	if opts.DiffAgainst != "" {
		existingActions, err := diff.ParseActionsFile(opts.DiffAgainst)
		if err != nil {
			_, _ = fmt.Fprintf(stderrWriter, "Warning: failed to read diff policy %s: %v\n", opts.DiffAgainst, err)
		} else {
			var capturedActions []string
			for _, item := range actionItems {
				capturedActions = append(capturedActions, item.Action)
			}
			diffRes := diff.Compare(existingActions, capturedActions)
			_, _ = io.WriteString(stderrWriter, "\n"+diffRes.Report())
		}
	}

	// 9. Write policy to output destination
	if opts.OutputFile != "" {
		if err := os.WriteFile(opts.OutputFile, []byte(renderedPolicy), 0644); err != nil {
			return nil, fmt.Errorf("writing policy to %q: %w", opts.OutputFile, err)
		}
	} else {
		_, _ = io.WriteString(stdoutWriter, renderedPolicy)
	}

	return &Result{
		Policy:   renderedPolicy,
		ExitCode: exitCode,
		Events:   rawEvents,
		Actions:  actionItems,
	}, nil
}

// ParseCSMPort parses the AWS_CSM_PORT environment variable if present.
func ParseCSMPort() int {
	p := os.Getenv("AWS_CSM_PORT")
	if p == "" {
		return 0
	}
	val, err := strconv.Atoi(p)
	if err != nil {
		return 0
	}
	return val
}

func sortStrings(s []string) []string {
	res := append([]string(nil), s...)
	sort.Strings(res)
	return res
}
