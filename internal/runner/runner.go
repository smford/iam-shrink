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
	"syscall"
	"time"

	"github.com/smford/iam-shrink/internal/csm"
	"github.com/smford/iam-shrink/internal/mapper"
	"github.com/smford/iam-shrink/internal/render"
)

// Options configures the execution of a child command and policy generation.
type Options struct {
	Command        []string
	Format         render.FormatType
	OutputFile     string
	IncludeFailed  bool
	GroupByService bool
	StrictARNs     bool
	CustomMappings string // Path to optional YAML overrides
	Stdout         io.Writer
	Stderr         io.Writer
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

	// 3. Prepare child process
	childCmd := exec.CommandContext(ctx, opts.Command[0], opts.Command[1:]...)

	// Inherit environment and inject CSM variables
	env := os.Environ()
	env = append(env,
		"AWS_CSM_ENABLED=true",
		fmt.Sprintf("AWS_CSM_PORT=%d", collector.Port()),
		"AWS_CSM_HOST=127.0.0.1",
	)
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
		for _, act := range resolved.Actions {
			actionItems = append(actionItems, render.ActionItem{
				Action:       act,
				Service:      resolved.ServicePrefix,
				ResourceARNs: resolved.ResourceARNs,
				IsFallback:   resolved.IsFallback,
				FallbackNote: fmt.Sprintf("unmapped fallback from SDK call %s:%s", evt.Service, evt.Api),
			})
		}
	}

	// 8. Render policy
	renderOpts := render.RenderOptions{
		Format:         opts.Format,
		GroupByService: opts.GroupByService,
		StrictARNs:     opts.StrictARNs,
	}

	renderedPolicy, err := render.Render(actionItems, renderOpts)
	if err != nil {
		return nil, fmt.Errorf("rendering policy: %w", err)
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
