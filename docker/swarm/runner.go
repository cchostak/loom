package swarm

import (
	"context"
	"fmt"
)

// Runner compares attack chains with and without Loom security controls.
type Runner struct {
	Guard        ContentGuard
	Capabilities map[string]map[string]bool
}

// NewRunner creates a runner with least-privilege tool grants.
func NewRunner(guard ContentGuard) *Runner {
	return &Runner{
		Guard: guard,
		Capabilities: map[string]map[string]bool{
			"scout":      {"read_file": true, "list_directory": true},
			"researcher": {"read_text_file": true, "search_files": true},
			"operator":   {"read_file": true},
			"planner":    {},
			"publisher":  {},
			"broker":     {},
		},
	}
}

// Run executes a scenario. Baseline mode intentionally disables controls.
func (r *Runner) Run(ctx context.Context, scenario Scenario, defended bool) (Result, error) {
	mode := "baseline"
	if defended {
		mode = "defended"
	}
	result := Result{Mode: mode, Scenario: scenario.Name, Events: make([]Event, 0, len(scenario.Steps))}

	for _, step := range scenario.Steps {
		event := Event{Agent: step.Agent, Action: describeAction(step), Reason: "attack step propagated"}
		if defended {
			decision, err := r.Guard.Inspect(ctx, step.Phase, step.Content)
			if err != nil {
				return Result{}, fmt.Errorf("scenario %s: %w", scenario.Name, err)
			}
			if decision.Blocked {
				event.Blocked = true
				event.Control = "content-guardrail"
				event.Reason = decision.Reason
				result.Events = append(result.Events, event)
				return result, nil
			}
			if step.CrossesTrustBoundary && step.Trust == "untrusted" {
				event.Blocked = true
				event.Control = "delegation-boundary"
				event.Reason = "untrusted context cannot cross into a more privileged agent"
				result.Events = append(result.Events, event)
				return result, nil
			}
			if step.Tool != "" && !r.Capabilities[step.Agent][step.Tool] {
				event.Blocked = true
				event.Control = "least-privilege-capability"
				event.Reason = fmt.Sprintf("agent %s is not allowed to call %s", step.Agent, step.Tool)
				result.Events = append(result.Events, event)
				return result, nil
			}
		}
		result.Events = append(result.Events, event)
	}

	result.Compromised = true
	return result, nil
}

// Compare runs all scenarios once without controls and once with live controls.
func (r *Runner) Compare(ctx context.Context, scenarios []Scenario) (Report, error) {
	report := Report{
		Baseline: make([]Result, 0, len(scenarios)),
		Defended: make([]Result, 0, len(scenarios)),
	}
	for _, scenario := range scenarios {
		baseline, err := r.Run(ctx, scenario, false)
		if err != nil {
			return Report{}, err
		}
		defended, err := r.Run(ctx, scenario, true)
		if err != nil {
			return Report{}, err
		}
		report.Baseline = append(report.Baseline, baseline)
		report.Defended = append(report.Defended, defended)
		if baseline.Compromised {
			report.BaselineCompromises++
		}
		if defended.Compromised {
			report.DefendedCompromises++
		}
	}
	if report.BaselineCompromises > 0 {
		report.BlockedAttackPercent = 100 * (report.BaselineCompromises - report.DefendedCompromises) / report.BaselineCompromises
	}
	return report, nil
}

func describeAction(step Step) string {
	if step.Tool != "" {
		return "call tool " + step.Tool
	}
	if step.TargetAgent != "" {
		return "handoff to " + step.TargetAgent
	}
	return "process content"
}
