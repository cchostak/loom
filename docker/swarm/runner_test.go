package swarm

import (
	"context"
	"errors"
	"testing"
)

type fakeGuard struct {
	blocked map[string]bool
	err     error
}

func (g fakeGuard) Inspect(_ context.Context, _ Phase, content string) (Decision, error) {
	if g.err != nil {
		return Decision{}, g.err
	}
	return Decision{Blocked: g.blocked[content], Reason: "test policy"}, nil
}

func TestRunBaselineCompromises(t *testing.T) {
	scenario := DefaultScenarios()[0]
	runner := NewRunner(fakeGuard{})

	result, err := runner.Run(context.Background(), scenario, false)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !result.Compromised {
		t.Fatal("baseline must demonstrate the attack chain")
	}
}

func TestRunContentGuardBlocks(t *testing.T) {
	scenario := DefaultScenarios()[0]
	runner := NewRunner(fakeGuard{blocked: map[string]bool{scenario.Steps[0].Content: true}})

	result, err := runner.Run(context.Background(), scenario, true)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Compromised || result.Events[0].Control != "content-guardrail" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestRunCapabilityPolicyBlocks(t *testing.T) {
	scenario := DefaultScenarios()[1]
	runner := NewRunner(fakeGuard{})

	result, err := runner.Run(context.Background(), scenario, true)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Compromised || result.Events[0].Control != "least-privilege-capability" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestRunDelegationBoundaryBlocks(t *testing.T) {
	scenario := DefaultScenarios()[2]
	runner := NewRunner(fakeGuard{})

	result, err := runner.Run(context.Background(), scenario, true)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Compromised || result.Events[0].Control != "delegation-boundary" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestCompareCalculatesScore(t *testing.T) {
	scenarios := DefaultScenarios()
	blocked := make(map[string]bool)
	blocked[scenarios[0].Steps[0].Content] = true
	blocked[scenarios[3].Steps[0].Content] = true
	runner := NewRunner(fakeGuard{blocked: blocked})

	report, err := runner.Compare(context.Background(), scenarios)
	if err != nil {
		t.Fatalf("Compare() error = %v", err)
	}
	if report.BaselineCompromises != 4 || report.DefendedCompromises != 0 || report.BlockedAttackPercent != 100 {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestRunFailsClosedOnGuardError(t *testing.T) {
	runner := NewRunner(fakeGuard{err: errors.New("offline")})

	_, err := runner.Run(context.Background(), DefaultScenarios()[0], true)
	if err == nil {
		t.Fatal("Run() error = nil, want guardrail error")
	}
}

func TestDescribeAction(t *testing.T) {
	tests := []struct {
		step Step
		want string
	}{
		{Step{Tool: "read_file"}, "call tool read_file"},
		{Step{TargetAgent: "planner"}, "handoff to planner"},
		{Step{}, "process content"},
	}
	for _, test := range tests {
		if got := describeAction(test.step); got != test.want {
			t.Errorf("describeAction(%+v) = %q, want %q", test.step, got, test.want)
		}
	}
}
