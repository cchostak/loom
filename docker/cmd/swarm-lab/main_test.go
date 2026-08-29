package main

import (
	"os"
	"testing"

	"guardrail-proxy/swarm"
)

func TestOutcome(t *testing.T) {
	if got := outcome(swarm.Result{Compromised: true}); got != "COMPROMISED" {
		t.Errorf("outcome(compromised) = %q", got)
	}
	if got := outcome(swarm.Result{}); got != "BLOCKED" {
		t.Errorf("outcome(blocked) = %q", got)
	}
}

func TestEnvOrDefault(t *testing.T) {
	const name = "LOOM_TEST_ENV_OR_DEFAULT"
	_ = os.Unsetenv(name)
	if got := envOrDefault(name, "fallback"); got != "fallback" {
		t.Errorf("envOrDefault() = %q, want fallback", got)
	}
	t.Setenv(name, "configured")
	if got := envOrDefault(name, "fallback"); got != "configured" {
		t.Errorf("envOrDefault() = %q, want configured", got)
	}
}
