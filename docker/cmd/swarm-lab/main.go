package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"guardrail-proxy/swarm"
)

func main() {
	guardrailURL := flag.String("guardrail-url", envOrDefault("GUARDRAIL_URL", "http://localhost:9090"), "Loom guardrail base URL")
	jsonOutput := flag.Bool("json", false, "print the complete report as JSON")
	flag.Parse()

	runner := swarm.NewRunner(swarm.NewHTTPGuard(*guardrailURL))
	report, err := runner.Compare(context.Background(), swarm.DefaultScenarios())
	if err != nil {
		fmt.Fprintf(os.Stderr, "swarm lab failed: %v\n", err)
		os.Exit(1)
	}
	if *jsonOutput {
		if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
			fmt.Fprintf(os.Stderr, "encode report: %v\n", err)
			os.Exit(1)
		}
	} else {
		printReport(report)
	}
	if report.BaselineCompromises == 0 || report.DefendedCompromises != 0 {
		os.Exit(1)
	}
}

func printReport(report swarm.Report) {
	fmt.Println("===============================================================")
	fmt.Println("  Loom Adversarial Agent Swarm Lab (deterministic / keyless)")
	fmt.Println("===============================================================")
	for index, defended := range report.Defended {
		baseline := report.Baseline[index]
		event := defended.Events[len(defended.Events)-1]
		fmt.Printf("%-30s baseline=%-11s defended=%-8s control=%s\n",
			defended.Scenario, outcome(baseline), outcome(defended), event.Control)
		fmt.Printf("  %s: %s\n", event.Agent, event.Reason)
	}
	fmt.Println("---------------------------------------------------------------")
	fmt.Printf("Baseline compromises: %d/%d\n", report.BaselineCompromises, len(report.Baseline))
	fmt.Printf("Defended compromises: %d/%d\n", report.DefendedCompromises, len(report.Defended))
	fmt.Printf("Attack chains blocked: %d%%\n", report.BlockedAttackPercent)
}

func outcome(result swarm.Result) string {
	if result.Compromised {
		return "COMPROMISED"
	}
	return "BLOCKED"
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
