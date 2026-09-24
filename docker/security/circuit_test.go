package security

import (
	"testing"
	"time"
)

func TestCircuit(t *testing.T) {
	for _, name := range []string{"initial", "one failure", "two failures", "three failures", "cooldown", "success resets"} {
		t.Run(name, func(t *testing.T) {
			c := new(Circuit)
			now := time.Now()
			failures := 0
			switch name {
			case "one failure":
				failures = 1
			case "two failures":
				failures = 2
			case "three failures", "cooldown", "success resets":
				failures = 3
			}
			for i := 0; i < failures; i++ {
				if name == "success resets" && i == 2 {
					c.Complete(true, now)
				}
				c.Complete(false, now)
			}
			if name == "cooldown" {
				now = now.Add(31 * time.Second)
			}
			if c.Allow(now) != (name != "three failures") {
				t.Fatal(name)
			}
		})
	}
}
