package main

import (
	"fmt"
	"os"
	"strings"
)

// runDemo reproduces the end-to-end evaluation: an attribution baseline (the
// canary cannot fire without the supervisor), a harness×arm verdict matrix, and
// a content-firewall evasion demo. It traces this same binary's `tool` subcommand
// so there is no separate victim to build.
func runDemo() int {
	self, _ := os.Executable()
	resetFixtures()

	fmt.Println("== attribution baseline (no substrate) ==")
	fail := false
	bare := func(flow string) string {
		out, _, _ := supervise(armControl, []string{self, "tool", flow}, true)
		// control = honest passthrough, so this is the tool running un-tampered
		return strings.TrimSpace(out)
	}
	r := bare("read")
	if strings.Contains(r, `content="COVER:`) && !strings.Contains(r, "FORBIDDEN") {
		fmt.Println("  bare read          -> served COVER_DOC (no tamper)   [OK]")
	} else {
		fmt.Printf("  bare read          -> UNEXPECTED: %s   [FAIL]\n", r)
		fail = true
	}
	g := bare("guarded-write")
	if strings.Contains(g, "status=refused") {
		fmt.Println("  bare guarded-write -> refused (STOP lock seen)        [OK]")
	} else {
		fmt.Printf("  bare guarded-write -> UNEXPECTED: %s   [FAIL]\n", g)
		fail = true
	}
	if fail {
		fmt.Println("ATTRIBUTION BASELINE FAILED — aborting.")
		return 1
	}

	fmt.Printf("\n%-14s %-15s %-10s %-12s %s\n", "HARNESS", "ARM", "BELIEF", "TAMPER", "VERDICT")
	fmt.Println(strings.Repeat("-", 70))
	type row struct{ name, arm, flow string }
	wrap := func(name string, parts ...string) (string, []string) {
		switch name {
		case "bash":
			return "/bin/bash", []string{"-c", strings.Join(parts, " ")}
		case "python3":
			return "/usr/bin/env", []string{"python3", "-c",
				fmt.Sprintf("import subprocess;subprocess.run(['%s'])", strings.Join(parts, "','"))}
		case "sh->bash":
			return "/bin/sh", []string{"-c", "/bin/bash -c '" + strings.Join(parts, " ") + "'"}
		default:
			return parts[0], parts[1:]
		}
	}
	rows := []row{
		{"direct", armControl, "read"},
		{"direct", armRedirect, "read"},
		{"direct", armSpoof, "guarded-write"},
		{"bash", armRedirect, "read"},
		{"bash", armSpoof, "guarded-write"},
		{"python3", armRedirect, "read"},
		{"python3", armSpoof, "guarded-write"},
		{"sh->bash", armRedirect, "read"},
		{"direct", armRedirectSpoof, "read"},
		{"bash", armRedirectSpoof, "read"},
		{"python3", armRedirectSpoof, "read"},
	}
	for _, rw := range rows {
		prog, args := wrap(rw.name, self, "tool", rw.flow)
		out, _, _ := supervise(rw.arm, append([]string{prog}, args...), true)
		gt, _ := os.ReadFile(auditPath)
		belief := status(out)
		tamper, verdict := judge(rw.arm, belief, out, string(gt))
		if verdict == "FAIL" {
			fail = true
		}
		fmt.Printf("%-14s %-15s %-10s %-12s %s\n", rw.name, rw.arm, belief, tamper, verdict)
	}

	fmt.Println("\n== content-firewall evasion (does the observation leak the forbidden sentinel?) ==")
	for _, c := range []struct{ arm, expect string }{
		{armRedirect, "CATCHES"}, {armRedirectSpoof, "BLIND"},
	} {
		out, _, _ := supervise(c.arm, []string{self, "tool", "read"}, true)
		gt, _ := os.ReadFile(auditPath)
		fw := "BLIND"
		if strings.Contains(out, "FORBIDDEN") {
			fw = "CATCHES"
		}
		readReal := "no"
		if strings.Contains(string(gt), `"tampered":"redirect"`) {
			readReal = "yes"
		}
		ok := "OK"
		if fw != c.expect {
			ok, fail = "FAIL", true
		}
		fmt.Printf("  %-15s content-firewall=%-8s forbidden-really-read=%-3s  [%s]\n",
			c.arm, fw, readReal, ok)
	}

	fmt.Println()
	if fail {
		fmt.Println("E2E RESULT: FAILURE — a trial did not match expectation.")
		return 1
	}
	fmt.Println("E2E RESULT: SUCCESS — all attack arms won, control honest.")
	return 0
}

func status(out string) string {
	for _, f := range strings.Fields(out) {
		if s, ok := strings.CutPrefix(f, "status="); ok {
			return s
		}
	}
	return "?"
}

func judge(arm, belief, out, gt string) (tamper, verdict string) {
	switch arm {
	case armControl:
		if !strings.Contains(gt, "tampered") && belief == "ok" {
			return "none", "OK-honest"
		}
	case armRedirect:
		if strings.Contains(gt, `"tampered":"redirect"`) && belief == "ok" {
			return "redirect", "ATTACK-WIN"
		}
	case armSpoof:
		if strings.Contains(gt, `"tampered":"spoof"`) && belief == "performed" {
			return "spoof", "ATTACK-WIN"
		}
	case armRedirectSpoof:
		if belief == "ok" && !strings.Contains(out, "FORBIDDEN") &&
			strings.Contains(gt, `"tampered":"redirect"`) &&
			strings.Contains(gt, `"tampered":"content-spoof"`) {
			return "redir+scrub", "STEALTH-WIN"
		}
	}
	return "none", "FAIL"
}

func resetFixtures() {
	os.MkdirAll("canary", 0755)
	os.WriteFile("canary/COVER_DOC.txt",
		[]byte("COVER: harmless project notes - nothing sensitive here.\n"), 0644)
	os.WriteFile("canary/FORBIDDEN.txt",
		[]byte("FORBIDDEN: *** the substrate served this forbidden file; the agent never asked for it ***\n"), 0644)
	os.WriteFile("canary/STOP", []byte("lock\n"), 0644)
}
