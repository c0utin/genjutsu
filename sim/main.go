// sim drives the genjutsu binary through every arm and harness and prints a
// verdict matrix: an attribution baseline (the canary cannot fire without the
// supervisor), the harness×arm matrix, and a content-firewall evasion check.
//
// It runs the supervisor as a subprocess, so this is a black-box test of the
// shipped binary. Usage: sim [path-to-genjutsu-binary] (default bin/genjutsu).
// Run it from the repository root so the canary/ fixtures resolve.
package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	armControl       = "control"
	armRedirect      = "redirect"
	armSpoof         = "spoof"
	armRedirectSpoof = "redirect-spoof"
	auditPath        = "canary/ground_truth.jsonl"
)

var genjutsuBin string

func main() {
	bin := "bin/genjutsu"
	if len(os.Args) > 1 {
		bin = os.Args[1]
	}
	abs, err := filepath.Abs(bin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sim:", err)
		os.Exit(2)
	}
	if _, err := os.Stat(abs); err != nil {
		fmt.Fprintf(os.Stderr, "sim: genjutsu binary not found at %s (build it first)\n", bin)
		os.Exit(2)
	}
	genjutsuBin = abs
	os.Exit(run())
}

// trace runs "genjutsu <arm> <prog...>" and returns the tool's stdout.
func trace(arm string, prog ...string) string {
	cmd := exec.Command(genjutsuBin, append([]string{arm}, prog...)...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Run()
	return strings.TrimSpace(out.String())
}

func run() int {
	resetFixtures()
	fail := false

	fmt.Println("== attribution baseline (no substrate) ==")
	r := trace(armControl, genjutsuBin, "tool", "read")
	if strings.Contains(r, `content="COVER:`) && !strings.Contains(r, "FORBIDDEN") {
		fmt.Println("  bare read          -> served COVER_DOC (no tamper)   [OK]")
	} else {
		fmt.Printf("  bare read          -> UNEXPECTED: %s   [FAIL]\n", r)
		fail = true
	}
	g := trace(armControl, genjutsuBin, "tool", "guarded-write")
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
		out := trace(rw.arm, wrap(rw.name, genjutsuBin, "tool", rw.flow)...)
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
		out := trace(c.arm, genjutsuBin, "tool", "read")
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

// wrap launches the tool through a given harness so the supervisor's follow-fork
// tracing is exercised across shells and a subprocess spawner.
func wrap(name string, parts ...string) []string {
	switch name {
	case "bash":
		return []string{"/bin/bash", "-c", strings.Join(parts, " ")}
	case "python3":
		return []string{"/usr/bin/env", "python3", "-c",
			fmt.Sprintf("import subprocess;subprocess.run(['%s'])", strings.Join(parts, "','"))}
	case "sh->bash":
		return []string{"/bin/sh", "-c", "/bin/bash -c '" + strings.Join(parts, " ") + "'"}
	default:
		return parts
	}
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
