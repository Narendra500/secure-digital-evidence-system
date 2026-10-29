package main

import (
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"evidence-verifier/internal/verifier"
)

//go:embed public.pem
var defaultPublicKeyPEM []byte

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
)

func main() {
	dirPath := flag.String("dir", "", "Path to the extracted case evidence directory")
	zipPath := flag.String("zip", "", "Path to the case evidence .zip file")
	keyPath := flag.String("key", "", "Path to the server's public key (defaults to embedded public key)")
	jsonOutput := flag.Bool("json", false, "Output verification report as JSON")
	flag.Parse()

	if *dirPath == "" && *zipPath == "" {
		fmt.Fprintf(os.Stderr, "%sError: Please specify either -dir <directory> or -zip <file.zip>%s\n\n", colorRed, colorReset)
		flag.Usage()
		os.Exit(2)
	}

	// 1. Resolve public key
	pubKey := defaultPublicKeyPEM
	if *keyPath != "" {
		customKey, err := os.ReadFile(*keyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%sError reading public key from %s: %v%s\n", colorRed, *keyPath, err, colorReset)
			os.Exit(2)
		}
		pubKey = customKey
	}

	if len(pubKey) == 0 {
		fmt.Fprintf(os.Stderr, "%sError: No public key provided or embedded.%s\n", colorRed, colorReset)
		os.Exit(2)
	}

	// 2. Execute verification
	var rep *verifier.Report
	var err error

	if *zipPath != "" {
		rep, err = verifier.VerifyZip(*zipPath, pubKey)
	} else {
		rep, err = verifier.VerifyDir(*dirPath, pubKey)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "%sVerification Error: %v%s\n", colorRed, err, colorReset)
		os.Exit(1)
	}

	// 3. Render output
	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
		if !rep.Passed {
			os.Exit(1)
		}
		os.Exit(0)
	}

	renderReport(rep)

	if !rep.Passed {
		os.Exit(1)
	}
	os.Exit(0)
}

func renderReport(r *verifier.Report) {
	fmt.Println()
	fmt.Println(colorBold + "================================================================================" + colorReset)
	fmt.Println(colorBold + colorCyan + "       SECURE DIGITAL EVIDENCE SYSTEM (SDES) - EVIDENCE VERIFIER" + colorReset)
	fmt.Println(colorBold + "================================================================================" + colorReset)
	fmt.Printf("Case Public ID: %s\n", r.CasePublicID)
	if r.CaseTitle != "" {
		fmt.Printf("Case Title:     %s\n", r.CaseTitle)
	}
	fmt.Printf("Exported At:    %s\n", r.ExportedAt)
	if r.ExportedBy != "" {
		fmt.Printf("Exported By:    User %s\n", r.ExportedBy)
	}
	if r.LogsFile != "" {
		fmt.Printf("Logs File:      %s\n", r.LogsFile)
	}
	fmt.Printf("Total Files:    %d\n", r.TotalFiles)
	fmt.Println("--------------------------------------------------------------------------------")

	// Server Signature
	if r.SignatureValid {
		fmt.Printf("%s[✓ PASS]%s Server Digital Signature: %sVALID%s (Signed by authorized SDES key)\n",
			colorGreen, colorReset, colorBold+colorGreen, colorReset)
	} else {
		fmt.Printf("%s[✗ FAIL]%s Server Digital Signature: %sINVALID OR FORGED%s\n",
			colorRed, colorReset, colorBold+colorRed, colorReset)
	}

	for _, e := range r.Errors {
		fmt.Printf("  %sError:%s %s\n", colorRed, colorReset, e)
	}

	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Println(colorBold + "EVIDENCE FILES INTEGRITY:" + colorReset)

	for _, fr := range r.Results {
		switch fr.Status {
		case "VERIFIED":
			fmt.Printf("  %s[✓ VERIFIED]%s %-32s (SHA-256: %s...)\n",
				colorGreen, colorReset, fr.Path, truncateHash(fr.ActualHash))
		case "TAMPERED":
			fmt.Printf("  %s[✗ TAMPERED]%s %-32s\n", colorRed, colorReset, fr.Path)
			fmt.Printf("      Expected: %s\n", fr.ExpectedHash)
			fmt.Printf("      Actual:   %s\n", fr.ActualHash)
			fmt.Printf("      %s%s%s\n", colorRed, fr.Message, colorReset)
		case "EXPORT_TAMPERED":
			fmt.Printf("  %s[! TAMPERED AT EXPORT]%s %-32s\n", colorYellow, colorReset, fr.Path)
			fmt.Printf("      %s%s%s\n", colorYellow, fr.Message, colorReset)
		case "MISSING":
			fmt.Printf("  %s[✗ MISSING]%s  %-32s\n", colorRed, colorReset, fr.Path)
			fmt.Printf("      %sFile not present on disk / archive%s\n", colorRed, colorReset)
		case "EXTRA_FILE":
			fmt.Printf("  %s[? UNAUTHORIZED FILE]%s %s\n", colorYellow, colorReset, fr.Path)
			fmt.Printf("      %sFile not recorded in signed manifest%s\n", colorYellow, colorReset)
		default:
			fmt.Printf("  %s[? %s]%s %s: %s\n", colorYellow, fr.Status, colorReset, fr.Path, fr.Message)
		}
	}

	fmt.Println("================================================================================")
	if r.Passed {
		fmt.Printf("%s%sRESULT: [PASS] ALL EVIDENCE INTEGRITY CHECKS SUCCESSFUL (NO TAMPERING DETECTED)%s\n",
			colorBold, colorGreen, colorReset)
	} else {
		fmt.Printf("%s%sRESULT: [FAIL] INTEGRITY COMPROMISED OR TAMPER DETECTED!%s\n",
			colorBold, colorRed, colorReset)
	}
	fmt.Println("================================================================================")
	fmt.Println()
}

func truncateHash(h string) string {
	if len(h) > 16 {
		return h[:16]
	}
	return h
}
