// Step-by-step demo of the FALCON keygen → sign → verify pipeline.
//
// Build:
//
//	go build -o gibbs-demo ./cmd/gibbs-demo                  # standard keygen
//	go build -tags gibbs -o gibbs-demo ./cmd/gibbs-demo      # Gibbs keygen
//
// Run with --variant to pick the parameterisation:
//
//	./gibbs-demo --variant det1024     (default; FALCON-DET1024)
//	./gibbs-demo --variant det512      (FALCON-DET512)
//	./gibbs-demo --variant rand1024    (randomised n=1024)
//	./gibbs-demo --variant rand512     (randomised n=512)
//
// Each step prints what it's doing, the inputs, the outputs, and a few
// derived fingerprints so a human can eyeball that two runs with the same
// seed produce identical keys (and, for deterministic variants, identical
// signatures).
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/algorandfoundation/falcon-signatures/falcongo"
)

func main() {
	seedStr := flag.String("seed", "demo-gibbs-seed", "text seed (any string; hashed to 48 bytes)")
	msg := flag.String("msg", "hello, gibbs", "message to sign")
	variantStr := flag.String("variant", "det1024",
		"falcon variant: det1024 | det512 | rand1024 | rand512")
	flag.Parse()

	variant, err := parseVariant(*variantStr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		flag.Usage()
		os.Exit(2)
	}

	// Derive a deterministic 48-byte seed from the input string. SHA-256
	// twice gives 64 bytes; we trim to 48. Don't use this for production —
	// there's no KDF salt or iteration count.
	h1 := sha256.Sum256([]byte(*seedStr))
	h2 := sha256.Sum256(h1[:])
	seed := append(h1[:], h2[:16]...)

	banner(variant)
	step1Keygen(variant, seed, *msg)
}

func parseVariant(s string) (falcongo.Variant, error) {
	switch strings.ToLower(s) {
	case "det1024":
		return falcongo.Det1024, nil
	case "det512":
		return falcongo.Det512, nil
	case "rand1024":
		return falcongo.Rand1024, nil
	case "rand512":
		return falcongo.Rand512, nil
	default:
		return 0, fmt.Errorf("unknown --variant %q (want det1024|det512|rand1024|rand512)", s)
	}
}

func banner(v falcongo.Variant) {
	line := "=================================================================="
	fmt.Println(line)
	fmt.Println("FALCON keygen → sign → verify, step-by-step demo")
	fmt.Println(line)
	fmt.Printf("Variant            : %s\n", v)
	fmt.Printf("Active keygen path : %s\n", keygenPath)
	if keygenWarning != "" {
		fmt.Printf("                     %s\n", keygenWarning)
	}
	fmt.Println(line)
	fmt.Println()
}

func step1Keygen(v falcongo.Variant, seed []byte, msg string) {
	section("Step 1 — Key generation")
	fmt.Printf("  Seed (48 bytes, hex)       : %s\n", hex.EncodeToString(seed))
	fmt.Printf("  Seed SHA-256 fingerprint   : %s\n", fingerprint(seed))

	t0 := time.Now()
	kp, err := falcongo.GenerateVariantKeyPair(v, seed)
	dt := time.Since(t0)
	if err != nil {
		fail("keygen", err)
	}

	fmt.Printf("  Keygen wall time           : %s\n", dt)
	fmt.Printf("  Public key  : %d bytes, fp=%s\n", len(kp.PublicKey), fingerprint(kp.PublicKey))
	fmt.Printf("  Private key : %d bytes, fp=%s\n", len(kp.PrivateKey), fingerprint(kp.PrivateKey))
	fmt.Printf("  Public key  prefix (32 B)  : %s...\n", hex.EncodeToString(prefix(kp.PublicKey, 32)))
	fmt.Printf("  Private key prefix (32 B)  : %s...\n", hex.EncodeToString(prefix(kp.PrivateKey, 32)))
	fmt.Println()

	step2Sign(&kp, msg)
}

func step2Sign(kp *falcongo.VariantKeyPair, msg string) {
	section("Step 2 — Sign")
	fmt.Printf("  Message (utf-8)            : %q\n", msg)
	fmt.Printf("  Message length             : %d bytes\n", len(msg))
	fmt.Printf("  Message SHA-256            : %s\n", fingerprint([]byte(msg)))

	t0 := time.Now()
	sig, err := kp.Sign([]byte(msg))
	dt := time.Since(t0)
	if err != nil {
		fail("sign", err)
	}

	fmt.Printf("  Sign wall time             : %s\n", dt)
	if kp.Variant.IsDeterministic() {
		fmt.Printf("  Signature size             : %d bytes (compressed, variable-length, deterministic)\n", len(sig))
	} else {
		fmt.Printf("  Signature size             : %d bytes (compressed, variable-length, randomised)\n", len(sig))
	}
	fmt.Printf("  Signature SHA-256          : %s\n", fingerprint(sig))
	fmt.Printf("  Signature prefix (32 B)    : %s...\n", hex.EncodeToString(prefix(sig, 32)))

	// Sign a second time and compare. For det variants the bytes must match;
	// for randomised variants they must differ.
	sig2, err := kp.Sign([]byte(msg))
	if err != nil {
		fail("sign (second)", err)
	}
	same := bytes.Equal(sig, sig2)
	switch {
	case kp.Variant.IsDeterministic() && !same:
		fmt.Printf("  Re-sign sanity check       : MISMATCH — UNEXPECTED for deterministic variant\n")
		os.Exit(1)
	case kp.Variant.IsDeterministic() && same:
		fmt.Printf("  Re-sign sanity check       : signatures match (expected for deterministic)\n")
	case !kp.Variant.IsDeterministic() && same:
		fmt.Printf("  Re-sign sanity check       : signatures identical — UNEXPECTED for randomised variant\n")
		os.Exit(1)
	default:
		fmt.Printf("  Re-sign sanity check       : signatures differ (expected for randomised)\n")
		fmt.Printf("                               second SHA-256: %s\n", fingerprint(sig2))
	}

	ctSig, err := falcongo.GetFixedLengthSignatureVariant(kp.Variant, sig)
	switch {
	case err == nil:
		fmt.Printf("  CT-format size             : %d bytes (constant-time, fixed-length)\n", len(ctSig))
	case errors.Is(err, falcongo.ErrCTConvertNotDet):
		fmt.Printf("  CT-format size             : (n/a — randomised variant; expected fixed length: %d bytes)\n",
			kp.Variant.SigCTSize())
	default:
		fmt.Printf("  CT-format size             : conversion error: %v\n", err)
	}
	fmt.Println()

	step3Verify(kp, msg, sig)
}

func step3Verify(kp *falcongo.VariantKeyPair, msg string, sig []byte) {
	section("Step 3 — Verify")
	fmt.Printf("  Verifying signature against original message...\n")
	t0 := time.Now()
	err := falcongo.VerifyVariant(kp.Variant, kp.PublicKey, sig, []byte(msg))
	dt := time.Since(t0)
	if err != nil {
		fmt.Printf("  Result                     : INVALID  (%v)\n", err)
		fail("verify (golden path)", err)
	}
	fmt.Printf("  Result                     : VALID\n")
	fmt.Printf("  Verify wall time           : %s\n", dt)
	fmt.Println()

	step4Tamper(kp, msg, sig)
}

func step4Tamper(kp *falcongo.VariantKeyPair, msg string, sig []byte) {
	section("Step 4 — Tamper test (sanity check that verify rejects bad inputs)")

	// 4a: tampered message
	tampered := []byte(msg)
	tampered[0] ^= 0x01
	fmt.Printf("  4a: flipping low bit of message[0] (%q → %q) ...\n", msg, string(tampered))
	if err := falcongo.VerifyVariant(kp.Variant, kp.PublicKey, sig, tampered); err != nil {
		fmt.Printf("      Result : INVALID — good (%v)\n", err)
	} else {
		fmt.Printf("      Result : VALID — UNEXPECTED, verifier accepted tampered message\n")
		os.Exit(1)
	}

	// 4b: tampered signature byte
	tamperedSig := make([]byte, len(sig))
	copy(tamperedSig, sig)
	tamperedSig[1] ^= 0x01
	fmt.Printf("  4b: flipping low bit of signature[1] ...\n")
	if err := falcongo.VerifyVariant(kp.Variant, kp.PublicKey, tamperedSig, []byte(msg)); err != nil {
		fmt.Printf("      Result : INVALID — good (%v)\n", err)
	} else {
		fmt.Printf("      Result : VALID — UNEXPECTED, verifier accepted tampered signature\n")
		os.Exit(1)
	}

	fmt.Println()
	section("Done — all four steps passed.")
}

func section(title string) {
	fmt.Println("------------------------------------------------------------------")
	fmt.Println(title)
	fmt.Println("------------------------------------------------------------------")
}

func fingerprint(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

func prefix(b []byte, n int) []byte {
	if len(b) < n {
		return b
	}
	return b[:n]
}

func fail(stage string, err error) {
	fmt.Fprintf(os.Stderr, "FAIL at %s: %v\n", stage, err)
	os.Exit(1)
}
