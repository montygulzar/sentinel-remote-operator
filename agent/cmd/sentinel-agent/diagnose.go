package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/montygulzar/sentinel-remote-operator/agent/internal/platform"
	"github.com/montygulzar/sentinel-remote-operator/agent/internal/screen"
)

// diagnoseReport is the result of a local screen-capture diagnostic.
type diagnoseReport struct {
	Display   string
	Width     int
	Height    int
	Format    string
	CaptureMs int64
	EncodeMs  int64
	Bytes     int
	OutPath   string
}

// diagnoseScreen captures one frame from p and encodes it through the exact
// same CaptureFrame + screen.Encode path that GET /v1/screen/grab uses, then
// writes the encoded image to outPath and returns a report. It is factored out
// of the command so it can be tested with a fake provider.
//
// This is owner-local diagnostic tooling: it runs in-process from the CLI, does
// no network I/O, opens no HTTP route, and touches no credential. Unlike the
// normal Grab Screen path — which keeps the frame in memory and discards it —
// this deliberately writes one clearly-named diagnostic image to a path the
// owner chose, and only here.
func diagnoseScreen(p platform.Provider, display string, format screen.Format, quality int, outPath string) (diagnoseReport, error) {
	frame, err := p.CaptureFrame(display)
	if err != nil {
		return diagnoseReport{}, fmt.Errorf("capture: %w", err)
	}
	encStart := time.Now()
	data, err := screen.Encode(frame.Image, format, quality)
	if err != nil {
		return diagnoseReport{}, fmt.Errorf("encode: %w", err)
	}
	encodeMs := time.Since(encStart).Milliseconds()

	if err := os.WriteFile(outPath, data, 0o600); err != nil {
		return diagnoseReport{}, fmt.Errorf("write %s: %w", outPath, err)
	}

	return diagnoseReport{
		Display:   frame.DisplayID,
		Width:     frame.Width,
		Height:    frame.Height,
		Format:    string(format),
		CaptureMs: frame.CaptureMs,
		EncodeMs:  encodeMs,
		Bytes:     len(data),
		OutPath:   outPath,
	}, nil
}

// cmdDiagnoseScreen is the `sentinel-agent diagnose-screen` command: a local
// field-verification helper for the Windows GDI capture path. It does not start
// the agent, open any port, or require pairing.
func cmdDiagnoseScreen(args []string) error {
	fs := flag.NewFlagSet("diagnose-screen", flag.ContinueOnError)
	out := fs.String("out", "", `output image path (required), e.g. .\sentinel-diagnostic.jpg`)
	display := fs.String("display", "", "display id to capture (default: primary display)")
	formatStr := fs.String("format", "jpeg", "image format: jpeg or png")
	quality := fs.Int("quality", 0, "JPEG quality 1..100 (0 = default)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("diagnose-screen requires -out <path>")
	}
	format, err := screen.ParseFormat(*formatStr)
	if err != nil {
		return err
	}
	if *quality != 0 && (*quality < 1 || *quality > 100) {
		return fmt.Errorf("quality must be between 1 and 100")
	}

	provider := platform.New("")
	rep, err := diagnoseScreen(provider, *display, format, *quality, *out)
	if err != nil {
		return err
	}

	fmt.Println("SENTINEL screen diagnostic — capture path OK")
	fmt.Printf("  display:    %s\n", rep.Display)
	fmt.Printf("  dimensions: %dx%d\n", rep.Width, rep.Height)
	fmt.Printf("  format:     %s\n", rep.Format)
	fmt.Printf("  capture:    %d ms\n", rep.CaptureMs)
	fmt.Printf("  encode:     %d ms\n", rep.EncodeMs)
	fmt.Printf("  output:     %s (%d bytes)\n", rep.OutPath, rep.Bytes)
	return nil
}
