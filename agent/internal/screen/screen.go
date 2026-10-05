// Package screen encodes captured display frames into a wire image format. It
// is deliberately platform-independent: the Windows-specific pixel grab lives
// behind platform.Provider, while format selection, quality handling and the
// encode itself are ordinary Go that is unit-tested on any OS.
//
// Grab Screen exists to be quicker and lighter than a live screen session
// (THIRD ARTILLERY ORDER), so the default format is JPEG, which keeps a
// full-desktop frame small while leaving text and progress bars readable. PNG
// is offered for when exactness matters more than size. Nothing here writes to
// disk: encoding is memory-to-memory.
package screen

import (
	"bytes"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"strings"
)

// Format is a supported wire image format.
type Format string

const (
	FormatJPEG Format = "jpeg"
	FormatPNG  Format = "png"

	// DefaultFormat and DefaultQuality are the server-side defaults when the
	// request does not specify them. Quality 80 is a sensible size/clarity
	// tradeoff for a readable desktop frame.
	DefaultFormat  = FormatJPEG
	DefaultQuality = 80
)

// ParseFormat maps a request string to a Format, defaulting an empty string to
// DefaultFormat. An unrecognised value is an error so a client learns it asked
// for something unsupported rather than silently getting a different format.
func ParseFormat(s string) (Format, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return DefaultFormat, nil
	case "jpeg", "jpg":
		return FormatJPEG, nil
	case "png":
		return FormatPNG, nil
	default:
		return "", fmt.Errorf("unsupported image format %q (want jpeg or png)", s)
	}
}

// ContentType returns the MIME type for the format.
func (f Format) ContentType() string {
	switch f {
	case FormatPNG:
		return "image/png"
	default:
		return "image/jpeg"
	}
}

// clampQuality constrains a JPEG quality to the valid 1..100 range. A
// non-positive value (i.e. unspecified) becomes DefaultQuality.
func clampQuality(q int) int {
	if q <= 0 {
		return DefaultQuality
	}
	if q > 100 {
		return 100
	}
	return q
}

// Encode renders img into the requested format and returns the encoded bytes.
// quality applies to JPEG only (1..100; <=0 means the default) and is ignored
// for PNG. The returned format is the one actually used.
func Encode(img image.Image, format Format, quality int) ([]byte, error) {
	if img == nil {
		return nil, fmt.Errorf("nil image")
	}
	var buf bytes.Buffer
	switch format {
	case FormatPNG:
		if err := png.Encode(&buf, img); err != nil {
			return nil, fmt.Errorf("encode png: %w", err)
		}
	case FormatJPEG:
		if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: clampQuality(quality)}); err != nil {
			return nil, fmt.Errorf("encode jpeg: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported image format %q", format)
	}
	return buf.Bytes(), nil
}
