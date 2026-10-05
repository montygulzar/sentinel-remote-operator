package screen

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"testing"
)

func gradient(w, h int) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{R: uint8(x), G: uint8(y), B: 0x40, A: 0xff})
		}
	}
	return img
}

func TestParseFormat(t *testing.T) {
	cases := map[string]Format{
		"":      FormatJPEG, // default
		"jpeg":  FormatJPEG,
		"JPG":   FormatJPEG,
		"png":   FormatPNG,
		" PNG ": FormatPNG,
	}
	for in, want := range cases {
		got, err := ParseFormat(in)
		if err != nil {
			t.Fatalf("ParseFormat(%q): unexpected error %v", in, err)
		}
		if got != want {
			t.Fatalf("ParseFormat(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := ParseFormat("gif"); err == nil {
		t.Fatalf("ParseFormat(gif) should error")
	}
}

func TestEncodeJPEGRoundTrip(t *testing.T) {
	img := gradient(320, 200)
	data, err := Encode(img, FormatJPEG, 80)
	if err != nil {
		t.Fatalf("Encode jpeg: %v", err)
	}
	if !bytes.HasPrefix(data, []byte{0xFF, 0xD8, 0xFF}) {
		t.Fatalf("output is not JPEG (bad magic)")
	}
	out, err := jpeg.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("decode jpeg: %v", err)
	}
	if out.Bounds().Dx() != 320 || out.Bounds().Dy() != 200 {
		t.Fatalf("decoded size = %dx%d, want 320x200", out.Bounds().Dx(), out.Bounds().Dy())
	}
}

func TestEncodePNGRoundTrip(t *testing.T) {
	img := gradient(64, 48)
	data, err := Encode(img, FormatPNG, 0)
	if err != nil {
		t.Fatalf("Encode png: %v", err)
	}
	out, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("decode png: %v", err)
	}
	if out.Bounds().Dx() != 64 || out.Bounds().Dy() != 48 {
		t.Fatalf("decoded size = %dx%d, want 64x48", out.Bounds().Dx(), out.Bounds().Dy())
	}
	// PNG is lossless, so a sampled pixel must survive exactly.
	r, g, b, a := out.At(10, 20).RGBA()
	if uint8(r>>8) != 10 || uint8(g>>8) != 20 || uint8(b>>8) != 0x40 || uint8(a>>8) != 0xff {
		t.Fatalf("png pixel not preserved: got r=%d g=%d b=%d a=%d", r>>8, g>>8, b>>8, a>>8)
	}
}

func TestEncodeQualityAffectsJPEGSize(t *testing.T) {
	img := gradient(256, 256)
	low, err := Encode(img, FormatJPEG, 20)
	if err != nil {
		t.Fatalf("encode low: %v", err)
	}
	high, err := Encode(img, FormatJPEG, 95)
	if err != nil {
		t.Fatalf("encode high: %v", err)
	}
	if len(low) >= len(high) {
		t.Fatalf("lower quality (%dB) should be smaller than higher quality (%dB)", len(low), len(high))
	}
}

func TestEncodeClampsQuality(t *testing.T) {
	img := gradient(32, 32)
	// quality <= 0 means "use default"; >100 clamps to 100. Both must succeed.
	if _, err := Encode(img, FormatJPEG, 0); err != nil {
		t.Fatalf("quality 0 (default): %v", err)
	}
	if _, err := Encode(img, FormatJPEG, 1000); err != nil {
		t.Fatalf("quality 1000 (clamped): %v", err)
	}
}

func TestEncodeNilImage(t *testing.T) {
	if _, err := Encode(nil, FormatJPEG, 80); err == nil {
		t.Fatalf("Encode(nil) should error")
	}
}

func TestContentType(t *testing.T) {
	if FormatJPEG.ContentType() != "image/jpeg" {
		t.Fatalf("jpeg content type wrong")
	}
	if FormatPNG.ContentType() != "image/png" {
		t.Fatalf("png content type wrong")
	}
}
