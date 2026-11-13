package host

import (
	"testing"
)

func TestParseInstanceUUIDAcceptsCanonicalAndHex(t *testing.T) {
	canonical := "87ede5a2-9c3d-492d-9bbe-989b9d07e742"
	id, text, err := parseInstanceUUID(canonical)
	if err != nil {
		t.Fatalf("parse canonical UUID: %v", err)
	}
	if text != canonical {
		t.Fatalf("canonical UUID string = %q, want %q", text, canonical)
	}
	if id == nil {
		t.Fatal("parsed UUID was nil")
	}

	_, compact, err := parseInstanceUUID("87EDE5A29C3D492D9BBE989B9D07E742")
	if err != nil {
		t.Fatalf("parse compact UUID: %v", err)
	}
	if compact != canonical {
		t.Fatalf("compact UUID string = %q, want %q", compact, canonical)
	}
}

func TestParseInstanceUUIDRejectsInvalidValues(t *testing.T) {
	for _, input := range []string{"", "not-a-uuid", "87ede5a2-9c3d-492d-9bbe", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"} {
		if _, _, err := parseInstanceUUID(input); err == nil {
			t.Fatalf("parseInstanceUUID(%q) succeeded", input)
		}
	}
}

func TestNewInstanceUUIDRoundTrip(t *testing.T) {
	id, text, err := newInstanceUUID()
	if err != nil {
		t.Fatalf("newInstanceUUID: %v", err)
	}
	parsed, parsedText, err := parseInstanceUUID(text)
	if err != nil {
		t.Fatalf("parse generated UUID: %v", err)
	}
	if parsedText != text {
		t.Fatalf("round-trip UUID string = %q, want %q", parsedText, text)
	}
	if parsed.GetPart1() != id.GetPart1() || parsed.GetPart2() != id.GetPart2() ||
		parsed.GetPart3() != id.GetPart3() || parsed.GetPart4() != id.GetPart4() {
		t.Fatalf("round-trip UUID parts = %+v, want %+v", parsed, id)
	}
}
