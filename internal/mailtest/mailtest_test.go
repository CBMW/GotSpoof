package mailtest

import "testing"

func TestValidateLocalPart(t *testing.T) {
	for _, good := range []string{"security.test", "first+proof", "x"} {
		if err := ValidateLocalPart(good); err != nil {
			t.Errorf("rejected %q: %v", good, err)
		}
	}
	for _, bad := range []string{"", ".x", "x.", "x..y", "x y", "x@y"} {
		if err := ValidateLocalPart(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestValidateRecipient(t *testing.T) {
	if got, err := ValidateRecipient("tester@example.com"); err != nil || got != "tester@example.com" {
		t.Fatalf("%q %v", got, err)
	}
	for _, bad := range []string{"Tester <tester@example.com>", "a@b.com\r\nBcc:x@y.com", "not-an-email"} {
		if _, err := ValidateRecipient(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestRenderAddsEvidenceHeader(t *testing.T) {
	raw, err := render(Message{From: "proof@example.com", To: "tester@example.net", Subject: "Evidence", Body: "hello"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{"X-GotSpoof-Test: authorized-security-assessment", "Subject: Evidence", "\r\n\r\nhello\r\n"} {
		if !contains(s, want) {
			t.Errorf("message missing %q", want)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
