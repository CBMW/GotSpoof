package assessment

import (
	"context"
	"errors"
	"testing"
)

type fakeResolver map[string][]string

func (f fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	return f[name], nil
}

type errResolver struct{}

func (errResolver) LookupTXT(context.Context, string) ([]string, error) {
	return nil, errors.New("offline")
}

func TestNormalizeDomain(t *testing.T) {
	got, err := NormalizeDomain(" Example.COM. ")
	if err != nil || got != "example.com" {
		t.Fatalf("got %q, %v", got, err)
	}
	for _, bad := range []string{"https://example.com", "a@b.com", "localhost", "-x.com"} {
		if _, err := NormalizeDomain(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestAssessmentVerdicts(t *testing.T) {
	tests := []struct {
		name, domain, want string
		dns                fakeResolver
	}{
		{"missing dmarc", "example.com", "exposed", fakeResolver{"example.com": {"v=spf1 -all"}}},
		{"reject", "example.com", "protected", fakeResolver{"example.com": {"v=spf1 -all"}, "_dmarc.example.com": {"v=DMARC1; p=reject"}}},
		{"plus-all bypasses reject", "example.com", "exposed", fakeResolver{"example.com": {"v=spf1 +all"}, "_dmarc.example.com": {"v=DMARC1; p=reject"}}},
		{"partial", "example.com", "warning", fakeResolver{"_dmarc.example.com": {"v=DMARC1; p=reject; pct=25"}}},
		{"inherited subdomain", "mail.example.com", "protected", fakeResolver{"_dmarc.example.com": {"v=DMARC1; p=reject; sp=reject"}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NewCheckerWithResolver(tc.dns).Check(context.Background(), tc.domain)
			if err != nil {
				t.Fatal(err)
			}
			if got.Level != tc.want {
				t.Fatalf("got %s: %+v", got.Level, got)
			}
		})
	}
}

func TestParseDMARC(t *testing.T) {
	if _, err := parseDMARC("v=DMARC1; p=reject"); err != nil {
		t.Fatal(err)
	}
	if _, err := parseDMARC("v=DMARC1; p=wat"); err == nil {
		t.Fatal("accepted invalid policy")
	}
	if _, err := parseDMARC("v=DMARC1; p=none; p=reject"); err == nil {
		t.Fatal("accepted duplicate tag")
	}
}
