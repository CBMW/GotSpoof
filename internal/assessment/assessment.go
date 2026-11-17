package assessment

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

type Resolver interface {
	LookupTXT(context.Context, string) ([]string, error)
}

type netResolver struct{ r *net.Resolver }

func (n netResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return n.r.LookupTXT(ctx, name)
}

type Finding struct {
	State  string `json:"state"`
	Policy string `json:"policy,omitempty"`
	Record string `json:"record,omitempty"`
	Note   string `json:"note"`
}

type Result struct {
	Domain  string  `json:"domain"`
	Verdict string  `json:"verdict"`
	Level   string  `json:"level"`
	Summary string  `json:"summary"`
	SPF     Finding `json:"spf"`
	DMARC   Finding `json:"dmarc"`
}

type Checker struct {
	resolver Resolver
	timeout  time.Duration
}

func NewChecker() *Checker {
	return &Checker{resolver: netResolver{net.DefaultResolver}, timeout: 8 * time.Second}
}

func NewCheckerWithResolver(r Resolver) *Checker {
	return &Checker{resolver: r, timeout: 8 * time.Second}
}

func NormalizeDomain(raw string) (string, error) {
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if d == "" || len(d) > 253 {
		return "", errors.New("enter a valid domain")
	}
	if strings.Contains(d, "://") || strings.ContainsAny(d, "/@ \\\t\r\n") {
		return "", errors.New("use a domain only, for example example.com")
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return "", errors.New("domain must include a public suffix")
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("enter a valid domain")
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return "", errors.New("only ASCII domain names are currently supported")
			}
		}
	}
	return d, nil
}

func (c *Checker) Check(parent context.Context, domain string) (Result, error) {
	ctx, cancel := context.WithTimeout(parent, c.timeout)
	defer cancel()

	spf := c.checkSPF(ctx, domain, 0)
	dmarc := c.checkDMARC(ctx, domain)
	result := Result{Domain: domain, SPF: spf, DMARC: dmarc}

	switch {
	case spf.Policy == "+all":
		result.Verdict, result.Level = "Appears spoofable", "exposed"
		result.Summary = "SPF authorizes every sender, allowing aligned SPF to satisfy DMARC even when DMARC is enforced."
	case dmarc.State == "enforced" && dmarc.Policy == "reject":
		result.Verdict, result.Level = "No obvious spoofing exposure", "protected"
		result.Summary = "DMARC requests rejection for unauthenticated, unaligned mail. Verify receiver behavior separately."
	case dmarc.State == "enforced" && dmarc.Policy == "quarantine":
		result.Verdict, result.Level = "Spoofing mitigated", "mitigated"
		result.Summary = "DMARC requests quarantine, not rejection. Inbox placement still depends on the receiver."
	case dmarc.State == "partial":
		result.Verdict, result.Level = "Partially exposed", "warning"
		result.Summary = "DMARC enforcement applies to only part of unauthenticated mail."
	case dmarc.State == "lookup-error":
		result.Verdict, result.Level = "Inconclusive", "unknown"
		result.Summary = "DMARC could not be resolved. Retry before reporting a finding."
	default:
		result.Verdict, result.Level = "Appears spoofable", "exposed"
		result.Summary = "No effective DMARC enforcement was found for visible From-domain impersonation."
	}
	return result, nil
}

func (c *Checker) txt(ctx context.Context, name string) ([]string, error) {
	records, err := c.resolver.LookupTXT(ctx, name)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return nil, nil
		}
		return nil, err
	}
	return records, nil
}

func prefixed(records []string, prefix string) []string {
	var matches []string
	for _, record := range records {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(record)), prefix) {
			matches = append(matches, strings.TrimSpace(record))
		}
	}
	sort.Strings(matches)
	return matches
}

func (c *Checker) checkSPF(ctx context.Context, domain string, depth int) Finding {
	records, err := c.txt(ctx, domain)
	if err != nil {
		return Finding{State: "lookup-error", Note: "DNS lookup failed: " + err.Error()}
	}
	spf := prefixed(records, "v=spf1")
	if len(spf) == 0 {
		return Finding{State: "missing", Note: "No SPF policy published"}
	}
	if len(spf) > 1 {
		return Finding{State: "invalid", Note: "Multiple SPF records cause a permanent error"}
	}
	record := spf[0]
	fields := strings.Fields(record)
	redirect := ""
	for _, field := range fields[1:] {
		lower := strings.ToLower(field)
		if strings.HasPrefix(lower, "redirect=") {
			redirect = strings.TrimPrefix(lower, "redirect=")
			continue
		}
		mechanism := strings.TrimLeft(lower, "+-~?")
		if mechanism != "all" {
			continue
		}
		qualifier := "+"
		if len(lower) > 0 && strings.ContainsRune("-~?", rune(lower[0])) {
			qualifier = lower[:1]
		}
		switch qualifier {
		case "-":
			return Finding{State: "strong", Policy: "-all", Record: record, Note: "Unauthorized envelope senders should fail SPF"}
		case "~":
			return Finding{State: "soft", Policy: "~all", Record: record, Note: "Unauthorized envelope senders receive softfail"}
		case "?":
			return Finding{State: "weak", Policy: "?all", Record: record, Note: "Unauthorized envelope senders receive neutral"}
		default:
			return Finding{State: "weak", Policy: "+all", Record: record, Note: "Any sender is authorized by SPF"}
		}
	}
	if redirect != "" && depth < 4 {
		redirected := c.checkSPF(ctx, redirect, depth+1)
		redirected.Record = record
		redirected.Note = "Redirects to " + redirect + ": " + redirected.Note
		return redirected
	}
	return Finding{State: "weak", Record: record, Note: "SPF has no terminal all mechanism"}
}

func parseDMARC(record string) (map[string]string, error) {
	tags := map[string]string{}
	for _, raw := range strings.Split(record, ";") {
		parts := strings.SplitN(strings.TrimSpace(raw), "=", 2)
		if len(parts) != 2 || parts[0] == "" {
			continue
		}
		key := strings.ToLower(parts[0])
		if _, exists := tags[key]; exists {
			return nil, fmt.Errorf("duplicate %s tag", key)
		}
		tags[key] = strings.ToLower(strings.TrimSpace(parts[1]))
	}
	if tags["v"] != "dmarc1" {
		return nil, errors.New("missing v=DMARC1")
	}
	p := tags["p"]
	if p != "none" && p != "quarantine" && p != "reject" {
		return nil, errors.New("missing or invalid p tag")
	}
	return tags, nil
}

func (c *Checker) checkDMARC(ctx context.Context, domain string) Finding {
	queryDomain := domain
	records, err := c.txt(ctx, "_dmarc."+queryDomain)
	if err != nil {
		return Finding{State: "lookup-error", Note: "DNS lookup failed: " + err.Error()}
	}
	dmarc := prefixed(records, "v=dmarc1")
	inherited := false
	if len(dmarc) == 0 {
		org, orgErr := publicsuffix.EffectiveTLDPlusOne(domain)
		if orgErr == nil && org != domain {
			queryDomain, inherited = org, true
			records, err = c.txt(ctx, "_dmarc."+org)
			if err != nil {
				return Finding{State: "lookup-error", Note: "DNS lookup failed: " + err.Error()}
			}
			dmarc = prefixed(records, "v=dmarc1")
		}
	}
	if len(dmarc) == 0 {
		return Finding{State: "missing", Note: "No DMARC policy found"}
	}
	if len(dmarc) > 1 {
		return Finding{State: "invalid", Note: "Multiple DMARC records found"}
	}
	tags, parseErr := parseDMARC(dmarc[0])
	if parseErr != nil {
		return Finding{State: "invalid", Record: dmarc[0], Note: "Invalid DMARC record: " + parseErr.Error()}
	}
	policy := tags["p"]
	if inherited && tags["sp"] != "" {
		policy = tags["sp"]
	}
	pct := 100
	if tags["pct"] != "" {
		parsed, pctErr := strconv.Atoi(tags["pct"])
		if pctErr != nil || parsed < 0 || parsed > 100 {
			return Finding{State: "invalid", Record: dmarc[0], Note: "Invalid DMARC pct value"}
		}
		pct = parsed
	}
	note := "Policy is " + policy
	if inherited {
		note += " (inherited from " + queryDomain + ")"
	}
	if policy == "none" {
		return Finding{State: "monitoring", Policy: policy, Record: dmarc[0], Note: note + "; no enforcement requested"}
	}
	if pct < 100 {
		return Finding{State: "partial", Policy: policy, Record: dmarc[0], Note: fmt.Sprintf("%s at %d%%", note, pct)}
	}
	return Finding{State: "enforced", Policy: policy, Record: dmarc[0], Note: note + " at 100%"}
}
