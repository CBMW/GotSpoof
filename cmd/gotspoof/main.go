package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"gotspoof/internal/assessment"
	"gotspoof/internal/mailtest"
	"gotspoof/internal/ui"
)

const version = "0.1.0"

func main() {
	if err := run(); err != nil && !errors.Is(err, ui.ErrExit) {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	jsonOutput := flag.Bool("json", false, "print assessment as JSON; never send mail")
	noColor := flag.Bool("no-color", false, "disable ANSI color")
	verbose := flag.Bool("verbose", false, "show raw DNS policy records")
	showVersion := flag.Bool("version", false, "print version")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "GotSpoof? checks SPF and DMARC signals for one domain.\n\nUsage:\n  gotspoof [flags] [domain]\n\nFlags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if *showVersion {
		fmt.Println("gotspoof", version)
		return nil
	}
	if flag.NArg() > 1 {
		return errors.New("provide one domain")
	}

	view := ui.New(*noColor)
	if !*jsonOutput {
		view.Banner()
	}
	domainArg := ""
	if flag.NArg() == 1 {
		domainArg = flag.Arg(0)
	} else if *jsonOutput {
		return errors.New("JSON mode requires a domain argument")
	}
	for {
		domain := domainArg
		domainArg = ""
		if domain == "" {
			var err error
			domain, err = view.Prompt("Target domain (or exit)")
			if err != nil {
				return err
			}
		}
		var err error
		domain, err = assessment.NormalizeDomain(domain)
		if err != nil {
			return err
		}

		if !*jsonOutput {
			fmt.Fprintf(os.Stdout, "\n%s %s\n", view.Muted("Checking"), view.Bold(domain))
		}
		result, err := assessment.NewChecker().Check(context.Background(), domain)
		if err != nil {
			return err
		}
		if *jsonOutput {
			encoder := json.NewEncoder(os.Stdout)
			encoder.SetIndent("", "  ")
			return encoder.Encode(result)
		}
		printResult(view, result, *verbose)

		if !view.IsTerminal() {
			fmt.Fprintln(os.Stdout, view.Muted("Interactive evidence test skipped: stdin is not a terminal."))
			return nil
		}
		choice, err := view.Select("Test spoofability?", []string{"No", "Yes"})
		if err != nil {
			return err
		}
		if choice == 1 {
			fmt.Fprintln(os.Stdout)
			if err := runMailTest(view, domain); err != nil {
				return err
			}
		}
		fmt.Fprintf(os.Stdout, "\n%s\n\n", view.Muted("────────────────────────────────────────"))
	}
}

func printResult(view *ui.UI, result assessment.Result, verbose bool) {
	verdict := result.Verdict
	switch result.Level {
	case "protected":
		verdict = view.Good(verdict)
	case "mitigated", "warning":
		verdict = view.Warn(verdict)
	case "exposed":
		verdict = view.Bad(verdict)
	default:
		verdict = view.Muted(verdict)
	}
	fmt.Fprintf(os.Stdout, "\n  %s  %s\n", view.Muted("Assessment"), view.Bold(verdict))
	fmt.Fprintf(os.Stdout, "  %s       %s\n", view.Muted("DMARC"), result.DMARC.Note)
	fmt.Fprintf(os.Stdout, "  %s         %s\n", view.Muted("SPF"), result.SPF.Note)
	fmt.Fprintf(os.Stdout, "  %s      %s\n\n", view.Muted("Signal"), result.Summary)
	if verbose {
		if result.DMARC.Record != "" {
			fmt.Fprintf(os.Stdout, "  %s %s\n", view.Muted("DMARC TXT"), result.DMARC.Record)
		}
		if result.SPF.Record != "" {
			fmt.Fprintf(os.Stdout, "  %s   %s\n", view.Muted("SPF TXT"), result.SPF.Record)
		}
		fmt.Fprintln(os.Stdout)
	}
}

func runMailTest(view *ui.UI, domain string) error {
	local, err := view.Prompt("Sender prefix (before @" + domain + ")")
	if err != nil {
		return err
	}
	if err := mailtest.ValidateLocalPart(local); err != nil {
		return err
	}
	from := local + "@" + domain
	fmt.Fprintf(os.Stdout, "  %s %s\n", view.Muted("From"), from)
	recipient, err := view.Prompt("Recipient email")
	if err != nil {
		return err
	}
	recipient, err = mailtest.ValidateRecipient(recipient)
	if err != nil {
		return err
	}
	subject, err := view.Prompt("Subject")
	if err != nil {
		return err
	}
	if subject == "" || strings.ContainsAny(subject, "\r\n") {
		return errors.New("enter a one-line subject")
	}
	body, err := view.Multiline("Message")
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "\n  %s %s\n  %s   %s\n\n", view.Muted("From"), from, view.Muted("To"), recipient)
	confirm, err := view.Select("Send email?", []string{"Cancel", "Send"})
	if err != nil || confirm == 0 {
		return err
	}

	fmt.Fprintln(os.Stdout, "\n"+view.Muted("Connecting directly to recipient MX…"))
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	receipt, err := mailtest.SendDirect(ctx, mailtest.Message{From: from, To: recipient, Subject: subject, Body: body})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "\n%s %s\n", view.Good("✓ Accepted by MX"), receipt.MX)
	fmt.Fprintln(os.Stdout, view.Muted("  This proves SMTP acceptance only. Confirm inbox placement and Authentication-Results manually."))
	return nil
}
