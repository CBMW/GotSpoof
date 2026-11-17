package ui

import (
	"bufio"
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestBannerRendersWordmark(t *testing.T) {
	var out bytes.Buffer
	u := &UI{Out: &out}

	u.Banner()

	got := out.String()
	for _, want := range []string{
		"┏━╸┏━┓╺┳╸┏━┓┏━┓┏━┓┏━┓┏━╸┏━┓",
		"┗━┛┗━┛ ╹ ┗━┛╹  ┗━┛┗━┛╹   ╹",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("banner missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "EVIDENCE CONSOLE") {
		t.Fatalf("banner contains removed subtitle:\n%s", got)
	}
}

func TestPromptExitIsCaseInsensitive(t *testing.T) {
	u := &UI{
		In:  bufio.NewReader(strings.NewReader("ExIt\n")),
		Out: &bytes.Buffer{},
	}

	_, err := u.Prompt("Target domain")
	if !errors.Is(err, ErrExit) {
		t.Fatalf("Prompt() error = %v, want ErrExit", err)
	}
}

func TestMultilineExitDoesNotBecomeMessageContent(t *testing.T) {
	u := &UI{
		In:  bufio.NewReader(strings.NewReader("first line\nexit\n")),
		Out: &bytes.Buffer{},
	}

	_, err := u.Multiline("Message")
	if !errors.Is(err, ErrExit) {
		t.Fatalf("Multiline() error = %v, want ErrExit", err)
	}
}
