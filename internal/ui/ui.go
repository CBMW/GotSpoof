package ui

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

var ErrExit = errors.New("exit requested")

type UI struct {
	In       *bufio.Reader
	Out      io.Writer
	Color    bool
	terminal bool
}

func New(noColor bool) *UI {
	fd := int(os.Stdin.Fd())
	return &UI{
		In:       bufio.NewReader(os.Stdin),
		Out:      os.Stdout,
		Color:    !noColor && os.Getenv("NO_COLOR") == "" && term.IsTerminal(int(os.Stdout.Fd())),
		terminal: term.IsTerminal(fd),
	}
}

func (u *UI) code(value, code string) string {
	if !u.Color {
		return value
	}
	return "\x1b[" + code + "m" + value + "\x1b[0m"
}

func (u *UI) Accent(s string) string { return u.code(s, "38;5;141") }
func (u *UI) Muted(s string) string  { return u.code(s, "38;5;245") }
func (u *UI) Good(s string) string   { return u.code(s, "38;5;78") }
func (u *UI) Warn(s string) string   { return u.code(s, "38;5;215") }
func (u *UI) Bad(s string) string    { return u.code(s, "38;5;203") }
func (u *UI) Bold(s string) string   { return u.code(s, "1") }

func (u *UI) Banner() {
	fmt.Fprintln(u.Out)
	fmt.Fprintln(u.Out, u.Accent("  ┏━╸┏━┓╺┳╸┏━┓┏━┓┏━┓┏━┓┏━╸┏━┓"))
	fmt.Fprintln(u.Out, u.Accent("  ┃╺┓┃ ┃ ┃ ┗━┓┣━┛┃ ┃┃ ┃┣╸  ╺┛"))
	fmt.Fprintln(u.Out, u.Accent("  ┗━┛┗━┛ ╹ ┗━┛╹  ┗━┛┗━┛╹   ╹ "))
	fmt.Fprintln(u.Out)
}

func (u *UI) Prompt(label string) (string, error) {
	fmt.Fprintf(u.Out, "%s  ", u.Accent("› "+label))
	value, err := u.In.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	value = strings.TrimSpace(value)
	if strings.EqualFold(value, "exit") {
		return "", ErrExit
	}
	return value, nil
}

func (u *UI) Multiline(label string) (string, error) {
	fmt.Fprintf(u.Out, "%s\n%s\n", u.Accent("› "+label), u.Muted("  Finish with a single . on its own line"))
	var lines []string
	for {
		fmt.Fprint(u.Out, u.Muted("  │ "))
		line, err := u.In.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		if strings.EqualFold(strings.TrimSpace(line), "exit") {
			return "", ErrExit
		}
		if line == "." {
			break
		}
		lines = append(lines, line)
		if errors.Is(err, io.EOF) {
			break
		}
	}
	return strings.Join(lines, "\n"), nil
}

func (u *UI) Select(question string, options []string) (int, error) {
	if len(options) == 0 {
		return -1, errors.New("no options")
	}
	if !u.terminal {
		fmt.Fprintf(u.Out, "%s [%s]: ", question, strings.Join(options, "/"))
		answer, err := u.In.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return -1, err
		}
		answer = strings.TrimSpace(strings.ToLower(answer))
		if answer == "exit" {
			return -1, ErrExit
		}
		for i, option := range options {
			if answer == strings.ToLower(option) || answer == strings.ToLower(option[:1]) {
				return i, nil
			}
		}
		return 0, nil
	}

	fd := int(os.Stdin.Fd())
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return -1, err
	}
	defer term.Restore(fd, oldState)

	selected := 0
	typed := ""
	draw := func(first bool) {
		if !first {
			fmt.Fprintf(u.Out, "\x1b[%dA", len(options)+1)
		}
		fmt.Fprintf(u.Out, "%s\x1b[K\r\n", u.Bold(question))
		for i, option := range options {
			if i == selected {
				fmt.Fprintf(u.Out, "  %s %s\x1b[K\r\n", u.Accent("❯"), u.Accent(option))
			} else {
				fmt.Fprintf(u.Out, "    %s\x1b[K\r\n", option)
			}
		}
	}
	draw(true)
	for {
		b, readErr := u.In.ReadByte()
		if readErr != nil {
			return -1, readErr
		}
		switch b {
		case 3:
			return -1, ErrExit
		case '\r', '\n':
			return selected, nil
		case 'k':
			typed = ""
			selected = (selected - 1 + len(options)) % len(options)
			draw(false)
		case 'j':
			typed = ""
			selected = (selected + 1) % len(options)
			draw(false)
		case 27:
			typed = ""
			second, e := u.In.ReadByte()
			if e != nil {
				return -1, e
			}
			third, e := u.In.ReadByte()
			if e != nil {
				return -1, e
			}
			if second == '[' && third == 'A' {
				selected = (selected - 1 + len(options)) % len(options)
				draw(false)
			}
			if second == '[' && third == 'B' {
				selected = (selected + 1) % len(options)
				draw(false)
			}
		default:
			if b >= 'A' && b <= 'Z' {
				b += 'a' - 'A'
			}
			if b >= 'a' && b <= 'z' {
				typed += string(b)
				if !strings.HasPrefix("exit", typed) {
					typed = ""
				}
				if typed == "exit" {
					return -1, ErrExit
				}
			}
		}
	}
}

func (u *UI) IsTerminal() bool { return u.terminal }
