package mailtest

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"os"
	"sort"
	"strings"
	"time"
)

type Message struct {
	From    string
	To      string
	Subject string
	Body    string
}

type Receipt struct {
	MX       string
	Accepted time.Time
}

func ValidateLocalPart(value string) error {
	if value == "" || len(value) > 64 || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") || strings.Contains(value, "..") {
		return errors.New("enter a valid email local part")
	}
	for _, c := range value {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.ContainsRune(".!#$%&'*+-/=?^_`{|}~", c) {
			continue
		}
		return errors.New("local part contains unsupported characters")
	}
	return nil
}

func ValidateRecipient(value string) (string, error) {
	if strings.ContainsAny(value, "\r\n") {
		return "", errors.New("enter one recipient address")
	}
	parsed, err := mail.ParseAddress(strings.TrimSpace(value))
	if err != nil || parsed.Address != strings.TrimSpace(value) || strings.Count(parsed.Address, "@") != 1 {
		return "", errors.New("enter one plain recipient address")
	}
	return parsed.Address, nil
}

func SendDirect(ctx context.Context, message Message) (Receipt, error) {
	if strings.ContainsAny(message.From+message.To+message.Subject, "\r\n") {
		return Receipt{}, errors.New("message headers cannot contain line breaks")
	}
	recipient, err := ValidateRecipient(message.To)
	if err != nil {
		return Receipt{}, err
	}
	parts := strings.Split(recipient, "@")
	domain := parts[len(parts)-1]
	mxs, err := net.DefaultResolver.LookupMX(ctx, domain)
	if err != nil {
		var dnsErr *net.DNSError
		if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
			return Receipt{}, fmt.Errorf("resolve recipient MX: %w", err)
		}
		mxs = []*net.MX{{Host: domain, Pref: 0}}
	}
	if len(mxs) == 0 {
		mxs = []*net.MX{{Host: domain, Pref: 0}}
	}
	sort.SliceStable(mxs, func(i, j int) bool { return mxs[i].Pref < mxs[j].Pref })

	raw, err := render(message)
	if err != nil {
		return Receipt{}, err
	}
	var attempts []string
	for _, mx := range mxs {
		host := strings.TrimSuffix(mx.Host, ".")
		if host == "" {
			return Receipt{}, errors.New("recipient domain publishes a null MX and does not accept email")
		}
		if err := deliver(ctx, host, message.From, recipient, raw); err != nil {
			attempts = append(attempts, host+": "+err.Error())
			continue
		}
		return Receipt{MX: host, Accepted: time.Now()}, nil
	}
	return Receipt{}, fmt.Errorf("no recipient MX accepted the message (%s)", strings.Join(attempts, "; "))
}

func deliver(ctx context.Context, host, from, to string, raw []byte) error {
	dialer := net.Dialer{Timeout: 12 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, "25"))
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer client.Close()
	localName := "localhost"
	if hostname, hostErr := os.Hostname(); hostErr == nil && hostname != "" {
		localName = hostname
	}
	if err := client.Hello(localName); err != nil {
		return err
	}
	if ok, _ := client.Extension("STARTTLS"); ok {
		if err := client.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("STARTTLS: %w", err)
		}
	}
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("MAIL FROM rejected: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("RCPT TO rejected: %w", err)
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA rejected: %w", err)
	}
	if _, err := w.Write(raw); err != nil {
		_ = w.Close()
		return err
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("message rejected: %w", err)
	}
	if err := client.Quit(); err != nil {
		return fmt.Errorf("SMTP close: %w", err)
	}
	return nil
}

func render(message Message) ([]byte, error) {
	idBytes := make([]byte, 12)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, err
	}
	fromDomain := "localhost"
	if at := strings.LastIndex(message.From, "@"); at >= 0 {
		fromDomain = message.From[at+1:]
	}
	body := strings.ReplaceAll(strings.ReplaceAll(message.Body, "\r\n", "\n"), "\r", "\n")
	body = strings.ReplaceAll(body, "\n", "\r\n")
	var out bytes.Buffer
	fmt.Fprintf(&out, "From: <%s>\r\n", message.From)
	fmt.Fprintf(&out, "To: <%s>\r\n", message.To)
	fmt.Fprintf(&out, "Subject: %s\r\n", mime.QEncoding.Encode("UTF-8", message.Subject))
	fmt.Fprintf(&out, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	fmt.Fprintf(&out, "Message-ID: <%s@%s>\r\n", hex.EncodeToString(idBytes), fromDomain)
	out.WriteString("MIME-Version: 1.0\r\n")
	out.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	out.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	out.WriteString("X-GotSpoof-Test: authorized-security-assessment\r\n")
	out.WriteString("\r\n")
	out.WriteString(body)
	if !strings.HasSuffix(body, "\r\n") {
		out.WriteString("\r\n")
	}
	return out.Bytes(), nil
}
