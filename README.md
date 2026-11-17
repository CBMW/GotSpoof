# GotSpoof?

A small Linux CLI for checking whether a domain publishes effective SPF and DMARC controls, then optionally sending one authorized evidence message directly to the recipient's mail exchanger.

The presentation is deliberately quiet: one target, one assessment, one decision.

## Build

Requires Go 1.22 or newer.

```sh
make check
make build
./dist/gotspoof example.com
```

The resulting binary has no runtime package dependencies. Cross-compile with, for example:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -buildvcs=false -trimpath -ldflags="-s -w" -o dist/gotspoof-linux-arm64 ./cmd/gotspoof
```

## Use

```text
  ┏━╸┏━┓╺┳╸┏━┓┏━┓┏━┓┏━┓┏━╸┏━┓
  ┃╺┓┃ ┃ ┃ ┗━┓┣━┛┃ ┃┃ ┃┣╸  ╺┛
  ┗━┛┗━┛ ╹ ┗━┛╹  ┗━┛┗━┛╹   ╹

› Target domain (or exit)  example.com

  Assessment  Appears spoofable
  DMARC       No DMARC policy found
  SPF         Unauthorized envelope senders should fail SPF
  Signal      No effective DMARC enforcement was found for visible From-domain impersonation.

Test spoofability?
  ❯ No
    Yes
```

Use Up/Down or `j`/`k`, then Enter. Type `exit` at any prompt or menu to quit. After an assessment or successful send, GotSpoof returns to the target prompt. A mail test shows a final From/To preview, sends to exactly one recipient after confirmation, and adds `X-GotSpoof-Test: authorized-security-assessment` to the message.

When asked for `Sender prefix (before @example.com)`, enter only the part before the `@`, such as `security`. The resulting sender will be `security@example.com`.

For scripts and evidence capture:

```sh
gotspoof --json example.com
gotspoof --verbose example.com
NO_COLOR=1 gotspoof example.com
```

## Evidence boundary

- SPF describes authorization for the SMTP envelope domain. DMARC governs alignment with the visible `From` domain. The tool weighs DMARC most heavily for visible-domain spoofing.
- A weak or missing policy is a configuration signal, not proof that every receiver will place a spoofed message in an inbox.
- The test is intentionally single-recipient and text-only. It makes a direct outbound TCP/25 connection to the recipient MX; it does not start a local SMTP server.
- `Accepted by MX` means the remote server accepted SMTP `DATA`. It does not prove inbox delivery. Preserve the received message and its `Authentication-Results` headers as evidence.
- Direct delivery may fail when the assessment host blocks outbound TCP/25, lacks usable reverse DNS, or has poor IP reputation. That is inconclusive rather than proof of protection.

Only test domains and recipient mailboxes covered by your written authorization.
