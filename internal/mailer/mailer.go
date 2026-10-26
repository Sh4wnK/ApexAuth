// Package mailer delivers passwordless login messages (magic links and OTP
// codes) through a pluggable backend. Two implementations ship:
//
//   - SMTPMailer: real delivery over SMTP (STARTTLS),
//   - LogMailer: writes messages to slog — aimed at development and the
//     Docker compose "email capture" service.
//
// The Mailer interface keeps ApexAuth testable without a mail server and
// lets deployments plug in providers (SES, Postmark, ...) with a few lines.
package mailer

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"strconv"
)

// Message is a single outgoing email.
type Message struct {
	To      string
	Subject string
	Text    string
	HTML    string
}

// Mailer sends a Message. Implementations must not block forever; they may
// queue internally.
type Mailer interface {
	Send(ctx context.Context, m Message) error
}

// ---------------------------------------------------------------------------
// Log mailer (development / test)

// LogMailer prints messages through slog at Info level.
type LogMailer struct {
	log *slog.Logger
}

// NewLogMailer returns a mailer that logs messages.
func NewLogMailer(log *slog.Logger) *LogMailer {
	if log == nil {
		log = slog.Default()
	}
	return &LogMailer{log: log}
}

// Send logs the message.
func (m *LogMailer) Send(ctx context.Context, msg Message) error {
	m.log.Info("mailer: outgoing message",
		"to", msg.To,
		"subject", msg.Subject,
		"text", msg.Text,
	)
	return nil
}

// ---------------------------------------------------------------------------
// SMTP mailer

// SMTPConfig holds connection parameters.
type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	// InsecureSkipVerify disables TLS certificate validation (testing only).
	InsecureSkipVerify bool
}

// SMTPMailer delivers mail via net/smtp with opportunistic STARTTLS.
type SMTPMailer struct {
	cfg SMTPConfig
	log *slog.Logger
}

// NewSMTPMailer validates the config and returns a mailer.
func NewSMTPMailer(cfg SMTPConfig, log *slog.Logger) (*SMTPMailer, error) {
	if cfg.Host == "" || cfg.Port == 0 {
		return nil, fmt.Errorf("mailer: smtp host and port required")
	}
	if log == nil {
		log = slog.Default()
	}
	return &SMTPMailer{cfg: cfg, log: log}, nil
}

// Send delivers a message through the configured SMTP server.
func (m *SMTPMailer) Send(ctx context.Context, msg Message) error {
	addr := net.JoinHostPort(m.cfg.Host, strconv.Itoa(m.cfg.Port))
	c, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("mailer: dial: %w", err)
	}
	defer c.Close()
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(nil); err != nil {
			return fmt.Errorf("mailer: starttls: %w", err)
		}
	}
	if m.cfg.Username != "" {
		auth := smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("mailer: auth: %w", err)
		}
	}
	body := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s",
		m.cfg.From, msg.To, msg.Subject, msg.Text)
	if err := c.Mail(m.cfg.From); err != nil {
		return fmt.Errorf("mailer: mail from: %w", err)
	}
	if err := c.Rcpt(msg.To); err != nil {
		return fmt.Errorf("mailer: rcpt: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("mailer: data: %w", err)
	}
	if _, err := w.Write([]byte(body)); err != nil {
		return fmt.Errorf("mailer: write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("mailer: close: %w", err)
	}
	m.log.Info("mailer: sent", "to", msg.To, "subject", msg.Subject)
	return nil
}
