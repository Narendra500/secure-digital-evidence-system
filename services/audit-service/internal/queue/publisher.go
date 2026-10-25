package queue

import (
	"audit-service/internal/store"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/nats-io/nats.go"
)

const (
	DefaultStream  = "AUDIT_STREAM"
	DefaultSubject = "audit.events"
)

type Publisher interface {
	PublishAuditEvent(ctx context.Context, event store.AuditEventMessage) error
	Close()
}

type natsPublisher struct {
	nc *nats.Conn
	js nats.JetStreamContext
}

func NewNATSPublisher(url string) (Publisher, error) {
	if url == "" {
		url = os.Getenv("NATS_URL")
	}
	if url == "" {
		url = "nats://nats:4222"
	}

	nc, err := nats.Connect(url, nats.Timeout(5*time.Second), nats.MaxReconnects(10), nats.ReconnectWait(2*time.Second))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to NATS at %s: %w", url, err)
	}

	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("failed to get JetStream context: %w", err)
	}

	// Ensure stream exists
	streamName := os.Getenv("NATS_STREAM_NAME")
	if streamName == "" {
		streamName = DefaultStream
	}
	subject := os.Getenv("NATS_SUBJECT")
	if subject == "" {
		subject = DefaultSubject
	}

	_, err = js.AddStream(&nats.StreamConfig{
		Name:     streamName,
		Subjects: []string{subject},
		Storage:  nats.FileStorage,
	})
	if err != nil && err != nats.ErrStreamNameAlreadyInUse {
		// Try checking if stream already exists
		_, infoErr := js.StreamInfo(streamName)
		if infoErr != nil {
			log.Printf("warning: could not ensure JetStream stream %s: %v", streamName, err)
		}
	}

	return &natsPublisher{
		nc: nc,
		js: js,
	}, nil
}

func (p *natsPublisher) PublishAuditEvent(ctx context.Context, event store.AuditEventMessage) error {
	subject := os.Getenv("NATS_SUBJECT")
	if subject == "" {
		subject = DefaultSubject
	}

	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal audit event: %w", err)
	}

	_, err = p.js.Publish(subject, data, nats.Context(ctx))
	if err != nil {
		return fmt.Errorf("failed to publish to JetStream subject %s: %w", subject, err)
	}

	log.Printf("Published audit event for evidence %d, action %s to %s", event.EvidenceID, event.ActionName, subject)
	return nil
}

func (p *natsPublisher) Close() {
	if p.nc != nil {
		p.nc.Close()
	}
}
