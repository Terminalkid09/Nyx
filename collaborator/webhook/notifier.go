package webhook

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/Terminalkid09/nyx/collaborator/storage"
)

type Notifier struct {
	url    string
	client *http.Client
}

func New(webhookURL string) *Notifier {
	return &Notifier{
		url: webhookURL,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (n *Notifier) Send(token string, eventType string, payload interface{}) {
	if n.url == "" {
		return
	}

	body := map[string]interface{}{
		"token":      token,
		"event_type": eventType,
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
		"payload":    payload,
	}

	data, err := json.Marshal(body)
	if err != nil {
		log.Printf("[webhook] marshal error: %v", err)
		return
	}

	go func() {
		resp, err := n.client.Post(n.url, "application/json", bytes.NewReader(data))
		if err != nil {
			log.Printf("[webhook] send error: %v", err)
			return
		}
		resp.Body.Close()
		if resp.StatusCode >= 300 {
			log.Printf("[webhook] unexpected status: %d", resp.StatusCode)
		}
	}()
}

func (n *Notifier) InteractionReceived(token string, interaction storage.Interaction) {
	n.Send(token, "interaction.received", interaction)
}
