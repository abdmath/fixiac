package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	defaultOllamaEndpoint = "http://localhost:11434"
	defaultOllamaModel    = "llama3.3:70b"
)

// ollamaClient implements the Client interface for the Ollama local API.
type ollamaClient struct {
	model    string
	endpoint string
	http     *http.Client
}

// ollamaChatRequest represents the request body for the Ollama chat API.
type ollamaChatRequest struct {
	Model    string          `json:"model"`
	Messages []openAIMessage `json:"messages"`
	Stream   bool            `json:"stream"`
}

// ollamaChatResponse represents the response from the Ollama chat API.
type ollamaChatResponse struct {
	Message struct {
		Content string `json:"content"`
	} `json:"message"`
	Model        string `json:"model"`
	DoneReason   string `json:"done_reason"`
	TotalDuration int64 `json:"total_duration"`
	EvalCount     int   `json:"eval_count"`
	PromptEvalCount int `json:"prompt_eval_count"`
}

// newOllamaClient creates a new Ollama local LLM client.
func newOllamaClient(model, endpoint string) *ollamaClient {
	if model == "" {
		model = defaultOllamaModel
	}
	if endpoint == "" {
		endpoint = defaultOllamaEndpoint
	}
	return &ollamaClient{
		model:    model,
		endpoint: endpoint,
		http: &http.Client{
			Timeout: 300 * time.Second, // local models can be slow
		},
	}
}

// Generate sends a prompt to the Ollama API and returns the generated response.
func (c *ollamaClient) Generate(ctx context.Context, req *GenerateRequest) (*GenerateResponse, error) {
	chatReq := ollamaChatRequest{
		Model: c.model,
		Messages: []openAIMessage{
			{Role: "system", Content: req.SystemPrompt},
			{Role: "user", Content: req.UserPrompt},
		},
		Stream: false,
	}

	body, err := json.Marshal(chatReq)
	if err != nil {
		return nil, fmt.Errorf("ollama: failed to marshal request: %w", err)
	}

	chatURL := c.endpoint + "/api/chat"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, chatURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("ollama: failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("ollama: request failed (is Ollama running at %s?): %w", c.endpoint, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ollama: failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ollama: unexpected status %d: %s", resp.StatusCode, string(respBody))
	}

	var chatResp ollamaChatResponse
	if err := json.Unmarshal(respBody, &chatResp); err != nil {
		return nil, fmt.Errorf("ollama: failed to parse response: %w", err)
	}

	return &GenerateResponse{
		Content:      chatResp.Message.Content,
		TokensUsed:   chatResp.PromptEvalCount + chatResp.EvalCount,
		Model:        chatResp.Model,
		Provider:     "ollama",
		FinishReason: chatResp.DoneReason,
	}, nil
}

// Name returns the display name of the Ollama provider.
func (c *ollamaClient) Name() string {
	return "ollama"
}

// Available checks if the Ollama server is running by querying the tags endpoint.
func (c *ollamaClient) Available() bool {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(c.endpoint + "/api/tags")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// Complete sends a simple user prompt and returns only the generated string.
func (c *ollamaClient) Complete(ctx context.Context, prompt string) (string, error) {
	resp, err := c.Generate(ctx, &GenerateRequest{UserPrompt: prompt, Temperature: 0.2})
	if err != nil {
		return "", err
	}
	return resp.Content, nil
}
