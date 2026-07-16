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
	defaultAnthropicEndpoint = "https://api.anthropic.com/v1/messages"
	defaultAnthropicModel    = "claude-sonnet-4-20250514"
	anthropicAPIVersion      = "2023-06-01"
)

// anthropicClient implements the Client interface for the Anthropic API.
type anthropicClient struct {
	model    string
	apiKey   string
	endpoint string
	http     *http.Client
}

// anthropicRequest represents the request body for the Anthropic messages API.
type anthropicRequest struct {
	Model     string            `json:"model"`
	MaxTokens int               `json:"max_tokens"`
	System    string            `json:"system,omitempty"`
	Messages  []anthropicMessage `json:"messages"`
}

// anthropicMessage represents a message in the Anthropic format.
type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// anthropicResponse represents the response from the Anthropic messages API.
type anthropicResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Model        string `json:"model"`
	StopReason   string `json:"stop_reason"`
	Usage        struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// newAnthropicClient creates a new Anthropic LLM client.
func newAnthropicClient(model, apiKey, endpoint string) *anthropicClient {
	if model == "" {
		model = defaultAnthropicModel
	}
	if endpoint == "" {
		endpoint = defaultAnthropicEndpoint
	}
	return &anthropicClient{
		model:    model,
		apiKey:   apiKey,
		endpoint: endpoint,
		http: &http.Client{
			Timeout: 120 * time.Second,
		},
	}
}

// Generate sends a prompt to the Anthropic API and returns the generated response.
func (c *anthropicClient) Generate(ctx context.Context, req *GenerateRequest) (*GenerateResponse, error) {
	if c.apiKey == "" {
		return nil, fmt.Errorf("anthropic: API key is required; set ANTHROPIC_API_KEY or pass --api-key")
	}

	maxTokens := req.MaxTokens
	if maxTokens == 0 {
		maxTokens = 4096
	}

	anthReq := anthropicRequest{
		Model:     c.model,
		MaxTokens: maxTokens,
		System:    req.SystemPrompt,
		Messages: []anthropicMessage{
			{Role: "user", Content: req.UserPrompt},
		},
	}

	body, err := json.Marshal(anthReq)
	if err != nil {
		return nil, fmt.Errorf("anthropic: failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("anthropic: failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", c.apiKey)
	httpReq.Header.Set("anthropic-version", anthropicAPIVersion)

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("anthropic: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("anthropic: failed to read response: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("anthropic: invalid API key (401): check your ANTHROPIC_API_KEY")
	}

	if resp.StatusCode != http.StatusOK {
		var errResp anthropicResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil && errResp.Error != nil {
			return nil, fmt.Errorf("anthropic: API error (HTTP %d): [%s] %s", resp.StatusCode, errResp.Error.Type, errResp.Error.Message)
		}
		return nil, fmt.Errorf("anthropic: unexpected status %d: %s", resp.StatusCode, string(respBody))
	}

	var anthResp anthropicResponse
	if err := json.Unmarshal(respBody, &anthResp); err != nil {
		return nil, fmt.Errorf("anthropic: failed to parse response: %w", err)
	}
	if anthResp.Error != nil {
		return nil, fmt.Errorf("anthropic: API error: [%s] %s", anthResp.Error.Type, anthResp.Error.Message)
	}
	if len(anthResp.Content) == 0 {
		return nil, fmt.Errorf("anthropic: no content in response")
	}

	// Find the first text content block.
	var text string
	for _, block := range anthResp.Content {
		if block.Type == "text" {
			text = block.Text
			break
		}
	}
	if text == "" {
		return nil, fmt.Errorf("anthropic: no text content block in response")
	}

	return &GenerateResponse{
		Content:      text,
		TokensUsed:   anthResp.Usage.InputTokens + anthResp.Usage.OutputTokens,
		Model:        anthResp.Model,
		Provider:     "anthropic",
		FinishReason: anthResp.StopReason,
	}, nil
}

// Name returns the display name of the Anthropic provider.
func (c *anthropicClient) Name() string {
	return "anthropic"
}

// Available returns true if the Anthropic API key is configured.
func (c *anthropicClient) Available() bool {
	return c.apiKey != ""
}

// Complete sends a simple user prompt and returns only the generated string.
func (c *anthropicClient) Complete(ctx context.Context, prompt string) (string, error) {
	resp, err := c.Generate(ctx, &GenerateRequest{UserPrompt: prompt, Temperature: 0.2})
	if err != nil {
		return "", err
	}
	return resp.Content, nil
}
