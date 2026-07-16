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
	defaultOpenAIEndpoint = "https://api.openai.com/v1/chat/completions"
	defaultOpenAIModel    = "gpt-4o"
)

// openAIClient implements the Client interface for the OpenAI API.
type openAIClient struct {
	model    string
	apiKey   string
	endpoint string
	http     *http.Client
}

// newOpenAIClient creates a new OpenAI LLM client.
func newOpenAIClient(model, apiKey, endpoint string) *openAIClient {
	if model == "" {
		model = defaultOpenAIModel
	}
	if endpoint == "" {
		endpoint = defaultOpenAIEndpoint
	}
	return &openAIClient{
		model:    model,
		apiKey:   apiKey,
		endpoint: endpoint,
		http: &http.Client{
			Timeout: 120 * time.Second,
		},
	}
}

// Generate sends a prompt to the OpenAI API and returns the generated response.
func (c *openAIClient) Generate(ctx context.Context, req *GenerateRequest) (*GenerateResponse, error) {
	if c.apiKey == "" {
		return nil, fmt.Errorf("openai: API key is required; set OPENAI_API_KEY or pass --api-key")
	}

	chatReq := openAIChatRequest{
		Model: c.model,
		Messages: []openAIMessage{
			{Role: "system", Content: req.SystemPrompt},
			{Role: "user", Content: req.UserPrompt},
		},
		MaxTokens:   req.MaxTokens,
		Temperature: req.Temperature,
	}

	body, err := json.Marshal(chatReq)
	if err != nil {
		return nil, fmt.Errorf("openai: failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("openai: failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("openai: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("openai: failed to read response: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("openai: invalid API key (401): check your OPENAI_API_KEY")
	}

	if resp.StatusCode != http.StatusOK {
		var errResp openAIChatResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil && errResp.Error != nil {
			return nil, fmt.Errorf("openai: API error (HTTP %d): %s", resp.StatusCode, errResp.Error.Message)
		}
		return nil, fmt.Errorf("openai: unexpected status %d: %s", resp.StatusCode, string(respBody))
	}

	var chatResp openAIChatResponse
	if err := json.Unmarshal(respBody, &chatResp); err != nil {
		return nil, fmt.Errorf("openai: failed to parse response: %w", err)
	}
	if chatResp.Error != nil {
		return nil, fmt.Errorf("openai: API error: %s", chatResp.Error.Message)
	}
	if len(chatResp.Choices) == 0 {
		return nil, fmt.Errorf("openai: no choices in response")
	}

	return &GenerateResponse{
		Content:      chatResp.Choices[0].Message.Content,
		TokensUsed:   chatResp.Usage.TotalTokens,
		Model:        chatResp.Model,
		Provider:     "openai",
		FinishReason: chatResp.Choices[0].FinishReason,
	}, nil
}

// Name returns the display name of the OpenAI provider.
func (c *openAIClient) Name() string {
	return "openai"
}

// Available returns true if the OpenAI API key is configured.
func (c *openAIClient) Available() bool {
	return c.apiKey != ""
}

// Complete sends a simple user prompt and returns only the generated string.
func (c *openAIClient) Complete(ctx context.Context, prompt string) (string, error) {
	resp, err := c.Generate(ctx, &GenerateRequest{UserPrompt: prompt, Temperature: 0.2})
	if err != nil {
		return "", err
	}
	return resp.Content, nil
}
