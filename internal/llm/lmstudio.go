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
	defaultLMStudioEndpoint = "http://localhost:1234/v1/chat/completions"
	defaultLMStudioModel    = "default"
)

// lmStudioClient implements the Client interface for the LM Studio local API.
// LM Studio exposes an OpenAI-compatible API.
type lmStudioClient struct {
	model    string
	endpoint string
	http     *http.Client
}

// newLMStudioClient creates a new LM Studio LLM client.
func newLMStudioClient(model, endpoint string) *lmStudioClient {
	if model == "" {
		model = defaultLMStudioModel
	}
	if endpoint == "" {
		endpoint = defaultLMStudioEndpoint
	}
	return &lmStudioClient{
		model:    model,
		endpoint: endpoint,
		http: &http.Client{
			Timeout: 300 * time.Second,
		},
	}
}

// Generate sends a prompt to the LM Studio API and returns the generated response.
func (c *lmStudioClient) Generate(ctx context.Context, req *GenerateRequest) (*GenerateResponse, error) {
	// Auto-detect model from server if set to "default".
	model := c.model
	if model == "default" {
		detected, err := c.detectModel(ctx)
		if err == nil && detected != "" {
			model = detected
		}
	}

	chatReq := openAIChatRequest{
		Model: model,
		Messages: []openAIMessage{
			{Role: "system", Content: req.SystemPrompt},
			{Role: "user", Content: req.UserPrompt},
		},
		MaxTokens:   req.MaxTokens,
		Temperature: req.Temperature,
	}

	body, err := json.Marshal(chatReq)
	if err != nil {
		return nil, fmt.Errorf("lmstudio: failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("lmstudio: failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("lmstudio: request failed (is LM Studio running at %s?): %w", c.endpoint, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("lmstudio: failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("lmstudio: unexpected status %d: %s", resp.StatusCode, string(respBody))
	}

	var chatResp openAIChatResponse
	if err := json.Unmarshal(respBody, &chatResp); err != nil {
		return nil, fmt.Errorf("lmstudio: failed to parse response: %w", err)
	}
	if chatResp.Error != nil {
		return nil, fmt.Errorf("lmstudio: API error: %s", chatResp.Error.Message)
	}
	if len(chatResp.Choices) == 0 {
		return nil, fmt.Errorf("lmstudio: no choices in response")
	}

	return &GenerateResponse{
		Content:      chatResp.Choices[0].Message.Content,
		TokensUsed:   chatResp.Usage.TotalTokens,
		Model:        chatResp.Model,
		Provider:     "lmstudio",
		FinishReason: chatResp.Choices[0].FinishReason,
	}, nil
}

// lmStudioModelsResponse represents the response from the LM Studio models endpoint.
type lmStudioModelsResponse struct {
	Data []struct {
		ID string `json:"id"`
	} `json:"data"`
}

// detectModel queries the LM Studio /v1/models endpoint to find a loaded model.
func (c *lmStudioClient) detectModel(ctx context.Context) (string, error) {
	// LM Studio models endpoint is at the same base as completions, minus the path.
	// Given endpoint like http://localhost:1234/v1/chat/completions,
	// models endpoint is http://localhost:1234/v1/models.
	modelsURL := "http://localhost:1234/v1/models"

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, modelsURL, nil)
	if err != nil {
		return "", fmt.Errorf("lmstudio: failed to create models request: %w", err)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("lmstudio: models request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("lmstudio: models endpoint returned %d", resp.StatusCode)
	}

	var modelsResp lmStudioModelsResponse
	if err := json.NewDecoder(resp.Body).Decode(&modelsResp); err != nil {
		return "", fmt.Errorf("lmstudio: failed to parse models response: %w", err)
	}

	if len(modelsResp.Data) > 0 {
		return modelsResp.Data[0].ID, nil
	}
	return "", fmt.Errorf("lmstudio: no models loaded")
}

// Name returns the display name of the LM Studio provider.
func (c *lmStudioClient) Name() string {
	return "lmstudio"
}

// Available checks if the LM Studio server is running and responding.
func (c *lmStudioClient) Available() bool {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://localhost:1234/v1/models")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// Complete sends a simple user prompt and returns only the generated string.
func (c *lmStudioClient) Complete(ctx context.Context, prompt string) (string, error) {
	resp, err := c.Generate(ctx, &GenerateRequest{UserPrompt: prompt, Temperature: 0.2})
	if err != nil {
		return "", err
	}
	return resp.Content, nil
}
