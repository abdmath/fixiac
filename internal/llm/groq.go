package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"time"
)

const (
	defaultGroqEndpoint = "https://api.groq.com/openai/v1/chat/completions"
	defaultGroqModel    = "llama-3.3-70b-versatile"
	groqMaxRetries      = 3
)

// groqClient implements the Client interface for the Groq API.
type groqClient struct {
	model    string
	apiKey   string
	endpoint string
	http     *http.Client
}

// newGroqClient creates a new Groq LLM client.
func newGroqClient(model, apiKey, endpoint string) *groqClient {
	if model == "" {
		model = defaultGroqModel
	}
	if endpoint == "" {
		endpoint = defaultGroqEndpoint
	}
	return &groqClient{
		model:    model,
		apiKey:   apiKey,
		endpoint: endpoint,
		http: &http.Client{
			Timeout: 120 * time.Second,
		},
	}
}

// openAIMessage represents a message in the OpenAI chat format.
type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// openAIChatRequest represents the request body for OpenAI-compatible APIs.
type openAIChatRequest struct {
	Model       string          `json:"model"`
	Messages    []openAIMessage `json:"messages"`
	MaxTokens   int             `json:"max_tokens,omitempty"`
	Temperature float64         `json:"temperature,omitempty"`
}

// openAIChatResponse represents the response from OpenAI-compatible APIs.
type openAIChatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		TotalTokens int `json:"total_tokens"`
	} `json:"usage"`
	Model string `json:"model"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    string `json:"code"`
	} `json:"error,omitempty"`
}

// Generate sends a prompt to the Groq API and returns the generated response.
func (c *groqClient) Generate(ctx context.Context, req *GenerateRequest) (*GenerateResponse, error) {
	if c.apiKey == "" {
		return nil, fmt.Errorf("groq: API key is required; set GROQ_API_KEY or pass --api-key")
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
		return nil, fmt.Errorf("groq: failed to marshal request: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt <= groqMaxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(math.Pow(2, float64(attempt-1))) * time.Second
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("groq: request cancelled: %w", ctx.Err())
			case <-time.After(backoff):
			}
		}

		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("groq: failed to create request: %w", err)
		}
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)

		resp, err := c.http.Do(httpReq)
		if err != nil {
			lastErr = fmt.Errorf("groq: request failed: %w", err)
			continue
		}

		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("groq: failed to read response: %w", err)
			continue
		}

		switch resp.StatusCode {
		case http.StatusOK:
			var chatResp openAIChatResponse
			if err := json.Unmarshal(respBody, &chatResp); err != nil {
				return nil, fmt.Errorf("groq: failed to parse response: %w", err)
			}
			if chatResp.Error != nil {
				return nil, fmt.Errorf("groq: API error: %s", chatResp.Error.Message)
			}
			if len(chatResp.Choices) == 0 {
				return nil, fmt.Errorf("groq: no choices in response")
			}
			return &GenerateResponse{
				Content:      chatResp.Choices[0].Message.Content,
				TokensUsed:   chatResp.Usage.TotalTokens,
				Model:        chatResp.Model,
				Provider:     "groq",
				FinishReason: chatResp.Choices[0].FinishReason,
			}, nil

		case http.StatusTooManyRequests:
			lastErr = fmt.Errorf("groq: rate limited (429)")
			continue

		case http.StatusUnauthorized:
			return nil, fmt.Errorf("groq: invalid API key (401): check your GROQ_API_KEY")

		default:
			var errResp openAIChatResponse
			if err := json.Unmarshal(respBody, &errResp); err == nil && errResp.Error != nil {
				lastErr = fmt.Errorf("groq: API error (HTTP %d): %s", resp.StatusCode, errResp.Error.Message)
			} else {
				lastErr = fmt.Errorf("groq: unexpected status %d: %s", resp.StatusCode, string(respBody))
			}
			continue
		}
	}

	return nil, fmt.Errorf("groq: failed after %d retries: %w", groqMaxRetries, lastErr)
}

// Name returns the display name of the Groq provider.
func (c *groqClient) Name() string {
	return "groq"
}

// Available returns true if the Groq API is reachable with the configured key.
func (c *groqClient) Available() bool {
	return c.apiKey != ""
}

// Complete sends a simple user prompt and returns only the generated string.
func (c *groqClient) Complete(ctx context.Context, prompt string) (string, error) {
	resp, err := c.Generate(ctx, &GenerateRequest{UserPrompt: prompt, Temperature: 0.2})
	if err != nil {
		return "", err
	}
	return resp.Content, nil
}
