// Package config provides Viper-based configuration management for the fixiac CLI.
package config

// Default configuration values used when no user-specified overrides are present.
const (
	// DefaultLLMProvider is the default LLM provider backend.
	DefaultLLMProvider = "groq"
	// DefaultLLMModel is the default model identifier for inference.
	DefaultLLMModel = "llama-3.3-70b-versatile"
	// DefaultGroqEndpoint is the Groq API chat completions endpoint.
	DefaultGroqEndpoint = "https://api.groq.com/openai/v1/chat/completions"
	// DefaultOllamaEndpoint is the default local Ollama server address.
	DefaultOllamaEndpoint = "http://localhost:11434"
	// DefaultLMStudioEndpoint is the default local LM Studio server address.
	DefaultLMStudioEndpoint = "http://localhost:1234/v1"
	// DefaultOpenAIEndpoint is the OpenAI API chat completions endpoint.
	DefaultOpenAIEndpoint = "https://api.openai.com/v1/chat/completions"
	// DefaultAnthropicEndpoint is the Anthropic API messages endpoint.
	DefaultAnthropicEndpoint = "https://api.anthropic.com/v1/messages"
	// DefaultScannerBackend is the default IaC scanner to use.
	DefaultScannerBackend = "checkov"
	// DefaultOutputFormat is the default output rendering format.
	DefaultOutputFormat = "terminal"
	// DefaultMaxRetries is the default number of LLM request retries.
	DefaultMaxRetries = 3
	// DefaultTemperature is the default LLM sampling temperature.
	DefaultTemperature = 0.2
	// DefaultPatchDir is the default directory for generated patch files.
	DefaultPatchDir = "./fixiac-patches"
)
