package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

// LLMConfig holds settings for the LLM provider used for remediation.
type LLMConfig struct {
	// Provider is the LLM backend (e.g. "groq", "ollama", "openai", "anthropic", "lmstudio").
	Provider string `yaml:"provider" mapstructure:"provider"`
	// Model is the model identifier to use for inference.
	Model string `yaml:"model" mapstructure:"model"`
	// APIKey is the authentication key for the LLM provider.
	APIKey string `yaml:"api_key" mapstructure:"api_key"`
	// Endpoint is the HTTP endpoint for the LLM API.
	Endpoint string `yaml:"endpoint" mapstructure:"endpoint"`
	// MaxRetries is the number of times to retry failed LLM requests.
	MaxRetries int `yaml:"max_retries" mapstructure:"max_retries"`
	// Temperature controls the randomness of LLM responses.
	Temperature float64 `yaml:"temperature" mapstructure:"temperature"`
}

// ScannerConfig holds settings for the IaC security scanner.
type ScannerConfig struct {
	// Backend is the scanner to use ("checkov" or "trivy").
	Backend string `yaml:"backend" mapstructure:"backend"`
	// CheckovPath is an optional explicit path to the checkov binary.
	CheckovPath string `yaml:"checkov_path" mapstructure:"checkov_path"`
	// TrivyPath is an optional explicit path to the trivy binary.
	TrivyPath string `yaml:"trivy_path" mapstructure:"trivy_path"`
}

// OutputConfig holds settings for result output.
type OutputConfig struct {
	// Format is the output format ("terminal", "json", "sarif").
	Format string `yaml:"format" mapstructure:"format"`
	// PatchDir is the directory where generated patch files are written.
	PatchDir string `yaml:"patch_dir" mapstructure:"patch_dir"`
}

// GitHubConfig holds settings for GitHub integration.
type GitHubConfig struct {
	// Token is the GitHub personal access token used for PR operations.
	Token string `yaml:"token" mapstructure:"token"`
}

// Config is the top-level configuration for the fixiac CLI.
type Config struct {
	// LLM contains LLM provider settings.
	LLM LLMConfig `yaml:"llm" mapstructure:"llm"`
	// Scanner contains IaC scanner settings.
	Scanner ScannerConfig `yaml:"scanner" mapstructure:"scanner"`
	// Output contains output formatting settings.
	Output OutputConfig `yaml:"output" mapstructure:"output"`
	// GitHub contains GitHub integration settings.
	GitHub GitHubConfig `yaml:"github" mapstructure:"github"`
}

// Load reads configuration from the YAML config file and environment variables.
// If configPath is empty, it defaults to ~/.fixiac.yaml. Environment variables
// override file-based values using the FIXIAC_ prefix (e.g. FIXIAC_LLM_API_KEY).
func Load(configPath string) (*Config, error) {
	v := viper.New()
	v.SetConfigType("yaml")

	// Set defaults.
	v.SetDefault("llm.provider", DefaultLLMProvider)
	v.SetDefault("llm.model", DefaultLLMModel)
	v.SetDefault("llm.endpoint", DefaultGroqEndpoint)
	v.SetDefault("llm.max_retries", DefaultMaxRetries)
	v.SetDefault("llm.temperature", DefaultTemperature)
	v.SetDefault("scanner.backend", DefaultScannerBackend)
	v.SetDefault("output.format", DefaultOutputFormat)
	v.SetDefault("output.patch_dir", DefaultPatchDir)

	// Determine config file location.
	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("unable to determine home directory: %w", err)
		}
		v.SetConfigName(".fixiac")
		v.AddConfigPath(home)
	}

	// Read config file (ignore "not found" — rely on defaults).
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			// If a specific path was requested, a missing file is an error.
			if configPath != "" {
				return nil, fmt.Errorf("reading config file %s: %w", configPath, err)
			}
			// For default location, swallow errors other than parse failures.
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("parsing config: %w", err)
			}
		}
	}

	// Bind environment variable overrides.
	bindEnvVars(v)

	cfg := &Config{}
	if err := v.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("unmarshalling config: %w", err)
	}

	// Resolve the endpoint to a provider-specific default when the user has
	// changed the provider but not the endpoint.
	cfg.LLM.Endpoint = resolveEndpoint(cfg.LLM.Provider, cfg.LLM.Endpoint)

	return cfg, nil
}

// Set sets a config value and writes it to disk.
func (c *Config) Set(key, value string) error {
	return Set(key, value)
}

// Get gets a config value by dot-notation key.
func (c *Config) Get(key string) string {
	return Get(key)
}

// GetAll gets all settings as a map.
func (c *Config) GetAll() map[string]interface{} {
	return GetAll()
}

// bindEnvVars wires well-known environment variables to their viper keys.
func bindEnvVars(v *viper.Viper) {
	_ = v.BindEnv("llm.api_key", "FIXIAC_LLM_API_KEY")
	_ = v.BindEnv("llm.provider", "FIXIAC_LLM_PROVIDER")
	_ = v.BindEnv("llm.model", "FIXIAC_LLM_MODEL")
	_ = v.BindEnv("llm.endpoint", "FIXIAC_LLM_ENDPOINT")
	_ = v.BindEnv("scanner.backend", "FIXIAC_SCANNER_BACKEND")
	_ = v.BindEnv("github.token", "GITHUB_TOKEN")
}

// resolveEndpoint returns the appropriate default endpoint for the given provider
// when the current endpoint is empty or still set to another provider's default.
func resolveEndpoint(provider, current string) string {
	defaults := map[string]string{
		"groq":      DefaultGroqEndpoint,
		"ollama":    DefaultOllamaEndpoint,
		"lmstudio":  DefaultLMStudioEndpoint,
		"openai":    DefaultOpenAIEndpoint,
		"anthropic": DefaultAnthropicEndpoint,
	}

	if current != "" {
		// Check if the current endpoint is another provider's default; if so, swap
		// it to the correct one for the active provider.
		isOtherDefault := false
		for p, ep := range defaults {
			if p != provider && current == ep {
				isOtherDefault = true
				break
			}
		}
		if !isOtherDefault {
			return current
		}
	}

	if ep, ok := defaults[strings.ToLower(provider)]; ok {
		return ep
	}
	return current
}

// Set writes a key-value pair to the configuration file. The key uses dot
// notation (e.g. "llm.provider"). The config file must already exist or the
// home directory must be writable.
func Set(key, value string) error {
	v := viper.New()
	v.SetConfigType("yaml")

	cfgPath, err := defaultConfigFilePath()
	if err != nil {
		return err
	}
	v.SetConfigFile(cfgPath)

	// Attempt to read existing file; ignore not-found.
	_ = v.ReadInConfig()

	v.Set(key, value)

	if err := v.WriteConfigAs(cfgPath); err != nil {
		return fmt.Errorf("writing config file: %w", err)
	}
	return nil
}

// Get reads a single configuration value by key (dot notation).
func Get(key string) string {
	v := viper.New()
	v.SetConfigType("yaml")

	cfgPath, err := defaultConfigFilePath()
	if err != nil {
		return ""
	}
	v.SetConfigFile(cfgPath)
	_ = v.ReadInConfig()
	bindEnvVars(v)

	return v.GetString(key)
}

// GetAll returns the entire configuration as a map.
func GetAll() map[string]interface{} {
	v := viper.New()
	v.SetConfigType("yaml")

	cfgPath, err := defaultConfigFilePath()
	if err != nil {
		return map[string]interface{}{}
	}
	v.SetConfigFile(cfgPath)
	_ = v.ReadInConfig()
	bindEnvVars(v)

	return v.AllSettings()
}

// defaultConfigFilePath returns the path to ~/.fixiac.yaml.
func defaultConfigFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("unable to determine home directory: %w", err)
	}
	return filepath.Join(home, ".fixiac.yaml"), nil
}
