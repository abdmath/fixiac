<p align="center">
  <img src="https://img.shields.io/badge/Go-1.22+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go Version">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Terraform-IaC-7B42BC?style=for-the-badge&logo=terraform&logoColor=white" alt="Terraform">
  <img src="https://img.shields.io/badge/AI_Powered-LLM-FF6F00?style=for-the-badge&logo=openai&logoColor=white" alt="AI Powered">
</p>

<h1 align="center">
  <br>
  fixiac
  <br>
  <sub><sup>AI-Native Terraform Security Remediation</sup></sub>
</h1>

<p align="center">
  <strong>Every IaC security tool stops at detection. fixiac does the part after.</strong>
</p>

<p align="center">
  fixiac reads your Terraform files, finds the misconfigurations, understands the context of your actual codebase — your module structure, your variable naming conventions, your existing patterns — and generates a valid fix that fits how your code is already written. Not a generic textbook fix. A fix that looks like <em>your team</em> wrote it.
</p>

---

## The Problem

You run Checkov. It finds 47 misconfigurations. Now what?

A human reads each finding. Understands the context. Writes a fix. Hopes it doesn't break anything. Repeats 46 more times. This is the reality of IaC security today — detection is solved, remediation is manual.

## The Solution

```
fixiac scan ./terraform --fix --interactive --apply
```

fixiac bridges the gap between **detection** and **remediation** by combining:

- 🔍 **Multi-engine scanning** (Checkov + Trivy) — or bring your own JSON output
- 🧠 **AST-level codebase analysis** — understands your variables, modules, naming conventions, tag standards, and resource dependencies
- 🤖 **LLM-powered fix generation** — Groq, OpenAI, Anthropic, Ollama, LM Studio
- ✅ **Automatic validation** — every fix is validated with `terraform validate` and `terraform plan`
- 🎯 **Context-aware remediation** — fixes match your existing code style and patterns
- 📋 **Compliance mapping** — enriches findings with SOC 2, ISO 27001, HIPAA, and CIS controls

---

## Quick Start

### Install

```bash
# From source
go install github.com/abdmath/fixiac/cmd/fixiac@latest

# Or clone and build
git clone https://github.com/abdmath/fixiac.git
cd fixiac
go build -o fixiac ./cmd/fixiac
```

### Configure an LLM Provider

```bash
# Option 1: Groq (free tier, fast — recommended for getting started)
export FIXIAC_LLM_API_KEY="gsk_your_key_here"

# Option 2: OpenAI
fixiac config set llm.provider openai
export FIXIAC_LLM_API_KEY="sk-your_key_here"

# Option 3: Local models (no API key needed)
fixiac config set llm.provider ollama
fixiac config set llm.endpoint http://localhost:11434

# Option 4: LM Studio
fixiac config set llm.provider lmstudio
fixiac config set llm.endpoint http://localhost:1234/v1
```

### Run Your First Scan

```bash
# Scan and generate fixes
fixiac scan ./terraform

# Scan with interactive TUI review
fixiac scan ./terraform --interactive

# Scan, fix, and apply changes to files
fixiac scan ./terraform --fix --apply

# Scan, fix, and open a GitHub PR
fixiac scan ./terraform --fix --pr
```

---

## Features

### 🔍 Multi-Engine Detection

fixiac wraps existing scanners — it doesn't reinvent detection. Use Checkov, Trivy, or both. Findings are deduplicated and normalized into a unified model.

```bash
# Use Checkov (default)
fixiac scan ./terraform --scanner checkov

# Use Trivy
fixiac scan ./terraform --scanner trivy

# Use both with automatic deduplication
fixiac scan ./terraform --scanner both

# Or pipe in pre-existing scanner output (great for CI/CD)
fixiac scan ./terraform --input checkov-results.json
```

### 🧠 Codebase Context Analysis

Before generating any fix, fixiac parses your entire Terraform codebase using HashiCorp's HCL v2 parser to understand:

| Context | What fixiac Learns |
|---|---|
| **Variables** | Names, types, defaults, and values from `.tfvars` |
| **Modules** | Source, version, inputs, local vs. registry |
| **Naming Conventions** | Separator style (`-` vs `_`), prefix/suffix patterns, variable interpolation |
| **Tag Standards** | Required tags, common keys, consistent patterns |
| **Providers** | Region, profile, feature flags, default tags |
| **Dependencies** | Resource reference graph via `hclwrite` AST traversal |

This context is injected into every LLM prompt so the generated fix matches your codebase's style.

### 🤖 Multi-Provider LLM Support

| Provider | Model | Local/Cloud |
|---|---|---|
| **Groq** | Llama 3.3 70B (default) | ☁️ Cloud |
| **OpenAI** | GPT-4o, GPT-4o-mini | ☁️ Cloud |
| **Anthropic** | Claude 3.5 Sonnet, Claude 4 | ☁️ Cloud |
| **Ollama** | Any local model | 🏠 Local |
| **LM Studio** | Any local model | 🏠 Local |

```bash
# Switch providers on the fly
fixiac config set llm.provider groq
fixiac config set llm.model llama-3.3-70b-versatile

# Or use environment variables
export FIXIAC_LLM_PROVIDER=openai
export FIXIAC_LLM_MODEL=gpt-4o
export FIXIAC_LLM_API_KEY=sk-...
```

### ✅ Automatic Validation

Every generated fix is automatically validated:

1. **`terraform validate`** — catches syntax errors and invalid references
2. **`terraform plan -detailed-exitcode`** — detects breaking changes
3. **Blast radius analysis** — identifies which resources are affected
4. **Conflict detection** — prevents overlapping modifications to the same file regions

Fixes that fail validation are retried with error context up to `--max-retries` times.

### 📋 Compliance Framework Mapping

Every finding is enriched with compliance framework controls:

| Framework | Coverage |
|---|---|
| **SOC 2 Type II** | CC6.x, CC7.x, CC8.x controls |
| **ISO 27001:2022** | Annex A controls |
| **HIPAA** | 164.xxx security rules |
| **CIS AWS Foundations** | Benchmark checks |

```bash
# Filter findings by compliance framework
fixiac scan ./terraform --framework soc2
fixiac scan ./terraform --framework hipaa
fixiac scan ./terraform --framework cis_aws
```

### 🎯 Interactive Review Mode

Review each fix in an interactive TUI before applying:

```bash
fixiac scan ./terraform --fix --interactive --apply
```

The TUI shows:
- The original finding with code context
- The proposed fix with a diff view
- Compliance impact
- Blast radius analysis

For each fix you can **accept**, **skip**, or **modify**.

### 📤 Multiple Output Formats

| Format | Use Case |
|---|---|
| `terminal` | Human-readable CLI output (default) |
| `json` | CI/CD pipelines, scripting, `jq` processing |
| `sarif` | GitHub Advanced Security, Azure DevOps |
| `markdown` | PR comments, documentation |
| `patch` | Standard `.patch` diff files |

```bash
# SARIF for GitHub Code Scanning
fixiac scan ./terraform --output sarif > results.sarif

# JSON for CI/CD (status messages go to stderr)
fixiac scan ./terraform --output json --fix=false > findings.json

# Markdown for PR comments
fixiac scan ./terraform --output markdown > report.md
```

---

## CLI Reference

### `fixiac scan [directory]`

The main command. Scans Terraform files and optionally generates, validates, and applies fixes.

```
Flags:
  --scanner string       Scanner to use: checkov, trivy, or both (default "checkov")
  --input string         Read scanner JSON from file instead of running CLI
  --fix                  Generate AI-powered fixes (default true)
  --validate             Validate fixes with terraform validate (default true)
  --max-retries int      Max LLM retries for fix generation (default 3)
  --severity string      Minimum severity: LOW, MEDIUM, HIGH, CRITICAL (default "LOW")
  --framework string     Filter by compliance framework: soc2, hipaa, iso27001, cis_aws
  -i, --interactive      Interactive TUI review mode
  --apply                Apply accepted fixes to files
  --pr                   Create a GitHub pull request with fixes
  --repo string          Git remote for PR creation (default "origin")
  -o, --output string    Output format: terminal, json, sarif, markdown, patch (default "terminal")
  -q, --quiet            Suppress non-essential output
  -v, --verbose          Enable verbose output
```

### `fixiac fix [rule_id]`

Fix a specific finding.

```bash
fixiac fix CKV_AWS_18 --file main.tf --resource aws_s3_bucket.logs --apply
```

### `fixiac explain [rule_id]`

Explain a security rule in plain English with compliance context.

```bash
fixiac explain CKV_AWS_19
```

### `fixiac suppress [rule_id]`

Suppress a finding with audit logging.

```bash
fixiac suppress CKV_AWS_21 \
  --resource aws_s3_bucket.temp \
  --reason "Temporary scratch bucket, cleaned nightly" \
  --expires 30d
```

### `fixiac config`

Manage configuration.

```bash
fixiac config list              # Show all configuration
fixiac config get llm.provider  # Get a specific value
fixiac config set llm.model gpt-4o  # Set a value
```

---

## Configuration

fixiac loads configuration from (in order of priority):

1. CLI flags
2. Environment variables (`FIXIAC_LLM_API_KEY`, `FIXIAC_LLM_PROVIDER`, `FIXIAC_LLM_MODEL`, `GITHUB_TOKEN`)
3. `.fixiac.yaml` in the current directory
4. `~/.fixiac.yaml` in the home directory

### Example `.fixiac.yaml`

```yaml
llm:
  provider: groq
  model: llama-3.3-70b-versatile
  temperature: 0.2
  max_retries: 3

scanner:
  backend: checkov

output:
  format: terminal
  patch_dir: ./fixiac-patches

github:
  token: ${GITHUB_TOKEN}
```

---

## Architecture

```
fixiac/
├── cmd/fixiac/           # CLI entry point
├── internal/
│   ├── cli/              # Cobra command definitions (scan, fix, explain, suppress, config, version)
│   ├── scanner/          # Scanner interface + Checkov/Trivy wrappers + JSON parsers
│   ├── context/          # HCL v2 AST analysis (variables, modules, conventions, tags, graph)
│   ├── llm/              # Multi-provider LLM client factory + prompt engineering
│   ├── remediation/      # Fix generator, validator, applier, patcher, blast radius, conflicts
│   ├── compliance/       # Framework mapping engine (SOC 2, ISO 27001, HIPAA, CIS)
│   ├── output/           # Formatters (terminal/lipgloss, JSON, SARIF 2.1, markdown, patch)
│   ├── interactive/      # Bubble Tea TUI for fix review
│   ├── suppress/         # YAML-based suppression store with expiry and audit
│   ├── config/           # Viper configuration management
│   └── github/           # GitHub REST API client (PR creation, comments)
├── configs/
│   ├── frameworks/       # Compliance framework YAML definitions
│   └── mappings/         # Checkov rule → framework control mappings
└── testdata/             # Sample Terraform files and scanner JSON for testing
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [pull_request]

jobs:
  fixiac:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.22'

      - name: Install fixiac
        run: go install github.com/abdma/fixiac/cmd/fixiac@latest

      - name: Install Checkov
        run: pip install checkov

      - name: Run fixiac scan
        env:
          FIXIAC_LLM_API_KEY: ${{ secrets.FIXIAC_LLM_API_KEY }}
        run: |
          fixiac scan . --output sarif --fix=false > results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### Offline / Air-Gapped Environments

```bash
# 1. Run Checkov separately and capture JSON
checkov -d ./terraform -o json > checkov-results.json

# 2. Feed results into fixiac with a local LLM
fixiac scan ./terraform \
  --input checkov-results.json \
  --fix \
  --output json
```

---

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
git clone https://github.com/abdmath/fixiac.git
cd fixiac
go mod tidy
go build ./cmd/fixiac
go test ./...
go vet ./...
```

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  <sub>Built with ❤️ for the DevSecOps community</sub>
</p>
