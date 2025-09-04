# AI Code Review Action

Automated AI-powered code review using OpenAI GPT models for GitHub pull requests.

## Features

- 🤖 AI-powered code analysis using OpenAI models
- 🔒 Secure handling of sensitive files and data
- 📊 Configurable severity levels and failure conditions
- 💬 Automatic PR comments with findings
- 📋 JSON artifacts for audit trails

## Usage

Add this to your repository's `.github/workflows/ai-code-review.yml`:

```yaml
name: AI Code Review

on:
  pull_request:
    types: [opened, reopened, synchronize, edited]

permissions:
  contents: read
  pull-requests: write
  checks: write

jobs:
  review:
    if: ${{ github.event.pull_request.head.repo.full_name == github.repository }}
    runs-on: ubuntu-latest
    steps:
      - name: AI Code Review
        uses: clearideas/ai-code-review-github-action@v1
        with:
          openai-api-key: ${{ secrets.OPENAI_API_KEY }}
          # Optional customization:
          ai-model: 'gpt-5-mini'
          max-diff-chars: '180000'
          fail-on-severity: '["high","critical","security"]'
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `github-token` | GitHub token for API access | No | `${{ github.token }}` |
| `openai-api-key` | OpenAI API key | Yes | - |
| `ai-model` | OpenAI model to use | No | `gpt-5-mini` |
| `max-diff-chars` | Max characters in diff | No | `180000` |
| `fail-on-severity` | Severities that fail the check | No | `["high","critical","security"]` |

## Setup

1. Add `OPENAI_API_KEY` to your repository secrets
2. Create the workflow file as shown above
3. The action will automatically run on pull requests

## Security

- Sensitive files are automatically excluded from AI analysis
- Secrets are redacted before sending to AI
- Only safe file types are reviewed
- All data handling follows security best practices

## License

MIT

