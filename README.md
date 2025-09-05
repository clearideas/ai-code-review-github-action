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
        uses: clearideas/ai-code-review-github-action@v1.0.9
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          openai_api_key: ${{ secrets.OPENAI_API_KEY }}
          # Optional customization:
          ai_model: 'gpt-5-mini'
          max_diff_chars: '180000'
          fail_on_severity: '["high","critical","security"]'
      
      # Optional: Upload the detailed JSON report as an artifact
      - name: Upload AI Review Report
        if: always()  # Upload even if the review fails
        uses: actions/upload-artifact@v4
        with:
          name: ai-review-report
          path: ai-review-report-*.json
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `github_token` | GitHub token for API access | Yes | `${{ secrets.GITHUB_TOKEN }}` |
| `openai_api_key` | OpenAI API key | Yes | - |
| `ai_model` | OpenAI model to use | No | `gpt-5-mini` |
| `max_diff_chars` | Max characters in diff | No | `180000` |
| `fail_on_severity` | Severities that fail the check | No | `["high","critical","security"]` |

## Setup

1. **Add OpenAI API Key**: Add `OPENAI_API_KEY` to your repository secrets
2. **GitHub Token**: The action uses `${{ secrets.GITHUB_TOKEN }}` which is automatically available in all GitHub workflows
3. **Create Workflow**: Create the workflow file as shown above
4. The action will automatically run on pull requests

**Note:** Make sure to include both `github_token` and `openai_api_key` in your workflow's `with:` section.

## Security

- Sensitive files are automatically excluded from AI analysis
- Secrets are redacted before sending to AI
- Only safe file types are reviewed
- All data handling follows security best practices

## License

MIT

