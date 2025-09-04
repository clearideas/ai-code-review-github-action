# AI Code Review Action

Automated AI-powered code review using OpenAI GPT models for GitHub pull requests.

## Features

- 🤖 AI-powered code analysis using OpenAI models
- 🔒 Secure handling of sensitive files and data
- 📊 Configurable severity levels and failure conditions
- 💬 Automatic PR comments with findings
- 📋 JSON artifacts for audit trails

## Changelog

### v1.0.2 (Latest)
- **Fixed:** Resolved `__classPrivateFieldGet` and dynamic require bundling errors
- **Improved:** Migrated from @vercel/ncc to esbuild for faster and more reliable bundling
- **Fixed:** Proper Node.js 20 compatibility with CommonJS format
- **Fixed:** Updated README to include required `github-token` input in usage examples

### v1.0.1
- **Fixed:** Resolved `ERR_MODULE_NOT_FOUND` error when action is invoked from other repositories
- **Improved:** Bundled all dependencies into single file for better reliability
- **Added:** Build process with @vercel/ncc for dependency bundling

### v1.0.0
- Initial release with AI-powered code review functionality

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
        uses: clearideas/ai-code-review-github-action@v1.0.4
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          openai-api-key: ${{ secrets.OPENAI_API_KEY }}
          # Optional customization:
          ai-model: 'gpt-5-mini'
          max-diff-chars: '180000'
          fail-on-severity: '["high","critical","security"]'
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `github-token` | GitHub token for API access | Yes | `${{ secrets.GITHUB_TOKEN }}` |
| `openai-api-key` | OpenAI API key | Yes | - |
| `ai-model` | OpenAI model to use | No | `gpt-5-mini` |
| `max-diff-chars` | Max characters in diff | No | `180000` |
| `fail-on-severity` | Severities that fail the check | No | `["high","critical","security"]` |

## Setup

1. **Add OpenAI API Key**: Add `OPENAI_API_KEY` to your repository secrets
2. **GitHub Token**: The action uses `${{ secrets.GITHUB_TOKEN }}` which is automatically available in all GitHub workflows
3. **Create Workflow**: Create the workflow file as shown above
4. The action will automatically run on pull requests

**Note:** Make sure to include both `github-token` and `openai-api-key` in your workflow's `with:` section.

## Security

- Sensitive files are automatically excluded from AI analysis
- Secrets are redacted before sending to AI
- Only safe file types are reviewed
- All data handling follows security best practices

## License

MIT

