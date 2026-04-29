# AI Code Review Action

Automated AI-powered code review using OpenAI GPT models for GitHub pull requests.

## Features

- 🤖 AI-powered code analysis using OpenAI Responses API
- 🔒 Secure handling of sensitive files and data
- 📊 Configurable severity levels and failure conditions
- 💬 Automatic PR comments with findings
- 📋 JSON artifacts for audit trails
- 🖥️ Local review mode for pre-push validation with stdout JSON output
- 🎯 More stable reruns with deterministic review settings and completeness guidance
- 🧱 Structured JSON output from the Responses API for reliable parsing
- 📚 Repository-specific review instructions through a workflow input
- ✨ **NEW in v1.2.0:** Refined AI prompt reduces false positives and improves severity classification
- ✨ **NEW in v1.1.0:** Robust plain-text parsing eliminates JSON encoding issues


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
        uses: clearideas/ai-code-review-github-action@latest
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          openai_api_key: ${{ secrets.OPENAI_API_KEY }}
          # Optional customization:
          ai_model: 'gpt-5.5'
          max_diff_chars: '180000'
          max_review_files: '100'
          max_output_tokens: '6000'
          reasoning_effort: 'medium'
          fail_on_severity: '["high","critical","security"]'
          review_instructions: |
            Project-specific context for this repository.
      
      # Optional: Upload the detailed JSON report as an artifact
      - name: Upload AI Review Report
        if: always()  # Upload even if the review fails
        uses: actions/upload-artifact@v4
        with:
          name: ai-review-report
          path: ai-review-report-*.json
```

### Version Options

- **`@latest`** - Always use the newest version (recommended for most users)
- **`@v1.2.4`** - Pin to a specific version (recommended for production environments)

## Local Review

Run the same reviewer locally before pushing:

```bash
npm run review:local
```

Requirements:

- `OPENAI_API_KEY` must be set in your shell
- the current directory must be a git repository

Optional environment variables:

- `BASE_REF` - base ref for the diff range, defaults to `origin/main`

The local run writes the same JSON report artifact to the repo root and exits non-zero when blocking severities are found.
It also prints the JSON report to stdout between `AI_REVIEW_JSON_START` and `AI_REVIEW_JSON_END` markers for easy agent/tool consumption.

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `github_token` | GitHub token for API access | Yes | `${{ secrets.GITHUB_TOKEN }}` |
| `openai_api_key` | OpenAI API key | Yes | - |
| `ai_model` | OpenAI model to use | No | `gpt-5.5` |
| `max_diff_chars` | Max characters in diff | No | `180000` |
| `max_review_files` | Max changed files to fetch from the PR | No | `100` |
| `max_output_tokens` | Max model output tokens for the review | No | `6000` |
| `reasoning_effort` | Reasoning effort for supported models: `low`, `medium`, or `high` | No | `medium` |
| `fail_on_severity` | Severities that fail the check | No | `["high","critical","security"]` |
| `review_instructions` | Inline repository-specific review instructions | No | - |
| `max_review_instructions_chars` | Max characters of review instructions to send | No | `12000` |

## Repository Instructions

For repo-specific context, pass `review_instructions` in the workflow. This keeps the review background explicit in CI configuration and avoids relying on repository checkout.

Use this for architectural facts and project-specific false-positive guidance:

```yaml
with:
  review_instructions: |
    Controllers receive already validated input from route middleware; do not request duplicate validation in controllers unless a route lacks validation middleware.
    Missing imports in changed Vue files are valid review findings when the diff clearly introduces a new unimported symbol.
```

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

## Changelog

### v1.2.4

**Model & Parsing Improvements:**
- 🤖 **Updated default model**: Default reviewer model is now `gpt-5.5`
- 🧱 **Structured review output**: Uses strict JSON schema output through the Responses API instead of relying on plain-text formatting
- 🧼 **Reduced CI log exposure**: Stops logging the full model response body to GitHub Actions output
- 🟢 **Aligned build target**: Bundles for Node 20 to match the declared GitHub Action runtime
- 📚 **Added repo-specific instructions**: Supports a `review_instructions` workflow input and injects it into the prompt
- ⚡ **Improved review efficiency**: Caps fetched files, uses bounded output, keeps medium reasoning by default, disables response storage, and reports PR coverage truncation in the review comment

### v1.2.3

**Local Review & Stability Improvements:**
- 🖥️ **Added local review mode**: Run the same reviewer locally with `npm run review:local`
- 📄 **Added stdout JSON output**: Local runs now print the full report between `AI_REVIEW_JSON_START` and `AI_REVIEW_JSON_END`
- 🔑 **Improved local env support**: Local review accepts standard `OPENAI_API_KEY`, not just GitHub Action inputs
- 🎯 **Reduced rerun churn**: Added prompt instructions to return a comprehensive, stable set of findings in one pass
- 🧊 **Made reviews more deterministic**: Sets `temperature: 0` to reduce issue drift between reruns

### v1.2.1

**Bug Fix:**
- 🔧 **Fixed release workflow permissions**: Added `contents: write` permission to release workflow to fix GitHub Actions release creation errors

### v1.2.0

**Prompt Refinement:**
- 🎯 **Reduced false positives**: AI now understands it only sees diffs, not full files - won't flag missing imports or undefined types
- 🔧 **Tooling awareness**: Explicitly recognizes that type checkers and linters are already running
- 📊 **Improved severity classification**: Added detailed severity guidelines with examples to prevent over-escalation
- ✅ **Higher confidence threshold**: Requires 95%+ confidence before flagging issues
- 🚫 **Expanded exclusion list**: Explicitly excludes code style, theoretical concerns, and micro-optimizations
- 💡 **Focused review**: Concentrates on runtime bugs and security vulnerabilities that slip through other tools

**Improvements:**
- Reduced noise from false positives (missing imports, undefined types, etc.)
- More accurate severity levels (no longer over-characterizes issues)
- Better understanding of diff-only context
- Clearer guidelines on what to flag vs. ignore

### v1.1.4 (2025-10-16)

**Critical Fix:**
- 🔧 **Fixed content extraction**: Corrected path to use `ai.output_text` instead of `ai.response?.content`
- ✅ **Resolves empty response error**: AI responses now properly extracted and parsed
- 🎯 **Verified working**: Successfully tested with real workflow execution

### v1.1.3 (2025-10-16)

**File Support & Debugging:**
- 🌐 **Added HTML/CSS support**: Now includes .html, .htm, .css, .scss, .sass, .less files
- 🔍 **Enhanced debugging**: Added detailed logging for empty AI responses
- 🐛 **Improved troubleshooting**: Better error messages with full response structure

### v1.1.2 (2025-10-16)

**API Fix:**
- 🔧 **Fixed OpenAI Responses API parameter**: Changed from 'instructions' to 'input'
- Resolves "Missing required parameter: input" runtime error
- Ensures compatibility with OpenAI Responses API specification

### v1.1.1 (2025-10-16)

**Security Fix:**
- 🔒 **Fixed ReDoS vulnerability**: Applied CodeQL-recommended fix to regex pattern
- Prevents potential catastrophic backtracking in file path parsing
- No functional changes - all existing behavior preserved

### v1.1.0 (2025-10-16)

**Major Improvements:**
- 🎯 **Eliminated JSON parsing errors**: Switched from JSON structured output to plain-text parsing with severity markers
- 🚀 **More reliable**: Parser now handles code with quotes, braces, and special characters without breaking
- 🔧 **Robust parsing**: Tolerates AI formatting variations (spacing, markdown, case sensitivity)
- 📝 **Better debugging**: Plain text output is human-readable and easier to troubleshoot
- 🔄 **Using Responses API**: Continues to use OpenAI's modern Responses API for future compatibility

**What Changed:**
- Removed Zod schema validation and JSON structured output requirements
- AI now outputs plain text with `[SEVERITY]` markers (e.g., `[HIGH]`, `[CRITICAL]`, `[SECURITY]`)
- Enhanced text parser extracts structured data from plain text responses
- Improved artifact reporting includes both raw response and parsed structure

**Migration Notes:**
- No action required - the action works identically from a user's perspective
- All existing configurations and inputs remain unchanged
- Output format in PR comments stays the same

### v1.0.14 and earlier

Previous versions used JSON structured output which occasionally failed when reviewing code containing special characters.

## License

MIT
