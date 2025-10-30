# AI Code Review Action

Automated AI-powered code review using OpenAI GPT models for GitHub pull requests.

## Features

- 🤖 AI-powered code analysis using OpenAI Responses API
- 🔒 Secure handling of sensitive files and data
- 📊 Configurable severity levels and failure conditions
- 💬 Automatic PR comments with findings
- 📋 JSON artifacts for audit trails
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

### Version Options

- **`@latest`** - Always use the newest version (recommended for most users)
- **`@v1.2.0`** - Pin to a specific version (recommended for production environments)

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

## Changelog

### v1.2.0 (Current)

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

