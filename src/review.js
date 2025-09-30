import fs from 'node:fs'
import { Octokit } from '@octokit/rest'
import { OpenAI } from 'openai'
import { z } from 'zod'

// Get inputs from GitHub Action environment
const {
  INPUT_GITHUB_TOKEN: GITHUB_TOKEN,
  INPUT_OPENAI_API_KEY: OPENAI_API_KEY,
  INPUT_AI_MODEL: AI_MODEL = 'gpt-5-mini',
  INPUT_MAX_DIFF_CHARS: MAX_DIFF_CHARS = '180000',
  INPUT_FAIL_ON_SEVERITY: FAIL_ON_SEVERITY = '["high","critical","security"]',
  GITHUB_REPOSITORY,
} = process.env

if (!GITHUB_TOKEN) throw new Error('Missing github_token input')
if (!OPENAI_API_KEY) throw new Error('Missing openai_api_key input')
if (!GITHUB_REPOSITORY || !GITHUB_REPOSITORY.includes('/')) {
  throw new Error('Missing or invalid GITHUB_REPOSITORY (expected owner/repo)')
}

const [owner, repo] = GITHUB_REPOSITORY.split('/')

// Get PR number from GitHub event or environment
let prNumber
if (process.env.GITHUB_EVENT_PATH) {
  try {
    const event = JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8'))
    prNumber = event.pull_request?.number
  } catch (error) {
    console.warn('Could not read GitHub event:', error.message)
  }
}

// Fallback to parsing from GITHUB_REF
if (!prNumber) {
  prNumber = parseInt(
    process.env.GITHUB_REF?.match(/refs\/pull\/(\d+)\/merge/)?.[1] ||
      process.env.GITHUB_REF_NAME ||
      process.env.PR_NUMBER ||
      '',
    10,
  )
}

if (!Number.isInteger(prNumber)) {
  throw new Error('Unable to determine pull request number from GitHub event or environment')
}

const octo = new Octokit({ auth: GITHUB_TOKEN })
const openai = new OpenAI({ apiKey: OPENAI_API_KEY })

const Issue = z.object({
  file: z.string().catch('unknown'),
  line: z.number().int().nullable().catch(null),
  severity: z.enum(['info', 'low', 'medium', 'high', 'critical', 'security']).catch('info'),
  title: z.string().catch('Untitled Issue'),
  detail: z.string().catch('No details provided'),
  suggestion: z.string().nullable().catch(null),
  tags: z.array(z.string()).nullable().catch(null),
})

const ReviewShape = z.object({
  summary: z.string().catch('AI review completed'),
  overall_risk: z.enum(['low', 'medium', 'high', 'critical']).catch('low'),
  issues: z.array(Issue).default([]).catch([]),
})

// Simplified JSON Schema for OpenAI structured outputs - more flexible to handle code content issues
const reviewJsonSchema = {
  type: "object",
  properties: {
    summary: {
      type: "string",
      description: "Brief, encouraging overview of the code review"
    },
    overall_risk: {
      type: "string",
      enum: ["low", "medium", "high", "critical"],
      description: "Overall risk assessment of the changes",
      default: "low"
    },
    issues: {
      type: "array",
      description: "Array of issues found in the code",
      items: {
        type: "object",
        properties: {
          file: {
            type: "string",
            description: "Path to the file where the issue was found",
            default: "unknown"
          },
          line: {
            type: ["integer", "null"],
            description: "Line number where the issue occurs (null if not applicable)",
            default: null
          },
          severity: {
            type: "string",
            enum: ["info", "low", "medium", "high", "critical", "security"],
            description: "Severity level of the issue",
            default: "info"
          },
          title: {
            type: "string",
            description: "Clear, specific title of the issue",
            default: "Untitled Issue"
          },
          detail: {
            type: "string",
            description: "Detailed explanation of the issue",
            default: "No details provided"
          },
          suggestion: {
            type: ["string", "null"],
            description: "Actionable suggestion to fix the issue (null if not applicable)",
            default: null
          },
          tags: {
            type: ["array", "null"],
            items: { type: "string" },
            description: "Optional tags for categorizing the issue (null if not applicable)",
            default: null
          }
        },
        // Removed strict requirements to allow flexibility with code content
        additionalProperties: true
      },
      default: []
    }
  },
  required: ["summary", "overall_risk", "issues"],
  // Allow additional properties in case AI includes extra fields
  additionalProperties: true
}

let failOn
try {
  const parsed = JSON.parse(FAIL_ON_SEVERITY)
  if (!Array.isArray(parsed)) {
    throw new Error('FAIL_ON_SEVERITY must be a JSON array')
  }
  const validSeverities = ['info', 'low', 'medium', 'high', 'critical', 'security']
  const invalid = parsed.filter(s => !validSeverities.includes(s))
  if (invalid.length > 0) {
    throw new Error(`Invalid severities in FAIL_ON_SEVERITY: ${invalid.join(', ')}`)
  }
  failOn = new Set(parsed)
} catch (error) {
  console.error('Failed to parse FAIL_ON_SEVERITY:', error.message)
  console.error('Using default: ["high", "critical", "security"]')
  failOn = new Set(['high', 'critical', 'security'])
}

function truncate(str, n) {
  if (str.length <= n) return str
  return str.slice(0, n) + '\n\n[...diff truncated for token safety...]'
}

// Exclude obviously sensitive files and paths from being sent to AI
const SENSITIVE_FILE_PATTERNS = [
  /(^|\/)\.env(\..*)?$/i,
  /(^|\/)secrets?(\/|$)/i,
  /(^|\/)node_modules\//,
  /(^|\/)dist\//,
  /(^|\/)build\//,
  /(^|\/)coverage\//,
  /(^|\/)vendor\//,
  /(^|\/)\.git\//,
  /\.pem$/i,
  /\.key$/i,
  /id_rsa/i,
  /id_dsa/i,
  /\.pfx$/i,
  /\.p12$/i,
  /\.crt$/i,
  /\.cert$/i,
  /\.keystore$/i,
  /package-lock\.json$/i,
  /pnpm-lock\.yaml$/i,
  /yarn\.lock$/i,
]

function isSensitiveFile(filename) {
  return SENSITIVE_FILE_PATTERNS.some(p => p.test(filename))
}

// Focus on code files for practical review
const ALLOWED_FILE_EXTENSIONS = [
  /\.js$/i,
  /\.ts$/i,
  /\.tsx$/i,
  /\.jsx$/i,
  /\.vue$/i,
  /\.py$/i,
  /\.go$/i,
  /\.rb$/i,
  /\.java$/i,
  /\.cs$/i,
  /\.sh$/i,
  /\.sql$/i,
  /\.md$/i,
  // Common config files
  /\.json$/i,
  /\.yml$/i,
  /\.yaml$/i,
]

// Allow common build/config files
const ALLOWED_FILENAMES = [/^Dockerfile$/i, /^Dockerfile\./i, /^Makefile$/i, /^package\.json$/i]

function isAllowedFile(filename) {
  const basename = filename.split('/').pop()
  return (
    ALLOWED_FILE_EXTENSIONS.some(r => r.test(filename)) ||
    ALLOWED_FILENAMES.some(r => r.test(basename))
  )
}

function filterSafeFiles(files) {
  const excluded = []
  const included = []

  for (const file of files) {
    if (isSensitiveFile(file.filename)) {
      excluded.push(`${file.filename} (sensitive pattern)`)
    } else if (!isAllowedFile(file.filename)) {
      excluded.push(`${file.filename} (not allowed extension)`)
    } else {
      included.push(file)
    }
  }

  // Log excluded files for auditability
  if (excluded.length > 0) {
    console.log(`Excluded ${excluded.length} files from AI review:`)
    excluded.forEach(reason => console.log(`  - ${reason}`))
  }

  console.log(`Including ${included.length} files in AI review`)
  return included
}

// Conservative redaction of obvious secrets only
function sanitizeDiff(diffText) {
  let sanitized = diffText

  // Only redact very obvious secret patterns to avoid breaking code

  // PEM blocks (clear delimiters)
  sanitized = sanitized.replace(
    /-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----/g,
    '[REDACTED_PEM_BLOCK]',
  )

  // AWS Access Key IDs (very specific format)
  sanitized = sanitized.replace(/AKIA[0-9A-Z]{16}/g, '[REDACTED_AWS_KEY]')

  // GitHub tokens (all known prefixes)
  sanitized = sanitized.replace(/gh[a-z]{1,3}_[A-Za-z0-9_-]{20,}/gi, '[REDACTED_GITHUB_TOKEN]')

  // Long base64-looking strings (likely secrets, 40+ chars)
  sanitized = sanitized.replace(/[A-Za-z0-9\/+=]{40,}/g, match => {
    // Only redact if it looks like a standalone secret (not code)
    if (/^[A-Za-z0-9\/+=]+$/.test(match) && match.length >= 40) {
      return '[REDACTED_LONG_STRING]'
    }
    return match
  })

  return sanitized
}

function formatUnifiedPatch(files) {
  // GitHub's listFiles returns `patch` (unified diff) per file; concatenate safely.
  let out = ''
  let totalSize = 0
  const maxFileSize = 50000 // Skip very large files
  const maxTotalSize = 150000 // Stop before hitting memory issues

  for (const f of files) {
    if (!f.patch) continue
    if (f.patch.length > maxFileSize) {
      out += `\n--- a/${f.filename}\n+++ b/${f.filename}\n[File too large for review]\n`
      continue
    }
    if (totalSize + f.patch.length > maxTotalSize) {
      out += `\n[Additional files truncated for size]\n`
      break
    }
    out += `\n--- a/${f.filename}\n+++ b/${f.filename}\n${f.patch}\n`
    totalSize += f.patch.length
  }
  return out
}

function escapeMarkdown(text) {
  // Escape markdown special characters to prevent injection
  return text.replace(/[[\\\]`*_{}()#+\-.!]/g, '\\$&')
}

function asMarkdown(review) {
  const lines = []
  lines.push(`### 🤖 AI Code Review (${review.overall_risk.toUpperCase()})`)
  lines.push('')
  lines.push(escapeMarkdown(review.summary))
  lines.push('')
  if (!review.issues.length) {
    lines.push('**No issues found.** ✅')
  } else {
    lines.push(`**Findings (${review.issues.length}):**`)
    for (const [i, iss] of review.issues.entries()) {
      const escapedTitle = escapeMarkdown(iss.title)
      const escapedDetail = escapeMarkdown(iss.detail)
      const escapedSuggestion = iss.suggestion ? escapeMarkdown(iss.suggestion) : ''
      lines.push(
        `- **${i + 1}. [${iss.severity.toUpperCase()}] ${escapedTitle}** — \`${iss.file}${iss.line ? `:${iss.line}` : ''}\`\n` +
          `  ${escapedDetail}${escapedSuggestion ? `\n  **Suggestion:** ${escapedSuggestion}` : ''}`,
      )
    }
  }
  return lines.join('\n')
}

function truncateComment(text, maxLen = 60000) {
  if (text.length <= maxLen) return text
  return text.slice(0, maxLen) + '\n\n[Comment truncated for size. See artifact for full report.]'
}

// Robust parsing function that tries multiple approaches when structured output fails
async function attemptRobustParsing(text) {
  console.log('🔄 Starting robust parsing attempts...')

  // Attempt 1: Try to extract JSON from the response (in case AI added extra text)
  const jsonMatch = text.match(/\{[\s\S]*\}/)
  if (jsonMatch) {
    try {
      console.log('🔍 Found JSON-like content, attempting to parse...')
      const jsonResponse = JSON.parse(jsonMatch[0])
      console.log('✅ JSON extraction and parsing successful')

      return {
        summary: jsonResponse.summary || 'AI review completed with parsing issues',
        overall_risk: ['low', 'medium', 'high', 'critical'].includes(jsonResponse.overall_risk)
          ? jsonResponse.overall_risk : 'low',
        issues: Array.isArray(jsonResponse.issues) ? jsonResponse.issues.map(issue => ({
          file: issue.file || 'unknown',
          line: typeof issue.line === 'number' ? issue.line : null,
          severity: ['info', 'low', 'medium', 'high', 'critical', 'security'].includes(issue.severity)
            ? issue.severity : 'info',
          title: issue.title || 'Untitled Issue',
          detail: issue.detail || 'No details provided',
          suggestion: issue.suggestion || null,
          tags: Array.isArray(issue.tags) ? issue.tags : null,
        })) : []
      }
    } catch (error) {
      console.log('❌ JSON extraction failed, trying next approach...')
    }
  }

  // Attempt 2: Pattern-based extraction for critical issues
  console.log('🔍 Attempting pattern-based extraction...')
  const patternData = extractIssuesFromText(text)

  if (patternData.issues.length > 0 || text.toLowerCase().includes('looks good') || text.toLowerCase().includes('no issues')) {
    console.log('✅ Pattern-based extraction found content')
    return patternData
  }

  // Attempt 3: If all else fails, create a generic response
  console.log('❌ All parsing attempts failed, using generic response')
  return {
    summary: 'AI review completed but response format was unexpected. Manual review recommended.',
    overall_risk: 'medium',
    issues: [{
      file: 'ai-review-script',
      line: null,
      severity: 'medium',
      title: 'Response parsing failed',
      detail: 'Could not parse AI response using multiple methods. Check artifacts for raw output.',
      suggestion: 'Report this issue for debugging.',
      tags: ['parsing-error']
    }]
  }
}

// Extract issues using pattern matching when JSON parsing fails
function extractIssuesFromText(text) {
  const issues = []
  let overall_risk = 'low'

  // Look for severity indicators in the text
  const highMatches = text.match(/\[?\b(HIGH|HIGH RISK|CRITICAL|CRITICAL RISK|SECURITY|SECURITY RISK)\b\]?/gi) || []
  const mediumMatches = text.match(/\[?\b(MEDIUM|MEDIUM RISK)\b\]?/gi) || []
  const lowMatches = text.match(/\[?\b(LOW|LOW RISK|INFO)\b\]?/gi) || []

  // Determine overall risk based on found indicators
  if (highMatches.length > 0) {
    overall_risk = 'high'
  } else if (mediumMatches.length > 0) {
    overall_risk = 'medium'
  }

  // Extract specific issues using regex patterns
  const issuePatterns = [
    // Pattern: [SEVERITY] Issue description (file:line)
    /\[?(HIGH|CRITICAL|SECURITY)\]?\s*([^-\n]+?)(?:\s*[-–]\s*([^:\n]+?):?(\d+)?)?/gi,
    // Pattern: Issue in file:line - severity
    /([^-\n]+?)\s*[-–]\s*([^:\n]+?):?(\d+)?\s*[-–]\s*\[?(HIGH|CRITICAL|SECURITY)\]?/gi,
    // Pattern: File: issue description [SEVERITY]
    /([^:\n]+?):(.+?)\[?(HIGH|CRITICAL|SECURITY)\]?/gi,
  ]

  for (const pattern of issuePatterns) {
    let match
    while ((match = pattern.exec(text)) !== null) {
      const severity = match.find(m => ['HIGH', 'CRITICAL', 'SECURITY', 'MEDIUM', 'LOW'].includes(m?.toUpperCase()))?.toLowerCase() || 'medium'
      const title = match.find(m => m && m.length > 3 && !m.match(/^\d+$/)) || 'Issue found'
      const file = match.find(m => m && m.includes('/')) || 'unknown'
      const line = match.find(m => m && /^\d+$/.test(m))

      // Only add if we haven't already captured this issue
      const issueKey = `${file}:${line || 'no-line'}:${severity}:${title}`
      if (!issues.some(issue => `${issue.file}:${issue.line || 'no-line'}:${issue.severity}:${issue.title}` === issueKey)) {
        issues.push({
          file: file.replace(/^\s*[-–]\s*/, ''),
          line: line ? parseInt(line, 10) : null,
          severity: severity,
          title: title.replace(/^\s*[-–]\s*/, '').trim(),
          detail: `Issue detected in code review requiring attention.`,
          suggestion: null,
          tags: ['pattern-extracted']
        })
      }
    }
  }

  // If no specific issues found but text suggests problems, create a generic issue
  if (issues.length === 0 && (highMatches.length > 0 || mediumMatches.length > 0)) {
    issues.push({
      file: 'unknown',
      line: null,
      severity: highMatches.length > 0 ? 'high' : 'medium',
      title: 'Issues detected in code review',
      detail: 'The AI review identified potential issues but specific details could not be extracted.',
      suggestion: 'Please review the raw AI response in artifacts for detailed findings.',
      tags: ['pattern-extracted']
    })
  }

  return {
    summary: issues.length > 0
      ? `AI review identified ${issues.length} potential issue${issues.length > 1 ? 's' : ''} requiring attention.`
      : 'AI review completed - no critical issues detected in parseable format.',
    overall_risk: overall_risk,
    issues: issues
  }
}

;(async () => {
  try {
    // 1) Load PR & changed files
    const { data: pr } = await octo.pulls.get({ owner, repo, pull_number: prNumber })
    const prBody = pr.body || ''
    const prTitle = pr.title || ''
    const files = await octo.paginate(octo.pulls.listFiles, {
      owner,
      repo,
      pull_number: prNumber,
      per_page: 100,
    })

    const safeFiles = filterSafeFiles(files)
    const rawDiff = formatUnifiedPatch(safeFiles)
    const redactedDiff = sanitizeDiff(rawDiff)
    const diff = truncate(redactedDiff, parseInt(MAX_DIFF_CHARS, 10))

    // 2) Ask AI to review
    const system = `You are a helpful coding assistant reviewing a pull request. The developer knows what they're doing - you're here to catch things they might have missed, not to question their architectural decisions.

GOAL: Be a useful pair programming buddy. Find obvious bugs and improvements, not theoretical security issues.

WHAT TO LOOK FOR (only flag if you're confident):
✅ Actual bugs:
   - Syntax errors or typos
   - Null/undefined dereferencing
   - Incorrect API usage
   - Logic errors that would cause failures

✅ Obvious improvements:
   - Missing error handling where it clearly should exist
   - Performance issues (infinite loops, obvious inefficiencies)
   - Clear security vulnerabilities (hardcoded passwords, SQL injection)

❌ DON'T FLAG:
   - Code style or formatting 
   - Missing tests or documentation
   - Theoretical security concerns
   - Config files (trust the developer)
   - Redacted values like [REDACTED_AWS_KEY]
   - Architectural decisions
   - "Could be" or "might be" issues

TONE: Assume the developer is competent. If you're not sure about an issue, don't report it.

RESPONSE FORMAT: Provide a JSON response matching this structure:
{
  "summary": "Brief, encouraging overview of the code review",
  "overall_risk": "low|medium|high|critical",
  "issues": [
    {
      "file": "path/to/file",
      "line": 123,
      "severity": "info|low|medium|high|critical|security",
      "title": "Clear, specific title",
      "detail": "Detailed explanation",
      "suggestion": "Actionable suggestion (or null)",
      "tags": ["tag1", "tag2"] (or null)
    }
  ]
}

If everything looks good, provide a positive summary with "low" overall_risk and an empty issues array.

IMPORTANT: Ensure your response is valid JSON even if the code contains special characters.`

    const user = [
      {
        role: 'user',
        content: `Pull Request Title: ${prTitle}

Pull Request Description:
${prBody}

Unified Diff (truncated if large):
${diff}
`,
      },
    ]

    console.log('🤖 AI Model being used:', AI_MODEL);
    console.log('🔄 Using responses API for structured outputs...')
    const ai = await openai.responses.create({
      model: AI_MODEL,
      instructions: system + '\n\nUser Request:\n' + user[0].content,
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "code_review_response",
          description: "AI code review analysis with structured output",
          schema: reviewJsonSchema,
          // Removed strict mode to be more flexible with code content
          strict: false
        }
      }
    })
    console.log('✅ Responses API call succeeded')

    // Detailed logging for debugging response structure issues
    console.log('📊 Full AI response object keys:', Object.keys(ai))
    if (ai.response) {
      console.log('📊 Response object keys:', Object.keys(ai.response))
    }
    console.log('📊 Full AI response object:', JSON.stringify(ai, null, 2))

    // Extract content from responses API format - OpenAI responses API returns { response: { content: "..." } }
    let text
    if (ai.response && ai.response.content) {
      text = ai.response.content
      console.log('✅ Found content in ai.response.content')
    } else if (ai.content) {
      // Fallback for older or different response formats
      text = ai.content
      console.log('✅ Found content in ai.content (fallback)')
    } else {
      console.error('❌ AI response missing content in expected location')
      console.error('❌ Available response paths:')
      console.error('  - ai.response.content:', ai.response?.content ? 'EXISTS' : 'MISSING')
      console.error('  - ai.content:', ai.content ? 'EXISTS' : 'MISSING')
      console.error('❌ Full response:', JSON.stringify(ai, null, 2))
      throw new Error('AI response missing content in expected location')
    }
    console.log('📝 AI Response length:', text.length)
    console.log('📝 AI Response content:', text)
    
    if (!text || text.trim() === '') {
      console.error('❌ AI returned empty response')
      console.error('❌ Full API response:', JSON.stringify(ai, null, 2))
      throw new Error('AI returned empty response')
    }
    let parsed
    try {
      // Parse JSON first
      let jsonResponse
      try {
        jsonResponse = JSON.parse(text)
        console.log('✅ JSON parsing successful')
      } catch (jsonError) {
        console.error('❌ JSON parsing failed:', jsonError.message)
        console.error('❌ Raw response length:', text.length)
        console.error('❌ Raw response preview:', text.substring(0, 500))
        if (text.length > 500) {
          console.error('❌ Raw response end:', text.substring(text.length - 500))
        }
        throw new Error(`Invalid JSON response: ${jsonError.message}`)
      }

      // Validate with forgiving Zod schema
      parsed = ReviewShape.parse(jsonResponse)
      console.log('✅ Successfully parsed and validated AI response')
    } catch (error) {
      console.error('❌ Error parsing AI response:', error.message)
      console.error('❌ Raw response length:', text.length)
      console.error('❌ Raw response preview:', text.substring(0, 500))
      if (text.length > 500) {
        console.error('❌ Raw response end:', text.substring(text.length - 500))
      }

      // Try multiple fallback approaches for robust parsing
      let fallbackData = await attemptRobustParsing(text)
      
      parsed = fallbackData
    }

    // 3) Persist raw JSON report for auditors
    const workspaceDir = process.env.GITHUB_WORKSPACE || process.cwd()
    const reportFileName = `ai-review-report-${Date.now()}.json`
    const reportPath = `${workspaceDir}/${reportFileName}`
    fs.writeFileSync(reportPath, JSON.stringify(parsed, null, 2))
    console.log(`AI review report written to: ${reportPath}`)
    console.log(`📄 To download as artifact, add this step to your workflow:`)
    console.log(`   - uses: actions/upload-artifact@v4`)
    console.log(`     with:`)
    console.log(`       name: ai-review-report`)
    console.log(`       path: ${reportFileName}`)

    // 4) Post (or update) a single summary comment
    const marker = '<!-- ai-code-review-bot -->'
    const bodyMd = `${marker}\n${asMarkdown(parsed)}\n${marker}`
    const allComments = await octo.paginate(octo.issues.listComments, {
      owner,
      repo,
      issue_number: prNumber,
      per_page: 100,
    })
    const botComment = allComments.find(c => c.body?.includes(marker))

    if (botComment) {
      await octo.issues.updateComment({
        owner,
        repo,
        comment_id: botComment.id,
        body: truncateComment(bodyMd),
      })
    } else {
      await octo.issues.createComment({
        owner,
        repo,
        issue_number: prNumber,
        body: truncateComment(bodyMd),
      })
    }

    // 5) Fail the check if any high-severity/security issues
    const shouldFail = parsed.issues.some(i => failOn.has(i.severity))
    if (shouldFail) {
      console.error(
        'AI review found blocking issues:',
        parsed.issues.filter(i => failOn.has(i.severity)).map(i => i.title),
      )
      process.exit(1)
    } else {
      console.log('AI review passed (no blocking issues).')
    }
  } catch (err) {
    console.error('AI review failed:', err)
    process.exit(1)
  }
})()