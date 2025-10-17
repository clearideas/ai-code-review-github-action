import fs from 'node:fs'
import { Octokit } from '@octokit/rest'
import { OpenAI } from 'openai'

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

// Parse plain text AI response with severity markers
function extractIssuesFromText(text) {
  const issues = []
  let overall_risk = 'low'
  let summary = ''

  // Extract overall risk from marker
  const riskMatch = text.match(/OVERALL\s+RISK:\s*(LOW|MEDIUM|HIGH|CRITICAL)/i)
  if (riskMatch) {
    overall_risk = riskMatch[1].toLowerCase()
  }

  // Extract summary (text before first severity marker or all text after OVERALL RISK)
  const firstIssueMatch = text.search(/\[(SECURITY|CRITICAL|HIGH|MEDIUM|LOW|INFO)\]/i)
  if (firstIssueMatch > 0) {
    summary = text.substring(0, firstIssueMatch).trim()
  } else {
    // No issues found, use all text
    summary = text.trim()
  }
  
  // Clean up summary - remove "OVERALL RISK:" line if present
  summary = summary.replace(/OVERALL\s+RISK:\s*(LOW|MEDIUM|HIGH|CRITICAL)\s*/gi, '').trim()
  if (!summary) {
    summary = 'AI review completed'
  }

  // Pattern to match issues: [SEVERITY] Title - file.js:line
  // More flexible pattern that handles:
  // [HIGH] Issue title - src/file.js:123
  // [SECURITY]Issue title-src/file.js (no spaces)
  // [CRITICAL] Issue title
  // **[MEDIUM]** Title (with markdown)
  // Fixed ReDoS vulnerability by excluding / from character class and matching it explicitly
  const issuePattern = /\*{0,2}\[(SECURITY|CRITICAL|HIGH|MEDIUM|LOW|INFO)\]\*{0,2}\s*([^\n]+?)(?:\s*-\s*((?:[^\s\n:/]+(?:\/[^\s\n:/]+)*)(?:\.[a-z0-9]{1,6})?)(?::(\d+))?)?(?:\n|$)/gi
  
  let match
  while ((match = issuePattern.exec(text)) !== null) {
    const severity = match[1].toLowerCase()
    // Clean up title - remove markdown formatting
    const title = match[2].trim().replace(/\*\*/g, '').replace(/_/g, '').trim()
    const file = match[3] || 'unknown'
    const line = match[4] ? parseInt(match[4], 10) : null

    // Extract detail and suggestion from the text following this issue
    const issueStart = match.index + match[0].length
    const nextIssueMatch = text.substring(issueStart).search(/\[(SECURITY|CRITICAL|HIGH|MEDIUM|LOW|INFO)\]/i)
    const issueEnd = nextIssueMatch > 0 ? issueStart + nextIssueMatch : text.length
    const issueBody = text.substring(issueStart, issueEnd).trim()
    
    // Split issueBody into detail and suggestion
    let detail = issueBody
    let suggestion = null
    
    const suggestionMatch = issueBody.match(/Suggestion:\s*(.+?)(?=\n\n|\n\[|$)/is)
    if (suggestionMatch) {
      suggestion = suggestionMatch[1].trim()
      detail = issueBody.substring(0, suggestionMatch.index).trim()
    }
    
    if (!detail) {
      detail = 'Issue detected in code review requiring attention.'
    }

    issues.push({
      file,
      line,
      severity,
      title,
      detail,
      suggestion,
      tags: null
    })
  }

  // Fallback: determine overall risk from issue severities if not explicitly stated
  if (!riskMatch && issues.length > 0) {
    const hasCritical = issues.some(i => i.severity === 'critical' || i.severity === 'security')
    const hasHigh = issues.some(i => i.severity === 'high')
    const hasMedium = issues.some(i => i.severity === 'medium')
    
    if (hasCritical) {
      overall_risk = 'critical'
    } else if (hasHigh) {
      overall_risk = 'high'
    } else if (hasMedium) {
      overall_risk = 'medium'
    }
  }

  return {
    summary,
    overall_risk,
    issues
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

RESPONSE FORMAT: Provide your review in plain text with the following structure:

OVERALL RISK: LOW|MEDIUM|HIGH|CRITICAL

Brief, encouraging summary of the code review.

For each issue found, use this format:
[SEVERITY] Issue Title - path/to/file.js:123
Detailed explanation of the issue.
Suggestion: Actionable suggestion to fix the issue.

Severity levels: [SECURITY], [CRITICAL], [HIGH], [MEDIUM], [LOW], [INFO]

Example:
OVERALL RISK: LOW

Great work! The code changes look solid with just a couple of minor suggestions.

[HIGH] SQL Injection Vulnerability - src/api/users.js:45
User input is directly concatenated into SQL query without parameterization.
Suggestion: Use parameterized queries or an ORM to prevent SQL injection.

[INFO] Consider error handling - src/utils/helper.js:12
The function doesn't handle the case when input is null.
Suggestion: Add null check at the start of the function.

If everything looks good, just provide a positive summary with "OVERALL RISK: LOW" and no issue markers.`

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
    console.log('🔄 Using responses API for plain text output...')
    const ai = await openai.responses.create({
      model: AI_MODEL,
      input: system + '\n\nUser Request:\n' + user[0].content,
      // No response_format specified = plain text output
    })
    console.log('✅ Responses API call succeeded')

    // Extract content from responses API format
    const text = ai.response?.content || ai.content
    
    if (!text || text.trim() === '') {
      console.error('❌ AI returned empty response')
      throw new Error('AI returned empty response')
    }
    
    console.log('📝 AI Response length:', text.length)
    console.log('📝 AI Response preview:', text.substring(0, 500))
    
    // Parse plain text response
    const parsed = extractIssuesFromText(text)
    console.log('✅ Successfully parsed AI response')
    console.log(`📊 Found ${parsed.issues.length} issues with overall risk: ${parsed.overall_risk}`)

    // 3) Persist report for auditors (includes both raw text and parsed structure)
    const workspaceDir = process.env.GITHUB_WORKSPACE || process.cwd()
    const reportFileName = `ai-review-report-${Date.now()}.json`
    const reportPath = `${workspaceDir}/${reportFileName}`
    const fullReport = {
      raw_response: text,
      parsed: parsed,
      timestamp: new Date().toISOString(),
      model: AI_MODEL
    }
    fs.writeFileSync(reportPath, JSON.stringify(fullReport, null, 2))
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