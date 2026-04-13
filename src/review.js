import fs from 'node:fs'
import { execFileSync } from 'node:child_process'
import { Octokit } from '@octokit/rest'
import { OpenAI } from 'openai'

const isLocalMode = process.argv.includes('--local')

// Get inputs from GitHub Action environment
const {
  INPUT_GITHUB_TOKEN: GITHUB_TOKEN,
  INPUT_OPENAI_API_KEY,
  OPENAI_API_KEY,
  INPUT_AI_MODEL: AI_MODEL = 'gpt-5-mini',
  INPUT_MAX_DIFF_CHARS: MAX_DIFF_CHARS = '180000',
  INPUT_FAIL_ON_SEVERITY: FAIL_ON_SEVERITY = '["high","critical","security"]',
  GITHUB_REPOSITORY,
} = process.env

const REVIEW_OPENAI_API_KEY = INPUT_OPENAI_API_KEY || OPENAI_API_KEY

if (!REVIEW_OPENAI_API_KEY) throw new Error('Missing openai_api_key input')
if (!isLocalMode && !GITHUB_TOKEN) throw new Error('Missing github_token input')
if (!isLocalMode && (!GITHUB_REPOSITORY || !GITHUB_REPOSITORY.includes('/'))) {
  throw new Error('Missing or invalid GITHUB_REPOSITORY (expected owner/repo)')
}

const [owner, repo] = isLocalMode ? [null, null] : GITHUB_REPOSITORY.split('/')

// Get PR number from GitHub event or environment
let prNumber
if (!isLocalMode && process.env.GITHUB_EVENT_PATH) {
  try {
    const event = JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8'))
    prNumber = event.pull_request?.number
  } catch (error) {
    console.warn('Could not read GitHub event:', error.message)
  }
}

// Fallback to parsing from GITHUB_REF
if (!isLocalMode && !prNumber) {
  prNumber = parseInt(
    process.env.GITHUB_REF?.match(/refs\/pull\/(\d+)\/merge/)?.[1] ||
      process.env.GITHUB_REF_NAME ||
      process.env.PR_NUMBER ||
      '',
    10,
  )
}

if (!isLocalMode && !Number.isInteger(prNumber)) {
  throw new Error('Unable to determine pull request number from GitHub event or environment')
}

const octo = isLocalMode ? null : new Octokit({ auth: GITHUB_TOKEN })
const openai = new OpenAI({ apiKey: REVIEW_OPENAI_API_KEY })

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

function runGit(args, options = {}) {
  return execFileSync('git', args, {
    encoding: 'utf8',
    cwd: options.cwd,
    stdio: ['ignore', 'pipe', 'pipe'],
  }).trimEnd()
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
  /\.html$/i,
  /\.htm$/i,
  /\.css$/i,
  /\.scss$/i,
  /\.sass$/i,
  /\.less$/i,
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

function getLocalReviewContext() {
  const repoRoot = runGit(['rev-parse', '--show-toplevel'])
  const baseRef = process.env.BASE_REF || 'origin/main'
  const mergeBase = runGit(['merge-base', baseRef, 'HEAD'], { cwd: repoRoot })
  const changedFiles = runGit(['diff', '--name-only', `${mergeBase}...HEAD`], { cwd: repoRoot })
    .split('\n')
    .map(name => name.trim())
    .filter(Boolean)

  const safeFiles = filterSafeFiles(changedFiles.map(filename => ({ filename })))
  const includedFileNames = safeFiles.map(file => file.filename)
  const rawDiff =
    includedFileNames.length > 0
      ? runGit(['diff', '--no-ext-diff', '--unified=3', `${mergeBase}...HEAD`, '--', ...includedFileNames], {
          cwd: repoRoot,
        })
      : ''
  const branchName = runGit(['rev-parse', '--abbrev-ref', 'HEAD'], { cwd: repoRoot })

  return {
    title: `Local review for ${branchName}`,
    body: `Local AI review against base ref \`${baseRef}\` from branch \`${branchName}\`.`,
    diff: rawDiff,
    workspaceDir: repoRoot,
    shouldPostComment: false,
    shouldUpdateCheck: false,
    prNumber: null,
  }
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

function getReviewPrompt(prTitle, prBody, diff) {
  const system = `You are reviewing a pull request by examining unified diffs. You ONLY see the changed lines, not the full codebase.

CRITICAL CONTEXT:
- ⚠️ IMPORTANT: This code has ALREADY PASSED type checking (TypeScript/Flow/etc.) and linting (ESLint/TSLint/etc.)
  * All type errors have been resolved - DO NOT flag type-related issues
  * All linting errors have been resolved - DO NOT flag style, formatting, or linting issues
  * If something compiles and passes lint, assume it's correct from a static analysis perspective
- You only see DIFFS (changed lines), not complete files. This means:
  * Imports/types may exist elsewhere - DO NOT flag "missing imports" or "undefined types"
  * Existing code patterns and context are not visible to you
  * Assume standard tooling (TypeScript, ESLint, etc.) already handles static analysis
- Other tools are running: type checkers, linters, formatters already catch most issues
- Your role: Find logic bugs, security vulnerabilities, and critical errors that slip through other tools

GOAL: Find REAL bugs and security vulnerabilities that would cause runtime failures or data breaches.

COMPLETENESS REQUIREMENTS:
- Review the ENTIRE diff before finalizing your answer.
- Return the most complete set of distinct findings you can identify in this pass.
- Do NOT stop after finding the first serious issue; continue checking the remaining files for additional independent issues.
- Do NOT intentionally hold back issues for future runs.
- If multiple observations stem from the same root cause, combine them into one finding with the clearest file/line reference.
- Favor consistency across reruns: if the same diff is reviewed again, the findings list should stay as stable and comprehensive as possible.

WHAT TO FLAG (only if you're 95%+ confident):
✅ Runtime bugs that would break in production:
   - Logic errors causing incorrect behavior (off-by-one, wrong conditions)
   - Race conditions or concurrency issues
   - Memory leaks or resource exhaustion
   - Infinite loops or performance hotspots (NOT micro-optimizations)

✅ Security vulnerabilities (actual, not theoretical):
   - SQL injection (user input concatenated into queries)
   - XSS vulnerabilities (unsanitized user input in HTML/JS)
   - Hardcoded secrets, passwords, API keys
   - Insecure random number generation (crypto)
   - Authorization bypasses (missing permission checks)

✅ Critical error handling gaps:
   - Unhandled exceptions that would crash the application
   - Missing validation that could corrupt data

❌ DO NOT FLAG (these are handled by type checkers and linters):
   - Type errors, type mismatches, or "any" types (TypeScript already checked this)
   - Missing type annotations or type definitions (type checker handles this)
   - Type narrowing issues or type guards (type checker validates this)
   - Missing imports, types, or "undefined" references (they exist elsewhere and type checker verified)
   - Unused variables, imports, or dead code (linter catches this)
   - Code style, formatting, indentation, spacing (linter/formatter handles this)
   - Naming conventions, variable naming, function naming (linter enforces this)
   - Missing semicolons, trailing commas, quote style (linter/formatter fixes this)
   - Missing return type annotations (type checker infers and validates)
   - Generic type parameters or type constraints (type checker validates)
   - Missing tests or documentation
   - Code complexity or refactoring suggestions
   - Theoretical security concerns ("could potentially")
   - Config files or build artifacts
   - Redacted values like [REDACTED_AWS_KEY]
   - Architectural patterns or design choices
   - Missing error handling for edge cases (only flag critical gaps)
   - Performance micro-optimizations
   - "Consider adding..." or "might want to..." suggestions
   - Issues that would be caught by ESLint, TSLint, Prettier, or similar tools

SEVERITY GUIDELINES (use conservatively):
[SECURITY] - Active vulnerability that allows unauthorized access or data breach
  Examples: SQL injection, XSS, hardcoded secrets, auth bypass
  
[CRITICAL] - Bug that would cause immediate production failure or data loss
  Examples: Null pointer in critical path, infinite loop, memory exhaustion
  
[HIGH] - Serious bug that causes incorrect behavior or frequent crashes
  Examples: Logic error causing wrong results, missing validation causing data corruption
  
[MEDIUM] - Bug that causes occasional failures or degraded functionality
  Examples: Race condition causing intermittent issues, resource leak
  
[LOW] - Minor issue that may cause problems in edge cases
  Examples: Potential null dereference in rarely-executed path

[INFO] - Rarely use - only for genuinely helpful suggestions, not required fixes

TONE: Assume competence. The code has passed type checking and linting - trust that static analysis tools have done their job. If you're not CERTAIN something is a runtime bug or security vulnerability, don't report it. False positives for lint/type issues waste time and erode trust.

FINAL SELF-CHECK BEFORE ANSWERING:
- Re-scan the diff one more time for any additional distinct runtime or security issues you may have missed.
- Ensure the final answer includes all issues you are confident about from this review pass.
- Ensure each finding is specific, actionable, and non-duplicative.

RESPONSE FORMAT: Provide your review in plain text with the following structure:

OVERALL RISK: LOW|MEDIUM|HIGH|CRITICAL

Brief, encouraging summary of the code review.

For each issue found, use this format:
[SEVERITY] Issue Title - path/to/file.js:123
Detailed explanation of the issue.
Suggestion: Actionable suggestion to fix the issue.

Example:
OVERALL RISK: LOW

Great work! The code changes look solid.

[SECURITY] SQL Injection Vulnerability - src/api/users.js:45
User input from req.body.id is directly concatenated into SQL query: "SELECT * FROM users WHERE id = " + req.body.id
Suggestion: Use parameterized queries: "SELECT * FROM users WHERE id = ?" with prepared statement parameters.

If everything looks good, just provide a positive summary with "OVERALL RISK: LOW" and no issue markers.`

  const user = `Pull Request Title: ${prTitle}

Pull Request Description:
${prBody}

Unified Diff (truncated if large):
${diff}
`

  return `${system}\n\nUser Request:\n${user}`
}

function printLocalJsonReport(report) {
  console.log('AI_REVIEW_JSON_START')
  console.log(JSON.stringify(report, null, 2))
  console.log('AI_REVIEW_JSON_END')
}

function printLocalSummary(parsed, reportPath, report = null) {
  console.log(asMarkdown(parsed))
  console.log('')
  console.log(`Report: ${reportPath}`)
  if (report) {
    console.log('')
    printLocalJsonReport(report)
  }
}

;(async () => {
  try {
    let reviewContext
    if (isLocalMode) {
      reviewContext = getLocalReviewContext()
    } else {
      const { data: pr } = await octo.pulls.get({ owner, repo, pull_number: prNumber })
      const files = await octo.paginate(octo.pulls.listFiles, {
        owner,
        repo,
        pull_number: prNumber,
        per_page: 100,
      })
      const safeFiles = filterSafeFiles(files)
      reviewContext = {
        title: pr.title || '',
        body: pr.body || '',
        diff: formatUnifiedPatch(safeFiles),
        workspaceDir: process.env.GITHUB_WORKSPACE || process.cwd(),
        shouldPostComment: true,
        shouldUpdateCheck: true,
        prNumber,
      }
    }

    const redactedDiff = sanitizeDiff(reviewContext.diff)
    const diff = truncate(redactedDiff, parseInt(MAX_DIFF_CHARS, 10))

    if (!diff.trim()) {
      const parsed = {
        summary: 'No reviewable code changes were found in the current diff.',
        overall_risk: 'low',
        issues: [],
      }
      const reportFileName = `ai-review-report-${Date.now()}.json`
      const reportPath = `${reviewContext.workspaceDir}/${reportFileName}`
      const fullReport = {
        raw_response: parsed.summary,
        parsed,
        timestamp: new Date().toISOString(),
        model: AI_MODEL,
        mode: isLocalMode ? 'local' : 'github-action',
      }
      fs.writeFileSync(reportPath, JSON.stringify(fullReport, null, 2))
      if (isLocalMode) {
        printLocalSummary(parsed, reportPath, fullReport)
      } else {
        console.log('AI review passed (no reviewable diff).')
      }
      process.exit(0)
    }

    console.log('🤖 AI Model being used:', AI_MODEL);
    console.log('🔄 Using responses API for plain text output...')
    const ai = await openai.responses.create({
      model: AI_MODEL,
      input: getReviewPrompt(reviewContext.title, reviewContext.body, diff),
      temperature: 0,
      // No response_format specified = plain text output
    })
    console.log('✅ Responses API call succeeded')

    // Debug: Log the full response structure
    console.log('🔍 Full AI response structure:', JSON.stringify(ai, null, 2))

    // Extract content from responses API format
    const text = ai.output_text || ai.response?.content || ai.content
    
    if (!text || text.trim() === '') {
      console.error('❌ AI returned empty response')
      console.error('❌ Response structure:', JSON.stringify(ai, null, 2))
      throw new Error('AI returned empty response')
    }
    
    console.log('📝 AI Response length:', text.length)
    console.log('📝 AI Response preview:', text.substring(0, 500))
    
    // Parse plain text response
    const parsed = extractIssuesFromText(text)
    console.log('✅ Successfully parsed AI response')
    console.log(`📊 Found ${parsed.issues.length} issues with overall risk: ${parsed.overall_risk}`)

    // 3) Persist report for auditors (includes both raw text and parsed structure)
    const workspaceDir = reviewContext.workspaceDir
    const reportFileName = `ai-review-report-${Date.now()}.json`
    const reportPath = `${workspaceDir}/${reportFileName}`
    const fullReport = {
      raw_response: text,
      parsed: parsed,
      timestamp: new Date().toISOString(),
      model: AI_MODEL,
      mode: isLocalMode ? 'local' : 'github-action',
    }
    fs.writeFileSync(reportPath, JSON.stringify(fullReport, null, 2))
    console.log(`AI review report written to: ${reportPath}`)
    console.log(`📄 To download as artifact, add this step to your workflow:`)
    console.log(`   - uses: actions/upload-artifact@v4`)
    console.log(`     with:`)
    console.log(`       name: ai-review-report`)
    console.log(`       path: ${reportFileName}`)

    // 4) Post (or update) a single summary comment
    if (reviewContext.shouldPostComment) {
      const marker = '<!-- ai-code-review-bot -->'
      const bodyMd = `${marker}\n${asMarkdown(parsed)}\n${marker}`
      const allComments = await octo.paginate(octo.issues.listComments, {
        owner,
        repo,
        issue_number: reviewContext.prNumber,
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
          issue_number: reviewContext.prNumber,
          body: truncateComment(bodyMd),
        })
      }
    } else {
      printLocalSummary(parsed, reportPath, fullReport)
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
