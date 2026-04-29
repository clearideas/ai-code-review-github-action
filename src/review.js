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
  INPUT_AI_MODEL: AI_MODEL = 'gpt-5.5',
  INPUT_MAX_DIFF_CHARS: MAX_DIFF_CHARS = '180000',
  INPUT_MAX_REVIEW_FILES: MAX_REVIEW_FILES = '100',
  INPUT_MAX_OUTPUT_TOKENS: MAX_OUTPUT_TOKENS = '6000',
  INPUT_REASONING_EFFORT: REASONING_EFFORT = 'medium',
  INPUT_FAIL_ON_SEVERITY: FAIL_ON_SEVERITY = '["high","critical","security"]',
  INPUT_REVIEW_INSTRUCTIONS: REVIEW_INSTRUCTIONS = '',
  INPUT_MAX_REVIEW_INSTRUCTIONS_CHARS: MAX_REVIEW_INSTRUCTIONS_CHARS = '12000',
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
const maxDiffChars = parsePositiveInt(MAX_DIFF_CHARS, 180000)
const maxReviewFiles = Math.min(parsePositiveInt(MAX_REVIEW_FILES, 100), 100)
const maxOutputTokens = parsePositiveInt(MAX_OUTPUT_TOKENS, 6000)
const validReasoningEfforts = new Set(['low', 'medium', 'high'])
const reasoningEffort = validReasoningEfforts.has(REASONING_EFFORT) ? REASONING_EFFORT : 'medium'

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

function truncateWithMetadata(str, n) {
  return {
    text: truncate(str, n),
    truncated: str.length > n,
    originalChars: str.length,
    maxChars: n,
  }
}

function parsePositiveInt(value, fallback) {
  const parsed = parseInt(value, 10)
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback
}

function runGit(args, options = {}) {
  return execFileSync('git', args, {
    encoding: 'utf8',
    cwd: options.cwd,
    stdio: ['ignore', 'pipe', 'pipe'],
  }).trimEnd()
}

function cleanInstructions(text, maxChars) {
  return truncate(sanitizeDiff(text.trim()), maxChars)
}

function getReviewInstructions() {
  const maxChars = parsePositiveInt(MAX_REVIEW_INSTRUCTIONS_CHARS, 12000)
  return REVIEW_INSTRUCTIONS.trim() ? cleanInstructions(REVIEW_INSTRUCTIONS, maxChars) : ''
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
    excluded.slice(0, 20).forEach(reason => console.log(`  - ${reason}`))
    if (excluded.length > 20) {
      console.log(`  - ...and ${excluded.length - 20} more`)
    }
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
    diffMetadata: {
      totalChangedFiles: changedFiles.length,
      reviewedFiles: includedFileNames.length,
      excludedFiles: changedFiles.length - includedFileNames.length,
      fileListCapped: false,
      maxReviewFiles: null,
      oversizedFiles: [],
      diffCappedByBuilder: false,
      diffTruncated: false,
      originalDiffChars: rawDiff.length,
      maxDiffChars,
    },
    reviewInstructions: getReviewInstructions(),
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

function formatUnifiedPatch(files, maxChars) {
  // GitHub's listFiles returns `patch` (unified diff) per file; concatenate safely.
  let out = ''
  let totalSize = 0
  const maxFileSize = Math.min(25000, maxChars)
  const maxTotalSize = maxChars
  const oversizedFiles = []
  let diffCappedByBuilder = false

  for (const f of files) {
    if (!f.patch) continue
    if (f.patch.length > maxFileSize) {
      out += `\n--- a/${f.filename}\n+++ b/${f.filename}\n[File too large for review]\n`
      oversizedFiles.push(f.filename)
      continue
    }
    if (totalSize + f.patch.length > maxTotalSize) {
      out += `\n[Additional files truncated for size]\n`
      diffCappedByBuilder = true
      break
    }
    out += `\n--- a/${f.filename}\n+++ b/${f.filename}\n${f.patch}\n`
    totalSize += f.patch.length
  }
  return {
    diff: out,
    metadata: {
      oversizedFiles,
      diffCappedByBuilder,
      originalDiffChars: out.length,
      maxDiffChars: maxChars,
    },
  }
}

async function createReviewResponse(params) {
  try {
    return await openai.responses.create(params)
  } catch (error) {
    const message = `${error.message || ''} ${error.error?.message || ''}`
    const unsupportedFastOption =
      /reasoning|max_output_tokens|temperature|store/i.test(message) &&
      /unsupported|unknown|invalid|not supported|unrecognized/i.test(message)

    if (!unsupportedFastOption) throw error

    console.warn('Fast response options were not accepted by this model; retrying with compatibility options.')
    const { reasoning, max_output_tokens, temperature, store, ...compatParams } = params
    return openai.responses.create(compatParams)
  }
}

function escapeMarkdown(text) {
  // Escape markdown special characters to prevent injection
  return text.replace(/[[\\\]`*_{}()#+\-.!]/g, '\\$&')
}

function formatDiffNotice(metadata) {
  if (!metadata) return []

  const notices = []
  if (metadata.fileListCapped) {
    notices.push(
      `Only the first ${metadata.fetchedFiles || metadata.maxReviewFiles} of ${metadata.totalChangedFiles} changed files were fetched for review.`,
    )
  }
  if (metadata.diffCappedByBuilder || metadata.diffTruncated) {
    notices.push(
      `The diff was truncated to ${metadata.maxDiffChars} characters from ${metadata.originalDiffChars} characters.`,
    )
  }
  if (metadata.oversizedFiles?.length) {
    notices.push(`${metadata.oversizedFiles.length} oversized file diff(s) were skipped.`)
  }

  return notices
}

function asMarkdown(review, diffMetadata = null) {
  const lines = []
  lines.push(`### 🤖 AI Code Review (${review.overall_risk.toUpperCase()})`)
  lines.push('')
  const diffNotices = formatDiffNotice(diffMetadata)
  if (diffNotices.length) {
    lines.push('**Review coverage note:**')
    diffNotices.forEach(notice => lines.push(`- ${escapeMarkdown(notice)}`))
    lines.push('')
  }
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

const reviewResponseSchema = {
  type: 'object',
  additionalProperties: false,
  required: ['summary', 'overall_risk', 'issues'],
  properties: {
    summary: {
      type: 'string',
      description: 'Brief encouraging summary of the review outcome.',
    },
    overall_risk: {
      type: 'string',
      enum: ['low', 'medium', 'high', 'critical'],
    },
    issues: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['file', 'line', 'severity', 'title', 'detail', 'suggestion', 'tags'],
        properties: {
          file: { type: 'string' },
          line: {
            type: ['integer', 'null'],
          },
          severity: {
            type: 'string',
            enum: ['info', 'low', 'medium', 'high', 'critical', 'security'],
          },
          title: { type: 'string' },
          detail: { type: 'string' },
          suggestion: {
            type: ['string', 'null'],
          },
          tags: {
            type: ['array', 'null'],
            items: { type: 'string' },
          },
        },
      },
    },
  },
}

function normalizeReview(parsed) {
  const issues = Array.isArray(parsed.issues) ? parsed.issues : []
  return {
    summary: typeof parsed.summary === 'string' && parsed.summary.trim()
      ? parsed.summary.trim()
      : 'AI review completed',
    overall_risk: ['low', 'medium', 'high', 'critical'].includes(parsed.overall_risk)
      ? parsed.overall_risk
      : 'low',
    issues: issues
      .filter(issue => issue && typeof issue === 'object')
      .map(issue => ({
        file: typeof issue.file === 'string' && issue.file.trim() ? issue.file.trim() : 'unknown',
        line: Number.isInteger(issue.line) ? issue.line : null,
        severity: ['info', 'low', 'medium', 'high', 'critical', 'security'].includes(issue.severity)
          ? issue.severity
          : 'info',
        title: typeof issue.title === 'string' && issue.title.trim()
          ? issue.title.trim()
          : 'Issue detected',
        detail: typeof issue.detail === 'string' && issue.detail.trim()
          ? issue.detail.trim()
          : 'Issue detected in code review requiring attention.',
        suggestion: typeof issue.suggestion === 'string' && issue.suggestion.trim()
          ? issue.suggestion.trim()
          : null,
        tags: Array.isArray(issue.tags) ? issue.tags.filter(tag => typeof tag === 'string') : null,
      })),
  }
}

function parseReviewResponse(text) {
  try {
    return normalizeReview(JSON.parse(text))
  } catch (error) {
    console.warn('Structured review JSON parse failed, falling back to text parser:', error.message)
    return extractIssuesFromText(text)
  }
}

function getReviewPrompt(prTitle, prBody, diff, reviewInstructions = '') {
  const system = `Review this pull request from unified diffs only. Assume type checks, linting, and formatting already passed.

Flag only high-confidence issues that can cause production bugs, security exposure, data loss/corruption, crashes, or clear runtime/build failures visible in the diff.

Good findings include:
- Logic errors, wrong conditions, off-by-one mistakes, race/resource problems, infinite loops, and serious performance hotspots.
- SQL/NoSQL injection, XSS, hardcoded secrets, insecure randomness, auth/authz bypasses, and unsafe trust boundaries.
- Critical missing validation/error handling only when it can corrupt data, expose data, or crash an important path.
- Missing imports/undefined symbols only when the changed lines clearly introduce a new symbol that is not imported, declared, auto-imported, globally available, or namespace-qualified.
- Repo convention violations only when the repo-specific instructions explicitly say they matter.

Do not report style, formatting, naming, missing tests/docs, refactors, theoretical risks, type-only issues, unused code, or anything standard linters/type checkers should catch.

Use conservative severities:
- security: active vulnerability or data exposure.
- critical: immediate production failure or data loss.
- high: serious incorrect behavior or likely crash.
- medium: intermittent failure or degraded functionality.
- low/info: rare edge cases or useful non-blocking observations.

Prefer repo-specific instructions over generic assumptions. Combine duplicate root causes. Return all distinct high-confidence findings, or an empty issues array if the diff looks safe. Return only JSON matching the schema.`

  const repoContext = reviewInstructions
    ? `\n\nRepository-specific review instructions:\n${reviewInstructions}\n`
    : ''

  const user = `Pull Request Title: ${prTitle}

Pull Request Description:
${prBody}

Unified Diff (truncated if large):
${diff}
`

  return `${system}${repoContext}\n\nUser Request:\n${user}`
}

function printLocalJsonReport(report) {
  console.log('AI_REVIEW_JSON_START')
  console.log(JSON.stringify(report, null, 2))
  console.log('AI_REVIEW_JSON_END')
}

function printLocalSummary(parsed, reportPath, report = null) {
  console.log(asMarkdown(parsed, report?.diff_metadata))
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
      const { data: files } = await octo.pulls.listFiles({
        owner,
        repo,
        pull_number: prNumber,
        per_page: maxReviewFiles,
      })
      const changedFilesCount = pr.changed_files ?? files.length
      const fileListCapped = changedFilesCount > files.length
      if (fileListCapped) {
        console.log(`Review file list capped at ${maxReviewFiles} files for speed.`)
      }
      const safeFiles = filterSafeFiles(files)
      const patch = formatUnifiedPatch(safeFiles, maxDiffChars)
      reviewContext = {
        title: pr.title || '',
        body: pr.body || '',
        diff: patch.diff,
        diffMetadata: {
          totalChangedFiles: changedFilesCount,
          fetchedFiles: files.length,
          reviewedFiles: safeFiles.length,
          excludedFiles: files.length - safeFiles.length,
          fileListCapped,
          maxReviewFiles,
          oversizedFiles: patch.metadata.oversizedFiles,
          diffCappedByBuilder: patch.metadata.diffCappedByBuilder,
          diffTruncated: false,
          originalDiffChars: patch.metadata.originalDiffChars,
          maxDiffChars,
        },
        reviewInstructions: getReviewInstructions(),
        workspaceDir: process.env.GITHUB_WORKSPACE || process.cwd(),
        shouldPostComment: true,
        shouldUpdateCheck: true,
        prNumber,
      }
    }

    const redactedDiff = sanitizeDiff(reviewContext.diff)
    const truncatedDiff = truncateWithMetadata(redactedDiff, maxDiffChars)
    const diff = truncatedDiff.text
    const diffMetadata = {
      ...reviewContext.diffMetadata,
      diffTruncated: reviewContext.diffMetadata?.diffTruncated || truncatedDiff.truncated,
      originalDiffChars: Math.max(
        reviewContext.diffMetadata?.originalDiffChars || 0,
        truncatedDiff.originalChars,
      ),
      maxDiffChars,
    }

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
        diff_metadata: diffMetadata,
      }
      fs.writeFileSync(reportPath, JSON.stringify(fullReport, null, 2))
      if (isLocalMode) {
        printLocalSummary(parsed, reportPath, fullReport)
      } else {
        console.log('AI review passed (no reviewable diff).')
      }
      process.exit(0)
    }

    console.log('🤖 AI Model being used:', AI_MODEL)
    if (reviewContext.reviewInstructions) {
      console.log('📚 Loaded repository-specific review instructions')
    }
    console.log('🔄 Using responses API with structured review output...')
    const ai = await createReviewResponse({
      model: AI_MODEL,
      input: getReviewPrompt(reviewContext.title, reviewContext.body, diff, reviewContext.reviewInstructions),
      temperature: 0,
      max_output_tokens: maxOutputTokens,
      reasoning: { effort: reasoningEffort },
      store: false,
      text: {
        format: {
          type: 'json_schema',
          name: 'ai_code_review',
          strict: true,
          schema: reviewResponseSchema,
        },
      },
    })
    console.log('✅ Responses API call succeeded')

    // Extract content from responses API format
    const text = ai.output_text || ai.response?.content || ai.content
    
    if (!text || text.trim() === '') {
      console.error('❌ AI returned empty response')
      throw new Error('AI returned empty response')
    }
    
    console.log('📝 AI Response length:', text.length)
    
    // Parse structured response, with a text-parser fallback for older model/action behavior.
    const parsed = parseReviewResponse(text)
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
      diff_metadata: diffMetadata,
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
      const bodyMd = `${marker}\n${asMarkdown(parsed, diffMetadata)}\n${marker}`
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
