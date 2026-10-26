const fs = require('node:fs');
const path = require('node:path');
const { parseRelease, compareReleases } = require('../version-range');

// Actions whose version tags were repointed to malicious commits.
// `exposure` marks an incident whose tags were since restored: the reference is not malicious
// today, but workflows that ran during the window leaked secrets. Without it, tags still
// point at the malicious commit. Tags at or above `safeFrom` were never affected.
// Extend via .shieldrc.json knownCompromised.actions: ["owner/repo"] or { "owner/repo": "note" }
const COMPROMISED_ACTIONS = {
  'aquasecurity/trivy-action': {
    note: 'GHSA-69fq-xp46-6x23 / CVE-2026-33634: 76 of 77 tags (0.0.1-0.34.2) pointed at a credential stealer, since restored; 0.35.0+ unaffected',
    exposure: 'March 19-20 2026',
    safeFrom: '0.35.0',
  },
  'aquasecurity/setup-trivy': {
    note: 'GHSA-69fq-xp46-6x23 / CVE-2026-33634: tags pointed at a credential stealer, since restored; 0.2.6 was recreated from a safe commit',
    exposure: 'March 19-20 2026',
    safeFrom: '0.2.6',
  },
  'actions-cool/issues-helper': {
    note: 'StepSecurity / Socket, 2026: every tag moved to an imposter commit that steals runner credentials; re-enabled Sept 16 without cleanup, disabled again Sept 25',
  },
  'actions-cool/maintain-one-comment': {
    note: 'StepSecurity / Socket, 2026: tags moved to the same imposter-commit credential stealer as issues-helper; disabled again Sept 25',
  },
};

// Publishers whose actions live in GitHub's own organisations
const FIRST_PARTY_OWNERS = new Set(['actions', 'github']);

const FULL_SHA = /^[a-f0-9]{40}$/i;

// Attacker-controlled contexts that become shell code when interpolated into run:/script:
const UNTRUSTED_EXPRESSION = new RegExp(
  '\\$\\{\\{\\s*(' +
    'github\\.head_ref|' +
    'github\\.event\\.(?:' +
      'issue\\.(?:title|body)|' +
      'pull_request\\.(?:title|body|head\\.(?:ref|label|repo\\.default_branch))|' +
      '(?:comment|review|review_comment)\\.body|' +
      'discussion\\.(?:title|body)|' +
      'pages\\.[^}]*?\\.page_name|' +
      'commits\\.[^}]*?\\.(?:message|author\\.(?:email|name))|' +
      'head_commit\\.(?:message|author\\.(?:email|name))|' +
      'workflow_run\\.(?:head_branch|display_title|head_commit\\.message)' +
    ')' +
  ')\\s*\\}\\}',
);

const PR_HEAD_REF = /github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref|refs\/pull\/[^/\s]*\/(?:head|merge)/;

function findWorkflowFiles(dir) {
  const files = [];
  const workflowDir = path.join(dir, '.github', 'workflows');
  try {
    for (const entry of fs.readdirSync(workflowDir, { withFileTypes: true })) {
      if (entry.isFile() && /\.ya?ml$/i.test(entry.name)) {
        files.push(path.join('.github', 'workflows', entry.name));
      }
    }
  } catch {
    // No workflows directory
  }
  // A repo that is itself a composite action can also call other actions
  for (const name of ['action.yml', 'action.yaml']) {
    if (fs.existsSync(path.join(dir, name))) files.push(name);
  }
  return files;
}

function indentOf(line) {
  return line.match(/^\s*/)[0].length;
}

function parseUses(value) {
  const ref = value.replace(/^['"]|['"]$/g, '');
  if (ref.startsWith('./') || ref.startsWith('../')) return null;
  if (ref.startsWith('docker://')) return null;
  const at = ref.lastIndexOf('@');
  const target = at === -1 ? ref : ref.slice(0, at);
  const version = at === -1 ? '' : ref.slice(at + 1);
  const [owner, repo] = target.split('/');
  if (!owner || !repo) return null;
  return { full: ref, owner: owner.toLowerCase(), repo: `${owner}/${repo}`.toLowerCase(), version };
}

function compromisedList(config) {
  const extra = (config.knownCompromised && config.knownCompromised.actions) || {};
  const list = { ...COMPROMISED_ACTIONS };
  if (Array.isArray(extra)) {
    for (const name of extra) list[String(name).toLowerCase()] = { note: 'Listed in .shieldrc.json knownCompromised.actions' };
  } else {
    for (const [name, note] of Object.entries(extra)) list[name.toLowerCase()] = { note: note || 'Listed in .shieldrc.json' };
  }
  return list;
}

function scanWorkflow(relPath, content, compromised) {
  const findings = [];
  const lines = content.split(/\r?\n/);
  const isPullRequestTarget = lines.some(l => !l.trim().startsWith('#') && /\bpull_request_target\b/.test(l));

  // Indent of the open run:/script: block key, or -1 when not inside one
  let blockIndent = -1;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    const lineNo = i + 1;

    if (blockIndent !== -1 && trimmed && indentOf(line) <= blockIndent) blockIndent = -1;
    if (!trimmed || trimmed.startsWith('#')) continue;

    // Script injection: untrusted context inside run: / script: (inline or block scalar)
    const scriptKey = line.match(/^(\s*)(?:-\s+)?(run|script)\s*:\s*(.*)$/);
    const inScript = blockIndent !== -1 || scriptKey;
    if (scriptKey && /^[|>][+-]?\s*$/.test(scriptKey[3])) {
      blockIndent = indentOf(line) + (line.trimStart().startsWith('-') ? 2 : 0);
    }
    if (inScript) {
      const expr = line.match(UNTRUSTED_EXPRESSION);
      if (expr) {
        findings.push({
          type: 'actions-script-injection',
          severity: 'high',
          file: relPath,
          line: lineNo,
          description: `Untrusted input \${{ ${expr[1]} }} is interpolated into a shell/script step`,
          match: trimmed.substring(0, 120),
          ecosystem: 'github-actions',
          recommendation: `Pass it through an environment variable instead (env: VALUE: \${{ ${expr[1]} }}) and reference "$VALUE" in the script`,
        });
      }
    }

    // pull_request_target checking out the untrusted PR head
    if (isPullRequestTarget && /^\s*(?:-\s+)?ref\s*:/.test(line) && PR_HEAD_REF.test(line)) {
      findings.push({
        type: 'actions-pwn-request',
        severity: 'high',
        file: relPath,
        line: lineNo,
        description: 'pull_request_target workflow checks out code from the pull request head',
        match: trimmed.substring(0, 120),
        ecosystem: 'github-actions',
        recommendation: 'Untrusted PR code runs with repository secrets and a write token. Use the pull_request trigger, or never build/run the checked-out PR code in this workflow',
      });
    }

    const usesMatch = line.match(/^\s*(?:-\s+)?uses\s*:\s*([^\s#]+)/);
    if (!usesMatch) continue;
    const uses = parseUses(usesMatch[1]);
    if (!uses) continue;

    const pinned = FULL_SHA.test(uses.version);
    const known = compromised[uses.repo];
    const tagRelease = parseRelease(uses.version);
    const safeTag = Boolean(known && known.safeFrom && tagRelease && compareReleases(tagRelease, parseRelease(known.safeFrom)) >= 0);

    if (known && known.exposure && !safeTag) {
      // Restored tags: report the past exposure once, then fall through to the ordinary pinning check
      findings.push({
        type: 'action-past-incident',
        severity: 'medium',
        file: relPath,
        line: lineNo,
        package: uses.repo,
        version: uses.version || '(none)',
        description: `${uses.repo}@${uses.version || '(none)'} served a credential stealer during ${known.exposure} (tags since restored)`,
        advisory: known.note,
        ecosystem: 'github-actions',
        recommendation: pinned
          ? `Confirm this commit is a legitimate release, and check whether this workflow ran during ${known.exposure}. If it did, rotate every secret it could read`
          : `Check whether this workflow ran during ${known.exposure}. If it did, rotate every secret it could read. Upgrade to ${known.safeFrom}+ pinned by SHA`,
      });
    } else if (known && !safeTag) {
      findings.push({
        type: 'compromised-action',
        severity: pinned ? 'medium' : 'critical',
        file: relPath,
        line: lineNo,
        package: uses.repo,
        version: uses.version || '(none)',
        description: pinned
          ? `Pinned to a SHA of a compromised action (${uses.repo}). Verify it predates the compromise`
          : `Compromised action referenced by mutable tag: ${uses.repo}@${uses.version || '(none)'}`,
        advisory: known.note,
        ecosystem: 'github-actions',
        recommendation: pinned
          ? 'Confirm this commit is from before the compromise, then rotate any secret the workflow could read if unsure'
          : 'Pin to a full commit SHA from before the compromise (or remove the action), then rotate every secret this workflow could read',
      });
      continue;
    }

    if (!pinned) {
      const firstParty = FIRST_PARTY_OWNERS.has(uses.owner);
      findings.push({
        type: 'unpinned-action',
        severity: firstParty ? 'low' : 'medium',
        file: relPath,
        line: lineNo,
        package: uses.repo,
        version: uses.version || '(none)',
        description: uses.version
          ? `Action pinned to mutable ref "${uses.version}" instead of a commit SHA: ${uses.full}`
          : `Action used without any version: ${uses.full}`,
        ecosystem: 'github-actions',
        recommendation: 'Pin to a full 40-character commit SHA (keep the tag in a comment, e.g. uses: owner/action@<sha> # v4.1.0). Tags can be moved to malicious commits',
      });
    }
  }

  return findings;
}

async function runActionsScan(dir, config = {}) {
  const findings = [];
  const compromised = compromisedList(config);

  for (const relPath of findWorkflowFiles(dir)) {
    let content;
    try {
      content = fs.readFileSync(path.join(dir, relPath), 'utf8');
    } catch {
      continue;
    }
    findings.push(...scanWorkflow(relPath, content, compromised));
  }

  return findings;
}

module.exports = { runActionsScan, scanWorkflow, parseUses };
