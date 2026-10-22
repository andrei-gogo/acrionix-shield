#!/usr/bin/env node

const fs = require('node:fs');
const path = require('node:path');

const file = path.resolve(process.argv[2] || path.join(__dirname, '..', 'CODEX_HANDOFF.md'));
const heading = /^## @claude response(?: \(round \d+\))?\s*$/gm;

function readResponse() {
  try {
    const content = fs.readFileSync(file, 'utf8');
    heading.lastIndex = 0;
    let match;
    let latest = null;
    while ((match = heading.exec(content))) latest = match;
    if (!latest) return '';
    const section = content.slice(latest.index + latest[0].length);
    return section.split(/^## /m)[0].trim();
  } catch (error) {
    console.error(`Cannot read ${file}: ${error.message}`);
    return '';
  }
}

let previous = readResponse();
console.log(`Watching ${file} for a new @claude response addressed to @codex. Press Ctrl+C to stop.`);

fs.watchFile(file, { interval: 2000 }, () => {
  const current = readResponse();
  if (current === previous) return;
  previous = current;
  if (/@codex\b/i.test(current)) {
    console.log(`[${new Date().toISOString()}] Claude's response changed and mentions @codex. Review ${file}.`);
  }
});

process.on('SIGINT', () => {
  fs.unwatchFile(file);
  process.exit(0);
});
