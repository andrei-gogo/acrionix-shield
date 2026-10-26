// Strict comparison of plain numeric releases ("1.2.0", "v24.22.1").
// Pre-release, post-release and local versions return null: callers must report them
// as not verified rather than guess, since PEP 440 and semver order them differently.

function parseRelease(version) {
  const match = String(version || '').trim().match(/^v?(\d+(?:\.\d+)*)$/);
  return match ? match[1].split('.').map(Number) : null;
}

function compareReleases(a, b) {
  const length = Math.max(a.length, b.length);
  for (let i = 0; i < length; i++) {
    const diff = (a[i] || 0) - (b[i] || 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

// entry: { versions: ['1.0.0', '*'] } for exact malicious releases, and/or
// { atLeast: '1.0.3', below: '1.2.1' } for a vulnerable range (inclusive lower, exclusive upper).
// Returns true (affected), false (not affected) or null (version can't be compared).
function entryMatches(version, entry) {
  if (entry.versions) {
    if (entry.versions.includes('*') || entry.versions.includes(version)) return true;
    if (!entry.atLeast && !entry.below) return false;
  }
  const release = parseRelease(version);
  if (!release) return null;
  if (entry.atLeast && compareReleases(release, parseRelease(entry.atLeast)) < 0) return false;
  if (entry.below && compareReleases(release, parseRelease(entry.below)) >= 0) return false;
  return true;
}

module.exports = { parseRelease, compareReleases, entryMatches };
