// SARIF 2.1.0 in, and ESLint JSON to SARIF for runs that start as ESLint output.
import path from 'node:path';

/**
 * A result's triage key: "<tool>/<ruleId>@<uri>:<line>". It's readable, so findings.json can be
 * written by hand.
 * ponytail: line-based, so moving code changes the key. Switch to partialFingerprints when
 * findings need to survive refactors.
 */
export function resultKey(run, result) {
  const tool = run.tool.driver.name;
  const loc = result.locations?.[0]?.physicalLocation;
  const uri = loc?.artifactLocation?.uri ?? '?';
  const line = loc?.region?.startLine ?? 0;
  return `${tool}/${result.ruleId}@${uri}:${line}`;
}

export function resultsOf(sarif) {
  if (sarif?.version !== '2.1.0' || !Array.isArray(sarif.runs))
    throw new Error('not a SARIF 2.1.0 log');
  return sarif.runs.flatMap((run) =>
    (run.results ?? []).map((result) => ({
      key: resultKey(run, result),
      run,
      result,
    })),
  );
}

/**
 * Our plugins prefix messages with their own tags ("🔒 CWE-78 OWASP:A05 CVSS:9.8 | text | HIGH").
 * A report states the analyst's mapping, so only the text in the middle is kept.
 */
export function plainMessage(message) {
  const first = message.split('\n')[0];
  const parts = first.split(' | ');
  return parts.length >= 3 && /CWE-\d+/.test(parts[0]) ? parts[1] : first;
}

/** ESLint `-f json` output to a SARIF run. Paths are made relative to `root`. */
export function eslintToSarifRun(eslintResults, { root, version }) {
  const rules = new Map();
  const results = [];
  for (const file of eslintResults) {
    for (const m of file.messages) {
      if (!m.ruleId) continue;
      rules.set(m.ruleId, { id: m.ruleId });
      results.push({
        ruleId: m.ruleId,
        level: m.severity === 2 ? 'error' : 'warning',
        message: { text: plainMessage(m.message) },
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                uri: path
                  .relative(root, file.filePath)
                  .split(path.sep)
                  .join('/'),
              },
              region: { startLine: m.line, startColumn: m.column },
            },
          },
        ],
      });
    }
  }
  return {
    tool: { driver: { name: 'eslint', version, rules: [...rules.values()] } },
    results,
  };
}
