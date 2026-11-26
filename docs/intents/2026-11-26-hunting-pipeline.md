---
slug: hunting-pipeline
opened: 2026-11-26
repo: ofri-peretz/security-research
---

**Status:** built 2026-11-26 under the owner's standing autonomy instruction ("full
permissions and autonomy", 2026-11-26). Review the merged result; it hasn't been through the
usual Design→Build acceptance.

## What

The bug-hunting workflow as five commands, so each step from candidate to public advisory
leaves a record and can't skip a gate:

| Stage   | Command                                                       | Writes                                                                                               |
| ------- | ------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| Hunt    | `npm run hunt -- <npm-package>[@version]`                     | SARIF and a summary of our plugins on the published package, in the private workspace                |
| Triage  | `npm run finding -- new <owner/repo> <npm-package> "<title>"` | a private `finding.json`, and the target added to `.open-findings`                                   |
| Report  | `npm run report-privately -- <finding-id> [--send]`           | a GitHub private vulnerability report to the maintainer; starts the 90-day clock                     |
| Track   | `npm run disclosure`                                          | every open finding: days since report, deadline, whether a fix shipped and the advisory is published |
| Publish | `npm run publish-advisory -- <finding-id> [--pr]`             | `advisories/<id>.md` and `<id>.osv.json` in this repo, and the target removed from `.open-findings`  |

## Why

- **Open findings stay off git.** The private workspace is `~/.security-research`
  (`SR_HOME`), outside the repo, so nothing in it can be committed by mistake. Opening a
  finding adds its target to the open-finding guard's list, so the guard knows about it
  before anything could leak.
- **Publishing is gated on evidence, not judgment.** An advisory goes out only once the fixed
  version is on npm **and** the maintainer's GHSA is published, or once the 90-day deadline has
  passed and that's stated explicitly.
- **Hunting uses our own plugins at scale.** Every package scanned is also a recall and
  precision sample for them.

## Constraints

- **Authorized targets only.** Hunting reads published source and never runs it: `npm pack`
  downloads the tarball, which is extracted into its own directory and only parsed. Testing a
  live system needs a program's scope or a signed authorization, recorded in `finding.json`.
- **Anything sent outside goes out only with `--send` / `--pr`.** Every command defaults to a
  dry run that prints what it would do.
- **Zero runtime dependencies.** The commands use `gh`, `npm` and `git`, which are already
  required.

## Measures

Findings opened, reported, fixed, published (from the workspace); median days from report to
fix; plugin hits per hunted package, and how many of those triaged as true positives.
