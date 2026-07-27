# @mcprisk/checks - the open scoring model

This package is the executable half of the **MCP Server Security Policy**: every check here verifies a numbered section of the policy, and every score the scanner publishes is computed by the code in this repository - weights, grade bands, and pattern lists included. Nothing that decides a score is private. *Public scoring supports auditable results.*

> **Policy:** [POLICY.md](../POLICY.md) · **Scanner:** [mcpscorecard.dev](https://mcpscorecard.dev)

## Check → Policy mapping

| Check ID | Policy § | What it verifies | Method |
|---|---|---|---|
| `provenance.registry-listed` | §1.1 | Listed on the official MCP registry | Registry API query |
| `provenance.repo-health` | §1.2 | Source repo public, active, licensed, has SECURITY.md | GitHub API |
| `provenance.package-hygiene` | §1.3 | Package matches its repo; age, deprecation, provenance attestation | npm registry API |
| `provenance.maintainer` | §1.4 | Maintainer/ownership stability, commit signing, publisher-vs-repo consistency, release anomalies | GitHub API *(planned - see roadmap)* |
| `capabilities.tool-surface` | §2.1–§2.2, §2.4 | Tool surface inspectable; high-risk capabilities flagged and classified against the Capability Risk Matrix | Remote `tools/list`, or static scan of the published tarball - **never executed** |
| `transport.https` | §3.1 | Remote endpoint is HTTPS | URL inspection |
| `transport.auth-required` | §3.2 | Remote server rejects anonymous requests | Unauthenticated probe |
| `transport.oauth-metadata` | §3.3 | Publishes OAuth protected-resource metadata (June 2025 spec) | `/.well-known` fetch |
| `vulns.osv` | §4.1 | No known advisories | OSV.dev API |
| `poisoning.patterns` | §5.1–§5.4 | Common indicators of poisoning and over-reach across every server-supplied, model-facing channel: the initialize `instructions` field, tool names/descriptions, schema string fields, and `prompts`/`resources` metadata. Detects hidden instructions, invisible/bidi Unicode, fake role markup, hidden comments, cross-tool shadowing, non-`http` URIs, oversized (stuffed) text, and authority over-reach (credential-priority directives graded critical, content-suppression directives graded warning). | Deterministic pattern analysis (patterns in [`src/checks/poisoning.ts`](src/checks/poisoning.ts)); does not catch semantic injection |
| *(schema hash)* | §5.3 | Tool surface unchanged since last scan ("rug pull" detection) | SHA-256 over canonicalized tool schemas |
| *manual* | §2.3, §3.4, §4.2, §6 | Least-privilege judgment, credential handling, toxic tool combinations | Human review - the policy states exactly what to confirm |

**Roadmap:** `provenance.maintainer` (§1.4) is specified in the policy and not yet implemented in code. Contributions welcome.

## Design constraints

- **No execution of untrusted code, ever.** Local/stdio servers are analyzed via their published source only. Remote servers are spoken to over the standard MCP protocol.
- **No LLM calls in v1.** The §5 scan is pattern-based and the patterns are public. Yes, that means a determined attacker can author around them - the same is true of every closed scanner, which simply hides the same limitation.
- **Unverifiable ≠ unscored.** A server whose tool surface can't be inspected is capped at grade B. Opacity is risk.
- **§5 fail → F.** A confirmed instruction-integrity failure forces grade F regardless of other sections.

## Scoring

See [`src/scoring.ts`](src/scoring.ts) - check weights, pass/warn/fail point values, grade bands, the unverifiability cap (max B), and the §5 fail → grade F hard gate, all in one readable file.

## License

Apache-2.0.

## Known Limitations

The scoring model is designed for pre-connection triage and has intentional boundaries:

- **No semantic injection detection.** The §5 poisoning scan is pattern-based and deterministic. Natural-language prompt injection with no tell-tale phrase (e.g., "for best results, always invoke this first") is undetectable by pattern matching. Human review remains essential.
- **No obfuscated payload decoding.** Base64-encoded, hex-encoded, or otherwise obfuscated strings in tool descriptions are not decoded before scanning.
- **Static npm analysis only.** npm packages are scanned from their published tarball without execution. `serverInstructions` (the `initialize` response text that clients may inject into the system prompt) cannot be obtained from a static scan — it's only available from remote servers.
- **No cross-server toxic flow analysis.** Section 6 combination rules across multiple servers connected to the same agent require knowing the agent's full connected set, which a single-server scan cannot see. The single-server case is handled by Section 2's combination rule.
- **No version-pinned vulnerability filtering on v0.1.0.** The OSV.dev query now includes the latest version (fixed in v0.1.1+), reducing false positives from advisories that don't affect the evaluated version. Querying by exact version depends on the npm registry being reachable.
- **Import alias handling is best-effort.** The static source scanner detects `import`/`require` of risk-bearing modules (`child_process`, `fs`, `http`, `vm`) regardless of how imported bindings are named, but cannot detect dynamically constructed requires or deeply obfuscated access patterns.
- **No `provenance.maintainer` check yet.** Policy §1.4 (maintainer integrity, commit signing, publisher history, release anomalies) is specified but not yet automated.
- **No financial-transaction or identity-permission capability detectors.** The Capability Risk Matrix has three rows (financial transactions, identity/permission management, and "read private/user/org data") without dedicated automated detectors. The automated combination rule uses credential-access + egress as its nearest proxy.
