# MCP Risk

**An open security standard for [Model Context Protocol](https://modelcontextprotocol.io) servers - and the open scoring model that verifies it.**

When you connect an MCP server to an agent, you grant code you didn't write the ability to act on your behalf. This repository is the standard for deciding, before you connect, whether that's a good idea, in two paired halves:

- **[POLICY.md](POLICY.md)** - the *MCP Server Security Policy*: a scored, human-readable acceptance standard. Six categories, each with a stated intent, the checks that verify it, and references to the authorities it operationalizes (the official MCP spec, OWASP MCP Top 10, NSA and CSA guidance, Anthropic's Zero Trust framework, and NIST's emerging AI-agent overlays).
- **[checks/](checks/)** - the *open scoring model*: the exact code, weights, grade bands, and pattern lists that compute a server's score. Nothing that decides a grade is hidden. *Public scoring supports auditable results.*

The hosted scanner that runs this scoring model for you lives at **[mcprisk.org](https://mcprisk.org)** - paste an npm package, GitHub repo, registry name, or server URL and get a grade with every finding linked back to its policy section.

## Why open

Several MCP scanners exist; none publish how they score. This one does, on purpose. The policy is the "what and why"; the scoring model is the "how we verify it" - the same pairing [OpenSSF](https://openssf.org) uses between its framework and its Scorecard checks. If you think a weight is wrong or a check is too blunt, [open an issue](https://github.com/bluemotionlabs/mcprisk/issues). That is the point.

## What it checks

| Policy § | Category | Verified how |
|---|---|---|
| §1 | Provenance & supply chain | Official registry listing, repo health, package↔repo consistency, provenance attestation |
| §2 | Capability scope & least privilege | Tool surface via live `tools/list` or static source analysis - **untrusted code is never executed**; shell, filesystem, egress, and credential access flagged |
| §3 | Auth & transport hardening | HTTPS, authentication required, OAuth 2.1 resource metadata (June 2025 spec) |
| §4 | Dependency & vulnerability hygiene | OSV.dev advisory lookup |
| §5 | Server-supplied instruction integrity | Common indicators of poisoning and authority over-reach across every model-facing channel a server supplies (the initialize `instructions` field, tool names/descriptions, schema string fields, `prompts`/`resources` metadata): hidden instructions, invisible/bidi Unicode, fake role markup, hidden comments, credential-priority directives (critical), content-suppression and cross-tool shadowing, non-`http` URIs, oversized (stuffed) text; plus tool-schema change ("rug pull") detection |
| §6 | Toxic flows (tool combinations) | Manual review steps defined in the policy |

## Using the scoring model directly

The checks are a standalone TypeScript package ([`checks/`](checks/)), runnable in any Workers-compatible or modern Node runtime:

```bash
cd checks
npm install
npm test
```

See [checks/README.md](checks/README.md) for the full check→policy mapping and design constraints.

## Not a guarantee

A good grade is not a promise of safety, and this scoring model is pre-connection triage, not a runtime monitor or a substitute for review of code you're about to trust. It never executes the scanned server. Treat it as one input to a decision, not the decision.

## License

Two licenses, one per half: [**POLICY.md**](POLICY.md) is [CC BY-SA 4.0](LICENSE-POLICY) (reuse and adapt, even commercially, but credit the original and keep modified versions open under the same terms). [**checks/**](checks/) is [Apache-2.0](LICENSE) (standard permissive code license). Maintained by [Blue Motion Labs](https://bluemotionlabs.com).
