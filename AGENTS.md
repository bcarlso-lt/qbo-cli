# qbo — QuickBooks Online CLI

CLI for humans and AI agents. Data goes to stdout (parseable), hints/progress to stderr.

## Build & Test

```bash
make build    # Build to bin/qbo (uses CGO_ENABLED=0 for pure Go)
make test     # Run tests with race detector
make lint     # golangci-lint
make vet      # go vet
make fmt      # gofmt
```

## Project Structure

- `cmd/qbo/main.go` — Thin entrypoint, wires Kong CLI
- `internal/cmd/` — CLI commands (Kong structs with `Run(g *Globals)` methods)
- `internal/api/` — QBO HTTP client, entity registry, query builder
- `internal/auth/` — OAuth 2.0 flow, keyring token storage
- `internal/output/` — JSON/plain/human output modes, field projection
- `internal/config/` — ~/.config/qbo/ company profiles
- `internal/errfmt/` — Exit codes, structured error types
- `skills/qbo/` — Agent skill (SKILL.md + references/)
- `docs/` — Scraped QBO API documentation

## Output Modes

- Human (default): colored tables, summaries on stderr.
- `--json` / `-j`: structured JSON to stdout. Auto-enabled when stdout is not a TTY and `QBO_AUTO_JSON=1`.
- `--plain` / `-p`: tab-separated values, no color.
- `--results-only`: strip pagination metadata, return data array only.
- `--select field1,field2`: project output to specified fields (dot paths supported).
- Desire-path aliases: `--fields` → `--select`, `--machine` → `--json`, `--tsv` → `--plain`, `--yes` → `--force`.

## Exit Codes

0=success, 1=error, 2=usage, 3=empty results, 4=auth required, 5=not found, 6=permission denied, 7=rate limited, 8=retryable, 10=config error.

## CLI Conventions

- Flags: long-form kebab-case (`--company-id`, `--start-date`).
- `--dry-run` / `-n` on all mutating commands: show what would happen, no API calls.
- `--no-input`: never prompt; fail if confirmation needed.
- `--company-id` / `QBO_COMPANY_ID`: target company. Multiple companies supported.
- `--sandbox`: target QBO sandbox environment.
- `qbo schema`: dump CLI command tree as JSON for agent introspection.

## Commits

Conventional Commits (`feat:`, `fix:`, `chore:`) with imperative summary. Keep changesets focused.

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:970c3bf2 -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

**Architecture in one line:** issues live in a local Dolt DB; sync uses `refs/dolt/data` on your git remote; `.beads/issues.jsonl` is a passive export. See https://github.com/gastownhall/beads/blob/main/docs/SYNC_CONCEPTS.md for details and anti-patterns.

## Agent Context Profiles

The managed Beads block is task-tracking guidance, not permission to override repository, user, or orchestrator instructions.

- **Conservative (default)**: Use `bd` for task tracking. Do not run git commits, git pushes, or Dolt remote sync unless explicitly asked. At handoff, report changed files, validation, and suggested next commands.
- **Minimal**: Keep tool instruction files as pointers to `bd prime`; use the same conservative git policy unless active instructions say otherwise.
- **Team-maintainer**: Only when the repository explicitly opts in, agents may close beads, run quality gates, commit, and push as part of session close. A current "do not commit" or "do not push" instruction still wins.

## Session Completion

This protocol applies when ending a Beads implementation workflow. It is subordinate to explicit user, repository, and orchestrator instructions.

1. **File issues for remaining work** - Create beads for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **Handle git/sync by active profile**:
   ```bash
   # Conservative/minimal/default: report status and proposed commands; wait for approval.
   git status

   # Team-maintainer opt-in only, unless current instructions forbid it:
   git pull --rebase
   bd dolt push
   git push
   git status
   ```
5. **Hand off** - Summarize changes, validation, issue status, and any blocked sync/commit/push step

**Critical rules:**
- Explicit user or orchestrator instructions override this Beads block.
- Do not commit or push without clear authority from the active profile or the current user request.
- If a required sync or push is blocked, stop and report the exact command and error.
<!-- END BEADS INTEGRATION -->

