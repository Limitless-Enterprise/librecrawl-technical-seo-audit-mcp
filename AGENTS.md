# Project agent memory

This file is the project's committed home for project-intrinsic agent knowledge: build, test, release, architecture, and sharp-edge notes that should travel with the code.

- Run the complete behavioral suite with `python -m unittest discover -v` after
  installing `requirements.txt`; the MCP dependency is intentionally pinned to
  v1 because `server.py` uses the FastMCP v1 API.
- Treat [`docs/FIRSTLOOK-STAGING.md`](docs/FIRSTLOOK-STAGING.md) as the
  authoritative boundary, rollout, and rollback reference for the attended
  fixed-domain mode. The underlying LibreCrawl engine is explicitly outside
  that hardened boundary.

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.
