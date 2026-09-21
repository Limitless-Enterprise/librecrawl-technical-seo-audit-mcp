# Firstlook attended staging boundary

## Decision and scope

This mode implements only the LibreCrawl MCP side of the attended Firstlook
Tower sample. It is a fixed-domain staging exception classified as **bounded
High risk**. It is not approval for production or for public visitor-submitted
domains. Allowing a visitor-controlled URL to reach the current website
fetcher is **Critical risk**.

Public automatic audit generation must remain disabled. Production remains
disabled until the website fetcher, render worker, MCP tools, and underlying
LibreCrawl crawler are each hardened and reviewed as a complete system.

The MCP wrapper and LibreCrawl are separate security boundaries:

- `server.py` is the MCP surface. In Firstlook mode, only its direct fixed-host
  site and schema checks are enabled for attended use.
- LibreCrawl is a separate full crawler process with its own URL frontier,
  redirects, rendering, and secondary fetches. This change does not make that
  engine SSRF-safe. The background runner is not started and all start/resume
  entrypoints are denied in Firstlook mode.

## Fail-closed configuration

The attended target is fixed in code. The only configuration switch is:

```sh
FIRSTLOOK_STAGING_MODE=true
```

The switch accepts only literal `true`, literal `false`, or an unset value.

The only authorized tool URL is
`https://www.limitlessenterprise.ai/audit`. It has:

- HTTPS only;
- port 443, whether implicit or explicit;
- no username or password;
- no query string;
- no fragment;
- a public, non-internal hostname or a public literal IP.

The tool-call URL is normalized and must equal that exact hard-coded URL. It is
never treated as authority to choose another host or path, and an environment
variable cannot override it.

## Network controls

Every direct request in the attended path:

1. accepts only a same-host HTTPS URL on port 443 with no credentials, query,
   or fragment;
2. resolves all A and AAAA answers once;
3. rejects the complete answer set if any address is loopback, private,
   link-local, multicast, reserved, unspecified, cloud metadata, or in
   `100.64.0.0/10` (CGNAT/Tailscale);
4. passes only a validated numeric address to the TCP connector;
5. keeps the approved hostname in the HTTP `Host` header and TLS SNI;
6. uses the default trusted CA store with hostname and certificate
   verification enabled;
7. returns 3xx responses without following them, whether `Location` is on-host
   or off-host; and
8. caps response bodies at 5 MiB.

The fixed-host site check may derive `/robots.txt` and the three conventional
sitemap paths on the same approved host. It has a 30-second overall request
budget and fetches at most 10 unique same-host sitemap documents, including
robots declarations and same-host sitemap-index children. From those documents
it selects and fetches at most 10 same-host pages. Selection prioritizes the
homepage, booking, one content page, lead magnet, conversion CTA, service,
offer, trust, and contact coverage. Query, canonical, and template variants are
deduplicated; archive and utility paths are skipped. Each returned page records
its discovery provenance, category, canonical result, and whether it was
included after deduplication. Coverage is marked partial when a deadline,
document/page limit, or fetch failure prevents complete bounded coverage.
External links are never followed. HTTP and alternate-host canonicalization
checks are intentionally skipped because they would cross the staging boundary.

## Outbound-path inventory in Firstlook mode

| Path | General behavior | Firstlook behavior |
|---|---|---|
| `librecrawl_site_check` / `_site_check` | Direct `httpx` fetches with redirects | Enabled only for exact approved URL through pinned HTTPS; redirects off |
| `librecrawl_schema_check` / `_extract_schema` | Direct `httpx` fetch with redirects | Enabled only for exact approved URL through pinned HTTPS; redirects off |
| `librecrawl_schema_audit` | Direct batch fetch | Disabled |
| `librecrawl_schema_validate` fallback | May fetch up to 50 pages | Disabled |
| `librecrawl_pagespeed*` | Sends target URLs to Google PSI | Disabled |
| `librecrawl_audit`, `librecrawl_start_crawl`, strict audit | Starts the full LibreCrawl engine | Disabled |
| `librecrawl_start_chunked_audit`, resume, force-advance | Starts/resumes runner and full crawler | Disabled; runner does not start at process boot |
| `sitemap_fill.py` | Direct concurrent page fetches | Unreachable because runner/full crawler is disabled |
| `content_audit.py` | Direct concurrent page fetches | Unreachable because runner is disabled |
| `extended_checks.py` | Direct sitemap/robots/page fetches | Unreachable because runner is disabled |
| `external_links.py` / external-links tool | Direct arbitrary outbound-link fetches | Tool disabled; runner unreachable |
| `librecrawl_audit_pdf` / WeasyPrint | Can resolve document resources | Disabled |
| All remaining MCP tools | Stored-result, control, maintenance, or mutation surfaces | Disabled; only the two attended checks are callable |

None of the disabled paths should be described as secured. They remain
production-hardening dependencies.

## Verification

Run the complete repository test suite:

```sh
python -m unittest discover -v
```

The adversarial suite covers direct and DNS-resolved private IPv4/IPv6,
loopback, link-local, multicast/reserved/unspecified, metadata, Tailscale CGNAT,
mixed public/private answers, rebinding, internal names, non-443 ports,
credentials, query/fragment input, exact URL mismatches, and both same-host and
off-host redirects. It also asserts that rejected inputs never reach the
connection factory, and successful calls hand only a validated numeric address
to the transport while preserving Host and TLS SNI. Site-check coverage also
asserts the 10-document sitemap ceiling, prioritized 10-page frontier,
same-host and utility filtering, query/canonical/template deduplication,
provenance, deadline propagation, and explicit fetch-failure reporting.

## Attended rollout

1. Keep the public automatic-audit route disabled.
2. Build and review one green commit from the Firstlook boundary PR.
3. Record the immutable source commit and resulting image digest in the Tower
   integration change record before starting the container.
4. Enable Firstlook mode only in the attended staging service; confirm the
   reported approved URL is `https://www.limitlessenterprise.ai/audit`.
5. Confirm an environment-provided target cannot change the reported approved
   URL, then exercise only the site and schema checks with that URL.
6. Confirm every tool except `librecrawl_site_check` and
   `librecrawl_schema_check` returns a Firstlook-disabled response.
7. Keep an operator present for the sample and retain request/denial logs in
   the Tower layer.

## Rollback

Disable or remove the attended staging service/revision and restore the prior
Tower integration revision. Do not turn off `FIRSTLOOK_STAGING_MODE` on a
publicly reachable MCP instance: that would restore the general-purpose tools.
If the sample must be stopped in place, remove its public route or stop the
staging workload through the Tower deployment workflow. This source task does
not deploy, restart, or mutate Tower.

## Immutable deployment evidence

No deployment is performed by this source task. Therefore there is no deployed
commit or image to claim here. The Tower integration task must attach all of:

- reviewed PR URL;
- exact 40-character green Git commit from `git rev-parse HEAD`;
- immutable container image reference in the form
  `registry/repository@sha256:<digest>` (not only a mutable tag);
- deployed Tower revision/change identifier; and
- timestamp and operator identity for the attended staging rollout.

Suggested change-record entry:

```text
LibreCrawl MCP commit: <40-char SHA>
LibreCrawl MCP image: <registry/repository@sha256:digest>
Tower revision: <revision>
Approved URL: https://www.limitlessenterprise.ai/audit
FIRSTLOOK_STAGING_MODE: true
Public automatic audit generation: disabled
Deployed at/by: <timestamp> / <operator>
```

Before review, a local source commit is evidence only of what was built; it is
not deployment evidence. The Tower task must replace every placeholder with
values observed from the deployed revision.
