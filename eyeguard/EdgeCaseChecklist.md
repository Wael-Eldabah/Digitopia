Software-only simulation / demo — no real systems will be contacted or modified.
# Edge Case Checklist

- **Invalid IP input**: `/api/v1/search` validates via `ipaddress`; returns HTTP 400 with `INVALID_IP` code.
- **API client errors**: httpx failures trigger fallback to `/mocks/DataExamples.txt` with structured warning logs.
- **Duplicate device registration**: `/api/v1/devices` and `/api/v1/simulation/devices` raise HTTP 409 when IP already exists.
- **Rate limiting**: Search endpoint enforces 30 requests/minute per normalized IP; returns HTTP 429.
- **Cache expiry**: Redis (or memory) TTL set to 3600 seconds; cache miss fetches fresh data and repopulates.
- **Missing mocks**: If `DataExamples.txt` absent, raises descriptive `ThreatClientError`.
- **Terminal misuse**: Unsupported commands return friendly error; session lookups return HTTP 404.
- **Signup domain enforcement**: `/api/v1/settings/users` rejects non `@eyeguard.com` addresses with HTTP 400.
- **PDF/CSV export failures**: Exceptions bubble as HTTP 500; recommend verifying `reportlab` install.
