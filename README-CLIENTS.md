# Al-Bayan Al-Arabi — Secure client portal (MVP)

1. Deploy via existing `render.yaml` (Node web service + PostgreSQL). Existing tables are preserved by additive SQL migration.
2. Admin adds a company using `/api/clients`, then creates its account via `/api/admin/users` with `{ "username":"client1", "password":"long-random-password", "role":"client", "client_id":1 }`. Admin bearer token required.
3. Create test runs using `/api/test-runs` with a valid `client_id`; add results via `/api/test-runs/:id/results`.
4. Client opens `/client.html`, signs in, and can only list, view, or download reports scoped to their own company. Export PDF, XLSX, PPTX.
5. Old unassigned test runs are invisible to clients until an administrator assigns `client_id`.

SECURITY: Authentication re-checks active user and token version in database for each request. The tenant scoping is enforced by SQL for the new client routes. Existing internal routes deny client-role accounts. Admins must validate ownership when assigning test runs; database-side RLS, audit trails, rate limiting, and automated cross-tenant tests are recommended before production.

LIMITATIONS: PDF/PPTX use English labels to avoid unsupported Arabic shaping/font issues. The report template uses brand colors and text, but logo embedding and true AI-powered testing are not implemented. This package is source code, not compiled EXE/APK. No deployment has been performed.
