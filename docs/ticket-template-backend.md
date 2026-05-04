# Ticket template — Part B (backend)

Copy from `---` to end; fill brackets. **No auth/RBAC/token edits** unless lead ticket says so.

---

**Title:** [short verb + object]

**Track:** Part B (backend collaborator, vertical slice)

**Summary:** [1–2 sentences: resource + HTTP surface]

**Allowed paths (exact):**
- [ ] `backend/src/repositories/[FILE].js`
- [ ] `backend/src/services/[FILE].js` — not `authService` / `tokenService`
- [ ] `backend/src/api/controllers/[FILE].js`
- [ ] `backend/src/api/routes/[FILE].js`
- [ ] `backend/src/api/validators/[FILE].js` (Zod)
- [ ] `backend/src/app.js` — **only if** wiring: `[mount path]`

**Auth:** Reuse existing only: `[e.g. requireAuth on router like users.js]` — do **not** change `middlewares/auth.js`, `routes/auth.js`, `controllers/auth.js`, `validators/auth.js`, `authService.js`, `tokenService.js`.

**Layering:** SQL in repos; `BackendError` for expected failures; validators on routes.

**Acceptance criteria:**
1. [endpoint + method + behavior]
2. […]

**Verify:** `[curl examples or steps]`

**Depends on:** [schema/ticket or none]

**Lead notes:** [optional]

---
