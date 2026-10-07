# Multi Factor Authentication

**Live demo (browser only, no server):** https://shishir19999.github.io/Multi-Factor-Authentication/

Email + password sign-in with a second factor: a 6-digit one-time code by e-mail, or a standard authenticator app (TOTP, RFC 6238), plus backup codes, trusted devices, a security dashboard and account recovery.

**Stack:** React 19 + Vite 8 (Frontend), Express 5 + Mongoose 9 + Nodemailer + bcrypt (Backend). Node 24 LTS or newer.

## Features
- Sign-up and sign-in with a live password-strength meter and rule checklist.
- E-mail one-time codes (5 minute expiry, attempt limit, resend cooldown) and authenticator-app TOTP enrolment with a QR code (works with Google Authenticator).
- Ten single-use backup codes (download, print, copy), shown once.
- Trusted-device option (skip the second step for 30 days) that can be revoked.
- Security dashboard: recent sign-in log, active sessions with revoke, change password, switch or disable 2FA after re-entering the password.
- Lockout and rate-limit messaging with a countdown; account recovery by e-mailed code.
- Light/dark theme (follows the OS, remembered), responsive from 320px, keyboard and screen-reader friendly (6-box code input with paste and auto-advance, aria-live messages).
- Parallax and scroll-reveal are used only on the landing hero and section backgrounds, never on forms, code entry or security screens. They use only transform and opacity, run through IntersectionObserver and requestAnimationFrame, and switch off for prefers-reduced-motion, small screens and low-power or data-saver devices.

## Run the browser-only demo
```bash
cd Frontend
npm install
VITE_DEMO=true npm run dev      # PowerShell: $env:VITE_DEMO='true'; npm run dev
npm run build:pages             # static site for GitHub Pages in Frontend/dist (base /Multi-Factor-Authentication/, hash routing)
```
The demo replaces the server with an in-browser backend (data in localStorage, realistic latency). No e-mail is sent: one-time codes appear in the labelled **Demo inbox** panel. TOTP is real (WebCrypto), so you can scan the QR code with an authenticator app. Use **Reset demo data** in the banner to start over.

Demo logins (password `Demo@12345`):

| E-mail | Second factor |
|---|---|
| `demo@example.com` | E-mail code (read it in the Demo inbox) |
| `alice@example.com` | Authenticator app (live code shown on the sign-in page, secret `JBSWY3DPEHPK3PXP`, backup code `abcde-fghjk`) |
| `bob@example.com` | None |

## Run full-stack
See Setup below. The real backend exposes `/auth/register`, `/auth/login`, `/auth/resend-otp`, `/auth/verify-otp`, `/auth/me`, `/auth/logout`, `/auth/security`, `/auth/activity`, `/auth/sessions` (list, `DELETE /:sid`, `POST /revoke-others`), `/auth/change-password`, `/auth/2fa/method`, `/auth/2fa/totp/setup`, `/auth/2fa/totp/enable`, `/auth/backup-codes/regenerate`, `/auth/trusted-devices` (DELETE), `/auth/recover/request` and `/auth/recover/reset`. Sensitive actions require the current password.

## Original e-mail flow
1. `POST /auth/register` - `{ email, password }`; password is stored bcrypt-hashed.
2. `POST /auth/login` - checks credentials, creates a 6-digit OTP (valid 5 minutes), stores only its bcrypt hash and e-mails it. Rate limited.
3. `POST /auth/resend-otp` - `{ email }`; a new OTP after a password login, with a 30 second cooldown (429 + `retryAfterSeconds`).
4. `POST /auth/verify-otp` - `{ email, otp }`; after 5 wrong attempts the OTP is invalidated. On success returns `{ success, token, user }` (JWT).
5. `GET /auth/me` - protected; send `Authorization: Bearer <token>`.

## Setup
```bash
# Backend
cd Backend
cp .env.example .env     # fill in MongoDB + SMTP details
npm install
npm start                # or: npm run dev (auto-restart)

# Frontend
cd Frontend
cp .env.example .env     # VITE_API_URL must point to the backend
npm install
npm run dev
```

## Environment variables
Backend: `PORT`, `MONGODB_URL`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`, `SMTP_USER` (alias `SMTP_EMAIL`), `SMTP_PASSWORD`, `SMTP_FROM`, `OTP_REDIRECT_EMAIL` (dev only), `DEMO_EMAIL` (seed), `JWT_SECRET` (required; the server exits without it - use a long random string).
Frontend: `VITE_API_URL` (default `http://localhost:8080`).

## Notes
- Never commit `Backend/.env`.

## Demo data
`cd Backend && npm run seed` (idempotent, deterministic, database `mfa`) creates 25 users in `users`, all with password `Demo@12345`. Documented logins: `demo@example.com`, `alice@example.com`, `bob@example.com` (the other 22 are `first.last@example.com` sample addresses). Set `DEMO_EMAIL` to change the demo account's address (default `demo@example.com`). Login still emails an OTP, so point `SMTP_*` at a mailbox you can read or a local fake SMTP server, or use `OTP_REDIRECT_EMAIL` (below).


## Deploy with Docker

Files: `Backend/Dockerfile`, `Frontend/Dockerfile` (Vite build served by nginx, SPA fallback in `Frontend/nginx.conf`), `.dockerignore` in both folders and `docker-compose.yml` here (mongo + backend + frontend).

```bash
cp .env.example .env      # optional: set JWT_SECRET and the SMTP_* values
docker compose up --build -d
```

- Frontend: http://localhost:8081 (`FRONTEND_PORT`), API: http://localhost:8080 (`BACKEND_PORT`). MongoDB is only reachable inside the compose network and its data lives in the `mongo-data` volume.
- `VITE_API_URL` is baked into the frontend bundle at build time and must be the address the **browser** uses to reach the backend (for a server: `http://<server-ip-or-domain>:8080`); rebuild with `docker compose build frontend` after changing it.
- `CORS_ORIGIN` must contain the origin the browser loads the frontend from (default `http://localhost:8081`); for a server use e.g. `http://<server-ip>:8081`.
- Seed demo data: `docker compose exec backend npm run seed` fails in the production image because the seed uses a dev dependency (`@faker-js/faker`); run the seed from your machine instead: `cd Backend && MONGODB_URL=mongodb://127.0.0.1:27017/mfa npm run seed` after temporarily publishing mongo (add `ports: ["27017:27017"]` to the `mongo` service).
- SMTP defaults to Gmail (see below). For local testing run a fake SMTP server on the host and use `SMTP_HOST=host.docker.internal`. Never commit real SMTP credentials.

> Note: these Docker files were written and reviewed but not built or run in the authoring environment (Docker engine was off).

## Open the app from a phone on the same Wi-Fi

1. Find the PC's LAN IP (`ipconfig` on Windows, look for the IPv4 address, e.g. `192.168.1.79`).
2. Start the backend bound to all interfaces (the default `HOST=0.0.0.0`) with the phone's origin allowed, and Vite with `--host`:
   ```bash
   # Backend
   CORS_ORIGIN=http://localhost:5173,http://192.168.1.79:5173 npm start
   # Frontend: the API URL must use the LAN IP, not localhost
   VITE_API_URL=http://192.168.1.79:8080 npm run dev -- --host 0.0.0.0 --port 5173
   ```
   (PowerShell: `$env:CORS_ORIGIN="..."; npm start`.)
3. Allow the two ports through Windows Firewall (first run usually prompts; otherwise add an inbound rule for TCP 8080 and 5173, "Private" network only).
4. On the phone (same network) open `http://192.168.1.79:5173`.

Without `CORS_ORIGIN` set the API accepts any origin. If the phone shows the page but API calls fail, `VITE_API_URL` still points at `localhost` or the origin is missing from `CORS_ORIGIN`.

## Tests

`cd Backend && npm test` (node:test + supertest) runs against a throwaway local database that is dropped afterwards (set `TEST_MONGO_URI` to change the server, default `mongodb://127.0.0.1:27017`).

## Logout and token revocation
`POST /auth/logout` (Bearer token) increments the user's `tokenVersion`; JWTs carry the version they were issued with, so every earlier token (all devices) is rejected with 401 "Token has been revoked", as are tokens of deleted users. This supersedes the "stateless JWT" note above. The Logout button calls it.

## Local testing without real email
Point SMTP at a local fake server, e.g. `SMTP_HOST=127.0.0.1 SMTP_PORT=2525 SMTP_USER= SMTP_PASSWORD=` (empty `SMTP_USER` disables SMTP auth; plain connections are only allowed to localhost). `npm test` uses a stub mailer and needs no SMTP.
