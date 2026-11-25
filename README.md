# Gather — User Profile App

Gather is a Dockerized profile-management application built with a static HTML/CSS/JavaScript client, an Express API, and MongoDB. It includes account registration and login, email verification and password recovery, private sessions, profile editing and visibility controls, and searchable public profiles.

## Features

- Passwords are hashed with Node.js `scrypt`; session and one-time email tokens are random, stored as hashes, and expire.
- Session cookies are HTTP-only and same-site; HTTPS deployments set `NODE_ENV=production` to enable secure cookies.
- Email verification and password-reset links are sent over configurable SMTP.
- Profile updates are validated, public profile listings are paginated and searchable, and private profiles are excluded from discovery.
- Authentication and password-reset endpoints are rate-limited.
- Docker Compose includes readiness/health checks, persistent MongoDB storage, an internal API reverse proxy, and restart policies.
- GitHub Actions runs backend checks/tests and builds the application containers.

## Run locally

Requirements: Docker Desktop with Docker Compose.

1. Copy `.env.example` to `.env` if you want to configure SMTP. Compose works without SMTP in local development; email verification is then skipped and password-reset emails are disabled.
2. Start the stack:

   ```sh
   docker compose up --build
   ```

3. Open [http://localhost:8080](http://localhost:8080).
4. Stop it with `docker compose down`. To also remove persisted local database data, use `docker compose down -v`.

The API is proxied through the frontend at `/api`; the backend and MongoDB are not published directly to the host. The health endpoint is `/api/health`.

## Email setup

Set `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`, `SMTP_USER`, `SMTP_PASSWORD`, and optionally `EMAIL_FROM` in `.env`. For SMTP port 465 set `SMTP_SECURE=true`; for most STARTTLS providers on port 587 use `false`.

In local development without SMTP, the API logs verification links for newly registered accounts. Do not use this mode in production.

Profiles stored by the earlier demo have no passwords. A returning user can claim a legacy profile by creating an account with the same email address; in production this requires completing email verification. Before migrating a production database, check for case-insensitive duplicate email addresses so MongoDB can enforce the new unique email index.

## Production deployment checklist

- Set `NODE_ENV=production`, `APP_ORIGIN` to the app's public HTTPS origin, and supply an authenticated TLS MongoDB `MONGO_URI` plus SMTP credentials through the host's secret manager (not a committed `.env` file).
- Terminate TLS at a trusted reverse proxy and set `TRUST_PROXY=true` only when the app is actually behind that proxy.
- Replace the Compose MongoDB service/URI with a managed, authenticated MongoDB deployment with encrypted connections, backups, and restore testing.
- Deploy behind an HTTPS load balancer; configure restrictive network access, monitoring, log collection, and alerting.
- The included in-memory rate limiter is suitable for a single API instance. Before running multiple replicas, configure a shared rate-limit store (for example Redis).
- Review retention, privacy, and account deletion requirements for the data and jurisdictions where the service will operate.

## Development

The backend tests use Node's built-in test runner:

```sh
cd backend
npm ci
npm run check
npm test
```

The GitHub Actions workflow runs these checks and builds both Docker images on pushes to `main` and pull requests.
