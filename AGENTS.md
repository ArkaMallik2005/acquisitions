# AGENTS.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Core development commands
- Install dependencies: `npm ci`
- Run API locally (watch mode): `npm run dev`
- Run API (non-watch): `npm start`
- Lint: `npm run lint`
- Auto-fix lint issues: `npm run lint:fix`
- Format files: `npm run format`
- Check formatting only: `npm run format:check`

## Database and schema (Drizzle + Neon)
- Generate migration files from `src/models/*.js`: `npm run db:generate`
- Apply migrations: `npm run db:migrate`
- Open Drizzle Studio: `npm run db:studio`
- Drizzle config is in `drizzle.config.js`, output migrations go to `drizzle/`.

## Docker workflows from README
- Dev stack (Neon Local + app): `docker compose --env-file .env.development up --build`
- Alternate dev compose file: `docker compose -f docker-compose.dev.yml --env-file .env.development up --build`
- Prod-style stack (app against Neon cloud DB): `docker compose -f docker-compose.prod.yml --env-file .env.production up --build -d`
- Convenience wrappers exist in package scripts (`npm run dev:docker`, `npm run prod:docker`) and `scripts/dev.sh`, `scripts/prod.sh`.

## Test status
- There is currently no `test` script in `package.json` and no test files/config detected, so there is no repository-defined command for running all tests or a single test yet.

## High-level architecture
- Entry path: `src/index.js` loads env and starts `src/server.js`.
- Server boot: `src/server.js` starts Express app from `src/app.js` on `PORT` (default `3000`).
- App composition in `src/app.js`:
  - Global middleware: Helmet, CORS, JSON/urlencoded parsers, cookie parser, Morgan (wired into Winston logger), then Arcjet-based `securityMiddleware`.
  - Base endpoints: `/`, `/health`, `/api`.
  - Feature routes: `/api/auth` and `/api/users`.
  - Terminal global error handler logs via Winston and returns JSON errors.
- Layering pattern:
  - `routes/*` define HTTP endpoints.
  - `controllers/*` validate/shape request/response and call services.
  - `services/*` contain business logic and DB operations.
  - `models/*` define Drizzle table schema.
  - `config/*` centralizes DB client (`database.js`), security policy (`arcjet.js`), and logging (`logger.js`).
  - `utils/*` includes JWT and cookie helpers.

## Data and auth flow
- Persistence uses Drizzle ORM with Neon serverless (`src/config/database.js`).
- `DATABASE_URL` is mandatory at startup.
- Auth flow:
  - Signup/login handlers in `src/controllers/auth.controller.js`.
  - Input validation uses Zod schemas in `src/validations/auth.validation.js`.
  - Password hashing/comparison is in `src/services/auth.service.js` with bcrypt.
  - JWT is created via `src/utils/jwt.js` and sent as an HTTP-only cookie via `src/utils/cookies.js`.

## Important repository-specific caveats
- `src/app.js` mounts `userRoutes` but does not import it (currently a runtime issue).
- `src/routes/users.routes.js` defines a router but does not export it.
- `src/services/users.services.js` currently contains invalid code (`db.await db.select(...)`) and is not in a runnable state.
- `src/config/database.js` computes `isNeonLocalHost` but currently sets `neonConfig.fetchEndpoint` to `http://neon-local:5432/sql` whenever `NODE_ENV === 'development'`.
