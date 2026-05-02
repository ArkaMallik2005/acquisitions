# Acquisitions API - Docker + Neon Setup
This project supports two database modes:
- Development: Neon Local proxy in Docker, with ephemeral branch creation.
- Production: direct Neon cloud database URL (no Neon Local container).

## Files added
- `Dockerfile`
- `docker-compose.yml` (default local/dev)
- `docker-compose.dev.yml`
- `docker-compose.prod.yml`
- `.env.development`
- `.env.production`

## Environment variable switching
Development uses `DATABASE_URL` from `.env.development`:
```
DATABASE_URL=postgres://neon:npg@neon-local:5432/neondb
```

Production uses `DATABASE_URL` from `.env.production`:
```
DATABASE_URL=postgres://user:password@your-project-id.your-region.aws.neon.tech/dbname?sslmode=require
```

Your application reads `process.env.DATABASE_URL`, and `src/config/database.js` automatically detects local hosts (`neon-local`, `localhost`, `127.0.0.1`) to configure the Neon serverless client for Neon Local (`fetchEndpoint=http://<host>:5432/sql`).

## Development workflow (Neon Local)
1. Fill `.env.development`:
   - `NEON_API_KEY`
   - `NEON_PROJECT_ID`
   - optional `PARENT_BRANCH_ID`
2. Start local stack:
   - `docker compose --env-file .env.development up --build`
   - or `docker compose -f docker-compose.dev.yml --env-file .env.development up --build`
3. App runs on `http://localhost:3000`.
4. Neon Local proxy runs on `localhost:5432` and creates ephemeral branches automatically.

Neon Local branch behavior:
- If `BRANCH_ID` is not set, Neon Local creates ephemeral branches by default.
- If `PARENT_BRANCH_ID` is set, ephemeral branches are created from that parent branch.
- `DELETE_BRANCH=true` ensures cleanup when the container stops.

## Production workflow (Neon cloud)
1. Fill `.env.production` with the real Neon cloud `DATABASE_URL`.
2. Start production stack:
   - `docker compose -f docker-compose.prod.yml --env-file .env.production up --build -d`
3. Only the app container runs. Database is your external Neon cloud project.

## Notes
- Do not hardcode credentials in code or compose files.
- Keep `.env.development` and `.env.production` out of version control.
- For local tools running outside Docker, you can use `postgres://neon:npg@localhost:5432/neondb` with Neon Local.
