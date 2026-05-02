import 'dotenv/config';

import { neon, neonConfig } from '@neondatabase/serverless';
import { drizzle } from 'drizzle-orm/neon-http';

const databaseUrl = process.env.DATABASE_URL;

if (!databaseUrl) {
  throw new Error('DATABASE_URL is not defined');
}

const parsedUrl = new URL(databaseUrl);
const isNeonLocalHost = ['neon-local', 'localhost', '127.0.0.1'].includes(parsedUrl.hostname);

if (process.env.NODE_ENV === 'development') {
  const port = parsedUrl.port || '5432';
  neonConfig.fetchEndpoint = `http://neon-local:5432/sql`;
  neonConfig.useSecureWebSocket = false;
  neonConfig.poolQueryViaFetch = true;
}

const sql = neon(databaseUrl);

const db = drizzle(sql);

export { db, sql };