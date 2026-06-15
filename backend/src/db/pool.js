import pg from 'pg';
import dotenv from 'dotenv';
dotenv.config();

function buildConfig() {
  const databaseUrl = process.env.DATABASE_URL || 'postgres://postgres:@localhost:5432/socsentinel';
  const url = new URL(databaseUrl);
  return {
    host: url.hostname || 'localhost',
    port: Number(url.port || 5432),
    user: decodeURIComponent(url.username || 'postgres'),
    password: decodeURIComponent(url.password || ''),
    database: (url.pathname || '/socsentinel').replace(/^\//, '') || 'socsentinel'
  };
}

export const pool = new pg.Pool(buildConfig());
