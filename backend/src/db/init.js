import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { pool } from './pool.js';
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const schema = fs.readFileSync(path.join(__dirname, '../../../database/schema.sql'), 'utf8');
await pool.query(schema);
console.log('Database initialized');
await pool.end();
