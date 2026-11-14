import {openDB,hashPassword} from '../db.mjs';
import {randomUUID} from 'node:crypto';
const {OWNER_EMAIL,OWNER_NAME='1128 Management',OWNER_PASSWORD}=process.env;
if(!OWNER_EMAIL || !OWNER_PASSWORD || OWNER_PASSWORD.length<14) throw Error('Set OWNER_EMAIL and OWNER_PASSWORD (at least 14 characters) in the environment.');
const db=openDB(process.env.DB_PATH||'data/portal.sqlite');
db.prepare('INSERT INTO users VALUES(?,?,?,?,?)').run(randomUUID(),OWNER_EMAIL.toLowerCase().trim(),OWNER_NAME,'owner',hashPassword(OWNER_PASSWORD));
console.log('Owner created.');db.close();
