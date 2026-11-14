import http from 'node:http';
import {randomBytes,randomUUID,createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {openDB,hashPassword,verifyPassword} from './db.mjs';
import {fileURLToPath} from 'node:url';
const root=fileURLToPath(new URL('.',import.meta.url));
export function createApp({dbPath=process.env.DB_PATH||'data/portal.sqlite',origin=process.env.PUBLIC_ORIGIN||'http://localhost:3000',secure=process.env.NODE_ENV==='production'}={}){
 const db=openDB(dbPath), attempts=new Map();
 const digest=t=>createHash('sha256').update(t).digest('hex');
 const dummy=hashPassword(randomBytes(32).toString('hex'));
 function audit(actor,action,target){db.prepare('INSERT INTO audit(actor,action,target) VALUES(?,?,?)').run(actor,action,target);}
 const server=http.createServer(async(req,res)=>{
  res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','same-origin');res.setHeader('X-Frame-Options','DENY');
  res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; font-src https://fonts.gstatic.com; img-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
  const send=(status,data)=>{res.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify(data));};
  try{
   const url=new URL(req.url,origin),path=url.pathname;
   if(!path.startsWith('/api/')){
    const files={'/':'index.html','/portal':'portal/index.html','/portal/':'portal/index.html','/portal/app.js':'portal/app.js','/portal/style.css':'portal/style.css','/assets/1128-logo.png':'assets/1128-logo.png'};
    if(req.method!=='GET'||!files[path])return send(404,{error:'Not found'});
    const file=files[path],body=await readFile(root+file);res.writeHead(200,{'Content-Type':file.endsWith('.html')?'text/html; charset=utf-8':file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'image/png'});return res.end(body);
   }
   res.setHeader('Cache-Control','no-store');
   const mutating=['POST','PATCH','DELETE'].includes(req.method);
   if(mutating&&req.headers.origin!==origin)return send(403,{error:'Invalid request origin'});
   let body={};if(mutating){
    if(!req.headers['content-type']?.startsWith('application/json'))return send(415,{error:'JSON required'});
    let raw='';for await(const chunk of req){raw+=chunk;if(Buffer.byteLength(raw)>32768)return send(413,{error:'Request too large'});}try{body=JSON.parse(raw||'{}');}catch{return send(400,{error:'Invalid JSON'});}
   }
   const field=(key,max=5000)=>{if(typeof body[key]!=='string'||!body[key].trim()||body[key].length>max)throw Object.assign(Error('Invalid '+key),{status:400});return body[key].trim();};
   const limited=(key,max)=>{const now=Date.now();if(attempts.size>10000)for(const[k,v]of attempts)if(v.until<now)attempts.delete(k);const a=attempts.get(key);if(a&&a.until>now){a.count++;return a.count>max;}attempts.set(key,{count:1,until:now+900000});return false;};
   if(path==='/api/login'&&req.method==='POST'){
    if(limited('login:'+req.socket.remoteAddress,20))return send(429,{error:'Too many attempts. Try again in 15 minutes.'});
    const email=field('email',254).toLowerCase(),password=field('password',256),u=db.prepare('SELECT * FROM users WHERE email=?').get(email);
    if(!verifyPassword(password,u?.password||dummy)||!u)return send(401,{error:'Email or password is incorrect'});
    const token=randomBytes(32).toString('hex');db.prepare('DELETE FROM sessions WHERE expires<?').run(Date.now());db.prepare('INSERT INTO sessions VALUES(?,?,?)').run(digest(token),u.id,Date.now()+8*3600000);
    res.setHeader('Set-Cookie',`portal_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${secure?'; Secure':''}`);audit(u.id,'login',u.id);return send(200,{ok:true});
   }
   if(path==='/api/intake'&&req.method==='POST'){
    if(limited('intake:'+req.socket.remoteAddress,5))return send(429,{error:'Too many requests. Please contact us.'});
    const email=field('email',254);if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))return send(400,{error:'Invalid email'});
    db.prepare('INSERT INTO requests(id,name,email,service,note) VALUES(?,?,?,?,?)').run(randomUUID(),field('name',150),email.toLowerCase(),field('service',200),field('note'));return send(201,{ok:true});
   }
   const token=req.headers.cookie?.split(';').map(s=>s.trim()).find(s=>s.startsWith('portal_session='))?.slice(15)||'';
   const user=db.prepare('SELECT u.id,u.name,u.email,u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.expires>?').get(digest(token),Date.now());
   if(!user)return send(401,{error:'Please sign in'});
   if(path==='/api/logout'&&req.method==='POST'){db.prepare('DELETE FROM sessions WHERE token=?').run(digest(token));res.setHeader('Set-Cookie',`portal_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secure?'; Secure':''}`);return send(200,{ok:true});}
   if(path==='/api/me'&&req.method==='GET')return send(200,user);
   if(path==='/api/projects'&&req.method==='GET')return send(200,user.role==='owner'?db.prepare('SELECT p.*,u.name client_name FROM projects p JOIN users u ON p.user_id=u.id ORDER BY updated DESC').all():db.prepare('SELECT * FROM projects WHERE user_id=? ORDER BY updated DESC').all(user.id));
   if(path==='/api/requests'&&req.method==='GET'){if(user.role!=='owner')return send(403,{error:'Owner access required'});return send(200,db.prepare('SELECT * FROM requests ORDER BY created DESC').all());}
   if(path==='/api/clients'&&req.method==='POST'){
    if(user.role!=='owner')return send(403,{error:'Owner access required'});
    const email=field('email',254).toLowerCase(),password=field('password',256),name=field('name',150),title=field('title',200);
    if(password.length<14||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))return send(400,{error:'Valid email and password of at least 14 characters required'});
    const id=randomUUID(),pid=randomUUID();db.exec('BEGIN');try{db.prepare('INSERT INTO users VALUES(?,?,?,?,?)').run(id,email,name,'client',hashPassword(password));db.prepare('INSERT INTO projects(id,user_id,title) VALUES(?,?,?)').run(pid,id,title);audit(user.id,'client_created',id);db.exec('COMMIT');}catch(e){db.exec('ROLLBACK');if(e.message.includes('UNIQUE'))return send(409,{error:'Email already exists'});throw e;}return send(201,{id,project_id:pid});
   }
   const match=path.match(/^\/api\/projects\/([^/]+)(\/messages)?$/);
   if(match){const p=db.prepare('SELECT * FROM projects WHERE id=?').get(match[1]);if(!p||(user.role!=='owner'&&p.user_id!==user.id))return send(404,{error:'Project not found'});
    if(match[2]&&req.method==='GET')return send(200,db.prepare('SELECT m.id,m.body,m.created,u.name,u.role FROM messages m JOIN users u ON m.author_id=u.id WHERE project_id=? ORDER BY m.created,m.id').all(p.id));
    if(match[2]&&req.method==='POST'){db.prepare('INSERT INTO messages(id,project_id,author_id,body) VALUES(?,?,?,?)').run(randomUUID(),p.id,user.id,field('body'));audit(user.id,'message_sent',p.id);return send(201,{ok:true});}
    if(!match[2]&&req.method==='PATCH'){if(user.role!=='owner')return send(403,{error:'Owner access required'});const status=field('status',40),next=typeof body.next_step==='string'?body.next_step.trim():'';if(!['Pending','In progress','Waiting on client','Completed'].includes(status)||next.length>5000)return send(400,{error:'Invalid status or next step'});db.prepare('UPDATE projects SET status=?,next_step=?,updated=CURRENT_TIMESTAMP WHERE id=?').run(status,next,p.id);audit(user.id,'project_updated',p.id);return send(200,{ok:true});}
   }
   return send(404,{error:'Not found'});
  }catch(e){if(!res.headersSent)send(e.status||500,{error:e.status?e.message:'Unable to complete request'});else res.end();}
 });return {server,db};
}
if(process.argv[1]===fileURLToPath(import.meta.url)){if(process.env.NODE_ENV==='production'&&!process.env.PUBLIC_ORIGIN?.startsWith('https://'))throw Error('Production requires HTTPS PUBLIC_ORIGIN');const {server}=createApp();server.listen(Number(process.env.PORT||3000),'0.0.0.0',()=>console.log('1128 portal server started'));}
