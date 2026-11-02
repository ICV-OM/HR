import http from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import { mkdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

mkdirSync(process.env.DATA_DIR || 'data', {recursive:true});
if(process.env.NODE_ENV==='production' && !process.env.SETUP_TOKEN)throw new Error('SETUP_TOKEN is required in production');
const db = new DatabaseSync(join(process.env.DATA_DIR || 'data','hr.sqlite'));
db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,name TEXT,email TEXT UNIQUE,password TEXT,role TEXT);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id INTEGER,expires INTEGER);
CREATE TABLE IF NOT EXISTS employees(id INTEGER PRIMARY KEY,name TEXT NOT NULL,email TEXT UNIQUE,department TEXT,title TEXT,salary REAL CHECK(salary>=0),status TEXT DEFAULT 'نشط');
CREATE TABLE IF NOT EXISTS attendance(id INTEGER PRIMARY KEY,employee_id INTEGER REFERENCES employees(id),day TEXT,check_in TEXT,check_out TEXT,UNIQUE(employee_id,day));
CREATE TABLE IF NOT EXISTS leaves(id INTEGER PRIMARY KEY,employee_id INTEGER REFERENCES employees(id),start TEXT,end TEXT,reason TEXT,status TEXT DEFAULT 'قيد المراجعة');
CREATE TABLE IF NOT EXISTS payroll(id INTEGER PRIMARY KEY,employee_id INTEGER REFERENCES employees(id),month TEXT,amount REAL,status TEXT DEFAULT 'مسودة',UNIQUE(employee_id,month));`);
const hash = p => {const salt=randomBytes(16).toString('hex'); return salt+':'+scryptSync(p,salt,64).toString('hex');};
const verify=(p,h)=>{const [s,k]=h.split(':');return timingSafeEqual(scryptSync(p,s,64),Buffer.from(k,'hex'));};
const send=(res,status,data)=>{res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});res.end(JSON.stringify(data));};
const all=t=>db.prepare(`SELECT * FROM ${t}`).all();
const attempts=new Map();
export const server=http.createServer(async(req,res)=>{
 try {
 const url=new URL(req.url,'http://localhost');const path=url.pathname;
 if(path==='/api/login' || path==='/api/setup'){
 const key=req.socket.remoteAddress;const now=Date.now();
 for(const [ip,v] of attempts)if(now-v.start>900000)attempts.delete(ip);
 const entry=attempts.get(key)||{start:now,count:0};entry.count++;attempts.set(key,entry);
 if(entry.count>20)return send(res,429,{error:'محاولات كثيرة. حاول بعد 15 دقيقة'});
 }
 res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('X-Frame-Options','DENY');res.setHeader('Content-Security-Policy',"default-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'");
 if(!path.startsWith('/api/')){const files={'/':'index.html','/app.js':'app.js','/style.css':'style.css'};if(!files[path])return send(res,404,{error:'غير موجود'});res.setHeader('Content-Type',path.endsWith('.js')?'text/javascript':path.endsWith('.css')?'text/css':'text/html; charset=utf-8');return res.end(readFileSync(new URL('./public/'+files[path],import.meta.url)));}
 let body={};if(req.method==='POST'){if(req.headers.origin && req.headers.origin!==`http://${req.headers.host}` && req.headers.origin!==`https://${req.headers.host}`)return send(res,403,{error:'مصدر غير مسموح'});let raw='';for await(const chunk of req){raw+=chunk;if(raw.length>20000)return send(res,413,{error:'طلب كبير'});}body=JSON.parse(raw||'{}');}
 if(path==='/api/health'){db.prepare('SELECT 1').get();return send(res,200,{ok:true});}
 if(path==='/api/status')return send(res,200,{needsSetup:!db.prepare('SELECT id FROM users LIMIT 1').get(),requiresSetupToken:!!process.env.SETUP_TOKEN});
 if(path==='/api/setup'&&req.method==='POST'){
 if(db.prepare('SELECT id FROM users LIMIT 1').get())return send(res,409,{error:'تم الإعداد مسبقاً'});
 if(process.env.SETUP_TOKEN){const expected=Buffer.from(process.env.SETUP_TOKEN);const supplied=Buffer.from(String(body.setup_token||''));if(expected.length!==supplied.length||!timingSafeEqual(expected,supplied))return send(res,403,{error:'رمز إعداد المدير غير صحيح'});}
 if(!body.name||!/^\S+@\S+\.\S+$/.test(body.email)||typeof body.password!=='string'||body.password.length<12)return send(res,400,{error:'أدخل الاسم والبريد وكلمة مرور لا تقل عن 12 حرفاً'});
 db.prepare('INSERT INTO users(name,email,password,role) VALUES(?,?,?,?)').run(body.name,body.email,hash(body.password),'admin');return send(res,201,{ok:true});}
 if(path==='/api/login'&&req.method==='POST'){const u=db.prepare('SELECT * FROM users WHERE email=?').get(String(body.email));if(!u||typeof body.password!=='string'||!verify(body.password,u.password))return send(res,401,{error:'بيانات الدخول غير صحيحة'});const token=randomBytes(32).toString('hex');db.prepare('INSERT INTO sessions VALUES(?,?,?)').run(token,u.id,Date.now()+28800000);res.setHeader('Set-Cookie',`session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${process.env.SECURE_COOKIE==='1'?'; Secure':''}`);return send(res,200,{ok:true});}
 const token=(req.headers.cookie||'').split('; ').find(x=>x.startsWith('session='))?.slice(8);const user=token&&db.prepare('SELECT users.id,name,email,role FROM sessions JOIN users ON users.id=sessions.user_id WHERE token=? AND expires>?').get(token,Date.now());
 if(!user)return send(res,401,{error:'يرجى تسجيل الدخول'});
 if(path==='/api/logout'){db.prepare('DELETE FROM sessions WHERE token=?').run(token);res.setHeader('Set-Cookie','session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');return send(res,200,{ok:true});}
 if(path==='/api/data')return send(res,200,{user,employees:all('employees'),attendance:all('attendance'),leaves:all('leaves'),payroll:all('payroll')});
 if(req.method!=='POST')return send(res,404,{error:'غير موجود'});
 if(user.role!=='admin')return send(res,403,{error:'صلاحيات غير كافية'});
 if(path==='/api/employees'){if(!body.name||!body.department||!body.title||!Number.isFinite(Number(body.salary))||Number(body.salary)<0)return send(res,400,{error:'تحقق من بيانات الموظف'});db.prepare('INSERT INTO employees(name,email,department,title,salary) VALUES(?,?,?,?,?)').run(body.name,body.email||null,body.department,body.title,Number(body.salary));}
 else if(path==='/api/attendance'){if(!/^\d{4}-\d{2}-\d{2}$/.test(body.day)||!/^\d{2}:\d{2}$/.test(body.check_in))return send(res,400,{error:'تحقق من التاريخ والوقت'});db.prepare('INSERT INTO attendance(employee_id,day,check_in,check_out) VALUES(?,?,?,?) ON CONFLICT(employee_id,day) DO UPDATE SET check_in=excluded.check_in,check_out=excluded.check_out').run(Number(body.employee_id),body.day,body.check_in,body.check_out||'');}
 else if(path==='/api/leaves'){if(!/^\d{4}-\d{2}-\d{2}$/.test(body.start)||!/^\d{4}-\d{2}-\d{2}$/.test(body.end)||body.end<body.start||!body.reason)return send(res,400,{error:'تحقق من فترة الإجازة والسبب'});db.prepare('INSERT INTO leaves(employee_id,start,end,reason) VALUES(?,?,?,?)').run(Number(body.employee_id),body.start,body.end,body.reason);}
 else if(path==='/api/leaves/review'){if(!['مقبولة','مرفوضة'].includes(body.status))return send(res,400,{error:'حالة غير صالحة'});db.prepare('UPDATE leaves SET status=? WHERE id=?').run(body.status,Number(body.id));}
 else if(path==='/api/payroll'){if(!/^\d{4}-\d{2}$/.test(body.month))return send(res,400,{error:'شهر غير صالح'});db.prepare("INSERT OR IGNORE INTO payroll(employee_id,month,amount) SELECT id,?,salary FROM employees WHERE status='نشط'").run(body.month);}
 else return send(res,404,{error:'غير موجود'});
 return send(res,201,{ok:true});
 }catch(e){return send(res,400,{error:e.code?.includes('SQLITE')?'تعذر الحفظ: تحقق من الموظف وعدم تكرار البريد':'تعذر تنفيذ الطلب'});}
});
if(process.env.NODE_ENV!=='test')server.listen(Number(process.env.PORT||3000),'0.0.0.0',()=>console.log('HR listening on port '+(process.env.PORT||3000)));
