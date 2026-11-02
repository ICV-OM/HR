import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
process.env.NODE_ENV='test';process.env.SETUP_TOKEN='integration-test-setup-token';process.env.SECURE_COOKIE='1';process.env.DATA_DIR=mkdtempSync(join(tmpdir(),'hr-test-'));
const {server}=await import('../server.js');
test('authenticated HR workflow and validation',async()=>{
 await new Promise(r=>server.listen(0,'127.0.0.1',r));const base=`http://127.0.0.1:${server.address().port}/api/`;let cookie='';
 const call=async(path,body)=>{const r=await fetch(base+path,{method:body?'POST':'GET',headers:{'Content-Type':'application/json',Cookie:cookie},body:body?JSON.stringify(body):undefined});return {status:r.status,body:await r.json(),cookie:r.headers.get('set-cookie')};};
 try{
 assert.equal((await call('data')).status,401);
 assert.equal((await call('health')).body.ok,true);
 assert.equal((await call('status')).body.requiresSetupToken,true);
 assert.equal((await call('setup',{name:'Blocked',email:'blocked@example.test',password:'long-password-123'})).status,403);
 assert.equal((await call('setup',{setup_token:process.env.SETUP_TOKEN,name:'Admin',email:'admin@example.test',password:'short'})).status,400);
 const credentials={setup_token:process.env.SETUP_TOKEN,name:'Admin',email:'admin@example.test',password:'test-password-123456'};
 assert.equal((await call('setup',credentials)).status,201);
 assert.equal((await call('setup',credentials)).status,409);
 assert.equal((await call('login',{email:credentials.email,password:'wrong'})).status,401);
 const login=await call('login',credentials);assert.equal(login.status,200);assert.match(login.cookie,/HttpOnly/);assert.match(login.cookie,/Secure/);cookie=login.cookie.split(';')[0];
 assert.equal((await call('employees',{name:'موظف اختبار',email:'employee@example.test',department:'التقنية',title:'مطور',salary:1000})).status,201);
 assert.equal((await call('employees',{name:'Invalid',department:'IT',title:'Dev',salary:-1})).status,400);
 const employee=(await call('data')).body.employees[0];
 assert.equal((await call('attendance',{employee_id:employee.id,day:'2026-11-02',check_in:'08:00',check_out:'16:00'})).status,201);
 assert.equal((await call('leaves',{employee_id:employee.id,start:'2026-11-03',end:'2026-11-01',reason:'Annual'})).status,400);
 assert.equal((await call('leaves',{employee_id:employee.id,start:'2026-11-03',end:'2026-11-05',reason:'إجازة سنوية'})).status,201);
 let state=(await call('data')).body;assert.equal(state.attendance.length,1);
 assert.equal((await call('leaves/review',{id:state.leaves[0].id,status:'مقبولة'})).status,201);
 assert.equal((await call('payroll',{month:'2026-11'})).status,201);
 await call('payroll',{month:'2026-11'});state=(await call('data')).body;
 assert.equal(state.payroll.length,1);assert.equal(state.payroll[0].amount,1000);assert.equal(state.leaves[0].status,'مقبولة');assert.equal(state.user.password,undefined);
 assert.equal((await call('logout',{})).status,200);assert.equal((await call('data')).status,401);
 }finally{await new Promise(r=>server.close(r));rmSync(process.env.DATA_DIR,{recursive:true,force:true});}
});
