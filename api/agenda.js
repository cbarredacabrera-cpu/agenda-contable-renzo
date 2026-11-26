const {randomBytes,randomUUID,scryptSync,timingSafeEqual,createHash}=require('node:crypto');
const accounts=[{"name":"Renzo Salas","login":"a955211076e960dab695f534ad1e2ada3b7fc78ff30d1135f613111066f4033b","salt":"b6055498246f5344c4d5cfa8fcc1d826","pass":"c05812ea993e414f912f20441a4fa292ba23d33a4fbb1a7d3bf58280ff77d75c"},{"name":"Fernando Paredes","login":"81253f59085b50bddfe2dcee9919c47194ffb856380996a4fd963d7ec7ffdb99","salt":"0adaa360417fbc47f0a542ec1bdf338c","pass":"331f8507a4b40cb5e4afbd0e9e612145a47f96a380645d5108884b5a0ed2130d"},{"name":"Maricielo Quispe","login":"8e747711105c4de97282360c90fcc16d7f9761be99bf81d1fc0af3d66e54dffb","salt":"eb8c93e15337476d87f79e6794ecc780","pass":"5cb3aa8c288fa7c1202dd868bc5fb8fbbf76596bfda9554cea307190182df074"}];
// Earlier deployments stored Fernando's previous display name in sessions and activities.
function currentName(name){
  return name==='Fernando Salas'?'Fernando Paredes':name;
}
const names=accounts.map(a=>a.name);
const hash=s=>createHash('sha256').update(s).digest('hex');
const key='agenda-renzo:v1:';
async function redis(...command){
  const url=process.env.UPSTASH_REDIS_REST_URL||process.env.KV_REST_API_URL;
  const token=process.env.UPSTASH_REDIS_REST_TOKEN||process.env.KV_REST_API_TOKEN;
  if(!url||!token)throw Error('storage');
  const resp=await fetch(url,{method:'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:JSON.stringify(command),signal:AbortSignal.timeout(8000)});
  if(!resp.ok)throw Error('storage');
  const data=await resp.json();if(data.error)throw Error('storage');return data.result;
}
const sessionCookie=(token,age)=>'__Host-agenda='+token+'; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age='+age;
module.exports=async(req,res)=>{
  res.setHeader('Cache-Control','private, no-store');
  const fail=(code,message)=>res.status(code).json({message});
  try{
    const method=req.method;
    if(!['POST','GET','PATCH','DELETE'].includes(method))return fail(405,'Método no permitido.');
    if(method!=='GET'&&req.headers['x-agenda']!=='1')return fail(403,'Solicitud no válida.');
    const b=req.body||{};
    if(method==='POST'&&b.action==='login'){
      const bucket=key+'login:'+hash(String(req.headers['x-vercel-forwarded-for']||req.headers['x-real-ip']||'local').split(',')[0]);
      const attempts=await redis('EVAL',"local n=redis.call('INCR',KEYS[1]); if n==1 then redis.call('EXPIRE',KEYS[1],300) end; return n",1,bucket);
      if(attempts>25)return fail(429,'Demasiados intentos. Vuelve en cinco minutos.');
      const a=accounts.find(a=>a.login===hash(String(b.user)));
      const digest=scryptSync(String(b.password).slice(0,128),(a||accounts[0]).salt,32);
      if(!a||!timingSafeEqual(digest,Buffer.from(a.pass,'hex')))return fail(401,'Usuario o contraseña incorrectos.');
      const token=randomBytes(32).toString('hex');await redis('SET',key+'session:'+hash(token),a.name,'EX',28800);
      res.setHeader('Set-Cookie',sessionCookie(token,28800));return res.json({name:a.name});
    }
    const token=(req.headers.cookie||'').match(/(?:^|;\s*)__Host-agenda=([a-f0-9]{64})(?:;|$)/)?.[1];
    const session=token&&key+'session:'+hash(token),name=session&&currentName(await redis('GET',session));
    if(!accounts.some(a=>a.name===name))return fail(401,'Ingresa con tu cuenta.');
    if(method==='POST'&&b.action==='logout'){await redis('DEL',session);res.setHeader('Set-Cookie',sessionCookie('',0));return res.json({ok:true})}
    const admin=name===accounts[0].name,table=key+'activities';
    if(method==='GET'){
      const rows=(await redis('HVALS',table)).map(s=>{
        const record=JSON.parse(s);
        record.person=currentName(record.person);
        return record;
      }).filter(r=>admin||r.person===name);
      return res.json({name,records:rows});
    }
    if(method!=='POST'&&!admin)return fail(403,'Solo Renzo puede modificar registros.');
    const remove=method==='DELETE',create=method==='POST';
    const id=create?randomUUID():b.id;
    if(typeof id!=='string'||id.length>64)return fail(400,'Registro no válido.');
    let row;
    if(!remove){
      const person=admin?currentName(b.person):name;
      if(!names.includes(person)||!/^\d{4}-\d\d-\d\d$/.test(b.date)||!Number.isFinite(Date.parse(b.date))||new Date(b.date).toISOString().slice(0,10)!==b.date||
        !['Completada','En proceso'].includes(b.status)||![['title',140],['detail',1600]].every(([f,max])=>typeof b[f]==='string'&&b[f].trim()&&b[f].length<=max))return fail(400,'Revisa los datos de la actividad.');
      row={id,person,date:b.date,title:b.title.trim(),detail:b.detail.trim(),status:b.status,time:new Date().toLocaleTimeString('es-PE',{timeZone:'America/Lima',hour:'2-digit',minute:'2-digit',hourCycle:'h23'}),rev:1};
    }
    if(create){await redis('HSET',table,id,JSON.stringify(row));return res.status(201).json({ok:true})}
    const current=await redis('HGET',table,id);if(!current)return fail(404,'La actividad ya no existe.');
    const old=JSON.parse(current);if(old.rev!==b.rev)return fail(409,'La actividad cambió. Actualiza la agenda.');
    if(!remove)Object.assign(row,{time:old.time,rev:old.rev+1,changed:new Date().toISOString()});
    const script="if redis.call('HGET',KEYS[1],ARGV[1])~=ARGV[2] then return 0 end; if ARGV[3]=='' then redis.call('HDEL',KEYS[1],ARGV[1]) else redis.call('HSET',KEYS[1],ARGV[1],ARGV[3]) end; return 1";
    if(!await redis('EVAL',script,1,table,id,current,remove?'':JSON.stringify(row)))return fail(409,'La actividad cambió. Actualiza la agenda.');
    return res.json({ok:true});
  }catch{return fail(503,'No se pudo conectar con el almacenamiento. Verifica la conexión de Upstash en Vercel y vuelve a intentar.')}
};
