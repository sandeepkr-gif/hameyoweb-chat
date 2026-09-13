const path=require('path');
const fs=require('fs');
const http=require('http');
const crypto=require('crypto');
const express=require('express');
const helmet=require('helmet');
const cookieParser=require('cookie-parser');
const bcrypt=require('bcryptjs');
const jwt=require('jsonwebtoken');
const multer=require('multer');
const {Server}=require('socket.io');

const app=express();
const server=http.createServer(app);
const io=new Server(server,{cors:{origin:false}});
const PORT=Number(process.env.PORT||3000);
const JWT_SECRET=process.env.JWT_SECRET||'CHANGE_ME_IN_PRODUCTION_'+crypto.randomBytes(24).toString('hex');
const COOKIE_SECURE=String(process.env.COOKIE_SECURE||'false')==='true';
const DB_FILE=path.join(__dirname,'data','db.json');
const uploadDir=path.join(__dirname,'public','uploads');
fs.mkdirSync(path.dirname(DB_FILE),{recursive:true});fs.mkdirSync(uploadDir,{recursive:true});
function readDB(){try{return JSON.parse(fs.readFileSync(DB_FILE,'utf8'))}catch{return {users:[],conversations:[],messages:[],groups:[],sessions:[]}}}
let db=readDB();
for(const k of ['users','conversations','messages','groups','sessions'])if(!Array.isArray(db[k]))db[k]=[];
function saveDB(){fs.writeFileSync(DB_FILE,JSON.stringify(db,null,2))}
function id(prefix='id'){return prefix+'_'+crypto.randomBytes(9).toString('hex')}
function publicUser(u){return {id:u.id,name:u.name,email:u.email,avatar:u.avatar,createdAt:u.createdAt,status:u.status||'offline',bio:u.bio||''}}
function tokenFor(u){return jwt.sign({sub:u.id},JWT_SECRET,{expiresIn:'7d'})}
function setAuth(res,u){res.cookie('hs_token',tokenFor(u),{httpOnly:true,sameSite:'lax',secure:COOKIE_SECURE,maxAge:7*24*60*60*1000})}
function currentUser(req){try{const t=req.cookies.hs_token;if(!t)return null;const p=jwt.verify(t,JWT_SECRET);return db.users.find(u=>u.id===p.sub)||null}catch{return null}}
function auth(req,res,next){const u=currentUser(req);if(!u)return res.status(401).json({error:'Authentication required'});req.user=u;next()}
function cleanText(v,max=4000){return String(v??'').trim().slice(0,max)}
function seed(){
 if(db.users.length)return;
 const now=new Date().toISOString();
 const names=[['Aarav','aarav@example.com'],['Priya','priya@example.com'],['Rahul','rahul@example.com'],['Neha','neha@example.com'],['Kabir','kabir@example.com'],['Maya','maya@example.com']];
 db.users=names.map(([name,email])=>({id:id('usr'),name,email,passwordHash:bcrypt.hashSync(crypto.randomBytes(18).toString('hex'),10),avatar:name[0],createdAt:now,bio:'Available for a chat',status:'online',demo:true}));
 const g1={id:id('grp'),name:'Web Developers',avatar:'WD',ownerId:db.users[0].id,members:db.users.slice(0,5).map(x=>x.id),createdAt:now};
 const g2={id:id('grp'),name:'Creative Studio',avatar:'CS',ownerId:db.users[1].id,members:db.users.slice(1,5).map(x=>x.id),createdAt:now};
 db.groups=[g1,g2];
 saveDB();
}
seed();
app.use(helmet({contentSecurityPolicy:false,crossOriginEmbedderPolicy:false}));
app.use(express.json({limit:'1mb'}));app.use(express.urlencoded({extended:true}));app.use(cookieParser());
app.use('/uploads',express.static(uploadDir));
app.use(express.static(path.join(__dirname,'public')));
const upload=multer({storage:multer.diskStorage({destination:uploadDir,filename:(req,file,cb)=>cb(null,Date.now()+'-'+crypto.randomBytes(5).toString('hex')+path.extname(file.originalname).toLowerCase())}),limits:{fileSize:10*1024*1024},fileFilter:(req,file,cb)=>{const ok=/^(image|video|audio|application\/pdf|text\/plain)/.test(file.mimetype);cb(ok?null:new Error('Unsupported file type'),ok)}});

app.get('/api/health',(req,res)=>res.json({ok:true,service:'HacKerSANDEEP Social',time:new Date().toISOString()}));
app.post('/api/auth/register',async(req,res)=>{
 const name=cleanText(req.body.name,60),email=cleanText(req.body.email,160).toLowerCase(),password=String(req.body.password||'');
 if(name.length<2)return res.status(400).json({error:'Name must contain at least 2 characters.'});
 if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))return res.status(400).json({error:'Enter a valid email address.'});
 if(password.length<8)return res.status(400).json({error:'Password must contain at least 8 characters.'});
 if(db.users.some(u=>u.email===email))return res.status(409).json({error:'An account with this email already exists.'});
 const user={id:id('usr'),name,email,passwordHash:await bcrypt.hash(password,12),avatar:name[0].toUpperCase(),createdAt:new Date().toISOString(),status:'online',bio:'Available for a chat'};
 db.users.push(user);saveDB();setAuth(res,user);res.status(201).json({user:publicUser(user)});
});
app.post('/api/auth/login',async(req,res)=>{
 const email=cleanText(req.body.email,160).toLowerCase(),password=String(req.body.password||'');
 const user=db.users.find(u=>u.email===email&&!u.demo);
 if(!user||!(await bcrypt.compare(password,user.passwordHash)))return res.status(401).json({error:'Invalid email or password.'});
 user.status='online';saveDB();setAuth(res,user);res.json({user:publicUser(user)});
});
app.post('/api/auth/logout',auth,(req,res)=>{req.user.status='offline';saveDB();res.clearCookie('hs_token');res.json({ok:true})});
app.get('/api/auth/me',auth,(req,res)=>res.json({user:publicUser(req.user)}));

app.get('/api/users',auth,(req,res)=>{
 const q=cleanText(req.query.q,80).toLowerCase();const list=db.users.filter(u=>u.id!==req.user.id&&!u.demo&&(u.name.toLowerCase().includes(q)||u.email.includes(q))).slice(0,50).map(publicUser);res.json({users:list});
});
app.get('/api/contacts',auth,(req,res)=>{
 const contacts=db.users.filter(u=>u.id!==req.user.id).map(u=>publicUser(u));
 const groups=db.groups.filter(g=>g.members.includes(req.user.id)).map(g=>({...g,members:g.members.map(mid=>db.users.find(u=>u.id===mid)).filter(Boolean).map(publicUser)}));
 res.json({contacts,groups});
});
app.get('/api/groups',auth,(req,res)=>res.json({groups:db.groups.filter(g=>g.members.includes(req.user.id))}));
app.post('/api/groups',auth,(req,res)=>{
 const name=cleanText(req.body.name,80);const memberIds=Array.isArray(req.body.memberIds)?req.body.memberIds.filter(x=>typeof x==='string'):[];
 if(name.length<2)return res.status(400).json({error:'Group name is required.'});
 const members=[req.user.id,...memberIds].filter((x,i,a)=>a.indexOf(x)===i&&db.users.some(u=>u.id===x));
 const g={id:id('grp'),name,avatar:name.split(/\s+/).map(x=>x[0]).slice(0,2).join('').toUpperCase(),ownerId:req.user.id,members,createdAt:new Date().toISOString()};db.groups.push(g);saveDB();res.status(201).json({group:g});
});
app.post('/api/groups/:id/members',auth,(req,res)=>{
 const g=db.groups.find(x=>x.id===req.params.id);if(!g)return res.status(404).json({error:'Group not found'});if(g.ownerId!==req.user.id)return res.status(403).json({error:'Only the group owner can add members.'});
 const uid=String(req.body.userId||'');if(!db.users.some(u=>u.id===uid))return res.status(404).json({error:'User not found'});if(!g.members.includes(uid))g.members.push(uid);saveDB();res.json({group:g});
});

function conversationKey(a,b){return [a,b].sort().join(':')}
app.get('/api/conversations',auth,(req,res)=>{
 const direct=db.conversations.filter(c=>c.type==='direct'&&(c.a===req.user.id||c.b===req.user.id)).map(c=>{const other=db.users.find(u=>u.id===(c.a===req.user.id?c.b:c.a));const last=db.messages.filter(m=>m.conversationId===c.id).slice(-1)[0];return {id:c.id,type:'direct',user:other?publicUser(other):null,lastMessage:last?{text:last.text,createdAt:last.createdAt}:null}});
 const groups=db.groups.filter(g=>g.members.includes(req.user.id)).map(g=>{const last=db.messages.filter(m=>m.conversationId===g.id).slice(-1)[0];return {id:g.id,type:'group',name:g.name,avatar:g.avatar,members:g.members,lastMessage:last?{text:last.text,createdAt:last.createdAt}:null}});
 res.json({conversations:[...direct,...groups]});
});
app.post('/api/conversations/direct',auth,(req,res)=>{
 const otherId=String(req.body.userId||'');if(otherId===req.user.id||!db.users.some(u=>u.id===otherId))return res.status(400).json({error:'Invalid contact.'});
 let c=db.conversations.find(x=>x.type==='direct'&&conversationKey(x.a,x.b)===conversationKey(req.user.id,otherId));if(!c){c={id:id('cnv'),type:'direct',a:req.user.id,b:otherId,createdAt:new Date().toISOString()};db.conversations.push(c);saveDB()}res.json({conversation:c});
});
function conversationAccess(userId,cid){const direct=db.conversations.find(c=>c.id===cid);if(direct)return direct.type==='direct'&&(direct.a===userId||direct.b===userId)?direct:null;const g=db.groups.find(x=>x.id===cid);if(g&&g.members.includes(userId))return g;return null}
app.get('/api/messages/:conversationId',auth,(req,res)=>{
 const c=conversationAccess(req.user.id,req.params.conversationId);if(!c)return res.status(403).json({error:'Conversation access denied'});
 const messages=db.messages.filter(m=>m.conversationId===c.id).slice(-200).map(m=>({...m,sender:publicUser(db.users.find(u=>u.id===m.senderId)||{id:m.senderId,name:'Unknown',email:'',avatar:'?',createdAt:''})}));res.json({messages});
});
app.post('/api/messages',auth,(req,res)=>{
 const conversationId=String(req.body.conversationId||'');const c=conversationAccess(req.user.id,conversationId);if(!c)return res.status(403).json({error:'Conversation access denied'});
 const text=cleanText(req.body.text,4000);if(!text&&!req.body.attachment)return res.status(400).json({error:'Message cannot be empty.'});
 const m={id:id('msg'),conversationId,senderId:req.user.id,text,attachment:req.body.attachment||null,createdAt:new Date().toISOString(),status:'sent'};db.messages.push(m);saveDB();const out={...m,sender:publicUser(req.user)};io.to('conv:'+conversationId).emit('message:new',out);res.status(201).json({message:out});
});
app.post('/api/upload',auth,upload.single('file'),(req,res)=>{if(!req.file)return res.status(400).json({error:'No file uploaded'});res.status(201).json({attachment:{url:'/uploads/'+req.file.filename,name:req.file.originalname,type:req.file.mimetype,size:req.file.size}})});
app.use((err,req,res,next)=>{if(err instanceof multer.MulterError||err) return res.status(400).json({error:err.message||'Request failed'});next()});
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));

const online=new Map();
io.use((socket,next)=>{try{const token=socket.handshake.auth?.token||socket.handshake.headers.cookie?.match(/hs_token=([^;]+)/)?.[1];if(!token)return next(new Error('unauthorized'));const p=jwt.verify(token,JWT_SECRET);const u=db.users.find(x=>x.id===p.sub);if(!u)return next(new Error('unauthorized'));socket.user=u;next()}catch{next(new Error('unauthorized'))}});
io.on('connection',socket=>{
 const u=socket.user;online.set(u.id,socket.id);u.status='online';saveDB();io.emit('presence:update',{userId:u.id,status:'online'});
 socket.on('conversation:join',cid=>{const c=conversationAccess(u.id,String(cid));if(c)socket.join('conv:'+c.id)});
 socket.on('conversation:leave',cid=>socket.leave('conv:'+cid));
 socket.on('typing:start',cid=>{const c=conversationAccess(u.id,String(cid));if(c)socket.to('conv:'+c.id).emit('typing',{conversationId:c.id,user:publicUser(u),active:true})});
 socket.on('typing:stop',cid=>socket.to('conv:'+cid).emit('typing',{conversationId:cid,user:publicUser(u),active:false}));
 socket.on('call:offer',payload=>{if(payload?.to)io.to(online.get(payload.to)||'').emit('call:offer',{...payload,from:u.id,fromUser:publicUser(u)})});
 socket.on('call:answer',payload=>{if(payload?.to)io.to(online.get(payload.to)||'').emit('call:answer',{...payload,from:u.id})});
 socket.on('call:ice',payload=>{if(payload?.to)io.to(online.get(payload.to)||'').emit('call:ice',{...payload,from:u.id})});
 socket.on('call:end',payload=>{if(payload?.to)io.to(online.get(payload.to)||'').emit('call:end',{from:u.id})});
 socket.on('disconnect',()=>{if(online.get(u.id)===socket.id){online.delete(u.id);u.status='offline';saveDB();io.emit('presence:update',{userId:u.id,status:'offline'})}});
});
server.listen(PORT,()=>console.log(`HacKerSANDEEP Social running at http://localhost:${PORT}`));
