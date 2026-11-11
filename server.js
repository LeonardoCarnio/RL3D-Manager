import express from 'express';
import helmet from 'helmet';
import dotenv from 'dotenv';
import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

dotenv.config();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const db = new Database(path.join(__dirname, 'rl3d.sqlite'));
db.pragma('journal_mode = WAL');
db.exec(`CREATE TABLE IF NOT EXISTS ml_auth (id INTEGER PRIMARY KEY CHECK(id=1), user_id TEXT NOT NULL, access_token TEXT NOT NULL, refresh_token TEXT NOT NULL, expires_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)`);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const required = ['ML_CLIENT_ID','ML_CLIENT_SECRET','ML_REDIRECT_URI','TOKEN_ENCRYPTION_KEY'];
function configError(){return required.filter(k=>!process.env[k]).join(', ')}
function encryptionKey(){const k=process.env.TOKEN_ENCRYPTION_KEY||'';if(!/^[a-fA-F0-9]{64}$/.test(k))throw new Error('TOKEN_ENCRYPTION_KEY precisa ter 64 caracteres hexadecimais.');return Buffer.from(k,'hex')}
function seal(value){const iv=crypto.randomBytes(12),cipher=crypto.createCipheriv('aes-256-gcm',encryptionKey(),iv);const data=Buffer.concat([cipher.update(value,'utf8'),cipher.final()]);return [iv.toString('hex'),cipher.getAuthTag().toString('hex'),data.toString('hex')].join(':')}
function unseal(value){const [iv,tag,data]=value.split(':');const decipher=crypto.createDecipheriv('aes-256-gcm',encryptionKey(),Buffer.from(iv,'hex'));decipher.setAuthTag(Buffer.from(tag,'hex'));return Buffer.concat([decipher.update(Buffer.from(data,'hex')),decipher.final()]).toString('utf8')}
function authRow(){return db.prepare('SELECT * FROM ml_auth WHERE id=1').get()}
function saveTokens(t){const now=Date.now();db.prepare(`INSERT INTO ml_auth(id,user_id,access_token,refresh_token,expires_at,updated_at) VALUES(1,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET user_id=excluded.user_id,access_token=excluded.access_token,refresh_token=excluded.refresh_token,expires_at=excluded.expires_at,updated_at=excluded.updated_at`).run(String(t.user_id),seal(t.access_token),seal(t.refresh_token),now+Number(t.expires_in||21600)*1000,now)}
async function token(){let row=authRow();if(!row)throw new Error('Conecte sua conta do Mercado Livre primeiro.');if(row.expires_at>Date.now()+60000)return unseal(row.access_token);const body=new URLSearchParams({grant_type:'refresh_token',client_id:process.env.ML_CLIENT_ID,client_secret:process.env.ML_CLIENT_SECRET,refresh_token:unseal(row.refresh_token)});const r=await fetch('https://api.mercadolibre.com/oauth/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body});const d=await r.json();if(!r.ok)throw new Error(d.message||d.error_description||'Não foi possível renovar o token. Reconecte a conta.');saveTokens(d);return d.access_token}
async function mlGet(url){const access=await token();const r=await fetch(url,{headers:{Authorization:`Bearer ${access}`}});const d=await r.json();if(!r.ok)throw new Error(d.message||`Erro Mercado Livre (${r.status})`);return d}
app.get('/auth/ml',(req,res)=>{const missing=configError();if(missing)return res.status(500).send(`Configure as variáveis: ${missing}`);const state=crypto.randomBytes(32).toString('hex');const sig=crypto.createHmac('sha256',process.env.TOKEN_ENCRYPTION_KEY).update(state).digest('hex');res.cookie('ml_oauth_state',`${state}.${sig}`,{httpOnly:true,secure:process.env.NODE_ENV==='production',sameSite:'lax',maxAge:10*60*1000});const u=new URL('https://auth.mercadolivre.com.br/authorization');u.searchParams.set('response_type','code');u.searchParams.set('client_id',process.env.ML_CLIENT_ID);u.searchParams.set('redirect_uri',process.env.ML_REDIRECT_URI);u.searchParams.set('state',state);res.redirect(u.toString())});
app.get('/auth/callback',async(req,res)=>{try{if(req.query.error)throw new Error(String(req.query.error_description||req.query.error));const [state,sig='']=String(req.cookies?.ml_oauth_state||'').split('.'); // cookie parser not used; read raw cookie below
const cookies=Object.fromEntries((req.headers.cookie||'').split(';').map(x=>x.trim().split('=').map(decodeURIComponent)));const saved=(cookies.ml_oauth_state||'').split('.');const expected=saved[0],expectedSig=saved[1]||'';const actual=String(req.query.state||'');const calc=expected?crypto.createHmac('sha256',process.env.TOKEN_ENCRYPTION_KEY).update(expected).digest('hex'):'';if(!expected||actual!==expected||!crypto.timingSafeEqual(Buffer.from(calc),Buffer.from(expectedSig)))throw new Error('Validação de segurança (state) falhou. Tente conectar novamente.');if(!req.query.code)throw new Error('Código de autorização não recebido.');const body=new URLSearchParams({grant_type:'authorization_code',client_id:process.env.ML_CLIENT_ID,client_secret:process.env.ML_CLIENT_SECRET,code:String(req.query.code),redirect_uri:process.env.ML_REDIRECT_URI});const r=await fetch('https://api.mercadolibre.com/oauth/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body});const d=await r.json();if(!r.ok)throw new Error(d.message||d.error_description||'Troca do código por token falhou.');saveTokens(d);res.clearCookie('ml_oauth_state');res.redirect('/?ml=connected')}catch(e){res.redirect('/?ml=error&reason='+encodeURIComponent(e.message))}});
app.get('/api/ml/status',(req,res)=>{const row=authRow();res.json({connected:!!row,userId:row?.user_id||null,expiresAt:row?.expires_at||null})});
app.post('/api/ml/disconnect',(req,res)=>{db.prepare('DELETE FROM ml_auth WHERE id=1').run();res.json({ok:true})});
app.post('/api/ml/sync',async(req,res)=>{try{const row=authRow();if(!row)return res.status(401).json({error:'Conta não conectada.'});const user=await mlGet('https://api.mercadolibre.com/users/me');const orders=await mlGet(`https://api.mercadolibre.com/orders/search?seller=${encodeURIComponent(user.id)}&sort=date_desc&limit=50`);res.json({ok:true,user:{id:user.id,nickname:user.nickname},orders:orders.paging?.total??orders.results?.length??0,ordersData:(orders.results||[]).map(o=>({id:o.id,date_created:o.date_created,status:o.status,total_amount:o.total_amount,currency_id:o.currency_id,order_items:o.order_items?.map(i=>({title:i.item?.title,quantity:i.quantity,unit_price:i.unit_price,listing_type_id:i.listing_type_id})),payments:o.payments?.map(p=>({status:p.status,total_paid_amount:p.total_paid_amount,transaction_amount:p.transaction_amount,date_approved:p.date_approved}))}))})}catch(e){res.status(500).json({error:e.message})}});
app.get('/api/ml/me',async(req,res)=>{try{res.json(await mlGet('https://api.mercadolibre.com/users/me'))}catch(e){res.status(500).json({error:e.message})}});
app.get('/health',(req,res)=>res.json({ok:true,service:'RL3D Mercado Livre OAuth'}));
const port=Number(process.env.PORT||3000);app.listen(port,()=>console.log(`RL3D rodando na porta ${port}`));
