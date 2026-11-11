import express from 'express';
import helmet from 'helmet';
import dotenv from 'dotenv';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

dotenv.config();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '100kb' }));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

const required = ['ML_CLIENT_ID', 'ML_CLIENT_SECRET', 'ML_REDIRECT_URI'];
let mlTokens = null; // Armazenamento temporário em memória: sem banco de dados.
const cookieName = 'rl3d_oauth_state';
function missingConfig() { return required.filter((key) => !process.env[key]); }
function readCookies(req) {
  return Object.fromEntries((req.headers.cookie || '').split(';').map((part) => {
    const i = part.indexOf('=');
    if (i < 0) return ['', ''];
    return [part.slice(0, i).trim(), decodeURIComponent(part.slice(i + 1).trim())];
  }).filter(([key]) => key));
}
function setStateCookie(res, value) {
  res.cookie(cookieName, value, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', maxAge: 10 * 60 * 1000, path: '/' });
}
function clearStateCookie(res) { res.clearCookie(cookieName, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', path: '/' }); }
function safeEqual(a, b) {
  const aa = Buffer.from(String(a)); const bb = Buffer.from(String(b));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
function saveTokens(data) {
  mlTokens = {
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    userId: String(data.user_id),
    expiresAt: Date.now() + Number(data.expires_in || 21600) * 1000
  };
}
async function refreshAccessToken() {
  if (!mlTokens) throw new Error('Conecte sua conta do Mercado Livre primeiro.');
  if (mlTokens.expiresAt > Date.now() + 60000) return mlTokens.accessToken;
  const body = new URLSearchParams({
    grant_type: 'refresh_token', client_id: process.env.ML_CLIENT_ID,
    client_secret: process.env.ML_CLIENT_SECRET, refresh_token: mlTokens.refreshToken
  });
  const response = await fetch('https://api.mercadolibre.com/oauth/token', {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body
  });
  const data = await response.json();
  if (!response.ok) { mlTokens = null; throw new Error(data.message || data.error_description || 'Não foi possível renovar o acesso. Conecte novamente.'); }
  saveTokens(data); // O refresh token é rotativo: guardar sempre o novo.
  return mlTokens.accessToken;
}
async function mlGet(url) {
  const accessToken = await refreshAccessToken();
  const response = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
  const data = await response.json();
  if (!response.ok) throw new Error(data.message || `Erro Mercado Livre (${response.status})`);
  return data;
}

app.get('/auth/ml', (req, res) => {
  const missing = missingConfig();
  if (missing.length) return res.status(500).send(`Configure no Render as variáveis: ${missing.join(', ')}`);
  const state = crypto.randomBytes(32).toString('hex');
  setStateCookie(res, state);
  const url = new URL('https://auth.mercadolivre.com.br/authorization');
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', process.env.ML_CLIENT_ID);
  url.searchParams.set('redirect_uri', process.env.ML_REDIRECT_URI);
  url.searchParams.set('state', state);
  res.redirect(url.toString());
});

app.get('/auth/callback', async (req, res) => {
  try {
    if (req.query.error) throw new Error(String(req.query.error_description || req.query.error));
    const savedState = readCookies(req)[cookieName];
    const receivedState = String(req.query.state || '');
    if (!savedState || !receivedState || !safeEqual(savedState, receivedState)) throw new Error('Validação de segurança falhou. Clique em conectar e tente novamente.');
    if (!req.query.code) throw new Error('Código de autorização não recebido.');
    const body = new URLSearchParams({
      grant_type: 'authorization_code', client_id: process.env.ML_CLIENT_ID,
      client_secret: process.env.ML_CLIENT_SECRET, code: String(req.query.code),
      redirect_uri: process.env.ML_REDIRECT_URI
    });
    const response = await fetch('https://api.mercadolibre.com/oauth/token', {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.message || data.error_description || 'A autorização não foi concluída.');
    saveTokens(data);
    clearStateCookie(res);
    res.redirect('/?ml=connected');
  } catch (error) {
    clearStateCookie(res);
    res.redirect('/?ml=error&reason=' + encodeURIComponent(error.message));
  }
});

app.get('/api/ml/status', (req, res) => {
  res.json({ connected: !!mlTokens, userId: mlTokens?.userId || null, expiresAt: mlTokens?.expiresAt || null, storage: 'memory' });
});
app.post('/api/ml/disconnect', (req, res) => { mlTokens = null; res.json({ ok: true }); });
app.get('/api/ml/me', async (req, res) => {
  try { res.json(await mlGet('https://api.mercadolibre.com/users/me')); }
  catch (error) { res.status(401).json({ error: error.message }); }
});
app.post('/api/ml/sync', async (req, res) => {
  try {
    if (!mlTokens) return res.status(401).json({ error: 'Conta não conectada. Clique em Conectar Mercado Livre.' });
    const user = await mlGet('https://api.mercadolibre.com/users/me');
    const url = new URL('https://api.mercadolibre.com/orders/search');
    url.searchParams.set('seller', user.id);
    url.searchParams.set('sort', 'date_desc');
    url.searchParams.set('limit', '50');
    const result = await mlGet(url.toString());
    const orders = (result.results || []).map((order) => ({
      id: order.id, date_created: order.date_created, status: order.status,
      buyer: { id: order.buyer?.id || null },
      total_amount: order.total_amount, currency_id: order.currency_id,
      order_items: (order.order_items || []).map((item) => ({
        item_id: item.item?.id, title: item.item?.title, quantity: item.quantity,
        unit_price: item.unit_price, listing_type_id: item.listing_type_id
      })),
      payments: (order.payments || []).map((payment) => ({
        id: payment.id, status: payment.status, total_paid_amount: payment.total_paid_amount,
        transaction_amount: payment.transaction_amount, date_approved: payment.date_approved
      }))
    }));
    res.json({ ok: true, user: { id: user.id, nickname: user.nickname }, total: result.paging?.total ?? orders.length, ordersData: orders, note: 'Consulta dos últimos 50 pedidos. O lucro depende também dos custos cadastrados no painel.' });
  } catch (error) { res.status(500).json({ error: error.message }); }
});
app.get('/health', (req, res) => res.json({ ok: true, service: 'RL3D Mercado Livre OAuth', storage: 'memory' }));
const port = Number(process.env.PORT || 3000);
app.listen(port, () => console.log(`RL3D rodando na porta ${port}`));
