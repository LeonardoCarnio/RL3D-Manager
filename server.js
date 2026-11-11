
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

app.get('/', (_req, res) => res.sendFile(path.join(__dirname, 'index.html')));

const required = ['ML_CLIENT_ID', 'ML_CLIENT_SECRET', 'ML_REDIRECT_URI'];
let mlTokens = null;
const pendingOAuth = new Map();
const OAUTH_TTL_MS = 10 * 60 * 1000;

const saoPauloDateParts = (date = new Date()) => {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'America/Sao_Paulo',
    year: 'numeric', month: '2-digit', day: '2-digit'
  }).formatToParts(date);
  return Object.fromEntries(parts.filter(part => part.type !== 'literal').map(part => [part.type, part.value]));
};

const saoPauloDateKey = (date = new Date()) => {
  const parts = saoPauloDateParts(date);
  return `${parts.year}-${parts.month}-${parts.day}`;
};

function missingConfig() {
  return required.filter(key => !process.env[key]);
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
    grant_type: 'refresh_token',
    client_id: process.env.ML_CLIENT_ID,
    client_secret: process.env.ML_CLIENT_SECRET,
    refresh_token: mlTokens.refreshToken
  });

  const response = await fetch('https://api.mercadolibre.com/oauth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString()
  });
  const data = await response.json();

  if (!response.ok) {
    mlTokens = null;
    throw new Error(data.message || data.error_description || 'Falha ao renovar token.');
  }
  saveTokens(data);
  return mlTokens.accessToken;
}

async function mlGet(url) {
  const accessToken = await refreshAccessToken();
  const response = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.message || data.error || `Erro Mercado Livre: ${response.status}`);
  }
  return data;
}

// INÍCIO DO OAUTH COM PKCE
app.get('/auth/ml', (req, res) => {
  const missing = missingConfig();
  if (missing.length) return res.status(500).send(`Configure no Render as variáveis: ${missing.join(', ')}`);

  const now = Date.now();
  for (const [key, value] of pendingOAuth.entries()) {
    if (value.expiresAt <= now) pendingOAuth.delete(key);
  }

  const state = crypto.randomBytes(32).toString('hex');
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');

  pendingOAuth.set(state, { codeVerifier, expiresAt: now + OAUTH_TTL_MS });

  const authorizationUrl = new URL('https://auth.mercadolivre.com.br/authorization');
  authorizationUrl.searchParams.set('response_type', 'code');
  authorizationUrl.searchParams.set('client_id', process.env.ML_CLIENT_ID);
  authorizationUrl.searchParams.set('redirect_uri', process.env.ML_REDIRECT_URI);
  authorizationUrl.searchParams.set('state', state);
  authorizationUrl.searchParams.set('code_challenge', codeChallenge);
  authorizationUrl.searchParams.set('code_challenge_method', 'S256');
  res.redirect(authorizationUrl.toString());
});

// CALLBACK OAUTH
app.get('/auth/callback', async (req, res) => {
  try {
    if (req.query.error) throw new Error(String(req.query.error_description || req.query.error));

    const receivedState = String(req.query.state || '');
    if (!receivedState) throw new Error('Parâmetro state não recebido.');

    const pending = pendingOAuth.get(receivedState);
    pendingOAuth.delete(receivedState);
    if (!pending || pending.expiresAt <= Date.now()) {
      throw new Error('Sessão expirada. Inicie a conexão novamente.');
    }
    if (!req.query.code) throw new Error('Código de autorização não recebido.');

    const tokenParams = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: process.env.ML_CLIENT_ID,
      client_secret: process.env.ML_CLIENT_SECRET,
      code: String(req.query.code),
      redirect_uri: process.env.ML_REDIRECT_URI,
      code_verifier: pending.codeVerifier
    });

    const tokenResponse = await fetch('https://api.mercadolibre.com/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: tokenParams.toString()
    });
    const tokenData = await tokenResponse.json();
    if (!tokenResponse.ok) {
      throw new Error(tokenData.message || tokenData.error_description || tokenData.error || 'Falha na autorização.');
    }

    saveTokens(tokenData);
    console.log('Mercado Livre conectado com sucesso.');
    res.redirect('/?ml=connected');
  } catch (error) {
    console.error('Falha OAuth:', error.message);
    res.redirect('/?ml=error&reason=' + encodeURIComponent(error.message));
  }
});

// STATUS DA CONEXÃO
app.get('/api/ml/status', (_req, res) => {
  res.json({
    connected: !!mlTokens,
    userId: mlTokens?.userId || null,
    expiresAt: mlTokens?.expiresAt || null,
    storage: 'memory'
  });
});

// DESCONEXÃO
app.post('/api/ml/disconnect', (_req, res) => {
  mlTokens = null;
  res.json({ ok: true });
});

// DADOS DO VENDEDOR
app.get('/api/ml/me', async (_req, res) => {
  try {
    const user = await mlGet('https://api.mercadolibre.com/users/me');
    res.json(user);
  } catch (error) {
    res.status(401).json({ error: error.message });
  }
});

// HISTÓRICO DE PEDIDOS DO ANO, COM PAGINAÇÃO
async function fetchYearOrders(sellerId, year) {
  const start = `${year}-01-01T00:00:00.000-03:00`;
  const todaySP = saoPauloDateKey();
  const endDate = String(year) === todaySP.slice(0, 4) ? todaySP : `${year}-12-31`;
  const end = `${endDate}T23:59:59.999-03:00`;
  const limit = 50;
  let offset = 0;
  let total = null;
  const all = [];
  const seen = new Set();

  while (total === null || offset < total) {
    const url = new URL('https://api.mercadolibre.com/orders/search');
    url.searchParams.set('seller', sellerId);
    url.searchParams.set('sort', 'date_desc');
    url.searchParams.set('limit', String(limit));
    url.searchParams.set('offset', String(offset));
    url.searchParams.set('order.date_created.from', start);
    url.searchParams.set('order.date_created.to', end);

    const page = await mlGet(url.toString());
    const results = Array.isArray(page.results) ? page.results : [];
    total = Number(page.paging?.total ?? (offset + results.length));

    for (const order of results) {
      const key = String(order.id);
      if (!seen.has(key)) {
        seen.add(key);
        all.push(order);
      }
    }

    if (!results.length) break;
    offset += results.length;
    if (offset > 100000) throw new Error('A consulta excedeu o limite de segurança de paginação.');
  }

  return { orders: all, total: total ?? all.length, start, end };
}

function compactOrder(order) {
  return {
    id: order.id,
    date_created: order.date_created,
    date_closed: order.date_closed,
    status: order.status,
    buyer: { id: order.buyer?.id || null },
    total_amount: order.total_amount,
    paid_amount: order.paid_amount,
    currency_id: order.currency_id,
    order_items: (order.order_items || []).map(item => ({
      item: {
        id: item.item?.id || null,
        title: item.item?.title || null
      },
      quantity: item.quantity,
      unit_price: item.unit_price,
      listing_type_id: item.listing_type_id
    })),
    payments: (order.payments || []).map(payment => ({
      id: payment.id,
      status: payment.status,
      total_paid_amount: payment.total_paid_amount,
      transaction_amount: payment.transaction_amount,
      date_approved: payment.date_approved
    }))
  };
}

// PRODUTOS VENDIDOS E ANÚNCIOS ATIVOS
async function fetchSoldProducts(orders, sellerId) {
  const soldIds = orders.flatMap(order =>
    (order.order_items || []).map(i => i.item?.id).filter(Boolean)
  );

  const activeIds = [];
  let offset = 0;
  let total = null;

  while (total === null || offset < total) {
    const url = new URL(`https://api.mercadolibre.com/users/${encodeURIComponent(sellerId)}/items/search`);
    url.searchParams.set('status', 'active');
    url.searchParams.set('limit', '100');
    url.searchParams.set('offset', String(offset));

    const page = await mlGet(url.toString());
    const results = Array.isArray(page.results) ? page.results : [];
    total = Number(page.paging?.total ?? (offset + results.length));
    activeIds.push(...results);

    if (!results.length) break;
    offset += results.length;
    if (offset >= 1000 || offset > total) break;
  }

  const ids = [...new Set([...soldIds, ...activeIds].map(String))];
  const products = [];
  const concurrency = 5;

  for (let i = 0; i < ids.length; i += concurrency) {
    const batch = ids.slice(i, i + concurrency);

    const results = await Promise.all(batch.map(async id => {
      try {
        const item = await mlGet(`https://api.mercadolibre.com/items/${encodeURIComponent(id)}`);
        return {
          id: item.id,
          title: item.title || id,
          price: item.price ?? null,
          original_price: item.original_price ?? null,
          currency_id: item.currency_id || 'BRL',
          status: item.status || 'unknown',
          thumbnail: item.thumbnail || item.pictures?.[0]?.secure_url || null,
          permalink: item.permalink || null,
          available_quantity: item.available_quantity ?? null
        };
      } catch (error) {
        console.warn(`Não foi possível consultar o anúncio ${id}: ${error.message}`);
        return {
          id,
          title: id,
          price: null,
          status: 'indisponível',
          thumbnail: null,
          permalink: null
        };
      }
    }));

    products.push(...results);
  }

  return products;
}

// VISUALIZAÇÕES MENSAIS
async function fetchYearVisits(userId, year) {
  const now = new Date();
  const todaySP = saoPauloDateParts(now);
  const currentYear = Number(todaySP.year);
  const currentMonth = Number(todaySP.month);
  const metrics = {};

  for (let month = 1; month <= 12; month++) {
    if (year > currentYear || (year === currentYear && month > currentMonth)) continue;

    const from = `${year}-${String(month).padStart(2, '0')}-01`;
    const lastDay = new Date(year, month, 0).getDate();

    const to = year === currentYear && month === currentMonth
      ? `${todaySP.year}-${todaySP.month}-${todaySP.day}`
      : `${year}-${String(month).padStart(2, '0')}-${String(lastDay).padStart(2, '0')}`;

    try {
      const url = new URL(`https://api.mercadolibre.com/users/${encodeURIComponent(userId)}/items_visits`);
      url.searchParams.set('date_from', from);
      url.searchParams.set('date_to', to);

      const data = await mlGet(url.toString());

      metrics[`${year}-${String(month).padStart(2, '0')}`] = {
        visits: Number(data.total_visits || 0),
        date_from: from,
        date_to: to
      };
    } catch (error) {
      console.warn(`Não foi possível consultar visitas de ${from} a ${to}: ${error.message}`);

      metrics[`${year}-${String(month).padStart(2, '0')}`] = {
        visits: null,
        date_from: from,
        date_to: to,
        unavailable: true
      };
    }
  }

  return metrics;
}

// SINCRONIZAÇÃO COMPLETA
app.post('/api/ml/sync', async (req, res) => {
  try {
    if (!mlTokens) {
      return res.status(401).json({ error: 'Conta não conectada.' });
    }

    const currentYearSP = Number(saoPauloDateParts().year);
    const requestedYear = Number(req.body?.year || currentYearSP);

    if (!Number.isInteger(requestedYear) || requestedYear < 2020 || requestedYear > currentYearSP) {
      return res.status(400).json({ error: 'Ano inválido para sincronização.' });
    }

    const user = await mlGet('https://api.mercadolibre.com/users/me');
    const history = await fetchYearOrders(user.id, requestedYear);

    const ordersData = history.orders.map(compactOrder);

    const [products, monthlyMetrics] = await Promise.all([
      fetchSoldProducts(history.orders, user.id),
      fetchYearVisits(user.id, requestedYear)
    ]);

    const paidOrders = ordersData.filter(o =>
      !['cancelled', 'refunded', 'invalid'].includes(String(o.status || '').toLowerCase()) &&
      (o.status === 'paid' || (o.payments || []).some(p => p.status === 'approved'))
    );

    res.json({
      ok: true,
      year: requestedYear,
      user: { id: user.id, nickname: user.nickname },
      total: history.total,
      loaded: ordersData.length,
      ordersData,
      products,
      dashboard: {
        year: requestedYear,
        monthlyMetrics,
        paidOrders: paidOrders.length,
        dateFrom: history.start,
        dateTo: history.end
      },
      note: `Histórico de ${requestedYear} consultado com paginação.`
    });
  } catch (error) {
    console.error('Erro na sincronização:', error);
    res.status(500).json({ error: error.message || 'Falha na sincronização.' });
  }
});

// POSIÇÃO ORGÂNICA DOS ANÚNCIOS
app.post('/api/ml/positions', async (req, res) => {
  try {
    if (!mlTokens) {
      return res.status(401).json({ error: 'Conecte sua conta do Mercado Livre primeiro.' });
    }

    const checks = Array.isArray(req.body?.checks) ? req.body.checks : [];

    if (!checks.length) {
      return res.status(400).json({ error: 'Informe ao menos um anúncio e uma palavra-chave.' });
    }

    if (checks.length > 20) {
      return res.status(400).json({ error: 'Consulte no máximo 20 anúncios por vez.' });
    }

    const results = [];

    for (const check of checks) {
      const itemId = String(check?.itemId || '').trim();
      const keyword = String(check?.keyword || '').trim().slice(0, 100);

      if (!itemId || !keyword) {
        results.push({
          itemId,
          keyword,
          found: false,
          error: 'Anúncio ou palavra-chave ausente.'
        });
        continue;
      }

      let found = null;
      let scanned = 0;
      let total = null;
      const pageSize = 50;
      const maxPages = 5;

      for (let pageIndex = 0; pageIndex < maxPages; pageIndex++) {
        const url = new URL('https://api.mercadolibre.com/sites/MLB/search');
        url.searchParams.set('q', keyword);
        url.searchParams.set('limit', String(pageSize));
        url.searchParams.set('offset', String(pageIndex * pageSize));

        const data = await mlGet(url.toString());
        const items = Array.isArray(data.results) ? data.results : [];

        total = Number(data.paging?.total ?? total ?? items.length);

        const index = items.findIndex(item => String(item.id) === itemId);
        scanned += items.length;

        if (index >= 0) {
          const position = pageIndex * pageSize + index + 1;

          found = {
            found: true,
            position,
            page: Math.ceil(position / pageSize),
            positionOnPage: ((position - 1) % pageSize) + 1,
            title: items[index].title || null,
            permalink: items[index].permalink || null
          };

          break;
        }

        if (!items.length || (total !== null && (pageIndex + 1) * pageSize >= total)) break;
      }

      results.push({
        itemId,
        keyword,
        ...(found || {
          found: false,
          position: null,
          page: null,
          positionOnPage: null
        }),
        scanned,
        total,
        checkedAt: new Date().toISOString(),
        source: 'Busca pública da API do Mercado Livre',
        placementType: 'orgânico estimado'
      });
    }

    res.json({
      ok: true,
      results,
      note: 'A posição reflete a ordem retornada pela busca pública da API. Posições patrocinadas e resultados personalizados podem não estar representados.'
    });

  } catch (error) {
    console.error('Erro ao consultar posições:', error);
    res.status(500).json({ error: error.message || 'Falha ao consultar posições.' });
  }
});

// TESTE DO SERVIDOR
app.get('/health', (_req, res) => {
  res.json({
    ok: true,
    service: 'RL3D Mercado Livre OAuth',
    storage: 'memory'
  });
});

const port = Number(process.env.PORT || 3000);

app.listen(port, () => {
  console.log(`RL3D rodando na porta ${port}`);
});
