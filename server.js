
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

// Painel principal
app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

const required = [
  'ML_CLIENT_ID',
  'ML_CLIENT_SECRET',
  'ML_REDIRECT_URI'
];

let mlTokens = null;

// Armazenamento temporário das tentativas OAuth
const pendingOAuth = new Map();
const OAUTH_TTL_MS = 10 * 60 * 1000;

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

// Renovação automática do token
async function refreshAccessToken() {
  if (!mlTokens) {
    throw new Error('Conecte sua conta do Mercado Livre primeiro.');
  }

  if (mlTokens.expiresAt > Date.now() + 60000) {
    return mlTokens.accessToken;
  }

  const body = new URLSearchParams({
    grant_type: 'refresh_token',
    client_id: process.env.ML_CLIENT_ID,
    client_secret: process.env.ML_CLIENT_SECRET,
    refresh_token: mlTokens.refreshToken
  });

  const response = await fetch(
    'https://api.mercadolibre.com/oauth/token',
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: body.toString()
    }
  );

  const data = await response.json();

  if (!response.ok) {
    mlTokens = null;
    throw new Error(
      data.message ||
      data.error_description ||
      'Falha ao renovar token.'
    );
  }

  saveTokens(data);
  return mlTokens.accessToken;
}

// Consultas autenticadas
async function mlGet(url) {
  const accessToken = await refreshAccessToken();

  const response = await fetch(url, {
    headers: {
      Authorization: `Bearer ${accessToken}`
    }
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(
      data.message || `Erro Mercado Livre: ${response.status}`
    );
  }

  return data;
}

// INÍCIO DO OAUTH COM PKCE
app.get('/auth/ml', (req, res) => {
  const missing = missingConfig();

  if (missing.length) {
    return res.status(500).send(
      `Configure no Render as variáveis: ${missing.join(', ')}`
    );
  }

  // Remove tentativas expiradas
  const now = Date.now();

  for (const [key, value] of pendingOAuth.entries()) {
    if (value.expiresAt <= now) {
      pendingOAuth.delete(key);
    }
  }

  // Gera state
  const state = crypto.randomBytes(32).toString('hex');

  // Gera PKCE verifier
  const codeVerifier = crypto
    .randomBytes(32)
    .toString('base64url');

  // Gera PKCE challenge SHA256
  const codeChallenge = crypto
    .createHash('sha256')
    .update(codeVerifier)
    .digest('base64url');

  // Guarda verifier no servidor
  pendingOAuth.set(state, {
    codeVerifier,
    expiresAt: now + OAUTH_TTL_MS
  });

  const authorizationUrl = new URL(
    'https://auth.mercadolivre.com.br/authorization'
  );

  authorizationUrl.searchParams.set('response_type', 'code');
  authorizationUrl.searchParams.set(
    'client_id',
    process.env.ML_CLIENT_ID
  );
  authorizationUrl.searchParams.set(
    'redirect_uri',
    process.env.ML_REDIRECT_URI
  );
  authorizationUrl.searchParams.set('state', state);

  authorizationUrl.searchParams.set(
    'code_challenge',
    codeChallenge
  );

  authorizationUrl.searchParams.set(
    'code_challenge_method',
    'S256'
  );

  res.redirect(authorizationUrl.toString());
});

// CALLBACK OAUTH
app.get('/auth/callback', async (req, res) => {
  try {
    if (req.query.error) {
      throw new Error(
        String(req.query.error_description || req.query.error)
      );
    }

    const receivedState = String(req.query.state || '');

    if (!receivedState) {
      throw new Error('Parâmetro state não recebido.');
    }

    const pending = pendingOAuth.get(receivedState);

    pendingOAuth.delete(receivedState);

    if (!pending || pending.expiresAt <= Date.now()) {
      throw new Error(
        'Sessão expirada. Inicie a conexão novamente.'
      );
    }

    if (!req.query.code) {
      throw new Error('Código de autorização não recebido.');
    }

    if (!pending.codeVerifier) {
      throw new Error('PKCE code_verifier não encontrado.');
    }

    // PARÂMETROS DA TROCA DO TOKEN
    const tokenParams = new URLSearchParams();

    tokenParams.set('grant_type', 'authorization_code');
    tokenParams.set('client_id', process.env.ML_CLIENT_ID);
    tokenParams.set(
      'client_secret',
      process.env.ML_CLIENT_SECRET
    );
    tokenParams.set('code', String(req.query.code));
    tokenParams.set(
      'redirect_uri',
      process.env.ML_REDIRECT_URI
    );

    // PARÂMETRO PKCE OBRIGATÓRIO
    tokenParams.set(
      'code_verifier',
      pending.codeVerifier
    );

    console.log(
      'Iniciando troca OAuth com code_verifier.'
    );

    const tokenResponse = await fetch(
      'https://api.mercadolibre.com/oauth/token',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: tokenParams.toString()
      }
    );

    const tokenData = await tokenResponse.json();

    if (!tokenResponse.ok) {
      console.error(
        'Erro OAuth:',
        tokenData.error || tokenData.message
      );

      throw new Error(
        tokenData.message ||
        tokenData.error_description ||
        tokenData.error ||
        'Falha na autorização.'
      );
    }

    saveTokens(tokenData);

    console.log('Mercado Livre conectado com sucesso.');

    return res.redirect('/?ml=connected');

  } catch (error) {
    console.error('Falha OAuth:', error.message);

    return res.redirect(
      '/?ml=error&reason=' +
      encodeURIComponent(error.message)
    );
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
    const user = await mlGet(
      'https://api.mercadolibre.com/users/me'
    );

    res.json(user);

  } catch (error) {
    res.status(401).json({
      error: error.message
    });
  }
});

// SINCRONIZAÇÃO DE VENDAS
app.post('/api/ml/sync', async (_req, res) => {
  try {
    if (!mlTokens) {
      return res.status(401).json({
        error: 'Conta não conectada.'
      });
    }

    const user = await mlGet(
      'https://api.mercadolibre.com/users/me'
    );

    const ordersUrl = new URL(
      'https://api.mercadolibre.com/orders/search'
    );

    ordersUrl.searchParams.set('seller', user.id);
    ordersUrl.searchParams.set('sort', 'date_desc');
    ordersUrl.searchParams.set('limit', '50');

    const result = await mlGet(ordersUrl.toString());

    const orders = (result.results || []).map(order => ({
      id: order.id,
      date_created: order.date_created,
      status: order.status,
      buyer: {
        id: order.buyer?.id || null
      },
      total_amount: order.total_amount,
      currency_id: order.currency_id,

      order_items: (order.order_items || []).map(item => ({
        item_id: item.item?.id,
        title: item.item?.title,
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
    }));

    res.json({
      ok: true,
      user: {
        id: user.id,
        nickname: user.nickname
      },
      total: result.paging?.total ?? orders.length,
      ordersData: orders,
      note: 'Consulta dos últimos 50 pedidos.'
    });

  } catch (error) {
    res.status(500).json({
      error: error.message
    });
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
