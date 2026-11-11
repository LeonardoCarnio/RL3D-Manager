# RL3D Manager — versão simples sem banco de dados

Aplicação privada de uma única loja, com painel HTML e backend Node.js para OAuth oficial do Mercado Livre. Não utiliza SQLite, PostgreSQL, Firebase ou Supabase.

## O que esta versão faz
- Botão para conectar a conta do Mercado Livre via OAuth.
- Troca do código de autorização por tokens no backend.
- Renovação do access token usando o refresh token rotativo enquanto o processo estiver ativo.
- Consulta do perfil do vendedor e dos últimos 50 pedidos.
- Os custos cadastrados no painel e o resultado da última sincronização ficam no LocalStorage do navegador.

## Limitação importante do modo sem banco
Os tokens ficam somente na memória do processo Node.js. Se o Render reiniciar o serviço, suspender a instância gratuita ou fizer novo deploy, será necessário clicar em **Conectar Mercado Livre** novamente. Os custos e dados locais do painel ficam no navegador em que foram cadastrados; limpar os dados do navegador ou trocar de dispositivo pode apagá-los.

Esta versão é indicada para teste e uso pessoal simples, não para operação financeira com histórico garantido. Para persistência confiável dos tokens e histórico, futuramente será necessário armazenamento persistente.

## Publicação no Render
1. No repositório GitHub, substitua `server.js`, `package.json`, `README.md`, `.env.example` e `index.html` pelos arquivos desta versão.
2. Render > New Web Service > selecione o repositório.
3. Runtime: Node; Build Command: `npm install`; Start Command: `npm start`.
4. Selecione Free para testar.
5. Em Environment Variables, configure `ML_CLIENT_ID`, `ML_CLIENT_SECRET`, `ML_REDIRECT_URI` e `NODE_ENV=production`.
6. Depois do primeiro deploy, copie a URL HTTPS do serviço e defina `ML_REDIRECT_URI` como `https://SEU-SERVICO.onrender.com/auth/callback`.
7. Cadastre exatamente a mesma Redirect URI na aplicação do Mercado Livre Developers.
8. Salve a variável e faça redeploy. Abra o site e clique em **Conectar Mercado Livre**.

## Segurança
- Gere um Client Secret novo; não reutilize o segredo que foi compartilhado em conversa.
- Nunca coloque Client Secret ou tokens no HTML, JavaScript do navegador ou GitHub.
- Mantenha o repositório privado se possível. As variáveis secretas devem ficar somente no Render.
- Esta aplicação é de uso individual e não implementa login multiusuário.

## Endpoints
- `GET /auth/ml`: inicia autorização OAuth.
- `GET /auth/callback`: recebe o retorno e troca o code por tokens.
- `GET /api/ml/status`: informa se a sessão atual está conectada.
- `GET /api/ml/me`: consulta o vendedor autenticado.
- `POST /api/ml/sync`: consulta os últimos 50 pedidos.
- `POST /api/ml/disconnect`: apaga os tokens da memória.
- `GET /health`: teste de disponibilidade.

A consulta de pedidos não substitui a conciliação financeira completa: para obter o valor efetivamente creditado, tarifas, frete, estornos e ajustes, serão necessários endpoints financeiros adicionais e validação de cada tipo de operação.
