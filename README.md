# RL3D — integração OAuth Mercado Livre

Este projeto entrega o painel web atual com um backend Node.js para conectar a conta do Mercado Livre pelo OAuth oficial.

## Requisitos
- Node.js 20+
- Aplicação criada em https://developers.mercadolivre.com.br/
- Hospedagem com HTTPS e suporte a Node.js (Render, Railway, Fly.io, VPS etc.)

## Configuração
1. Copie `.env.example` para `.env`.
2. Preencha `ML_CLIENT_ID` e `ML_CLIENT_SECRET` com as credenciais do DevCenter. Gere um Client Secret novo, pois o anterior foi compartilhado em conversa.
3. Gere a chave de criptografia: `openssl rand -hex 32` e coloque em `TOKEN_ENCRYPTION_KEY`.
4. Publique o serviço em um domínio HTTPS.
5. Defina `ML_REDIRECT_URI` como `https://SEU-DOMINIO/auth/callback`.
6. Cadastre exatamente essa mesma URL como Redirect URI na aplicação do Mercado Livre.
7. Instale e inicie: `npm install` e `npm start`.
8. Abra o site e clique em **Conectar Mercado Livre**. Entre com a conta principal do vendedor e autorize.

## Rotas
- `GET /auth/ml`: inicia OAuth e valida state.
- `GET /auth/callback`: troca code por tokens.
- `GET /api/ml/status`: estado da conexão.
- `GET /api/ml/me`: testa acesso ao perfil do vendedor.
- `POST /api/ml/sync`: consulta os últimos 50 pedidos e pagamentos.
- `POST /api/ml/disconnect`: remove os tokens armazenados.

## Segurança e produção
- Client Secret e tokens ficam apenas no backend. Tokens são criptografados com AES-256-GCM no SQLite.
- O Refresh Token do Mercado Livre é rotativo e de uso único; o backend armazena o novo token a cada renovação.
- Faça backup seguro do arquivo `rl3d.sqlite` e proteja o volume/disco da hospedagem.
- Configure HTTPS, variáveis secretas no painel do host, backups e monitoramento.
- Antes de uso multiusuário, implemente autenticação própria, isolamento por usuário/loja, proteção CSRF nas rotas administrativas, rate limiting e armazenamento transacional/gerenciado para tokens. Esta primeira entrega é destinada a uma conta privada RL3D.
- A rota de sincronização consulta até 50 pedidos recentes nesta versão; paginação incremental, webhooks, métricas de anúncios e conciliação completa de custos/logística são etapas seguintes.

## Observações
O redirect URI precisa corresponder exatamente ao cadastrado no DevCenter. O Mercado Livre recomenda validar `state`, trocar o code no servidor e manter Client Secret e tokens fora do navegador. Consulte https://developers.mercadolivre.com.br/pt_br/mensagens-post-venda/autenticacao-e-autorizacao.
