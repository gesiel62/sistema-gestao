# Stage 1: build deps (instala node_modules baseado em package.json)
FROM node:18-alpine AS deps
WORKDIR /app

# Instalar dependências de sistema necessárias (se houver)
RUN apk add --no-cache libc6-compat

# Copia package.json e package-lock (se houver) e instala dependências
COPY package.json package-lock.json* ./
RUN npm ci --production

# Stage 2: runtime
FROM node:18-alpine AS runner
WORKDIR /app

# copiar apenas node_modules do builder
COPY --from=deps /app/node_modules ./node_modules
# copiar código
COPY . .

# criar usuário não-root (melhor segurança)
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

ENV NODE_ENV=production
ENV PORT=3000

EXPOSE 3000

CMD ["node", "server.js"]
