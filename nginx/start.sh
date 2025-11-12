#!/bin/bash

# Criar diretórios necessários
mkdir -p /app/nginx/ssl /app/nginx/templates /app/data

# Gerar certificado SSL inicial se não existir
if [ ! -f /app/nginx/ssl/cert.pem ]; then
    echo "🔐 Gerando certificado SSL inicial..."
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /app/nginx/ssl/key.pem \
        -out /app/nginx/ssl/cert.pem \
        -subj "/CN=localhost"
fi

# Testar configuração Nginx
echo "🔧 Verificando configuração Nginx..."
nginx -t

# Iniciar Nginx
echo "🚀 Iniciando Nginx..."
nginx -g "daemon off;" &

# Aguardar Nginx inicializar
sleep 3

# Verificar se Nginx está rodando
if pgrep nginx > /dev/null; then
    echo "✅ Nginx está rodando"
else
    echo "❌ Nginx não iniciou corretamente"
    exit 1
fi

# Iniciar servidor DNS em background
echo "🚀 Iniciando Servidor DNS..."
python /app/dns_server.py &

# Iniciar Flask app (frontend)
echo "🚀 Iniciando Interface Web..."
exec python /app/app.py