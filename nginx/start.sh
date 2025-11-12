#!/bin/bash

echo "🏗️  Construindo estrutura completa do Nginx..."

# Criar TODOS os diretórios necessários
mkdir -p /app/data /app/nginx/templates
mkdir -p /var/log/nginx
mkdir -p /etc/nginx/conf.d /etc/nginx/sites-available /etc/nginx/sites-enabled /etc/nginx/ssl

# Configuração principal do Nginx (MAIS SIMPLES - sem incluir mime.types)
echo "📁 Configurando Nginx principal..."
cat > /etc/nginx/nginx.conf << 'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    # Configurações básicas - SEM mime.types para evitar erro
    default_type application/octet-stream;

    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;

    # Configurações de SSL padrão
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # Headers de segurança
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";

    # Incluir configurações (estrutura padrão)
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF
echo "✅ nginx.conf configurado"

# Configuração base em conf.d/
echo "📁 Configurando base em conf.d/"
cat > /etc/nginx/conf.d/00-base.conf << 'EOF'
# Configurações base do servidor
proxy_connect_timeout 30s;
proxy_send_timeout 30s;
proxy_read_timeout 30s;
proxy_buffering on;
proxy_buffer_size 4k;
proxy_buffers 8 4k;
EOF
echo "✅ 00-base.conf configurado"

# Gerar certificado SSL PADRÃO se não existir
if [ ! -f /etc/nginx/ssl/cert.pem ]; then
    echo "🔐 Gerando certificado SSL padrão..."
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/nginx/ssl/key.pem \
        -out /etc/nginx/ssl/cert.pem \
        -subj "/CN=localhost"
    echo "✅ Certificado padrão gerado em /etc/nginx/ssl/"
else
    echo "📄 Certificado padrão já existe"
fi

# Template para domínios (CORRIGIDO - usando placeholders simples)
echo "📄 Configurando template para domínios..."
cat > /app/nginx/templates/server_template.conf << 'EOF'
# Template para configuração de servidores Nginx
# Variáveis: domain, ip, http_port, ssl_port, cert_file, key_file

server {
    listen 80;
    server_name domain;
    return 301 https://$server_name$request_uri;
}

server {
    listen ssl_port ssl;
    server_name domain;
    
    ssl_certificate cert_file;
    ssl_certificate_key key_file;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    
    location / {
        proxy_pass http://ip:http_port;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF
echo "✅ server_template.conf configurado"

# Limpar symlinks quebrados em sites-enabled
echo "🧹 Limpando symlinks quebrados..."
find /etc/nginx/sites-enabled/ -type l ! -exec test -e {} \; -delete

# Verificar estrutura criada
echo "📊 Estrutura criada:"
echo "   📁 /etc/nginx/"
echo "   ├── 📄 nginx.conf"
echo "   ├── 📁 conf.d/"
echo "   │   └── 📄 00-base.conf"
echo "   ├── 📁 sites-available/ ($(ls /etc/nginx/sites-available/*.conf 2>/dev/null | wc -l) sites)"
echo "   ├── 📁 sites-enabled/ ($(ls /etc/nginx/sites-enabled/*.conf 2>/dev/null | wc -l) ativos)"
echo "   └── 📁 ssl/ ($(ls /etc/nginx/ssl/*.crt 2>/dev/null | wc -l) certificados)"
echo "   📁 /app/nginx/templates/"
echo "   └── 📄 server_template.conf"
echo "   📁 /var/log/nginx/ (logs)"
echo "   📁 /app/data/ (dados DNS)"

# Testar configuração Nginx
echo "🔧 Verificando configuração Nginx..."
if nginx -t; then
    echo "✅ Configuração Nginx testada com sucesso"
else
    echo "❌ Erro na configuração do Nginx"
    echo "📋 Tentando diagnóstico..."
    nginx -t 2>&1 | head -20
    exit 1
fi

# Iniciar Nginx
echo "🚀 Iniciando Nginx..."
nginx -g "daemon off;" &

# Aguardar Nginx inicializar
sleep 5

# Verificar se Nginx está rodando
if pgrep nginx > /dev/null; then
    echo "✅ Nginx está rodando"
    
    # Verificar sites ativos
    active_sites=$(ls /etc/nginx/sites-enabled/*.conf 2>/dev/null | wc -l)
    echo "🌐 Sites ativos: $active_sites"
else
    echo "❌ Nginx não iniciou corretamente"
    echo "📋 Logs de erro:"
    tail -30 /var/log/nginx/error.log 2>/dev/null || echo "Nenhum log encontrado"
    exit 1
fi

# Iniciar servidor DNS em background
echo "🚀 Iniciando Servidor DNS..."
python /app/dns_server.py &

# Aguardar DNS inicializar
sleep 3

# Verificar se DNS está rodando
if pgrep -f "python /app/dns_server.py" > /dev/null; then
    echo "✅ Servidor DNS está rodando"
else
    echo "❌ Servidor DNS não iniciou"
fi

# Iniciar Flask app (frontend)
echo "🚀 Iniciando Interface Web..."
exec python /app/app.py