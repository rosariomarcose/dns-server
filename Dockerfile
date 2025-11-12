FROM python:3.11-slim

RUN apt update && apt install -y \
    nginx openssl iputils-ping curl dnsutils net-tools bash procps \
    && rm -rf /var/lib/apt/lists/* \
    && apt clean

WORKDIR /app

# Copiar arquivos
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY dns-server/ .
COPY nginx/ /app/nginx/

# Criar diretórios e dar permissões
RUN mkdir -p /app/data /app/nginx/ssl /app/nginx/templates
RUN chmod +x /app/nginx/start.sh 

# Configurar logs do Nginx
RUN ln -sf /dev/stdout /var/log/nginx/access.log \
    && ln -sf /dev/stderr /var/log/nginx/error.log

EXPOSE 80 443 53/udp

# Usar o script de inicialização
CMD ["/app/nginx/start.sh"]  