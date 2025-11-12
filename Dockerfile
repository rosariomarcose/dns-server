FROM python:3.11-slim

RUN apt update && apt install -y \
    nginx openssl iputils-ping curl dnsutils net-tools bash procps \
    && rm -rf /var/lib/apt/lists/* \
    && apt clean

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY dns-server/ /app/
COPY nginx/templates /app/nginx/templates

COPY nginx/start.sh .
RUN chmod +x /app/start.sh

RUN mkdir -p /app/data

RUN ln -sf /dev/stdout /var/log/nginx/access.log \
    && ln -sf /dev/stderr /var/log/nginx/error.log

EXPOSE 80 443 53/udp

CMD ["/app/start.sh"]