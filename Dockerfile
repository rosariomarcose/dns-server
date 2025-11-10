FROM python:3.11-slim

# Pacotes necessários
RUN apt update && apt install -y \
    iputils-ping curl dnsutils net-tools bash \
    && rm -rf /var/lib/apt/lists/* \
    && apt clean

WORKDIR /app
COPY dns-server/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY dns-server/ .

EXPOSE 8000 53/udp
CMD ["python", "app.py"]