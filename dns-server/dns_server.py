# dns_server.py
import threading
import time
import os
import json
import subprocess
from dnslib import DNSRecord, RR, A
from dnslib.server import DNSServer, DNSLogger

DATA_FILE = "/app/data/hosts.json"

class CustomResolver:
    def __init__(self):
        self.records = self.load_records()
        self.lock = threading.Lock()

    def load_records(self):
        if not os.path.exists(DATA_FILE):
            os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)
            with open(DATA_FILE, "w", encoding="utf-8") as f:
                json.dump({"hosts": {}}, f, indent=2, ensure_ascii=False)
            return {}
        try:
            with open(DATA_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("hosts", {})
        except:
            return {}

    def save(self):
        with self.lock:
            with open(DATA_FILE, "w", encoding="utf-8") as f:
                json.dump({"hosts": self.records}, f, indent=2, ensure_ascii=False)

    def resolve(self, request, handler):
        qname = str(request.q.qname).rstrip('.').lower()
        reply = request.reply()

        # Apenas resoluções internas; sem fallback para upstream
        with self.lock:
            if qname in self.records:
                ip = self.records[qname]
                reply.add_answer(*RR.fromZone(f"{qname} 60 A {ip}"))
                print(f"INTERNO → {qname} → {ip}")
                return reply

        # Se não encontrado, retorna NXDOMAIN (não existe)
        reply.header.rcode = 3  # NXDOMAIN
        print(f"NXDOMAIN → {qname}")
        return reply

def start_dns_server(resolver):
    logger = DNSLogger(prefix=False)

    server = DNSServer(
        resolver=resolver,
        port=53,
        address="0.0.0.0",
        logger=logger
    )

    print("Servidor DNS rodando na porta 53/UDP (apenas resoluções internas)")
    server.start()

def health_monitor(resolver):
    print("Monitor de saúde iniciado (a cada 30s)")
    while True:
        time.sleep(30)
        print("\n" + "═" * 80)
        with resolver.lock:
            for domain, ip in resolver.records.items():
                result = subprocess.run(
                    ["ping", "-c", "1", "-W", "2", ip],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                status = "ONLINE" if result.returncode == 0 else "OFFLINE"
                print(f"{domain} → {ip} [{status}]")
        print("═" * 80)