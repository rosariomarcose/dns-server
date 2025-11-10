import threading
import time
import os
import json
import socket
import subprocess
from dnslib import DNSRecord, RR, A
from dnslib.server import DNSServer, DNSLogger

DATA_FILE = "/app/data/hosts.json"
UPSTREAM_DNS = "8.8.8.8"
UPSTREAM_PORT = 53

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
        except Exception:
            return {}

    def save(self):
        with self.lock:
            with open(DATA_FILE, "w", encoding="utf-8") as f:
                json.dump({"hosts": self.records}, f, indent=2, ensure_ascii=False)

    def resolve(self, request, handler):
        qname = str(request.q.qname).rstrip('.').lower()
        qtype = request.q.qtype
        reply = request.reply()

        with self.lock:
            if qname in self.records:
                ip = self.records[qname]
                reply.add_answer(RR(qname, qtype, rdata=A(ip), ttl=60))
                print(f"[LOCAL] {qname} → {ip}")
                return reply

        # Consulta externa (proxy recursivo)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.sendto(request.pack(), (UPSTREAM_DNS, UPSTREAM_PORT))
            data, _ = sock.recvfrom(4096)
            sock.close()
            print(f"[UPSTREAM] {qname} via {UPSTREAM_DNS}")
            return DNSRecord.parse(data)
        except Exception as e:
            print(f"[FALHA] {qname} → erro ao consultar {UPSTREAM_DNS}: {e}")
            reply.header.rcode = 3  # NXDOMAIN
            return reply

def start_dns_server(resolver):
    logger = DNSLogger(prefix=False)
    server = DNSServer(resolver, port=53, address="0.0.0.0", logger=logger)
    print("✅ Servidor DNS iniciado em 0.0.0.0:53 (interno + recursivo externo)")
    server.start_thread()

def health_monitor(resolver):
    print("🩺 Monitor de saúde iniciado (a cada 30s)")
    while True:
        time.sleep(30)
        print("\n" + "═" * 80)
        with resolver.lock:
            for domain, ip in resolver.records.items():
                cmd = ["ping", "-n", "1", ip] if os.name == "nt" else ["ping", "-c", "1", "-W", "2", ip]
                result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                status = "ONLINE" if result.returncode == 0 else "OFFLINE"
                print(f"{domain} → {ip} [{status}]")
        print("═" * 80)

if __name__ == "__main__":
    resolver = CustomResolver()
    threading.Thread(target=health_monitor, args=(resolver,), daemon=True).start()
    start_dns_server(resolver)
    while True:
        time.sleep(1)
