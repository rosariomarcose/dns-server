import threading
import time
import os
import json
import socket
import subprocess
from dnslib import DNSRecord, RR, A, TXT
from dnslib.server import DNSServer, DNSLogger

DATA_FILE = "/app/data/hosts.json"
UPSTREAM_DNS = "8.8.8.8"
UPSTREAM_PORT = 53

class CustomResolver:
    def __init__(self):
        self.records = self.load_records()
        self.lock = threading.Lock()
        print(f"✅ DNS Server inicializado com {len(self.records)} registros")

    def load_records(self):
        if not os.path.exists(DATA_FILE):
            os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)
            default_data = {
                "hosts": {},
                "ssl_enabled": {},
                "ssl_ports": {},
                "http_ports": {}
            }
            with open(DATA_FILE, "w", encoding="utf-8") as f:
                json.dump(default_data, f, indent=2, ensure_ascii=False)
            return default_data["hosts"]
        
        try:
            with open(DATA_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("hosts", {})
        except Exception as e:
            print(f"Erro ao carregar registros: {e}")
            return {}

    def get_full_config(self):
        """Retorna toda a configuração"""
        if not os.path.exists(DATA_FILE):
            return {"hosts": {}, "ssl_enabled": {}, "ssl_ports": {}, "http_ports": {}}
        
        try:
            with open(DATA_FILE, "r", encoding="utf-8") as f:
                config = json.load(f)
                # Garante que todas as chaves existam
                if "ssl_enabled" not in config:
                    config["ssl_enabled"] = {}
                if "ssl_ports" not in config:
                    config["ssl_ports"] = {}
                if "http_ports" not in config:
                    config["http_ports"] = {}
                return config
        except Exception:
            return {"hosts": {}, "ssl_enabled": {}, "ssl_ports": {}, "http_ports": {}}

    def save_full_config(self, config):
        """Salva toda a configuração"""
        with self.lock:
            # Garante que todas as chaves existam antes de salvar
            if "ssl_enabled" not in config:
                config["ssl_enabled"] = {}
            if "ssl_ports" not in config:
                config["ssl_ports"] = {}
            if "http_ports" not in config:
                config["http_ports"] = {}
                
            with open(DATA_FILE, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=2, ensure_ascii=False)

    def save(self):
       """Mantém compatibilidade com código existente"""
       config = self.get_full_config()
       config["hosts"] = self.records
       self.save_full_config(config)
       print(f"💾 Registros salvos: {len(self.records)} hosts")

    def add_host(self, domain, ip, ssl_enabled=False, ssl_port=443, http_port=80):
        """Adiciona host com configurações SSL"""
        with self.lock:
            self.records[domain.lower()] = ip
            
            config = self.get_full_config()
            config["hosts"][domain.lower()] = ip
            config["ssl_enabled"][domain.lower()] = ssl_enabled
            config["ssl_ports"][domain.lower()] = ssl_port
            config["http_ports"][domain.lower()] = http_port
            
            self.save_full_config(config)
            print(f"✅ Host adicionado: {domain} → {ip} (SSL: {ssl_enabled})")

    def get_ssl_info(self, domain):
        """Retorna informações SSL para um domínio"""
        config = self.get_full_config()
        domain_lower = domain.lower()
        
        return {
            "ssl_enabled": config.get("ssl_enabled", {}).get(domain_lower, False),
            "ssl_port": config.get("ssl_ports", {}).get(domain_lower, 443),
            "http_port": config.get("http_ports", {}).get(domain_lower, 80)
        }

    def update_ssl_config(self, domain, ssl_enabled=None, ssl_port=None, http_port=None):
        """Atualiza configuração SSL de um host"""
        domain_lower = domain.lower()
        config = self.get_full_config()
        
        # Garante que as chaves existam
        if "ssl_enabled" not in config:
            config["ssl_enabled"] = {}
        if "ssl_ports" not in config:
            config["ssl_ports"] = {}
        if "http_ports" not in config:
            config["http_ports"] = {}
        
        if ssl_enabled is not None:
            config["ssl_enabled"][domain_lower] = ssl_enabled
        if ssl_port is not None:
            config["ssl_ports"][domain_lower] = ssl_port
        if http_port is not None:
            config["http_ports"][domain_lower] = http_port
        
        self.save_full_config(config)
        return True

    def resolve(self, request, handler):
        qname = str(request.q.qname).rstrip('.').lower()
        qtype = request.q.qtype
        reply = request.reply()

        # Resposta para consultas TXT com informações SSL
        if qtype == 16:  # TXT record
            ssl_info = self.get_ssl_info(qname)
            if ssl_info["ssl_enabled"]:
                txt_data = f"ssl_enabled=true;ssl_port={ssl_info['ssl_port']};http_port={ssl_info['http_port']}"
                reply.add_answer(RR(qname, qtype, rdata=TXT(txt_data), ttl=60))
                print(f"[SSL-INFO] {qname} → {txt_data}")
                return reply

        with self.lock:
            if qname in self.records:
                ip = self.records[qname]
                reply.add_answer(RR(qname, qtype, rdata=A(ip), ttl=60))
                
                # Adiciona informação SSL como TXT record adicional
                ssl_info = self.get_ssl_info(qname)
                if ssl_info["ssl_enabled"]:
                    txt_data = f"ssl_enabled=true;port_https={ssl_info['ssl_port']};port_http={ssl_info['http_port']}"
                    reply.add_answer(RR(qname, 16, rdata=TXT(txt_data), ttl=60))
                
                status = "🔒" if ssl_info["ssl_enabled"] else "🔓"
                print(f"[LOCAL] {status} {qname} → {ip}")
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
    print("✅ Servidor DNS iniciado em 0.0.0.0:53")
    print("   - Suporte a registros SSL/TXT para hosts locais")
    server.start_thread()

def health_monitor(resolver):
    print("🩺 Monitor de saúde iniciado (a cada 30s)")
    while True:
        time.sleep(30)
        print("\n" + "═" * 80)
        config = resolver.get_full_config()
        
        for domain, ip in config.get("hosts", {}).items():
            # Teste de conectividade
            cmd = ["ping", "-n", "1", ip] if os.name == "nt" else ["ping", "-c", "1", "-W", "2", ip]
            ping_result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            ping_status = "ONLINE" if ping_result.returncode == 0 else "OFFLINE"
            
            # Informações SSL
            ssl_enabled = config.get("ssl_enabled", {}).get(domain, False)
            ssl_port = config.get("ssl_ports", {}).get(domain, 443)
            http_port = config.get("http_ports", {}).get(domain, 80)
            
            ssl_icon = "🔒" if ssl_enabled else "🔓"
            print(f"{ssl_icon} {domain} → {ip} [{ping_status}]")
            if ssl_enabled:
                print(f"   HTTPS: porta {ssl_port} | HTTP: porta {http_port}")
        
        print("═" * 80)

if __name__ == "__main__":
    resolver = CustomResolver()
    
    # Iniciar monitor de saúde
    threading.Thread(target=health_monitor, args=(resolver,), daemon=True).start()
    
    # Iniciar servidor DNS
    start_dns_server(resolver)
    
    # Manter servidor rodando
    while True:
        time.sleep(1)