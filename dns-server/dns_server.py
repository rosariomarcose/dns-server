import threading
import time
import os
import json
import socket
import subprocess
import re
from dnslib import DNSRecord, RR, A, TXT, PTR
from dnslib.server import DNSServer, DNSLogger

DATA_FILE = "/app/data/hosts.json"
UPSTREAM_DNS = "8.8.8.8"
UPSTREAM_PORT = 53

# Carregar configurações DNS se existirem
dns_config_file = "/app/data/dns_config.json"
if os.path.exists(dns_config_file):
    with open(dns_config_file, "r") as f:
        dns_config = json.load(f)
        UPSTREAM_DNS = dns_config.get("upstream_dns", "8.8.8.8")
        UPSTREAM_PORT = dns_config.get("upstream_port", 53)

class CustomResolver:
    def __init__(self):
        self.records = self.load_records()
        self.ssl_config = {}
        self.nginx_lock = threading.Lock()
        self.lock = threading.Lock()
        self.load_ssl_config()
        print(f"✅ DNS Server inicializado com {len(self.records)} registros")
        
        # Garantir que todos os domínios com SSL estão configurados no Nginx
        self.ensure_all_ssl_configs()

    def ensure_all_ssl_configs(self):
        """Garante que todos os domínios com SSL estão configurados no Nginx"""
        print("🔧 Verificando configurações SSL existentes...")
        config = self.get_full_config()

        for domain, ssl_enabled in config.get("ssl_enabled", {}).items():
            if domain in self.records:  # Verificar se domínio existe nos registros
                ssl_port = config.get("ssl_ports", {}).get(domain, 443)
                http_port = config.get("http_ports", {}).get(domain, 80)

                # Verificar se a configuração já existe
                config_file = f"/etc/nginx/sites-available/{domain.replace('.', '_')}.conf"
                if not os.path.exists(config_file):
                    print(f"⚠️  Configuração faltando para {domain}, recriando...")
                    if ssl_enabled:
                        self.configure_nginx_ssl(domain, ssl_port, http_port)
                    else:
                        self.configure_nginx_http(domain, http_port)  # Nova função para HTTP

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

    def load_ssl_config(self):
        """Carrega configurações SSL do arquivo"""
        ssl_file = "/app/data/ssl_config.json"
        if os.path.exists(ssl_file):
            with open(ssl_file, "r") as f:
                self.ssl_config = json.load(f)
        else:
            self.ssl_config = {"auto_generate_ssl": True}
            self.save_ssl_config()

    def load_ca_config(self):
        """Carrega configurações da Autoridade Certificadora"""
        ca_file = "/app/data/ca_config.json"
        if os.path.exists(ca_file):
            with open(ca_file, "r") as f:
                return json.load(f)
        else:
            # Configurações padrão da CA
            return {
                "common_name": "DNS-Resolver-CA",
                "organization": "Local Network",
                "organizational_unit": "IT Department",
                "country": "BR",
                "validity_days": 3650
            }

    def save_ca_config(self, config):
        """Salva configurações da Autoridade Certificadora"""
        ca_file = "/app/data/ca_config.json"
        with open(ca_file, "w") as f:
            json.dump(config, f, indent=2)
        print("💾 Configuração CA salva")
    
    def save_ssl_config(self):
        """Salva configurações SSL"""
        with open("/app/data/ssl_config.json", "w") as f:
            json.dump(self.ssl_config, f, indent=2)

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
            with open(DATA_FILE, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            print(f"💾 Configuração salva em: {DATA_FILE}")

    def save(self):
        """Mantém compatibilidade com código existente"""
        config = self.get_full_config()
        config["hosts"] = self.records
        self.save_full_config(config)

    def add_host(self, domain, ip, ssl_enabled=False, ssl_port=443, http_port=80):
        """Adiciona host sem configurar Nginx (apenas DNS)"""
        print(f"🔄 Iniciando adição de host: {domain} → {ip} (SSL: {ssl_enabled})")
        with self.lock:
            self.records[domain.lower()] = ip

            config = self.get_full_config()
            config["hosts"][domain.lower()] = ip
            config["ssl_enabled"][domain.lower()] = ssl_enabled
            config["ssl_ports"][domain.lower()] = ssl_port
            config["http_ports"][domain.lower()] = http_port

            self.save_full_config(config)

            print(f"✅ Host adicionado: {domain} → {ip} (SSL: {ssl_enabled})")
            print(f"📁 Configuração salva no arquivo: {DATA_FILE}")

            # Configuração Nginx só acontece quando SSL é habilitado via interface
            # Isso torna a adição instantânea sem delays desnecessários
    
    def configure_nginx_ssl(self, domain, ssl_port=443, http_port=80):
        """Configura SSL no Nginx automaticamente"""
        with self.nginx_lock:
            try:
                # 1. Gerar certificado INDIVIDUAL para o domínio
                cert_file, key_file = self.generate_ssl_certificate(domain)
                
                # 2. Configurar Nginx com certificados específicos
                success = self.update_nginx_config(domain, ssl_port, http_port, cert_file, key_file)
                
                if success:
                    print(f"🔒 SSL configurado para: {domain}")
                    print(f"   📄 Certificado: {cert_file}")
                    print(f"   🔑 Chave: {key_file}")
                else:
                    print(f"❌ Falha ao configurar SSL para: {domain}")
                
            except Exception as e:
                print(f"❌ Erro ao configurar SSL para {domain}: {e}")

    def configure_nginx_http(self, domain, http_port=80):
        """Configura Nginx para um domínio SEM SSL (apenas HTTP)"""
        with self.nginx_lock:
            try:
                # Configurar Nginx sem SSL
                success = self.update_nginx_config_http(domain, http_port)

                if success:
                    print(f"🌐 HTTP configurado para: {domain}")
                else:
                    print(f"❌ Falha ao configurar HTTP para: {domain}")

            except Exception as e:
                print(f"❌ Erro ao configurar HTTP para {domain}: {e}")

    def update_nginx_config_http(self, domain, http_port=80):
        """Atualiza configuração do Nginx para um domínio APENAS HTTP (sem SSL)"""
        print(f"🔧 Iniciando configuração Nginx HTTP para: {domain}")

        # ESTRUTURA PADRÃO: sites-available e sites-enabled
        sites_available_dir = "/etc/nginx/sites-available"
        sites_enabled_dir = "/etc/nginx/sites-enabled"
        os.makedirs(sites_available_dir, exist_ok=True)
        os.makedirs(sites_enabled_dir, exist_ok=True)

        # Verificar se o domínio existe nos registros
        if domain.lower() not in self.records:
            print(f"❌ Domínio {domain} não encontrado nos registros DNS")
            return False

        ip = self.records[domain.lower()]
        print(f"📡 Configurando {domain} → {ip}:{http_port} (HTTP ONLY)")

        # Template para configuração HTTP ONLY
        config_content = f"""server {{
    listen {http_port};
    server_name {domain};

    location / {{
        proxy_pass http://{ip}:{http_port};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Configurações adicionais para melhor compatibilidade
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }}
}}
"""

        # ESTRUTURA PADRÃO: criar em sites-available e ativar em sites-enabled
        config_file_available = f"{sites_available_dir}/{domain.replace('.', '_')}.conf"
        config_file_enabled = f"{sites_enabled_dir}/{domain.replace('.', '_')}.conf"

        # Salvar em sites-available
        try:
            with open(config_file_available, "w") as f:
                f.write(config_content)
            print(f"💾 Configuração HTTP salva em: {config_file_available}")
        except Exception as e:
            print(f"❌ Erro ao salvar configuração HTTP: {e}")
            return False

        # Criar symlink em sites-enabled (estrutura padrão)
        try:
            if os.path.exists(config_file_enabled):
                os.remove(config_file_enabled)
                print(f"🗑️  Removido link anterior: {config_file_enabled}")

            os.symlink(config_file_available, config_file_enabled)
            print(f"🔗 Link criado: {config_file_enabled} → {config_file_available}")
        except Exception as e:
            print(f"❌ Erro ao criar symlink: {e}")
            return False

        print(f"✅ Site HTTP configurado: {domain}")
        print(f"   - IP: {ip}")
        print(f"   - HTTP Port: {http_port}")

        return self.test_and_reload_nginx()

    def generate_ssl_certificate(self, domain):
        """Gera certificado SSL INDIVIDUAL para cada domínio"""
        cert_dir = "/etc/nginx/ssl"
        os.makedirs(cert_dir, exist_ok=True)

        # Nomes de arquivo específicos do domínio
        cert_file = f"{cert_dir}/{domain}.crt"
        key_file = f"{cert_dir}/{domain}.key"

        # Só gera se não existir
        if not os.path.exists(cert_file):
            print(f"🔐 Gerando certificado SSL para {domain}...")
            try:
                # Criar CA própria se não existir
                ca_cert = f"{cert_dir}/ca.crt"
                ca_key = f"{cert_dir}/ca.key"

                if not os.path.exists(ca_cert):
                    print("🏛️  Criando Autoridade Certificadora local...")
                    ca_config = self.load_ca_config()

                    # Gerar chave privada da CA
                    subprocess.run([
                        "openssl", "genrsa", "-out", ca_key, "2048"
                    ], check=True, capture_output=True, timeout=30)

                    # Construir subject da CA com configurações customizadas
                    ca_subject = f"/CN={ca_config['common_name']}/O={ca_config['organization']}"
                    if ca_config.get('organizational_unit'):
                        ca_subject += f"/OU={ca_config['organizational_unit']}"
                    if ca_config.get('country'):
                        ca_subject += f"/C={ca_config['country']}"

                    # Gerar certificado da CA
                    subprocess.run([
                        "openssl", "req", "-x509", "-new", "-nodes", "-key", ca_key,
                        "-sha256", "-days", str(ca_config.get('validity_days', 3650)),
                        "-out", ca_cert,
                        "-subj", ca_subject
                    ], check=True, capture_output=True, timeout=30)
                    print("✅ Autoridade Certificadora criada")

                # Gerar chave privada do domínio
                subprocess.run([
                    "openssl", "genrsa", "-out", key_file, "2048"
                ], check=True, capture_output=True, timeout=30)

                # Criar CSR (Certificate Signing Request)
                csr_file = f"{cert_dir}/{domain}.csr"
                ca_config = self.load_ca_config()

                # Usar configurações da CA para o certificado do domínio
                domain_subject = f"/CN={domain}/O={ca_config['organization']}"
                if ca_config.get('organizational_unit'):
                    domain_subject += f"/OU={ca_config['organizational_unit']}"
                if ca_config.get('country'):
                    domain_subject += f"/C={ca_config['country']}"

                subprocess.run([
                    "openssl", "req", "-new", "-key", key_file, "-out", csr_file,
                    "-subj", domain_subject
                ], check=True, capture_output=True, timeout=30)

                # Assinar certificado com a CA
                subprocess.run([
                    "openssl", "x509", "-req", "-in", csr_file, "-CA", ca_cert,
                    "-CAkey", ca_key, "-CAcreateserial", "-out", cert_file,
                    "-days", "365", "-sha256"
                ], check=True, capture_output=True, timeout=30)

                # Limpar arquivos temporários
                if os.path.exists(csr_file):
                    os.remove(csr_file)

                print(f"✅ Certificado assinado gerado: {cert_file}")

            except subprocess.CalledProcessError as e:
                print(f"❌ Erro ao gerar certificado: {e.stderr}")
                # Fallback para certificado padrão
                cert_file = "/etc/nginx/ssl/cert.pem"
                key_file = "/etc/nginx/ssl/key.pem"
                print(f"🔄 Usando certificado padrão: {cert_file}")

        return cert_file, key_file
    
    def update_nginx_config(self, domain, ssl_port=443, http_port=80, cert_file=None, key_file=None):
        """Atualiza configuração do Nginx para um domínio com certificados específicos"""
        print(f"🔧 Iniciando configuração Nginx para: {domain}")
        
        # ESTRUTURA PADRÃO: sites-available e sites-enabled
        sites_available_dir = "/etc/nginx/sites-available"
        sites_enabled_dir = "/etc/nginx/sites-enabled"
        os.makedirs(sites_available_dir, exist_ok=True)
        os.makedirs(sites_enabled_dir, exist_ok=True)

        # Verificar se o domínio existe nos registros
        if domain.lower() not in self.records:
            print(f"❌ Domínio {domain} não encontrado nos registros DNS")
            return False

        ip = self.records[domain.lower()]
        print(f"📡 Configurando {domain} → {ip}:{http_port} (SSL: {ssl_port})")

        # Usar certificados específicos ou fallback
        if not cert_file or not key_file:
            cert_file = "/etc/nginx/ssl/cert.pem"
            key_file = "/etc/nginx/ssl/key.pem"
            print("⚠️  Usando certificado padrão (fallback)")

        # Usar template padrão
        template_file = "/app/nginx/templates/server_template.conf"
        custom_template = None

        if os.path.exists(template_file):
            try:
                with open(template_file, "r") as f:
                    custom_template = f.read()
                print(f"📄 Usando template: {template_file}")
            except Exception as e:
                print(f"⚠️ Erro ao ler template {template_file}: {e}")

        # Template fallback CORRIGIDO - HTTPS sempre na porta 443
        if not custom_template:
            custom_template = """
server {
    listen 80;
    server_name domain;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl;
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

        # Configurações adicionais para melhor compatibilidade
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_ssl_verify off;
    }
}
"""
            print("📄 Usando template integrado")

        # APLICAÇÃO CORRIGIDA das variáveis - substituindo placeholders simples
        config_content = custom_template.replace('domain', domain) \
                                       .replace('ip', ip) \
                                       .replace('http_port', str(http_port)) \
                                       .replace('ssl_port', str(ssl_port)) \
                                       .replace('cert_file', cert_file) \
                                       .replace('key_file', key_file)
        
        # ESTRUTURA PADRÃO: criar em sites-available e ativar em sites-enabled
        config_file_available = f"{sites_available_dir}/{domain.replace('.', '_')}.conf"
        config_file_enabled = f"{sites_enabled_dir}/{domain.replace('.', '_')}.conf"
        
        # Salvar em sites-available
        try:
            with open(config_file_available, "w") as f:
                f.write(config_content)
            print(f"💾 Configuração salva em: {config_file_available}")
        except Exception as e:
            print(f"❌ Erro ao salvar configuração: {e}")
            return False
        
        # Criar symlink em sites-enabled (estrutura padrão)
        try:
            if os.path.exists(config_file_enabled):
                os.remove(config_file_enabled)
                print(f"🗑️  Removido link anterior: {config_file_enabled}")
            
            os.symlink(config_file_available, config_file_enabled)
            print(f"🔗 Link criado: {config_file_enabled} → {config_file_available}")
        except Exception as e:
            print(f"❌ Erro ao criar symlink: {e}")
            return False
        
        print(f"✅ Site configurado: {domain}")
        print(f"   - IP: {ip}")
        print(f"   - HTTP Port: {http_port}")
        print(f"   - HTTPS Port: {ssl_port}")
        print(f"   - Certificado: {cert_file}")
        print(f"   - Chave: {key_file}")
        
        return self.test_and_reload_nginx()

    def test_and_reload_nginx(self):
        """Testa e recarrega a configuração do Nginx"""
        try:
            # Testar configuração primeiro
            result = subprocess.run(["nginx", "-t"], capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                print(f"❌ Erro na configuração Nginx: {result.stderr}")
                return False

            print("✅ Configuração Nginx válida")

            # Verificar se Nginx está rodando antes de tentar recarregar
            check_result = subprocess.run(["pgrep", "nginx"], capture_output=True, timeout=5)
            if check_result.returncode != 0:
                print("⚠️ Nginx não está rodando, pulando reload")
                return True

            # Recarregar Nginx
            reload_result = subprocess.run(["nginx", "-s", "reload"], capture_output=True, text=True, timeout=60)
            if reload_result.returncode == 0:
                print("🔄 Nginx recarregado com sucesso")
                return True
            else:
                print(f"⚠️ Erro ao recarregar Nginx: {reload_result.stderr}")
                return False

        except subprocess.TimeoutExpired:
            print("⏰ Timeout ao testar/recarregar Nginx")
            return False
        except Exception as e:
            print(f"❌ Erro ao testar Nginx: {e}")
            return False
        
    def reload_nginx(self):
        """Recarrega configuração do Nginx"""
        try:
            # Verifica se nginx está rodando
            result = subprocess.run(["pgrep", "nginx"], capture_output=True, timeout=5)
            if result.returncode == 0:
                # Testa configuração antes de recarregar
                test_result = subprocess.run(["nginx", "-t"], capture_output=True, text=True, timeout=30)
                if test_result.returncode == 0:
                    subprocess.run(["nginx", "-s", "reload"], check=True, timeout=60)
                    print("🔄 Nginx recarregado")
                else:
                    print(f"⚠️ Configuração Nginx inválida, pulando reload: {test_result.stderr}")
            else:
                print("⚠️  Nginx não está rodando")
        except subprocess.TimeoutExpired:
            print("⏰ Timeout ao recarregar Nginx")
        except Exception as e:
            print(f"❌ Erro ao recarregar Nginx: {e}")

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

        # Se está DESABILITANDO SSL, remove certificados automaticamente
        if ssl_enabled is False and config.get("ssl_enabled", {}).get(domain_lower, False):
            self.cleanup_ssl_certificates(domain)
            print(f"🧹 Certificados SSL removidos para: {domain}")

        if ssl_enabled is not None:
            config["ssl_enabled"][domain_lower] = ssl_enabled
            # Configura Nginx IMEDIATAMENTE independente do SSL
            if ssl_enabled:
                print(f"🚀 Configurando SSL para: {domain}")
                self.configure_nginx_ssl(domain, ssl_port or 443, http_port or 80)
            else:
                print(f"🌐 Configurando HTTP para: {domain}")
                self.configure_nginx_http(domain, http_port or 80)

        if ssl_port is not None:
            config["ssl_ports"][domain_lower] = ssl_port

        if http_port is not None:
            config["http_ports"][domain_lower] = http_port

        self.save_full_config(config)

        # Recarrega Nginx após salvar configurações apenas se SSL foi alterado
        if ssl_enabled is not None:
            time.sleep(1)  # Pequena pausa para garantir que tudo foi salvo
            self.reload_nginx()

        return True

    def cleanup_ssl_certificates(self, domain):
        """Remove certificados SSL de um domínio específico"""
        cert_dir = "/etc/nginx/ssl"
        domain_lower = domain.lower()

        # Arquivos a remover
        files_to_remove = [
            f"{cert_dir}/{domain_lower}.crt",
            f"{cert_dir}/{domain_lower}.key",
            f"{cert_dir}/{domain_lower}.csr"
        ]

        for file_path in files_to_remove:
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                    print(f"🗑️ Removido: {file_path}")
                except Exception as e:
                    print(f"⚠️ Erro ao remover {file_path}: {e}")

    def cleanup_domain_ssl(self, domain):
        """Remove todos os arquivos SSL/HTTP relacionados a um domínio (usado na remoção completa)"""
        cert_dir = "/etc/nginx/ssl"
        sites_available = "/etc/nginx/sites-available"
        sites_enabled = "/etc/nginx/sites-enabled"

        domain_lower = domain.lower()
        domain_filename = domain_lower.replace('.', '_')

        # Remove certificados
        self.cleanup_ssl_certificates(domain)

        # Remove configurações Nginx (tanto SSL quanto HTTP)
        nginx_files = [
            f"{sites_available}/{domain_filename}.conf",
            f"{sites_enabled}/{domain_filename}.conf"
        ]

        for file_path in nginx_files:
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                    print(f"🗑️ Removido configuração Nginx: {file_path}")
                except Exception as e:
                    print(f"⚠️ Erro ao remover {file_path}: {e}")

    def get_ca_certificate_info(self):
        """Retorna informações do certificado da CA"""
        ca_cert_path = "/etc/nginx/ssl/ca.crt"
        if not os.path.exists(ca_cert_path):
            return None

        try:
            # Usar openssl para obter informações do certificado
            result = subprocess.run([
                "openssl", "x509", "-in", ca_cert_path, "-text", "-noout"
            ], capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                cert_text = result.stdout

                # Extrair informações básicas
                info = {}

                # Subject
                subject_match = re.search(r'Subject: (.+)', cert_text)
                if subject_match:
                    info['subject'] = subject_match.group(1).strip()

                # Issuer
                issuer_match = re.search(r'Issuer: (.+)', cert_text)
                if issuer_match:
                    info['issuer'] = issuer_match.group(1).strip()

                # Validity
                not_before_match = re.search(r'Not Before: (.+)', cert_text)
                not_after_match = re.search(r'Not After : (.+)', cert_text)
                if not_before_match:
                    info['not_before'] = not_before_match.group(1).strip()
                if not_after_match:
                    info['not_after'] = not_after_match.group(1).strip()

                # Serial Number
                serial_match = re.search(r'Serial Number:\s*([0-9A-Fa-f:]+)', cert_text)
                if serial_match:
                    info['serial'] = serial_match.group(1).strip()

                # Public Key
                pubkey_match = re.search(r'Public-Key: \(([0-9]+) bit\)', cert_text)
                if pubkey_match:
                    info['public_key_bits'] = pubkey_match.group(1)

                return info

        except Exception as e:
            print(f"Erro ao obter informações do certificado CA: {e}")

        return None

    def regenerate_ca_certificate(self):
        """Regenera o certificado da CA com as novas configurações"""
        cert_dir = "/etc/nginx/ssl"
        ca_cert = f"{cert_dir}/ca.crt"
        ca_key = f"{cert_dir}/ca.key"

        try:
            # Backup do certificado antigo
            if os.path.exists(ca_cert):
                backup_file = f"{ca_cert}.backup.{int(time.time())}"
                import shutil
                shutil.copy2(ca_cert, backup_file)
                print(f"📋 Backup do certificado antigo criado: {backup_file}")

            # Remover certificado antigo
            if os.path.exists(ca_cert):
                os.remove(ca_cert)

            # A CA será recriada automaticamente na próxima geração de certificado
            print("✅ Certificado CA será regenerado na próxima emissão")
            return True

        except Exception as e:
            print(f"❌ Erro ao regenerar certificado CA: {e}")
            return False

    def cleanup_orphaned_files(self):
        """Remove arquivos órfãos: certificados SSL e configurações Nginx não correspondentes a domínios ativos"""
        print("🧹 Iniciando limpeza de arquivos órfãos...")

        # Carregar domínios ativos
        config = self.get_full_config()
        active_domains = set(config.get("hosts", {}).keys())
        active_domains_lower = {domain.lower() for domain in active_domains}

        # Arquivos protegidos (não remover)
        protected_files = {"ca.crt", "ca.key", "cert.pem", "key.pem"}

        # 1. Limpar certificados SSL órfãos
        cert_dir = "/etc/nginx/ssl"
        if os.path.exists(cert_dir):
            print("🔍 Verificando certificados SSL...")
            for filename in os.listdir(cert_dir):
                if filename in protected_files:
                    continue  # Preservar arquivos da CA e certificados padrão

                # Verificar se é certificado de domínio (formato: dominio.crt, dominio.key)
                if filename.endswith('.crt') or filename.endswith('.key') or filename.endswith('.csr'):
                    # Extrair nome do domínio do filename
                    domain_name = filename.rsplit('.', 1)[0]  # Remove extensão

                    # Verificar se domínio ainda existe
                    if domain_name.lower() not in active_domains_lower:
                        file_path = os.path.join(cert_dir, filename)
                        try:
                            os.remove(file_path)
                            print(f"🗑️ Certificado órfão removido: {filename}")
                        except Exception as e:
                            print(f"⚠️ Erro ao remover certificado {filename}: {e}")

        # 2. Limpar configurações Nginx órfãs
        sites_available_dir = "/etc/nginx/sites-available"
        sites_enabled_dir = "/etc/nginx/sites-enabled"

        for directory in [sites_available_dir, sites_enabled_dir]:
            if os.path.exists(directory):
                print(f"🔍 Verificando configurações em {directory}...")
                for filename in os.listdir(directory):
                    if filename.endswith('.conf'):
                        # Extrair nome do domínio do filename (formato: dominio_com_br.conf)
                        domain_name = filename.replace('_', '.').replace('.conf', '')

                        # Verificar se domínio ainda existe
                        if domain_name.lower() not in active_domains_lower:
                            file_path = os.path.join(directory, filename)
                            try:
                                os.remove(file_path)
                                print(f"🗑️ Configuração Nginx órfã removida: {filename}")
                            except Exception as e:
                                print(f"⚠️ Erro ao remover configuração {filename}: {e}")

        print("✅ Limpeza de arquivos órfãos concluída")
        return True

    def resolve(self, request, handler):
        qname = str(request.q.qname).rstrip('.').lower()
        qtype = request.q.qtype
        reply = request.reply()

        # Debug: mostrar queries para domínios locais
        if any(local_domain in qname for local_domain in ['dns-server', 'homolog', 'dev', 'publicacao']):
            print(f"[DEBUG] Query LOCAL recebida: {qname} (type: {qtype})")

        # PTR records para reverse DNS (mostrar nome do servidor no nslookup)
        if qtype == 12:  # PTR record
            # Carregar nome do servidor da configuração
            server_hostname = "dns-server.local"
            dns_config_file = "/app/data/dns_config.json"
            if os.path.exists(dns_config_file):
                with open(dns_config_file, "r") as f:
                    dns_config = json.load(f)
                    server_hostname = dns_config.get("server_hostname", "dns-server.local")

            # Mapeamento IP -> Nome para o servidor DNS
            ptr_records = {
                "100.4.168.192.in-addr.arpa": server_hostname,
                "192.168.4.100": server_hostname
            }

            if qname in ptr_records:
                reply.add_answer(RR(qname, qtype, rdata=PTR(ptr_records[qname]), ttl=60))
                print(f"[PTR] {qname} → {ptr_records[qname]}")
                return reply

        # Resposta para consultas TXT com informações SSL
        if qtype == 16:  # TXT record
            ssl_info = self.get_ssl_info(qname)
            if ssl_info["ssl_enabled"]:
                txt_data = f"ssl_enabled=true;ssl_port={ssl_info['ssl_port']};http_port={ssl_info['http_port']}"
                reply.add_answer(RR(qname, qtype, rdata=TXT(txt_data), ttl=60))
                print(f"[SSL-INFO] {qname} → {txt_data}")
                return reply

        # Verificar se é registro local - SEM LOCK para evitar problemas de concorrência
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

        # Debug para queries não locais
        if any(local_domain in qname for local_domain in ['dns-server', 'homolog', 'dev', 'publicacao']):
            print(f"[DEBUG] {qname} não encontrado localmente, indo para upstream")

        # Consulta externa (proxy recursivo) - APENAS se não for local
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

    def ensure_nginx_config(self, domain):
        """Garante que a configuração Nginx existe para o domínio"""
        domain_lower = domain.lower()
        if domain_lower in self.records:
            ssl_info = self.get_ssl_info(domain)
            print(f"🔧 Verificando configuração Nginx para: {domain}")
            if ssl_info["ssl_enabled"]:
                self.configure_nginx_ssl(domain, ssl_info["ssl_port"], ssl_info["http_port"])
            else:
                self.configure_nginx_http(domain, ssl_info["http_port"])

def start_dns_server(resolver):
    logger = DNSLogger(prefix=False)
    server = DNSServer(resolver, port=53, address="0.0.0.0", logger=logger)
    print("✅ Servidor DNS iniciado em 0.0.0.0:53")
    print("   - Suporte a registros SSL/TXT para hosts locais")
    server.start_thread()

    # Adicionar PTR record para o servidor DNS (reverse DNS)
    import socket
    hostname = socket.gethostname()
    try:
        # Tentar obter IP do hostname
        ip_addr = socket.gethostbyname(hostname)
        print(f"📋 PTR record configurado: {ip_addr} → {hostname}")
    except Exception as e:
        print(f"⚠️ Não foi possível configurar PTR record: {e}")

def health_monitor(resolver):
    print("🩺 Monitor de saúde iniciado (a cada 30s)")
    while True:
        time.sleep(30)
        print("\n" + "═" * 80)
        config = resolver.get_full_config()
        
        for domain, ip in config.get("hosts", {}).items():
            # Teste de conectividade
            cmd = ["ping", "-c", "1", "-W", "2", ip]
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