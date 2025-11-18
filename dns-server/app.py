from flask import Flask, render_template, request, redirect, flash, url_for, session, jsonify, send_file
import threading, subprocess, json, os, time, bcrypt, re, ipaddress
from functools import wraps
import sys
import logging

# Adiciona o diretório atual ao path
sys.path.append('/app')

# CONFIGURAÇÃO CORRIGIDA DO TEMPLATE FOLDER
template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')

app = Flask(__name__,
            template_folder=template_dir,
            static_folder=static_dir)
app.secret_key = os.urandom(24)
SESSION_TIMEOUT = 600  # 10 minutos

# Log de diagnóstico
print(f"🔧 Configurando Flask...")
print(f"📁 Template folder: {app.template_folder}")
print(f"📁 Static folder: {app.static_folder}")
print(f"📁 Templates existem: {os.path.exists(app.template_folder)}")
if os.path.exists(app.template_folder):
    print(f"📁 Arquivos templates: {os.listdir(app.template_folder)}")

# Caminho absoluto para o arquivo de dados
DATA_DIR = "/app/data"
USERS_FILE = os.path.join(DATA_DIR, "users.json")
HOSTS_FILE = os.path.join(DATA_DIR, "hosts.json")

# Garante que o diretório data existe
os.makedirs(DATA_DIR, exist_ok=True)

# Inicializa resolver DNS
print("🚀 Iniciando servidor DNS...")

# Importa e inicia o DNS server
from dns_server import CustomResolver, start_dns_server, health_monitor

print("🔄 Aplicando correção de inicialização do resolver...")
resolver = CustomResolver()
print("✅ DNS Server inicializado")

# Inicia DNS e monitor em background
threading.Thread(target=start_dns_server, args=(resolver,), daemon=True).start()
threading.Thread(target=health_monitor, args=(resolver,), daemon=True).start()
print("✅ Servidor DNS iniciado com sucesso!")

USERS_FILE = os.path.join("data", "users.json")
os.makedirs("data", exist_ok=True)
os.makedirs("static/css", exist_ok=True)

# -----------------------------
# Funções auxiliares
# -----------------------------
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)  # Oculta logs do Werkzeug

@app.after_request
def after_request(response):
    """Oculta logs 400 de handshake SSL"""
    if response.status_code == 400 and 'Bad request version' in response.description:
        return response
    return response

def load_users():
    if not os.path.exists(USERS_FILE):
        # Cria admin padrão com senha hash
        admin_pass = bcrypt.hashpw("admin123".encode(), bcrypt.gensalt()).decode()
        users = {"admin": {"password": admin_pass, "is_admin": True}}
        with open(USERS_FILE, "w") as f:
            json.dump(users, f, indent=2)
    with open(USERS_FILE) as f:
        users = json.load(f)

    # Atualiza senhas não-hash automaticamente
    changed = False
    for user, data in users.items():
        pwd = data["password"]
        if not pwd.startswith("$2b$"):  # não é hash bcrypt
            hashed = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt()).decode()
            users[user]["password"] = hashed
            changed = True
    if changed:
        save_users(users)
    return users

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)

print("🔄 Aplicando correção de inicialização do resolver...")
resolver = CustomResolver()
print("✅ Resolver inicializado com sucesso")

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = session.get("user")
        last_activity = session.get("last_activity")
        now = time.time()
        if not user or not last_activity or now - last_activity > SESSION_TIMEOUT:
            session.clear()
            flash("Sessão expirada. Faça login novamente.", "danger")
            return redirect(url_for("login"))
        session["last_activity"] = now
        return f(*args, **kwargs)
    return wrapper

def validate_domain(domain):
    """Valida formato do domínio"""
    # Permite letras, números, hífens, underscores e pontos
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9_.-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9_.-]{0,61}[a-zA-Z0-9])?)*$'
    return bool(re.match(pattern, domain)) and len(domain) <= 253

def validate_ip(ip):
    """Valida IP e verifica se é privado"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        # Aceita IPs privados:
        # - 192.168.0.0/16
        # - 10.0.0.0/8
        # - 172.16.0.0/12
        return ip_obj.is_private
    except ValueError:
        return False

def sanitize_input(text):
    """Remove caracteres potencialmente perigosos, mantendo hífens e underscores"""
    return re.sub(r'[^\w\.\-_]', '', text.strip())

# -----------------------------
# Rotas de autenticação
# -----------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = sanitize_input(request.form["username"]).lower()
        password = request.form["password"].strip().encode()
        users = load_users()

        if username in users:
            stored_hash = users[username]["password"].encode()
            if bcrypt.checkpw(password, stored_hash):
                session["user"] = username
                session["is_admin"] = users[username].get("is_admin", False)
                session["last_activity"] = time.time()
                # Remover mensagem de boas-vindas fixa, manter apenas popups temporários
                return redirect(url_for("index"))

        flash("Usuário ou senha incorretos.", "danger")
    return render_template("login.html")

@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    flash("Você saiu da sessão.", "success")
    return redirect(url_for("login"))

# -----------------------------
# Painel principal
# -----------------------------
@app.route("/")
@login_required
def index():
    if not hasattr(resolver, "records") or resolver.records is None:
        resolver.records = {}

    edit_domain = request.args.get("edit")
    current_ip = resolver.records.get(edit_domain, "") if edit_domain else ""

    # 🔍 Gera as infos de SSL uma única vez
    ssl_status = {}
    for domain, ip in resolver.records.items():
        try:
            info = resolver.get_ssl_info(domain)
        except Exception as e:
            info = {"ssl_enabled": False, "ssl_port": 443, "http_port": 80, "error": str(e)}
        ssl_status[domain] = info

    # Ordenação inteligente: agrupa por domínio base e depois por IP
    def sort_records(records):
        grouped = {}
        for domain, ip in records:
            # Extrair base do domínio (antes do primeiro '_' ou mantendo se não houver)
            base = domain.split('_')[0] if '_' in domain else domain
            if base not in grouped:
                grouped[base] = []
            grouped[base].append((domain, ip))

        # Ordenar dentro de cada grupo por domínio completo
        sorted_groups = []
        for base in sorted(grouped.keys()):
            sorted_groups.extend(sorted(grouped[base]))

        print(f"🔄 Ordenação aplicada: {len(sorted_groups)} registros agrupados por domínio")
        return sorted_groups

    response = render_template(
        "index.html",
        user=session["user"],
        is_admin=session.get("is_admin", False),
        records=sort_records(resolver.records.items()),
        edit_domain=edit_domain,
        current_ip=current_ip,
        ssl_status=ssl_status
    )

    # Forçar headers para evitar cache
    from flask import make_response
    response = make_response(response)
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# -----------------------------
# Rotas de CRUD DNS - CORRIGIDAS
# -----------------------------
@app.route("/add", methods=["POST"])
@login_required
def add():
    print("🔄 DEBUG: Iniciando rota /add")
    try:
        print("🔍 DEBUG: Recebendo dados do formulário...")
        # Verificar se os campos existem
        domain_raw = request.form.get("domain", "").strip()
        ip_raw = request.form.get("ip", "").strip()

        print(f"🔍 DEBUG: domain_raw='{domain_raw}' (len={len(domain_raw)})")
        print(f"🔍 DEBUG: ip_raw='{ip_raw}' (len={len(ip_raw)})")

        # Validações básicas primeiro (rápidas)
        if not domain_raw or not ip_raw:
            print("❌ DEBUG: Campos obrigatórios vazios")
            flash("Domínio e IP são obrigatórios.", "danger")
            return redirect("/")

        print("🔍 DEBUG: Sanitizando dados...")
        # Sanitizar e validar domínio
        domain = sanitize_input(domain_raw).lower()
        print(f"🔍 DEBUG: domain_sanitized='{domain}' (len={len(domain)})")

        if not domain or not validate_domain(domain):
            print(f"❌ DEBUG: validate_domain('{domain}') = {validate_domain(domain)}")
            flash("Domínio inválido. Use apenas letras, números, hífens, underscores e pontos.", "danger")
            return redirect("/")

        # Sanitizar e validar IP
        ip = sanitize_input(ip_raw)
        print(f"🔍 DEBUG: ip_sanitized='{ip}' (len={len(ip)})")

        if not ip or not validate_ip(ip):
            print(f"❌ DEBUG: validate_ip('{ip}') = {validate_ip(ip)}")
            flash("IP inválido. Use apenas IPs privados (192.168.x.x, 10.x.x.x, 172.16-31.x.x).", "danger")
            return redirect("/")

        ssl_enabled = request.form.get("ssl_enabled") == "on"
        ssl_port = int(request.form.get("ssl_port", 443))
        http_port = int(request.form.get("http_port", 80))

        print(f"📝 DEBUG: Dados finais - domain: '{domain}', ip: '{ip}', ssl: {ssl_enabled}")

        # Se o domínio já existe, permite sobrescrever (corrige o problema de timeout)
        print(f"🔍 DEBUG: Verificando se domínio existe: {domain in resolver.records}")
        domain_exists = domain in resolver.records
        if domain_exists:
            print(f"⚠️ DEBUG: Domínio já existe, sobrescrevendo: {domain}")
            # Remove configurações antigas antes de sobrescrever
            config = resolver.get_full_config()
            for key in ['ssl_enabled', 'ssl_ports', 'http_ports']:
                if key in config and domain in config[key]:
                    del config[key][domain]
            resolver.save_full_config(config)

        print(f"🔍 DEBUG: Registros antes: {len(resolver.records)}")

        # RESPOSTA ULTRA-RÁPIDA: Apenas salva no arquivo JSON (sempre funciona)
        print("🔍 DEBUG: Salvando diretamente no arquivo JSON...")
        try:
            config = resolver.get_full_config()
            config["hosts"][domain.lower()] = ip
            config["ssl_enabled"][domain.lower()] = ssl_enabled
            config["ssl_ports"][domain.lower()] = ssl_port
            config["http_ports"][domain.lower()] = http_port
            resolver.save_full_config(config)

            # Atualiza o resolver em memória também
            resolver.records[domain.lower()] = ip
            print(f"✅ DEBUG: Host adicionado diretamente - registros agora: {len(resolver.records)}")
            print(f"✅ DEBUG: Verificação - domínio no records: {domain in resolver.records}")
        except Exception as e:
            print(f"❌ DEBUG: Erro ao salvar: {type(e).__name__}: {e}")
            flash(f"Erro ao adicionar registro: {e}", "danger")
            return redirect("/")

        # Configuração SSL assíncrona (não bloqueia)
        if ssl_enabled:
            def configure_ssl_bg():
                try:
                    print(f"🔒 CONFIG SSL BG: Iniciando configuração SSL para {domain}")
                    resolver.configure_nginx_ssl(domain, ssl_port, http_port)
                    print(f"✅ CONFIG SSL BG: SSL configurado com sucesso para {domain}")
                except Exception as e:
                    print(f"❌ CONFIG SSL BG: Erro ao configurar SSL para {domain}: {e}")

            print("🔍 DEBUG: Iniciando configuração SSL em background...")
            threading.Thread(target=configure_ssl_bg, daemon=True).start()

        # Verifica conectividade em background (não bloqueia a resposta)
        def check_connectivity_bg():
            try:
                ping_result = subprocess.run(
                    ["ping", "-c", "1", "-W", "2", ip],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5
                )
                if ping_result.returncode == 0:
                    status = " (SSL)" if ssl_enabled else ""
                    print(f"📡 DEBUG BG: Ping para {ip}: ONLINE{status}")
                else:
                    print(f"📡 DEBUG BG: Ping para {ip}: OFFLINE")
            except Exception as e:
                print(f"📡 DEBUG BG: Ping falhou para {ip}: {e}")

        # Inicia verificação em background
        print("🔍 DEBUG: Iniciando thread de ping em background...")
        threading.Thread(target=check_connectivity_bg, daemon=True).start()

        # RESPOSTA IMEDIATA (não espera nada)
        print("🔍 DEBUG: Preparando resposta...")
        status = " (SSL)" if ssl_enabled else ""
        action = "Atualizado" if domain_exists else "Adicionado"
        flash(f"{action}{status}: {domain} → {ip}", "success")

        print("🚀 DEBUG: Criando redirect...")
        try:
            response = redirect("/")
            print("🚀 DEBUG: Redirect criado com sucesso")
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
            print("🚀 DEBUG: Headers adicionados, retornando resposta...")
            return response
        except Exception as e:
            print(f"🚀 DEBUG: ERRO no redirect: {type(e).__name__}: {e}")
            import traceback
            print(f"📋 DEBUG TRACE REDIRECT:\n{traceback.format_exc()}")
            raise

    except Exception as e:
        print(f"❌ DEBUG: ERRO CRÍTICO GERAL: {type(e).__name__}: {e}")
        import traceback
        print(f"📋 DEBUG TRACE COMPLETO:\n{traceback.format_exc()}")
        flash(f"Erro crítico: {e}", "danger")
        try:
            return redirect("/")
        except:
            return "Erro interno", 500

    except Exception as e:
        print(f"❌ DEBUG: ERRO CRÍTICO: {type(e).__name__}: {e}")
        import traceback
        print(f"📋 DEBUG TRACE COMPLETO:\n{traceback.format_exc()}")
        flash(f"Erro ao adicionar registro: {e}", "danger")
        try:
            return redirect("/")
        except:
            return "Erro interno", 500

# Adicione esta rota para configuração SSL
@app.route("/ssl/<domain>", methods=["GET", "POST"])
@login_required
def ssl_config(domain):
    if domain not in resolver.records:
        flash("Domínio não encontrado.", "danger")
        return redirect("/")

    ssl_info = resolver.get_ssl_info(domain)

    if request.method == "POST":
        try:
            ssl_enabled = request.form.get("ssl_enabled") == "on"
            ssl_port = int(request.form.get("ssl_port", 443))
            http_port = int(request.form.get("http_port", 80))

            # Força a reconfiguração do Nginx
            if ssl_enabled:
                print(f"🔧 Reconfigurando Nginx para: {domain}")
                resolver.configure_nginx_ssl(domain, ssl_port, http_port)

            if resolver.update_ssl_config(domain,
                                        ssl_enabled=ssl_enabled,
                                        ssl_port=ssl_port,
                                        http_port=http_port):
                status = "habilitado" if ssl_enabled else "desabilitado"
                flash(f"Configuração SSL para {domain} {status} com sucesso!", "success")

                # Recarrega Nginx
                time.sleep(1)
                resolver.reload_nginx()

            else:
                flash("Erro ao atualizar configuração SSL.", "danger")
        except Exception as e:
            flash(f"Erro ao atualizar SSL: {e}", "danger")

        return redirect("/")

    return render_template("ssl_config.html",
                          domain=domain,
                          ip=resolver.records[domain],
                          ssl_info=ssl_info,
                          user=session["user"],
                          is_admin=session.get("is_admin", False))

# Rota para editar DOMÍNIO (não apenas IP) - CORRIGIDA
@app.route("/edit/<domain>")
@login_required
def edit(domain):
    if domain in resolver.records:
        return redirect(url_for("index", edit=domain))
    flash("Domínio não encontrado.", "danger")
    return redirect("/")

@app.route("/update/<old_domain>", methods=["POST"])
@login_required
def update(old_domain):
    print(f"🔄 Iniciando atualização de domínio: {old_domain}")
    try:
        # Verificar se os campos existem no formulário
        new_domain = request.form.get("new_domain", "").strip()
        new_ip = request.form.get("new_ip", "").strip()

        print(f"📝 Dados RAW recebidos - new_domain: '{new_domain}', new_ip: '{new_ip}'")

        # Sanitizar os inputs
        new_domain = sanitize_input(new_domain).lower() if new_domain else ""
        new_ip = sanitize_input(new_ip)

        print(f"📝 Dados sanitizados - Domínio: '{new_domain}', IP: '{new_ip}'")

        if not new_ip:
            print("❌ IP é obrigatório")
            flash("IP é obrigatório.", "danger")
            return redirect("/")

        if not validate_ip(new_ip):
            print(f"❌ IP inválido: {new_ip}")
            flash("IP inválido. Use apenas IPs privados.", "danger")
            return redirect("/")

        if old_domain not in resolver.records:
            print(f"❌ Domínio não encontrado: {old_domain}")
            flash("Domínio não encontrado.", "danger")
            return redirect("/")

        # Se o domínio foi alterado, verifica se o novo domínio já existe
        if new_domain and new_domain != old_domain:
            if new_domain in resolver.records:
                print(f"❌ Domínio já existe: {new_domain}")
                flash(f"Domínio {new_domain} já existe.", "danger")
                return redirect("/")

        # Verifica se o IP está online
        try:
            ping_result = subprocess.run(
                ["ping", "-c", "1", "-W", "2", new_ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5
            )
            is_online = ping_result.returncode == 0
            print(f"📡 Ping para {new_ip}: {'ONLINE' if is_online else 'OFFLINE'}")
        except subprocess.TimeoutExpired:
            is_online = False
            print(f"⏰ Timeout no ping para {new_ip}")

        ssl_info = resolver.get_ssl_info(old_domain)
        print(f"🔒 SSL info para {old_domain}: {ssl_info}")

        if new_domain and new_domain != old_domain:
            print(f"🔄 Alterando domínio: {old_domain} → {new_domain}")
            # Remover domínio antigo e adicionar novo - TUDO dentro do lock
            try:
                with resolver.lock:
                    del resolver.records[old_domain]
                    print(f"✅ Domínio antigo removido: {old_domain}")

                    # Atualizar configuração completa
                    config = resolver.get_full_config()
                    config["hosts"][new_domain.lower()] = new_ip
                    config["ssl_enabled"][new_domain.lower()] = ssl_info["ssl_enabled"]
                    config["ssl_ports"][new_domain.lower()] = ssl_info["ssl_port"]
                    config["http_ports"][new_domain.lower()] = ssl_info["http_port"]

                    # Remover configurações antigas
                    if old_domain.lower() in config["hosts"]:
                        del config["hosts"][old_domain.lower()]
                    if old_domain.lower() in config["ssl_enabled"]:
                        del config["ssl_enabled"][old_domain.lower()]
                    if old_domain.lower() in config["ssl_ports"]:
                        del config["ssl_ports"][old_domain.lower()]
                    if old_domain.lower() in config["http_ports"]:
                        del config["http_ports"][old_domain.lower()]

                    resolver.save_full_config(config)
                    print(f"✅ Novo domínio adicionado: {new_domain} → {new_ip}")

                msg_prefix = f"{old_domain} → {new_domain} → {new_ip}"
            except Exception as e:
                print(f"❌ Erro ao alterar domínio: {e}")
                flash(f"Erro ao alterar domínio: {e}", "danger")
                return redirect("/")
        else:
            # Apenas atualizar IP - dentro do lock para consistência
            print(f"🔄 Atualizando IP: {old_domain} → {new_ip}")
            try:
                with resolver.lock:
                    resolver.records[old_domain] = new_ip

                    # Atualizar apenas o IP no config completo
                    config = resolver.get_full_config()
                    config["hosts"][old_domain.lower()] = new_ip
                    resolver.save_full_config(config)

                print(f"✅ IP atualizado com sucesso")
                msg_prefix = f"{old_domain} → {new_ip}"
            except Exception as e:
                print(f"❌ Erro ao atualizar IP: {e}")
                flash(f"Erro ao atualizar IP: {e}", "danger")
                return redirect("/")

        if is_online:
            flash(f"✅ Atualizado (online): {msg_prefix}", "success")
        else:
            flash(f"⚠️ IP {new_ip} offline, mas registro atualizado: {msg_prefix}", "warning")

        print(f"✅ Atualização concluída com sucesso: {msg_prefix}")

        # Forçar resposta imediata com headers de no-cache
        response = redirect("/")
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        print("🚀 Redirecionando para página inicial...")
        return response

    except Exception as e:
        print(f"❌ Erro geral na atualização: {e}")
        import traceback
        print(f"📋 Stack trace: {traceback.format_exc()}")
        flash(f"Erro ao atualizar: {e}", "danger")
        return redirect("/")

@app.route("/delete/<domain>", methods=["POST"])
@login_required
def delete_domain(domain):
    print(f"🗑️ Iniciando remoção de domínio: {domain}")
    try:
        if domain in resolver.records:
            removed_ip = resolver.records.pop(domain)
            resolver.save()

            # Limpar configurações órfãs (SSL, ports) para este domínio
            config = resolver.get_full_config()
            domain_keys_to_clean = [
                'ssl_enabled', 'ssl_ports', 'http_ports'
            ]

            for key in domain_keys_to_clean:
                if key in config and domain in config[key]:
                    del config[key][domain]
                    print(f"🧹 Removido {key} para: {domain}")

            resolver.save_full_config(config)

            # LIMPEZA AUTOMÁTICA COMPLETA: certificados SSL + configurações Nginx
            resolver.cleanup_domain_ssl(domain)
            print(f"🧹 Limpeza SSL completa realizada para: {domain}")

            # Recarregar Nginx após limpeza
            resolver.reload_nginx()

            flash(f"Removido: {domain} → {removed_ip}", "danger")
            print(f"✅ Removido com sucesso: {domain} → {removed_ip}")
        else:
            flash("Domínio não encontrado.", "danger")
            print(f"❌ Domínio não encontrado: {domain}")

        print("🚀 Redirecionando após remoção")
        response = redirect("/")
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    except Exception as e:
        print(f"❌ Erro na remoção: {e}")
        flash(f"Erro ao remover domínio: {e}", "danger")
        return redirect("/")

# -----------------------------
# Painel administrativo
# -----------------------------
@app.route("/admin", methods=["GET", "POST"])
@login_required
def admin_panel():
    if not session.get("is_admin"):
        flash("Acesso negado. Somente administrador.", "danger")
        return redirect("/")

    users = load_users()

    if request.method == "POST":
        action = request.form.get("action")
        username = sanitize_input(request.form.get("username", "")).lower()

        if action == "add":
            password = request.form.get("password", "").strip()
            if not username or not password:
                flash("Usuário e senha são obrigatórios.", "danger")
            elif not re.match(r'^[a-zA-Z0-9_-]{3,20}$', username):
                flash("Usuário deve ter 3-20 caracteres (apenas letras, números, _ e -).", "danger")
            elif len(password) < 6:
                flash("A senha deve ter pelo menos 6 caracteres.", "danger")
            elif username in users:
                flash("Usuário já existe.", "danger")
            else:
                hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
                users[username] = {"password": hashed, "is_admin": False}
                save_users(users)
                flash(f"Usuário {username} criado com sucesso.", "success")

        elif action == "delete" and username != "admin":
            if username in users:
                users.pop(username)
                save_users(users)
                flash(f"Usuário {username} removido.", "warning")
            else:
                flash("Usuário não encontrado.", "danger")

        elif action == "reset":
            new_pass = request.form.get("new_password", "").strip()
            if username in users and new_pass:
                if len(new_pass) < 6:
                    flash("A senha deve ter pelo menos 6 caracteres.", "danger")
                else:
                    users[username]["password"] = bcrypt.hashpw(new_pass.encode(), bcrypt.gensalt()).decode()
                    save_users(users)
                    flash(f"Senha de {username} redefinida.", "success")
            else:
                flash("Usuário não encontrado ou senha inválida.", "danger")

    return render_template("admin.html", users=users)

# -----------------------------
# -----------------------------
# Reset Total do Sistema
# -----------------------------
@app.route("/full-restore", methods=["POST"])
@login_required
def full_restore():
    """Reset total do sistema - APENAS ADMIN"""
    if not session.get("is_admin"):
        flash("Acesso negado. Somente administrador.", "danger")
        return redirect("/")

    try:
        print("🔄 Iniciando RESET TOTAL DO SISTEMA...")

        # 1. Limpar todos os registros DNS
        print("🗑️ Removendo todos os registros DNS...")
        resolver.records.clear()

        # Resetar configuração completa
        default_config = {
            "hosts": {},
            "ssl_enabled": {},
            "ssl_ports": {},
            "http_ports": {}
        }
        resolver.save_full_config(default_config)

        # 2. Resetar usuários para apenas admin padrão
        print("👤 Resetando usuários...")
        admin_pass = bcrypt.hashpw("admin123".encode(), bcrypt.gensalt()).decode()
        default_users = {"admin": {"password": admin_pass, "is_admin": True}}
        with open(USERS_FILE, "w") as f:
            json.dump(default_users, f, indent=2)

        # 3. Limpar certificados SSL
        print("🧹 Limpando certificados SSL...")
        cert_dir = "/etc/nginx/ssl"
        if os.path.exists(cert_dir):
            import shutil
            for filename in os.listdir(cert_dir):
                if filename not in ["ca.crt", "ca.key"]:  # Preservar CA se existir
                    file_path = os.path.join(cert_dir, filename)
                    if os.path.isfile(file_path):
                        os.remove(file_path)
                        print(f"🗑️ Removido: {filename}")

        # 4. Limpar configurações Nginx
        print("🧹 Limpando configurações Nginx...")
        sites_dirs = ["/etc/nginx/sites-available", "/etc/nginx/sites-enabled"]
        for sites_dir in sites_dirs:
            if os.path.exists(sites_dir):
                for filename in os.listdir(sites_dir):
                    if filename.endswith('.conf'):
                        file_path = os.path.join(sites_dir, filename)
                        if os.path.isfile(file_path):
                            os.remove(file_path)
                            print(f"🗑️ Removido config: {filename}")

        # 5. Resetar configurações SSL e CA
        print("🔧 Resetando configurações SSL/CA...")
        resolver.ssl_config = {"auto_generate_ssl": True}
        resolver.save_ssl_config()

        # Resetar CA config para padrão
        default_ca_config = {
            "common_name": "DNS-Resolver-CA",
            "organization": "Local Network",
            "organizational_unit": "IT Department",
            "country": "BR",
            "validity_days": 3650
        }
        resolver.save_ca_config(default_ca_config)

        # 6. Recarregar Nginx
        print("🔄 Recarregando Nginx...")
        resolver.reload_nginx()

        # 7. Limpar sessão e redirecionar
        session.clear()
        print("✅ RESET TOTAL CONCLUÍDO!")
        flash("Sistema restaurado ao estado de fábrica. Faça login com admin/admin123.", "success")
        return redirect("/login")

    except Exception as e:
        print(f"❌ Erro durante reset total: {e}")
        import traceback
        print(f"📋 Trace: {traceback.format_exc()}")
        flash(f"Erro durante reset total: {e}", "danger")
        return redirect("/admin")

# Alteração de senha segura para admin
# -----------------------------
@app.route("/change_password", methods=["POST"])
@login_required
def change_password():
    if session.get("user") != "admin":
        flash("Apenas o administrador pode alterar sua senha.", "danger")
        return redirect("/admin")

    users = load_users()
    current_password = request.form.get("current_password", "").strip()
    new_password = request.form.get("new_password", "").strip()
    confirm_password = request.form.get("confirm_password", "").strip()

    if not current_password or not new_password or not confirm_password:
        flash("Preencha todos os campos.", "warning")
        return redirect("/admin")

    stored_hash = users["admin"]["password"].encode()

    if not bcrypt.checkpw(current_password.encode(), stored_hash):
        flash("Senha atual incorreta.", "danger")
        return redirect("/admin")

    if new_password != confirm_password:
        flash("A nova senha e a confirmação não são iguais.", "warning")
        return redirect("/admin")

    if len(new_password) < 6:
        flash("A nova senha precisa ter pelo menos 6 caracteres.", "warning")
        return redirect("/admin")

    users["admin"]["password"] = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
    save_users(users)
    flash("Senha alterada com sucesso!", "success")
    return redirect("/admin")

# -----------------------------
# Tratamento de erros
# -----------------------------
@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f'Server Error: {error}')
    flash("Erro interno no servidor. Verifique os registros DNS ou tente novamente.", "danger")
    return redirect(url_for("index"))

@app.route("/ssl-settings", methods=["GET", "POST"])
@login_required
def ssl_settings():
    """Configurações globais de SSL"""
    if request.method == "POST":
        auto_generate = request.form.get("auto_generate_ssl") == "on"
        resolver.ssl_config["auto_generate_ssl"] = auto_generate
        resolver.save_ssl_config()
        flash("Configurações SSL atualizadas!", "success")

    return render_template("ssl_settings.html",
                          ssl_config=resolver.ssl_config,
                          user=session["user"])

@app.route("/dns-server-settings", methods=["GET", "POST"])
@login_required
def dns_server_settings():
    """Configurações do servidor DNS"""
    if not session.get("is_admin"):
        flash("Acesso negado. Somente administrador.", "danger")
        return redirect("/")

    if request.method == "POST":
        server_hostname = request.form.get("server_hostname", "").strip()
        upstream_dns = request.form.get("upstream_dns", "").strip()
        upstream_port = int(request.form.get("upstream_port", 53))

        # Salvar configurações DNS
        dns_config = {
            "server_hostname": server_hostname,
            "server_ip": "192.168.4.100",  # IP fixo do servidor
            "upstream_dns": upstream_dns,
            "upstream_port": upstream_port
        }

        # Salvar no arquivo de configuração
        dns_config_file = "/app/data/dns_config.json"
        with open(dns_config_file, "w") as f:
            json.dump(dns_config, f, indent=2)

        # Atualizar variáveis globais
        global UPSTREAM_DNS, UPSTREAM_PORT
        UPSTREAM_DNS = upstream_dns
        UPSTREAM_PORT = upstream_port

        flash("Configurações DNS salvas com sucesso!", "success")
        return redirect("/dns-server-settings")

    # Carregar configurações atuais
    dns_config_file = "/app/data/dns_config.json"
    if os.path.exists(dns_config_file):
        with open(dns_config_file, "r") as f:
            dns_config = json.load(f)
    else:
        dns_config = {
            "server_hostname": "dns-server.local",
            "server_ip": "192.168.4.100",
            "upstream_dns": "8.8.8.8",
            "upstream_port": 53
        }

    return render_template("dns_server_settings.html",
                          dns_config=dns_config,
                          user=session["user"],
                          is_admin=session.get("is_admin", False))

@app.route("/ssl-ca-settings", methods=["GET", "POST"])
@login_required
def ssl_ca_settings():
    """Configurações da Autoridade Certificadora"""
    if request.method == "POST":
        action = request.form.get("action", "save")

        if action == "save":
            # Salvar configurações da CA
            ca_config = {
                "common_name": request.form.get("common_name", "DNS-Resolver-CA"),
                "organization": request.form.get("organization", "Local Network"),
                "organizational_unit": request.form.get("organizational_unit", ""),
                "country": request.form.get("country", "BR"),
                "validity_days": int(request.form.get("validity_days", 3650))
            }
            resolver.save_ca_config(ca_config)
            flash("Configurações da Autoridade Certificadora salvas!", "success")

        elif action == "regenerate":
            # Regenerar certificado da CA
            if resolver.regenerate_ca_certificate():
                flash("Certificado da CA será regenerado. Novos certificados usarão as configurações atualizadas.", "warning")
            else:
                flash("Erro ao regenerar certificado da CA.", "danger")

        return redirect("/ssl-ca-settings")

    # Carregar configurações atuais
    ca_config = resolver.load_ca_config()
    ca_cert_info = resolver.get_ca_certificate_info()

    return render_template("ssl_ca_settings.html",
                          ca_config=ca_config,
                          ca_cert_info=ca_cert_info,
                          user=session["user"],
                          is_admin=session.get("is_admin", False))

@app.route("/cleanup-orphaned", methods=["POST"])
@login_required
def cleanup_orphaned():
    """Executa limpeza de arquivos órfãos"""
    if not session.get("is_admin"):
        flash("Acesso negado. Somente administrador.", "danger")
        return redirect("/")

    try:
        print("🧹 Iniciando limpeza manual de arquivos órfãos...")
        result = resolver.cleanup_orphaned_files()

        if result:
            flash("Limpeza de arquivos órfãos concluída com sucesso!", "success")
        else:
            flash("Erro durante a limpeza de arquivos órfãos.", "danger")

    except Exception as e:
        print(f"❌ Erro na limpeza: {e}")
        flash(f"Erro na limpeza: {e}", "danger")

    return redirect("/admin")

@app.route("/ssl-certificate", methods=["POST"])
@login_required
def upload_ssl_certificate():
    """Upload de certificado SSL customizado"""
    if request.files.get("cert_file") and request.files.get("key_file"):
        cert_file = request.files["cert_file"]
        key_file = request.files["key_file"]

        cert_file.save("/app/nginx/ssl/cert.pem")
        key_file.save("/app/nginx/ssl/key.pem")

        # Remove marca de auto-geração
        auto_file = "/app/nginx/ssl/auto_generated.txt"
        if os.path.exists(auto_file):
            os.remove(auto_file)

        resolver.reload_nginx()
        flash("Certificado SSL atualizado!", "success")

    return redirect("/ssl-settings")

@app.route("/debug-nginx")
@login_required
def debug_nginx():
    """Rota de diagnóstico para Nginx"""
    import glob

    debug_info = {
        "nginx_status": "running" if subprocess.run(["pgrep", "nginx"], capture_output=True).returncode == 0 else "stopped",
        "sites_available": glob.glob("/etc/nginx/sites-available/*.conf"),
        "sites_enabled": glob.glob("/etc/nginx/sites-enabled/*.conf"),
        "ssl_cert_exists": os.path.exists("/etc/nginx/ssl/cert.pem"),
        "ssl_key_exists": os.path.exists("/etc/nginx/ssl/key.pem"),
        "nginx_config_test": subprocess.run(["nginx", "-t"], capture_output=True, text=True).stdout
    }

    return jsonify(debug_info)

@app.route("/debug-templates")
def debug_templates():
    """Rota de diagnóstico para templates"""
    debug_info = {
        "template_folder": app.template_folder,
        "static_folder": app.static_folder,
        "templates_exist": os.path.exists(app.template_folder),
        "static_exist": os.path.exists(app.static_folder),
        "templates_list": os.listdir(app.template_folder) if os.path.exists(app.template_folder) else "NÃO EXISTE",
        "static_list": os.listdir(app.static_folder) if os.path.exists(app.static_folder) else "NÃO EXISTE",
        "current_dir": os.getcwd(),
        "app_dir": os.path.dirname(os.path.abspath(__file__))
    }
    return jsonify(debug_info)

@app.route("/debug-edit/<domain>")
@login_required
def debug_edit(domain):
    """Rota de diagnóstico para edição"""
    debug_info = {
        "domain": domain,
        "domain_in_records": domain in resolver.records,
        "records_keys": list(resolver.records.keys()),
        "current_url": request.url,
        "edit_param": request.args.get("edit")
    }
    return jsonify(debug_info)

@app.route('/ca-cert')
def download_ca_cert():
    """Endpoint para baixar o certificado da CA"""
    ca_cert_path = "/etc/nginx/ssl/ca.crt"
    if os.path.exists(ca_cert_path):
        return send_file(ca_cert_path, as_attachment=True, download_name='dns-resolver-ca.crt')
    else:
        return "Certificado CA não encontrado", 404

# -----------------------------
if __name__ == "__main__":
    print("""
    ⚡ DNS SERVER - LAN
    📊 Painel: http://192.168.5.248:8000
    🌐 DNS:    127.0.0.1:53
    """)
    app.run(host="0.0.0.0", port=8000, debug=True)