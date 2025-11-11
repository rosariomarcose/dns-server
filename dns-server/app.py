from flask import Flask, render_template, request, redirect, flash, url_for, session
import threading, subprocess, json, os, time, bcrypt, re, ipaddress
from functools import wraps

app = Flask(__name__)
app.secret_key = os.urandom(24)
SESSION_TIMEOUT = 600  # 10 minutos

# Inicializa resolver (assumindo que dns_server.py existe)
try:
    from dns_server import CustomResolver, start_dns_server, health_monitor
    resolver = CustomResolver()
    if not hasattr(resolver, "records") or not isinstance(resolver.records, dict):
        resolver.records = {}
    
    # Inicia DNS e monitor em background
    threading.Thread(target=start_dns_server, args=(resolver,), daemon=True).start()
    threading.Thread(target=health_monitor, args=(resolver,), daemon=True).start()
except ImportError:
    print("⚠️  Módulo dns_server não encontrado. Executando em modo simulação.")
    class MockResolver:
        def __init__(self):
            self.records = {}
        def save(self):
            pass
    resolver = MockResolver()

USERS_FILE = os.path.join("data", "users.json")
os.makedirs("data", exist_ok=True)
os.makedirs("static/css", exist_ok=True)

# -----------------------------
# Funções auxiliares
# -----------------------------
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
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
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
    """Remove caracteres potencialmente perigosos"""
    return re.sub(r'[^\w\.\-\@]', '', text.strip())

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
                flash(f"Bem-vindo, {username}!", "success")
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

    return render_template(
        "index.html",
        user=session["user"],
        is_admin=session.get("is_admin", False),
        records=sorted(resolver.records.items()),
        edit_domain=edit_domain,
        current_ip=current_ip,
    )

# -----------------------------
# Rotas de CRUD DNS
# -----------------------------
@app.route("/add", methods=["POST"])
@login_required
def add():
    domain = sanitize_input(request.form["domain"]).lower()
    ip = sanitize_input(request.form["ip"])
    
    if not domain or not ip:
        flash("Domínio e IP são obrigatórios.", "danger")
        return redirect("/")
    
    if not validate_domain(domain):
        flash("Domínio inválido. Use apenas letras, números e hífens.", "danger")
        return redirect("/")
    
    if not validate_ip(ip):
        flash("IP inválido. Use apenas IPs privados (192.168.x.x, 10.x.x.x, 172.16-31.x.x).", "danger")
        return redirect("/")
    
    # Verifica se o IP está online
    try:
        ping_result = subprocess.run(
            ["ping", "-c", "1", "-W", "2", ip],
            stdout=subprocess.DEVNULL, 
            stderr=subprocess.DEVNULL,
            timeout=5
        )
        if ping_result.returncode == 0:
            resolver.records[domain] = ip
            resolver.save()
            flash(f"Adicionado (online): {domain} → {ip}", "success")
        else:
            flash(f"⚠️ IP {ip} offline, mas registro adicionado.", "warning")
            resolver.records[domain] = ip
            resolver.save()
    except (subprocess.TimeoutExpired, Exception):
        flash(f"⚠️ Não foi possível verificar o IP {ip}, mas registro adicionado.", "warning")
        resolver.records[domain] = ip
        resolver.save()
    
    return redirect("/")

@app.route("/edit/<domain>")
@login_required
def edit(domain):
    if domain in resolver.records:
        return redirect(url_for("index", edit=domain))
    flash("Domínio não encontrado.", "danger")
    return redirect("/")

@app.route("/update/<domain>", methods=["POST"])
@login_required
def update(domain):
    new_ip = sanitize_input(request.form["new_ip"])
    
    if not new_ip:
        flash("IP é obrigatório.", "danger")
        return redirect("/")
    
    if not validate_ip(new_ip):
        flash("IP inválido. Use apenas IPs privados.", "danger")
        return redirect("/")
    
    if domain not in resolver.records:
        flash("Domínio não encontrado.", "danger")
        return redirect("/")
    
    # Verifica se o IP está online
    try:
        ping_result = subprocess.run(
            ["ping", "-c", "1", "-W", "2", new_ip],
            stdout=subprocess.DEVNULL, 
            stderr=subprocess.DEVNULL,
            timeout=5
        )
        if ping_result.returncode == 0:
            resolver.records[domain] = new_ip
            resolver.save()
            flash(f"Atualizado (online): {domain} → {new_ip}", "success")
        else:
            flash(f"⚠️ IP {new_ip} offline, mas registro atualizado.", "warning")
            resolver.records[domain] = new_ip
            resolver.save()
    except (subprocess.TimeoutExpired, Exception):
        flash(f"⚠️ Não foi possível verificar o IP {new_ip}, mas registro atualizado.", "warning")
        resolver.records[domain] = new_ip
        resolver.save()
    
    return redirect("/")

@app.route("/delete/<domain>", methods=["POST"])
@login_required
def delete(domain):
    if domain in resolver.records:
        removed_ip = resolver.records.pop(domain)
        resolver.save()
        flash(f"Removido: {domain} → {removed_ip}", "danger")
    else:
        flash("Domínio não encontrado.", "danger")
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

# -----------------------------
if __name__ == "__main__":
    print("""
    ⚡ DNS SERVER LOCAL (APENAS REDE INTERNA)
    📊 Painel: http://localhost:8000
    🌐 DNS:    127.0.0.1:53
    """)
    app.run(host="0.0.0.0", port=8000, debug=True)