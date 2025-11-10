from flask import Flask, render_template, request, redirect, flash, url_for, session
import threading, subprocess, json, os, time, bcrypt
from functools import wraps
from dns_server import CustomResolver, start_dns_server, health_monitor

app = Flask(__name__)
app.secret_key = "super-secreto-123"
SESSION_TIMEOUT = 600  # 10 minutos

resolver = CustomResolver()

# Inicia DNS e monitor em background
threading.Thread(target=start_dns_server, args=(resolver,), daemon=True).start()
threading.Thread(target=health_monitor, args=(resolver,), daemon=True).start()

USERS_FILE = os.path.join("data", "users.json")
os.makedirs("data", exist_ok=True)

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
        if not pwd.startswith("$2b$"):  # não é hash
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

# -----------------------------
# Rotas de autenticação
# -----------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip().lower()
        password = request.form["password"].strip().encode()
        users = load_users()

        if username in users:
            stored_hash = users[username]["password"].encode()
            if bcrypt.checkpw(password, stored_hash):
                session["user"] = username
                session["is_admin"] = users[username].get("is_admin", False)
                session["last_activity"] = time.time()
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
    return render_template(
        "index.html",
        user=session["user"],
        is_admin=session.get("is_admin", False),
        records=sorted(resolver.records.items()),
        edit_domain=request.args.get("edit"),
        current_ip=resolver.records.get(request.args.get("edit"), "")
        if request.args.get("edit")
        else "",
    )

# -----------------------------
# Rotas de CRUD DNS
# -----------------------------
@app.route("/add", methods=["POST"])
@login_required
def add():
    domain = request.form["domain"].strip().lower()
    ip = request.form["ip"].strip()
    if domain and ip:
        ping_result = subprocess.run(["ping", "-c", "1", "-W", "2", ip],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if ping_result.returncode == 0:
            resolver.records[domain] = ip
            resolver.save()
            flash(f"Adicionado (online): {domain} → {ip}", "success")
        else:
            flash(f"Erro: IP {ip} offline ou inválido.", "danger")
    else:
        flash("Campos obrigatórios: domínio e IP.", "danger")
    return redirect("/")

@app.route("/edit/<domain>")
@login_required
def edit(domain):
    if domain in resolver.records:
        return render_template("index.html",
                               records=sorted(resolver.records.items()),
                               edit_domain=domain,
                               current_ip=resolver.records[domain],
                               user=session["user"],
                               is_admin=session.get("is_admin", False))
    return redirect("/")

@app.route("/update/<domain>", methods=["POST"])
@login_required
def update(domain):
    new_ip = request.form["new_ip"].strip()
    if new_ip and domain in resolver.records:
        ping_result = subprocess.run(["ping", "-c", "1", "-W", "2", new_ip],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if ping_result.returncode == 0:
            resolver.records[domain] = new_ip
            resolver.save()
            flash(f"Atualizado (online): {domain} → {new_ip}", "success")
        else:
            flash(f"Erro: Novo IP {new_ip} offline ou inválido.", "danger")
    else:
        flash("IP inválido ou domínio não encontrado.", "danger")
    return redirect("/")

@app.route("/delete/<domain>", methods=["POST"])
@login_required
def delete(domain):
    if domain in resolver.records:
        removed = resolver.records.pop(domain)
        resolver.save()
        flash(f"Removido: {domain} → {removed}", "danger")
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
        username = request.form.get("username").strip().lower()
        if action == "add":
            password = request.form.get("password").strip()
            if username and password and username not in users:
                hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
                users[username] = {"password": hashed, "is_admin": False}
                save_users(users)
                flash(f"Usuário {username} criado com sucesso.", "success")
            else:
                flash("Usuário já existe ou campos inválidos.", "danger")
        elif action == "delete" and username != "admin":
            users.pop(username, None)
            save_users(users)
            flash(f"Usuário {username} removido.", "warning")
        elif action == "reset":
            new_pass = request.form.get("new_password").strip()
            if username in users and new_pass:
                users[username]["password"] = bcrypt.hashpw(new_pass.encode(), bcrypt.gensalt()).decode()
                save_users(users)
                flash(f"Senha de {username} redefinida.", "success")

    return render_template("admin.html", users=load_users()) 

# -----------------------------
if __name__ == "__main__":
    print("""
    DNS SERVER LOCAL (APENAS REDE INTERNA)
    Painel: http://localhost:8000
    DNS:    127.0.0.1:53
    """)
    app.run(host="0.0.0.0", port=8000, debug=False)
