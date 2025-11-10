# app.py
from flask import Flask, render_template, request, redirect, flash, url_for
import threading
import subprocess
from dns_server import CustomResolver, start_dns_server, health_monitor

app = Flask(__name__)
app.secret_key = "super-secreto-123"

resolver = CustomResolver()

# Inicia servidores em background
threading.Thread(target=start_dns_server, args=(resolver,), daemon=True).start()
threading.Thread(target=health_monitor, args=(resolver,), daemon=True).start()

@app.route("/")
def index():
    return render_template("index.html", 
                         records=sorted(resolver.records.items()),
                         edit_domain=request.args.get("edit"),
                         current_ip=resolver.records.get(request.args.get("edit"), "") if request.args.get("edit") else "")

@app.route("/add", methods=["POST"])
def add():
    domain = request.form["domain"].strip().lower()
    ip = request.form["ip"].strip()
    if domain and ip:
        # Teste de ping antes de adicionar
        ping_result = subprocess.run(["ping", "-c", "1", "-W", "2", ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if ping_result.returncode == 0:
            resolver.records[domain] = ip
            resolver.save()
            flash(f"Adicionado (online): {domain} → {ip}", "success")
        else:
            flash(f"Erro: IP {ip} offline ou inválido. Não adicionado.", "danger")
    else:
        flash("Campos obrigatórios: domínio e IP.", "danger")
    return redirect("/")

@app.route("/edit/<domain>")
def edit(domain):
    if domain in resolver.records:
        return render_template("index.html", 
                             records=sorted(resolver.records.items()),
                             edit_domain=domain,
                             current_ip=resolver.records[domain])
    return redirect("/")

@app.route("/update/<domain>", methods=["POST"])
def update(domain):
    new_ip = request.form["new_ip"].strip()
    if new_ip and domain in resolver.records:
        # Teste de ping antes de atualizar
        ping_result = subprocess.run(["ping", "-c", "1", "-W", "2", new_ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if ping_result.returncode == 0:
            resolver.records[domain] = new_ip
            resolver.save()
            flash(f"Atualizado (online): {domain} → {new_ip}", "success")
        else:
            flash(f"Erro: Novo IP {new_ip} offline ou inválido. Não atualizado.", "danger")
    else:
        flash("IP inválido ou domínio não encontrado.", "danger")
    return redirect("/")

@app.route("/delete/<domain>", methods=["POST"])
def delete(domain):
    if domain in resolver.records:
        removed = resolver.records.pop(domain)
        resolver.save()
        flash(f"Removido: {domain} → {removed}", "danger")
    return redirect("/")

if __name__ == "__main__":
    print("""
    DNS SERVER LOCAL (APENAS REDE INTERNA)
    Painel: http://localhost:8000
    DNS:    127.0.0.1:53
    """)
    app.run(host="0.0.0.0", port=8000, debug=False)