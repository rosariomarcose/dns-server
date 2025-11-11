# 🧭 DNS Resolver Local - Servidor DNS com Interface Web

Um **servidor DNS local completo** com interface web intuitiva para gerenciar domínios internos na rede.  
Permite criar mapeamentos personalizados como `meuservidor.local → 192.168.1.100` de forma simples e visual.

---

## 📋 Sobre o Projeto
O **DNS Resolver Local** combina um servidor DNS leve com um painel administrativo web para gerenciamento visual dos registros internos da sua rede.  
Ideal para ambientes de **desenvolvimento, homelabs e redes internas**.

---

## 🚀 Funcionalidades Principais

- 🌐 **Servidor DNS Integrado** – Resolve domínios locais e encaminha consultas externas  
- 🖥️ **Interface Web Amigável** – Painel administrativo intuitivo e responsivo  
- 🔒 **Sistema Multiusuário** – Login seguro com níveis de acesso  
- ⚡ **Monitoramento Automático** – Verificação em tempo real dos IPs  
- 📊 **Gerenciamento Visual** – Adicione, edite e remova registros com cliques  
- 🐳 **Pronto para Docker** – Deploy simples e rápido com containers  
- 📱 **Design Responsivo** – Funciona bem em desktops e dispositivos móveis  

---

## 🎯 Como Funciona

1. **Instalação Rápida**
   ```bash
   docker-compose up -d
   ```

2. **Acesso ao Painel**
   - Abra [http://localhost:8000](http://localhost:8000)

3. **Login Padrão**
   ```
   Usuário: admin  
   Senha: admin123
   ```

4. **Adicionar Domínios**
   - Exemplo: `meuapp.local → 192.168.1.10`

5. **Configurar DNS do Sistema**
   - Utilize `127.0.0.1` como servidor DNS.

---

## 💡 Casos de Uso

- 🧑‍💻 **Desenvolvimento:** domínios locais para projetos (`meuapp.local`)  
- 🖥️ **Rede Interna:** nomes amigáveis para servidores e dispositivos  
- 🧪 **Testes:** simulação de múltiplos domínios  
- 🏠 **Homelab:** DNS centralizado e fácil de administrar  

---

## 🛠️ Tecnologias Utilizadas

| Camada | Tecnologias |
|:-------|:-------------|
| **Backend** | Python + Flask |
| **DNS Server** | dnspython |
| **Frontend** | HTML5, CSS3, JavaScript |
| **Segurança** | bcrypt |
| **Containerização** | Docker + Docker Compose |
| **Rede** | Suporte a IPv4 privado |

---

## 📦 Estrutura do Projeto

```
dns-resolver-local/
├── app.py                # Aplicação Flask principal
├── dns_server.py         # Servidor DNS customizado
├── requirements.txt      # Dependências Python
├── docker-compose.yml    # Orquestração Docker
├── Dockerfile            # Build da imagem
├── data/                 # Armazenamento de dados persistentes
├── static/css/           # Estilos CSS
└── templates/            # Templates HTML
```

---

## 🔧 Configuração Rápida

### 🐳 Com Docker (Recomendado)

```bash
git clone [url-do-repositorio]
cd dns-resolver-local
docker-compose up -d
```

### 🔗 Acesso

- **Interface Web:** [http://localhost:8000](http://localhost:8000)  
- **Servidor DNS:** `127.0.0.1:53`  
- **Credenciais padrão:** `admin / admin123`

---

## 🎮 Comandos Úteis

```bash
# Iniciar o serviço
docker-compose up -d

# Parar o serviço
docker-compose down

# Ver logs do DNS
docker logs dns-server

# Fazer backup dos dados
cp -r data/ data-backup/
```

---

## 🔒 Segurança

- Autenticação com hash **bcrypt**  
- Sessões com **expiração automática**  
- Validação apenas de **IPs privados**  
- Proteção contra **injeção e XSS**  
- Acesso **restrito por nível administrativo**

---

## 🌐 IPs Suportados

- `192.168.x.x` – Redes domésticas ou empresariais  
- `10.x.x.x` – Redes privadas de grande porte  
- `172.16.x.x` a `172.31.x.x` – Redes privadas médias  

---

## 🤝 Suporte e Contribuições

Este é um projeto **open-source**, criado para facilitar o gerenciamento de DNS em redes locais.  
Contribuições, sugestões e melhorias são sempre bem-vindas!

📬 **Contato / Contribua:** abra uma issue ou envie um pull request.  

---

⭐ Se este projeto te ajudou, deixe uma estrela no repositório!
