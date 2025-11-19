## Prompt Técnico Estruturado

**Objetivo:**  
Corrigir o erro ERR_NAME_NOT_RESOLVED para o domínio dns-resolver.local.com.br, garantindo que o servidor DNS local resolva corretamente domínios configurados no hosts.json e permita acesso HTTPS ao painel de administração.

**Contexto Atual:**  
- Projeto: DNS resolver Docker com servidor DNS personalizado (porta 53/UDP) e Nginx para proxy reverso.  
- Domínio: dns-resolver.local.com.br → 192.168.4.100 (IP do servidor DNS, porta HTTP 8000).  
- Configurações: SSL habilitado, container rodando com portas expostas (80, 443, 53/udp, 8000).  
- Sintomas: ERR_NAME_NOT_RESOLVED indica que o DNS do sistema não está resolvendo domínios locais; provável causa é que o resolver DNS do sistema não aponta para 127.0.0.1:53.  
- Arquivos chave: dns-server/data/hosts.json, docker-compose.yaml, dns-server/dns_server.py.  

**Tarefas a Executar:**  
1. Verificar se o container dns-resolver está rodando e o serviço DNS ativo (porta 53/UDP).  
2. Configurar o DNS do sistema (Windows/Linux) para usar 127.0.0.1 como nameserver primário.  
3. Testar resolução DNS com nslookup dns-resolver.local.com.br 127.0.0.1.  
4. Verificar conteúdo do hosts.json e confirmar mapeamento dns-resolver.local.com.br → 192.168.4.100.  
5. Executar testes de conectividade: curl http://192.168.4.100:8000 e curl -k https://192.168.4.100 (via IP direto).  
6. Ajustar configurações se necessário (ex.: verificar se Nginx está configurado corretamente para o domínio).  
7. Testar acesso completo via domínio: https://dns-resolver.local.com.br/.  
8. Documentar mudanças e verificar logs do DNS/Nginx para erros.  

**Tecnologias Envolvidas:**  
- Docker (container dns-resolver).  
- DNS personalizado (Python com dnslib, upstream para 8.8.8.8).  
- Nginx (proxy reverso com SSL).  

**Limitações:**  
- Ambiente local; DNS deve ser configurado no sistema host.  
- SSL usa certificados auto-assinados (CA local).  

**Resultados Esperados:**  
- nslookup dns-resolver.local.com.br retorna 192.168.4.100.  
- Acesso HTTPS a https://dns-resolver.local.com.br/ funcionando sem ERR_NAME_NOT_RESOLVED.  
- Painel de administração acessível via HTTPS com certificado local.  
