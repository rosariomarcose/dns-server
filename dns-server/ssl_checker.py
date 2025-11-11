#!/usr/bin/env python3
import dns.resolver
import sys

def check_ssl_info(domain):
    """Consulta informações SSL de um domínio"""
    try:
        # Consulta o registro TXT
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt_string = str(rdata).strip('"')
            if 'ssl_enabled' in txt_string:
                print(f"🔍 Informações SSL para {domain}:")
                print(f"   {txt_string}")
                return
        
        print(f"ℹ️  {domain} não tem informações SSL configuradas")
        
    except dns.resolver.NoAnswer:
        print(f"❌ Nenhum registro TXT encontrado para {domain}")
    except dns.resolver.NXDOMAIN:
        print(f"❌ Domínio {domain} não existe")
    except Exception as e:
        print(f"❌ Erro ao consultar {domain}: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python ssl_checker.py <dominio>")
        sys.exit(1)
    
    check_ssl_info(sys.argv[1])