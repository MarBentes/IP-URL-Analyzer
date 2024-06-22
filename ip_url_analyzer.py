import requests
import time
import re
import os
import webbrowser
import socket
import ssl
import datetime
import shodan
from urllib.parse import urlparse

# Supresses only the specific InsecureRequestWarning from urllib3
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Replace with your API keys
VIRUSTOTAL_API_KEY = 'SUA_API_KEY'
IPINFO_API_KEY = 'SUA_API_KEY'
ABUSEIPDB_API_KEY = 'SUA_API_KEY'
THREATFOX_API_KEY = 'SUA_API_KEY'
URLHAUS_API_KEY = 'SUA_API_KEY'
SHODAN_API_KEY = 'SUA_API_KEY'
WHOISXMLAPI_KEY = 'SUA_API_KEY'
ALIENVAULT_OTX_API_KEY = 'SUA_API_KEY'

VIRUSTOTAL_SCAN_ENDPOINT = 'https://www.virustotal.com/vtapi/v2/url/scan'
VIRUSTOTAL_REPORT_ENDPOINT = 'https://www.virustotal.com/vtapi/v2/url/report'
IPINFO_ENDPOINT = 'https://ipinfo.io'
ABUSEIPDB_ENDPOINT = 'https://api.abuseipdb.com/api/v2/check'
THREATFOX_ENDPOINT = 'https://threatfox-api.abuse.ch/api/v1/'
URLHAUS_ENDPOINT = 'https://urlhaus-api.abuse.ch/v1/url/'
ALIENVAULT_OTX_IP_ENDPOINT = 'https://otx.alienvault.com/api/v1/indicators/IPv4/'

def is_valid_ip(address):
    ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return ip_pattern.match(address) is not None

def extract_domain(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc or parsed_url.path
    parts = domain.split('.')
    if len(parts) > 2:
        domain = '.'.join(parts[-2:])
    return domain

def get_ip_geolocation(ip):
    response = requests.get(f"{IPINFO_ENDPOINT}/{ip}", params={'token': IPINFO_API_KEY})
    if response.status_code == 200:
        geo_data = response.json()
        city = geo_data.get('city', 'Cidade não encontrada')
        country = geo_data.get('country', 'País não encontrado')
        org = geo_data.get('org', 'Organização não encontrada')
        loc = geo_data.get('loc', 'Coordenadas não encontradas')
        hostname = geo_data.get('hostname', 'Hostname não encontrado')
        asn = geo_data.get('asn', 'ASN não encontrado')
        as_owner = geo_data.get('asn_owner', 'Organização não encontrada')

        return {
            'location': f"{city}, {country} (Org: {org}, Coordenadas: {loc})",
            'hostname': hostname,
            'asn': asn,
            'as_owner': as_owner,
            'country': country
        }
    else:
        return {
            'location': 'Geolocalização não encontrada',
            'hostname': 'Hostname não encontrado',
            'asn': 'ASN não encontrado',
            'as_owner': 'Organização não encontrada',
            'country': 'País não encontrado'
        }

def get_abuseipdb_reputation(ip):
    headers = {
        'Key': ABUSEIPDB_API_KEY,
        'Accept': 'application/json'
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': 90
    }
    response = requests.get(ABUSEIPDB_ENDPOINT, headers=headers, params=params)
    if response.status_code == 200:
        abuse_data = response.json()
        return abuse_data.get('data', {}).get('abuseConfidenceScore', 'Reputação não encontrada')
    else:
        print(f"Erro ao obter dados do AbuseIPDB. Código de status: {response.status_code}")
    return 'Reputação não encontrada'

def get_virustotal_verdict(resource, is_url=True):
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }
    params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': resource}
    response = requests.get(VIRUSTOTAL_REPORT_ENDPOINT, params=params)
    if response.status_code == 200:
        report_data = response.json()
        positives = report_data.get('positives', 'Positivos não encontrados')
        total = report_data.get('total', 'Total não encontrado')
        scans = report_data.get('scans', {})
        relevant_verdicts = [(engine, details['result']) for engine, details in scans.items() if details.get('detected')]
        last_analysis_date = report_data.get('scan_date', 'Data da última análise não encontrada')
        
        return positives, total, relevant_verdicts, report_data, last_analysis_date
    elif response.status_code == 204:
        print("Resultados ainda não disponíveis. Tentando novamente em 5 segundos...")
        time.sleep(5)
    else:
        print("Relatório não encontrado, iniciando nova análise.")
        scan_params = {'apikey': VIRUSTOTAL_API_KEY, 'url': resource} if is_url else {'apikey': VIRUSTOTAL_API_KEY, 'ip': resource}
        response = requests.post(VIRUSTOTAL_SCAN_ENDPOINT, data=scan_params)
        if response.status_code == 200:
            scan_data = response.json()
            scan_id = scan_data.get('scan_id', 'N/A')
            time.sleep(15)  # Esperar para permitir que a análise seja processada

            for _ in range(10):
                response = requests.get(VIRUSTOTAL_REPORT_ENDPOINT, params={'apikey': VIRUSTOTAL_API_KEY, 'resource': resource, 'scan': 1})
                if response.status_code == 200:
                    report_data = response.json()
                    positives = report_data.get('positives', 'Positivos não encontrados')
                    total = report_data.get('total', 'Total não encontrado')
                    scans = report_data.get('scans', {})
                    relevant_verdicts = [(engine, details['result']) for engine, details in scans.items() if details.get('detected')]
                    last_analysis_date = report_data.get('scan_date', 'Data da última análise não encontrada')
                    
                    return positives, total, relevant_verdicts, report_data, last_analysis_date
                elif response.status_code == 204:
                    print("Resultados ainda não disponíveis. Tentando novamente em 5 segundos...")
                    time.sleep(5)
                else:
                    print(f"Erro ao obter resultado do relatório. Código de status: {response.status_code}")
                    break
        else:
            print(f"Erro ao iniciar a análise no VirusTotal. Código de status: {response.status_code}")
    return None, None, None, None, None

def get_threatfox_info(ioc):
    headers = {
        'API-KEY': THREATFOX_API_KEY
    }
    data = {
        'query': 'search_ioc',
        'search_term': ioc
    }
    response = requests.post(THREATFOX_ENDPOINT, headers=headers, json=data)
    if response.status_code == 200:
        threatfox_data = response.json()
        if threatfox_data.get('query_status') == 'no_result':
            return {
                'Threat Type': 'N/A',
                'Malware': 'N/A',
                'Malware Alias': 'N/A',
                'Confidence Level': 'N/A',
                'Tags': 'N/A'
            }
        if 'data' in threatfox_data and isinstance(threatfox_data['data'], list) and threatfox_data['data']:
            threatfox_info = threatfox_data['data'][0]
            return {
                'Threat Type': threatfox_info.get('threat_type', 'N/A'),
                'Malware': threatfox_info.get('malware', 'N/A'),
                'Malware Alias': threatfox_info.get('malware_alias', 'N/A'),
                'Confidence Level': f"{threatfox_info.get('confidence_level', 'N/A')}%",
                'Tags': ', '.join(threatfox_info.get('tags', [])) if threatfox_info.get('tags') else 'N/A'
            }
    else:
        print(f"Erro ao obter dados do ThreatFox. Código de status: {response.status_code}")
    return {
        'Threat Type': 'N/A',
        'Malware': 'N/A',
        'Malware Alias': 'N/A',
        'Confidence Level': 'N/A',
        'Tags': 'N/A'
    }

def check_urlhaus(url):
    response = requests.post(
        URLHAUS_ENDPOINT,
        data={'url': url},
        headers={'API-KEY': URLHAUS_API_KEY}
    )
    if response.status_code == 200:
        urlhaus_data = response.json()
        return {
            'URL Status': urlhaus_data.get('query_status', 'N/A'),
            'Host': urlhaus_data.get('host', 'N/A'),
            'Date Added': urlhaus_data.get('date_added', 'N/A'),
            'Threat': urlhaus_data.get('threat', 'N/A'),
            'Tags': urlhaus_data.get('tags', 'N/A')
        }
    else:
        print(f"Erro ao obter dados do URLhaus. Código de status: {response.status_code}")
        return {
            'URL Status': 'N/A',
            'Host': 'N/A',
            'Date Added': 'N/A',
            'Threat': 'N/A',
            'Tags': 'N/A'
        }

def check_url_protocol(url):
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'http://' + url
    try:
        response = requests.get(url, verify=False, timeout=10)  # Adicionado timeout
        return response.url.startswith('https://'), response.url
    except requests.exceptions.RequestException as e:
        print(f"Erro ao verificar o protocolo da URL: {e}")
        return f"Erro ao verificar o protocolo: {e}", url

def check_ssl(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname if parsed_url.hostname else url

    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, 443), timeout=10) as sock:  # Adicionado timeout
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                print(f"SSL certificate for {hostname} is valid.")
                return "SSL certificate is valid"
    except Exception as e:
        print(f"SSL certificate for {hostname} is not valid or does not exist: {e}")
        return f"SSL certificate is not valid: {e}"

def check_ip_categories(ip):
    api = shodan.Shodan(SHODAN_API_KEY)
    try:
        # Fetch the Shodan data for the IP
        ip_info = api.host(ip)
        
        # Check various categories based on the Shodan data
        proxy_ip = 'proxy' in ip_info.get('tags', [])
        vpn_ip = 'vpn' in ip_info.get('tags', [])
        tor_ip = 'tor' in ip_info.get('tags', [])
        hosting_ip = ip_info.get('org') is not None and 'hosting' in ip_info.get('org').lower()
        mobile_ip = 'mobile' in ip_info.get('tags', [])
        cdn_ip = 'cdn' in ip_info.get('tags', [])
        scanner_ip = 'scanner' in ip_info.get('tags', [])
        special_issue = 'malicious' in ip_info.get('tags', [])
        ip_reputation = ip_info.get('vulns', 'N/A')
        security_tags = ip_info.get('tags', [])

        return {
            'Proxy IP': proxy_ip,
            'VPN IP': vpn_ip,
            'Tor IP': tor_ip,
            'Hosting IP': hosting_ip,
            'Mobile IP': mobile_ip,
            'CDN IP': cdn_ip,
            'Scanner IP': scanner_ip,
            'Special Issue': special_issue,
            'IP Reputation': ip_reputation,
            'Security Tags': ', '.join(security_tags) if security_tags else 'N/A'
        }
    except shodan.APIError as e:
        print(f"Error: {e}")
        return {
            'Proxy IP': 'N/A',
            'VPN IP': 'N/A',
            'Tor IP': 'N/A',
            'Hosting IP': 'N/A',
            'Mobile IP': 'N/A',
            'CDN IP': 'N/A',
            'Scanner IP': 'N/A',
            'Special Issue': 'N/A',
            'IP Reputation': 'N/A',
            'Security Tags': 'N/A'
        }

def get_open_ports(ip):
    api = shodan.Shodan(SHODAN_API_KEY)
    try:
        ip_info = api.host(ip)
        open_ports = ip_info.get('ports', [])
        return open_ports
    except shodan.APIError as e:
        print(f"Error: {e}")
        return []

def get_whois_info(domain):
    api_key = WHOISXMLAPI_KEY  # Sua chave de API
    url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={api_key}&domainName={domain}&outputFormat=JSON"
    
    try:
        response = requests.get(url)
        data = response.json()
        whois_record = data.get("WhoisRecord")
        
        if whois_record:
            return {
                'Domain Name': whois_record.get('domainName', 'N/A'),
                'Registrar': whois_record.get('registrarName', 'N/A'),
                'Updated Date': whois_record.get('updatedDate', 'N/A'),
                'Creation Date': whois_record.get('createdDate', 'N/A'),
                'Registry Expiry Date': whois_record.get('expiresDate', 'N/A'),
                'Registrar Abuse Contact Email': whois_record.get('contactEmail', 'N/A')
            }
        else:
            return {
                'Domain Name': 'N/A',
                'Registrar': 'N/A',
                'Updated Date': 'N/A',
                'Creation Date': 'N/A',
                'Registry Expiry Date': 'N/A',
                'Registrar Abuse Contact Email': 'N/A'
            }
    except Exception as e:
        print(f"Erro ao obter dados WHOIS: {e}")
        return {
            'Domain Name': 'N/A',
            'Registrar': 'N/A',
            'Updated Date': 'N/A',
            'Creation Date': 'N/A',
            'Registry Expiry Date': 'N/A',
            'Registrar Abuse Contact Email': 'N/A'
        }

def get_alienvault_otx_info(ip):
    headers = {
        'X-OTX-API-KEY': ALIENVAULT_OTX_API_KEY
    }
    response = requests.get(f"{ALIENVAULT_OTX_IP_ENDPOINT}{ip}/general", headers=headers)
    if response.status_code == 200:
        otx_data = response.json()
        pulse_info = otx_data.get('pulse_info', {})
        pulses = pulse_info.get('pulses', [])
        threat_info = {}
        for pulse in pulses:
            category = pulse.get('name').split()[0]  # Assuming the first word indicates the category
            if category not in threat_info:
                threat_info[category] = []
            threat_info[category].append(f"{pulse['name']} (Created: {pulse['created']})")
        return threat_info
    else:
        print(f"Erro ao obter dados do AlienVault OTX. Código de status: {response.status_code}")
    return {}

def generate_conclusion(threat_info):
    conclusion = "Este IP está associado a várias atividades suspeitas e maliciosas, incluindo:\n"
    if 'Webscanners' in threat_info:
        conclusion += "- Varreduras na web e solicitações HTTP incorretas.\n"
    if '网络扫描仪' in threat_info:
        conclusion += "- Varreduras de rede detectadas.\n"
    if 'CINS' in threat_info:
        conclusion += "- Má reputação em inteligência de ameaças ativa da CINS.\n"
    if 'IOC' in threat_info:
        conclusion += "- Listado em registros de Indicadores de Comprometimento (IOCs).\n"
    if 'Apache' in threat_info:
        conclusion += "- Registrado em logs de honeypot do Apache.\n"
    if 'ETIC' in threat_info:
        conclusion += "- Realização de varreduras de porta detectadas pela ETIC Cybersecurity.\n"
    if 'Malicious' in threat_info:
        conclusion += "- Marcado diretamente como IP malicioso.\n"
    if 'Honeypot' in threat_info:
        conclusion += "- Visitante de honeypot, indicando comportamento malicioso.\n"
    if 'Network' in threat_info:
        conclusion += "- Identificado como scanner de rede.\n"
    if not any(key in threat_info for key in ['Webscanners', '网络扫描仪', 'CINS', 'IOC', 'Apache', 'ETIC', 'Malicious', 'Honeypot', 'Network']):
        conclusion += "- Nenhuma atividade maliciosa específica encontrada.\n"
    return conclusion

def format_value(key, value):
    if key in ['VirusTotal Positivos', 'SSL']:
        if value in ['Positivos não encontrados/Total não encontrado', 'SSL certificate is valid']:
            return f'<span style="color: green;">{value}</span>'
        elif key == 'VirusTotal Positivos':
            try:
                positives = int(value.split('/')[0])
                if positives > 0:
                    return f'<span style="color: red;">{value}</span>'
                else:
                    return f'<span style="color: green;">{value}</span>'
            except ValueError:
                return value
    if key == 'Reputação (AbuseIPDB)':
        try:
            score = int(value)
            color = 'red' if score >= 1 else 'green'
            return f'<span style="color: {color};">{score}%</span>'
        except ValueError:
            return value
    if isinstance(value, list):
        value = ", ".join(str(v) for v in value)
    if isinstance(value, (datetime.datetime, datetime.date)):
        value = value.strftime("%Y-%m-%d %H:%M:%S")
    if value == True or value == 'True':
        return f'<span style="color: red;">{value}</span>'
    if value == 'N/A':
        return ''
    return value

def save_results_to_html(results, filename):
    abuse_confidence_score = results.get('Reputação (AbuseIPDB)', 0)
    virustotal_positives = results.get('VirusTotal Positivos', '0/0').split('/')[0]
    urlhaus_status = results.get('URL Status', 'N/A')
    threatfox_malware = results.get('Malware', 'N/A')
    
    try:
        virustotal_positives = int(virustotal_positives)
    except ValueError:
        virustotal_positives = 0

    # Determina se é malicioso com base no score de confiança do AbuseIPDB, nos positivos do VirusTotal, no status do URLhaus ou na presença de malware no ThreatFox
    is_malicious = abuse_confidence_score >= 1 or virustotal_positives >= 1 or urlhaus_status == 'ok' or threatfox_malware != 'N/A'
    verdict_color = 'red' if is_malicious else 'green'
    final_verdict = 'Malicioso' if is_malicious else 'Não Malicioso'

    html_content = f"""
    <html>
    <head>
        <title>Resultados da Análise</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 20px;
                text-align: center;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-bottom: 20px;
                margin-left: auto;
                margin-right: auto;
            }}
            table, th, td {{
                border: 1px solid black;
            }}
            th, td {{
                padding: 8px;
                text-align: left;
            }}
            th {{
                background-color: #f2f2f2;
            }}
            .observation {{
                font-weight: bold;
            }}
        </style>
    </head>
    <body>
        <h1>Resultados da Análise</h1>
        <table>
            <tr><th>Atributo</th><th>Valor</th></tr>
            {''.join(f'<tr><td>{key}</td><td>{format_value(key, value)}</td></tr>' for key, value in results.items() if value != 'N/A')}
            <tr><th>Veredito Final</th><th style="color: {verdict_color};">{final_verdict}</th></tr>
        </table>
        <p class="observation">Observação: Esta análise foi realizada utilizando várias ferramentas online (VirusTotal, AbuseIPDB, ThreatFox, URLhaus, Shodan e AlienVault OTX) para fornecer uma visão abrangente da reputação e segurança do IP/URL analisado. Os resultados são baseados em dados disponíveis no momento da consulta e não garantem 100% de assertividade.</p>
        <p class="observation">Criado por Marcelo Bentes</p>
    </body>
    </html>
    """
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html_content)

def main():
    input_value = input("Digite a URL ou IP que você deseja analisar: ").strip()
    
    if is_valid_ip(input_value):
        final_ip = input_value
        geo_data = get_ip_geolocation(final_ip)
        abuse_reputation = get_abuseipdb_reputation(final_ip)
        positives, total, relevant_verdicts, report_data, last_analysis_date = get_virustotal_verdict(final_ip, is_url=False)
        threatfox_info = get_threatfox_info(final_ip)
        shodan_data = check_ip_categories(final_ip)
        open_ports = get_open_ports(final_ip)
        alienvault_info = get_alienvault_otx_info(final_ip)
        conclusion = generate_conclusion(alienvault_info)
        
        if positives is not None:
            results = {
                'IP': final_ip,
                'Hostname': geo_data['hostname'],
                'País': geo_data['country'],
                'ASN': geo_data['asn'],
                'Geolocalização': geo_data['location'],
                'Reputação (AbuseIPDB)': abuse_reputation,
                'VirusTotal Positivos': f"{positives}/{total}",
                'Data da Última Análise': last_analysis_date,
                'Detecções': ', '.join(f"{engine}: {result}" for engine, result in relevant_verdicts) if relevant_verdicts else 'Nenhuma detecção encontrada.',
                'Portas Abertas': ', '.join(str(port) for port in open_ports),
                'AlienVault OTX': ', '.join(f"{category}: {'; '.join(info)}" for category, info in alienvault_info.items()) if alienvault_info else 'Nenhuma informação de ameaça encontrada',
                'Conclusão': conclusion,
                **shodan_data,
                **threatfox_info
            }

            # Salvar os resultados em um arquivo HTML
            filename = 'resultados_analise.html'
            save_results_to_html(results, filename)

            # Abrir o arquivo HTML no navegador
            webbrowser.open(f'file://{os.path.realpath(filename)}')

        else:
            print("Não foi possível obter o veredito da análise.")
    else:
        is_https, final_url = check_url_protocol(input_value)
        ssl_verification = check_ssl(final_url) if isinstance(is_https, bool) else is_https
        
        positives, total, relevant_verdicts, report_data, last_analysis_date = get_virustotal_verdict(final_url)
        urlhaus_info = check_urlhaus(final_url)
        threatfox_info = get_threatfox_info(final_url)
        
        if positives is not None:
            domain = extract_domain(final_url)
            whois_info = get_whois_info(domain)
            results = {
                'URL': final_url,
                'Protocolo': 'HTTPS' if is_https else 'HTTP',
                'SSL': ssl_verification,
                'VirusTotal Positivos': f"{positives}/{total}",
                'Data da Última Análise': last_analysis_date,
                'Detecções': ', '.join(f"{engine}: {result}" for engine, result in relevant_verdicts) if relevant_verdicts else 'Nenhuma detecção encontrada.',
                **whois_info,
                **urlhaus_info,
                **threatfox_info
            }

            # Salvar os resultados em um arquivo HTML
            filename = 'resultados_analise.html'
            save_results_to_html(results, filename)

            # Abrir o arquivo HTML no navegador
            webbrowser.open(f'file://{os.path.realpath(filename)}')

        else:
            print("Não foi possível obter o veredito da análise.")

if __name__ == "__main__":
    main()

# ### Script criado por Marcelo Bentes ###
