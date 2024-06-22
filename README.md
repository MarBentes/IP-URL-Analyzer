# IP-URL-Analyzer
# Análise Profunda de IPs e URLs: Uma Abordagem em Python para Segurança Cibernética

## Descrição
Este script em Python realiza uma análise de segurança abrangente de endereços IP e URLs. Ele integra várias APIs de serviços de segurança online para fornecer uma visão detalhada e atualizada sobre a reputação e a segurança de um determinado IP ou URL, permitindo uma resposta rápida e eficaz a ameaças potenciais.

## Funcionalidades
1. **Verificação de Protocolo e SSL:**
   - Verifica se a URL utiliza HTTPS.
   - Realiza verificação do certificado SSL para garantir sua validade.
2. **Análise de Reputação e Malware:**
   - **VirusTotal:** Avalia a presença de malware e a reputação usando múltiplas engines de segurança.
   - **AbuseIPDB:** Verifica a reputação de IPs, informando sobre o nível de confiança de atividades maliciosas.
   - **ThreatFox:** Identifica associações de IPs ou URLs com ameaças conhecidas.
   - **URLhaus:** Verifica se a URL é uma fonte conhecida de malware ou phishing.
3. **Geolocalização e Informações de Rede:**
   - **IPinfo:** Fornece dados como cidade, país, organização responsável e ASN.
4. **Detecção de Categorias de IP:**
   - **Shodan:** Identifica categorias como proxy, VPN, Tor, entre outros, e alerta sobre vulnerabilidades.
5. **Informações WHOIS:**
   - **WhoisXMLAPI:** Coleta dados WHOIS de domínios, incluindo datas de registro e informações do registrante.
6. **Inteligência de Ameaças:**
   - **AlienVault OTX:** Fornece dados sobre ameaças associadas ao IP.
7. **Geração de Relatório HTML:**
   - Os resultados são salvos em um arquivo HTML, aberto automaticamente para revisão.

## Instalação
1. Clone o repositório:
   ```bash
   git clone https://github.com/MarceloBentes/IP-URL-Analyzer.git
Instale as dependências:
bash
Copiar código
pip install -r requirements.txt
Uso
Forneça uma URL ou IP quando solicitado pelo script. As análises e consultas são realizadas automaticamente, e um relatório HTML é gerado.

Benefícios
Prevenção de Ameaças: A identificação precoce ajuda a prevenir ataques.
Tomada de Decisão Informada: As informações detalhadas ajudam na gestão de segurança.
Economia de Tempo: Automatiza verificações, poupando esforços manuais.
Facilidade de Uso: Interface simples que não requer conhecimentos técnicos avançados.
Casos de Uso
Profissionais de TI: Avaliam a segurança de IPs e URLs antes de liberar acessos em redes corporativas.
Pesquisadores de Segurança: Utilizam a ferramenta em estudos e análises.
Usuários Individuais: Verificam a segurança de sites que planejam visitar.
Conclusão
Este script é uma ferramenta poderosa e versátil para análise de segurança, integrando múltiplas fontes de dados e fornecendo uma análise abrangente, capacitando os usuários a tomar decisões informadas e agir proativamente contra ameaças cibernéticas.

FAQ
Pergunta 1: Como obtenho as chaves API necessárias para as várias integrações?
Resposta: Você precisa registrar-se nos sites dos serviços (como VirusTotal, AbuseIPDB) para obter as chaves.

Pergunta 2: Posso executar este script em qualquer sistema operacional?
Resposta: Sim, o script é compatível com qualquer sistema que suporte Python 3.

Contribuições
Contribuições para melhorar
