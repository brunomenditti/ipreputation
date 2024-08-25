import streamlit as st
import requests
from datetime import datetime
from pyppeteer import launch
import asyncio
import base64
from io import BytesIO

# Carregar as API Keys do secrets
VT_API_KEY = st.secrets["virus_total"]["api_key"]
ABUSEIPDB_API_KEY = st.secrets["abuseipdb"]["api_key"]

# Configurações da página
st.set_page_config(page_title="Verificador de Reputação de IP - VirusTotal e AbuseIPDB", page_icon="🛡️", layout="wide")

# Título do aplicativo
st.title("🛡️ Verificador de Reputação de IP")

# Campo de entrada para o IP
ip_address = st.text_input("Digite o endereço IP que deseja verificar:", placeholder="Exemplo: 8.8.8.8")

async def take_screenshot(url, file_name):
    browser = await launch(headless=True)
    page = await browser.newPage()
    await page.goto(url)
    await page.screenshot({'path': file_name})
    await browser.close()

    # Ler a imagem como base64
    with open(file_name, "rb") as img_file:
        img_str = base64.b64encode(img_file.read()).decode()

    href = f'<a href="data:file/png;base64,{img_str}" download="{file_name}">Download Screenshot</a>'
    return href

def check_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "x-apikey": VT_API_KEY
    }
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})

        # Estatísticas de análise
        analysis_stats = attributes.get("last_analysis_stats", {})
        harmless = analysis_stats.get("harmless", 0)
        malicious = analysis_stats.get("malicious", 0)
        suspicious = analysis_stats.get("suspicious", 0)
        undetected = analysis_stats.get("undetected", 0)
        timeout = analysis_stats.get("timeout", 0)

        # Última análise
        last_analysis_date = attributes.get("last_analysis_date")
        if last_analysis_date:
            last_analysis_date = datetime.fromtimestamp(last_analysis_date).strftime('%d/%m/%Y %H:%M:%S')

        # Reputação
        reputation = attributes.get("reputation", "N/A")

        # País
        country = attributes.get("country", "N/A")

        # Tags
        tags = attributes.get("tags", [])

        # ASN
        asn = attributes.get("asn", "N/A")
        as_owner = attributes.get("as_owner", "N/A")

        return {
            "country": country,
            "asn": f"{asn} ({as_owner})",
            "last_analysis_date": last_analysis_date,
            "harmless": harmless,
            "malicious": malicious,
            "suspicious": suspicious,
            "undetected": undetected,
            "timeout": timeout,
            "reputation": reputation,
            "tags": tags,
            "link": f"https://www.virustotal.com/gui/ip-address/{ip}"
        }
    else:
        st.error(f"Erro ao consultar o VirusTotal: {response.status_code}")
        return None

def check_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    querystring = {
        "ipAddress": ip,
        "maxAgeInDays": "90"
    }
    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }
    response = requests.get(url, headers=headers, params=querystring)

    if response.status_code == 200:
        data = response.json().get("data", {})

        # Dados relevantes do AbuseIPDB
        abuse_score = data.get("abuseConfidenceScore", "N/A")
        country = data.get("countryCode", "N/A")
        isp = data.get("isp", "N/A")
        total_reports = data.get("totalReports", "N/A")
        last_reported_at = data.get("lastReportedAt", "N/A")

        return {
            "abuse_score": abuse_score,
            "country": country,
            "isp": isp,
            "total_reports": total_reports,
            "last_reported_at": last_reported_at,
            "link": f"https://www.abuseipdb.com/check/{ip}"
        }
    else:
        st.error(f"Erro ao consultar o AbuseIPDB: {response.status_code}")
        return None

# Botão para verificar
if st.button("Verificar Reputação"):
    if ip_address:
        with st.spinner("Consultando VirusTotal e AbuseIPDB..."):
            vt_data = check_virustotal(ip_address)
            abuseipdb_data = check_abuseipdb(ip_address)

        if vt_data and abuseipdb_data:
            st.subheader(f"Resultados para o IP: {ip_address}")

            # Exibição horizontal dos resultados com 3 colunas por linha
            row1_col1, row1_col2, row1_col3 = st.columns(3)
            row2_col1, row2_col2, row2_col3 = st.columns(3)
            row3_col1, row3_col2, row3_col3 = st.columns(3)

            # Linha 1
            row1_col1.metric("VirusTotal - 🗺️ País", vt_data["country"])
            row1_col2.metric("VirusTotal - 🏢 ASN", vt_data["asn"])
            row1_col3.metric("VirusTotal - 📅 Última Análise", vt_data["last_analysis_date"])

            # Linha 2
            row2_col1.metric("VirusTotal - ✅ Harmless", vt_data["harmless"])
            row2_col2.metric("VirusTotal - ❌ Malicious", vt_data["malicious"])
            row2_col3.metric("VirusTotal - ⚠️ Suspicious", vt_data["suspicious"])

            # Linha 3
            row3_col1.metric("VirusTotal - ❓ Undetected", vt_data["undetected"])
            row3_col2.metric("VirusTotal - ⏰ Timeout", vt_data["timeout"])
            row3_col3.metric("VirusTotal - ⭐ Reputação", vt_data["reputation"])

            st.markdown(f"[🔗 Ver mais detalhes no VirusTotal]({vt_data['link']})")

            # Botão para gerar e baixar a screenshot do VirusTotal
            if st.button("Obter Screenshot do VirusTotal"):
                screenshot_link = asyncio.run(take_screenshot(vt_data["link"], "virustotal_screenshot.png"))
                st.markdown(screenshot_link, unsafe_allow_html=True)

            st.markdown("---")

            # Exibição dos resultados do AbuseIPDB
            st.subheader("AbuseIPDB")

            row4_col1, row4_col2, row4_col3 = st.columns(3)
            row5_col1, row5_col2, row5_col3 = st.columns(3)

            # Linha 4
            row4_col1.metric("AbuseIPDB - 🗺️ País", abuseipdb_data["country"])
            row4_col2.metric("AbuseIPDB - 🏢 ISP", abuseipdb_data["isp"])
            row4_col3.metric("AbuseIPDB - 📊 Abuse Score", abuseipdb_data["abuse_score"])

            # Linha 5
            row5_col1.metric("AbuseIPDB - 📅 Último Relato", abuseipdb_data["last_reported_at"])
            row5_col2.metric("AbuseIPDB - 📈 Total de Relatos", abuseipdb_data["total_reports"])
            row5_col3.markdown(f"[🔗 Ver mais detalhes no AbuseIPDB]({abuseipdb_data['link']})")

            # Botão para gerar e baixar a screenshot do AbuseIPDB
            if st.button("Obter Screenshot do AbuseIPDB"):
                screenshot_link = asyncio.run(take_screenshot(abuseipdb_data["link"], "abuseipdb_screenshot.png"))
                st.markdown(screenshot_link, unsafe_allow_html=True)

            # Se houver tags no VirusTotal, mostre-as
            if vt_data["tags"]:
                st.markdown("**VirusTotal - Tags associadas:**")
                st.write(", ".join(vt_data["tags"]))
    else:
        st.warning("Por favor, insira um endereço IP válido.")
