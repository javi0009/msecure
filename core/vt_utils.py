from dotenv import load_dotenv
from .utils import print_warn
import requests
import os

# Ruta relativa a la carpeta del script actual
dotenv_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env')
load_dotenv(dotenv_path=dotenv_path, override=True)
API_KEY = os.environ.get("API_KEY")

def consultar_virustotal_por_nombre(nombre_paquete):
    url = f"https://www.virustotal.com/api/v3/search?query={nombre_paquete}"
    headers = {"x-apikey": API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        datos = response.json()
        matches = datos.get("data", [])
        if matches:
            archivo = matches[0]
            stats = archivo["attributes"]["last_analysis_stats"]
            detecciones = stats["malicious"]
            total = sum(stats.values())
            return detecciones, total
        else:
            return None, None
    else:
        print_warn(f"Error en consulta para {nombre_paquete} ({response.status_code})")
        return None, None
    

def consultar_ip_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            datos = response.json()
            stats = datos.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            detecciones = stats.get("malicious", 0)
            total = sum(stats.values())
            return detecciones, total
        else:
            print_warn(f"Error en consulta para {ip} ({response.status_code})")
            return None, None
    except Exception as e:
        print_warn(f"Excepción en consulta VirusTotal: {e}")
        return None, None