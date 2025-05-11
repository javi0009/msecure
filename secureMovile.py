import subprocess
import time
import json
import shutil
import os
import hashlib
import requests
import sys
from tqdm import tqdm
from dotenv import load_dotenv
from fpdf import FPDF
from fpdf.enums import XPos, YPos
from datetime import datetime

load_dotenv(override=True)

def print_step(msg):
    print(f"{CYAN}[*] {msg}{RESET}")

def print_ok(msg):
    print(f"{GREEN}[✓] {msg}{RESET}")

def print_warn(msg):
    print(f"{YELLOW}[!] {msg}{RESET}")

def print_error(msg):
    print(f"{RED}[✗] {msg}{RESET}")

# Colores ANSI para terminal
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RESET = "\033[0m"
BOLD = "\033[1m"

if os.path.isdir("output"):
    print_ok("Carpeta output existe")
else:
    os.makedirs("output")
    print_step("Carpeta output creada")

API_KEY = os.environ.get("API_KEY") 

def wait_device():
    print_step("Esperando a que se conecte un dispositivo ADB...")
    while True:
        try:
            result = subprocess.check_output(['adb', 'devices']).decode()
        except FileNotFoundError:
            print_error("ADB no está instalado o no está en el PATH.")
            exit(1)

        lines = result.strip().split('\n')[1:]
        connected = [line.split()[0] for line in lines if '\tdevice' in line]

        if connected:
            print_ok(f"Dispositivo detectado: {connected[0]}")
            return connected[0]
        else:
            unauthorized = [line for line in lines if 'unauthorized' in line]
            if unauthorized:
                print_warn("Dispositivo conectado pero no autorizado. Revisa el teléfono y acepta la depuración USB.")
        time.sleep(2)

def is_rooted():
    print("\n")
    print_step("Comprobando si el dispositivo está rooteado...")
    try:
        output = subprocess.check_output(['adb', 'shell', 'which su'])
        if output.strip():
            print_ok("Acceso root detectado.")
            return True
        else:
            print_ok("El dispositivo no está rooteado.")
            return False
    except subprocess.CalledProcessError:
        print_ok("El dispositivo no está rooteado.")
        return False

def check_version_status():
    print("\n")
    print_step("Comparando versión de Android con lista de parches conocidos...")

    try:
        android_version = subprocess.check_output(['adb', 'shell', 'getprop', 'ro.build.version.release']).decode().strip()
        sdk = subprocess.check_output(['adb', 'shell', 'getprop', 'ro.build.version.sdk']).decode().strip()
        security_patch = subprocess.check_output(['adb', 'shell', 'getprop', 'ro.build.version.security_patch']).decode().strip()
    except subprocess.CalledProcessError:
        print_error("No se pudo obtener la versión del dispositivo.")
        return {}

    try:
        with open("utils/android_patches.txt", "r") as f:
            patch_dates = [line.strip() for line in f if line.strip()]
            latest_patch = max(patch_dates)
    except FileNotFoundError:
        print_error("No se encontró el archivo android_patches.txt.")
        return {}

    status = "Actualizado"
    recomendacion = "Ninguna"

    try:
        fecha_actual = datetime.strptime(security_patch, "%Y-%m-%d")
        fecha_referencia = datetime.strptime(latest_patch, "%Y-%m-%d")

        if fecha_actual < fecha_referencia:
            status = "Desactualizado"
            recomendacion = f"Actualiza al menos al parche del {latest_patch}"
    except ValueError:
        print_warn("Formato de fecha inválido en el parche de seguridad.")
        status = "Desconocido"
        recomendacion = "Verifica manualmente la fecha del parche."

    print_func = print_ok if status == "Actualizado" else print_warn
    print_func(f"Parche: {security_patch} → {status}")

    return {
        "security_patch": security_patch,
        "latest_known_patch": latest_patch,
        "status": status,
        "recomendacion": recomendacion
    }

def dangerous_permissions():
    print("\n")
    print_step("Analizando permisos peligrosos de las aplicaciones...")
    result = subprocess.check_output(['adb', 'shell', 'pm', 'list', 'packages', '-3'])
    packages = [line.split(':')[1] for line in result.decode().splitlines()]

    dangerous = [
        'READ_SMS: granted=true',               # Leer mensajes de texto (muy sensible)
        'RECEIVE_SMS: granted=true',            # Detectar y recibir mensajes (usado por spyware)
        'RECORD_AUDIO: granted=true',           # Activar micrófono y grabar audio
        'CAMERA: granted=true',                 # Acceso directo a la cámara
        'ACCESS_FINE_LOCATION: granted=true',   # Ubicación precisa (GPS)
        'READ_CONTACTS: granted=true',          # Leer lista de contactos
        'READ_CALL_LOG: granted=true',          # Leer historial de llamadas
        'PROCESS_OUTGOING_CALLS: granted=true', # Detectar llamadas salientes
        'READ_PHONE_STATE: granted=true',       # Obtener número, red, estado de llamadas
        'SEND_SMS: granted=true'                # Enviar mensajes (riesgo de fraudes)
        ]


    danger = {}

    for pkg in packages:
        perms = subprocess.check_output(['adb', 'shell', 'dumpsys', 'package', pkg])
        found = []
        for line in perms.decode().splitlines():
            for key in dangerous:
                if key in line:
                    found.append(line.strip())
        if found:
            danger[pkg] = found

    print_ok(f"Aplicaciones con permisos sensibles detectadas: {len(danger)}")
    return danger
    
def ps_dump():
    print("\n")
    print_step("Obteniendo lista de procesos en ejecución...")
    try:
        result = subprocess.check_output(['adb', 'shell', 'ps']).decode()
        print_ok("Procesos listados correctamente, comprobando malware...")
        process_danger = []
        with open('utils/procesos_peligrosos_android.txt', 'r') as peligrosos:
            for line in peligrosos:
                if line in result:
                    print_warn(f"Posible proceso malicioso: {line}")
                    process_danger.append(line)

        return process_danger

    except subprocess.CalledProcessError:
        print_error("Error al obtener los servicios.")
        return "No se pudieron obtener los servicios en ejecución."   

def obtener_paquetes_usuario():
    print_step("Listando paquetes de usuario en el dispositivo...")
    paquetes = subprocess.check_output(["adb", "shell", "pm", "list", "packages", "-3"]).decode().strip().splitlines()
    nombres = [linea.split(":")[1].strip() for linea in paquetes]
    print_ok(f"{len(nombres)} paquetes de usuario encontrados.")
    return nombres

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
    
def analizar():
    paquetes = obtener_paquetes_usuario()
    print("\n")
    print_step("Consultando VirusTotal por nombre de paquete...")
    print("\n")
    barra = tqdm(paquetes, desc="Analizando apps", unit="app", leave=True, dynamic_ncols=True, file=sys.stdout)
    ret = []

    for nombre in barra:
        detecciones, total = consultar_virustotal_por_nombre(nombre)

        if detecciones is None:
            ret.append(f"{nombre}: No encontrado")
            estado = "No encontrado"
        elif detecciones > 0:
            ret.append(f"{nombre}: {detecciones}/{total}")
            estado = f"💀 posible app maliciosa con detecciones de {detecciones}/{total} antivirus"
        else:
            ret.append(f"{nombre}: Limpio")
            estado = "✔️ Limpio"

        barra.set_postfix_str(f"{nombre}: {estado}")
        time.sleep(15)  # Evitar límites de la API gratuita

    print("\n\033[92m✔️ Análisis completado.\033[0m")
    return ret

def device_info():
    print("\n")
    print_step("Recopilando información del dispositivo...")

    props = {
        "model": "ro.product.model",
        "manufacturer": "ro.product.manufacturer",
        "android_version": "ro.build.version.release",
        "sdk": "ro.build.version.sdk",
        "platform": "ro.board.platform",
        "hardware": "ro.hardware",
        "serial": "ro.serialno",
    }

    info = {}
    for key, prop in props.items():
        try:
            value = subprocess.check_output(['adb', 'shell', 'getprop', prop]).decode().strip()
            info[key] = value
        except subprocess.CalledProcessError:
            info[key] = "Desconocido"

    print_ok("Información del dispositivo obtenida correctamente.")
    return info

def save_report(data, filename="output/reporte_seguridad_movil.json"):
    with open(filename, "w", encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    print_ok(f"Reporte guardado como {filename}")

def get_prop():
    print("\n")
    print_step("Comprobando características del sistema...")
    result = subprocess.check_output(['adb', 'shell', 'getprop']).decode()
    ret = prop_compare(result)
    return ret

def prop_compare(result):
    output = []
    try:
        with open("utils/prop_compare.txt", "r", encoding="utf-8") as f:
            for linea in f:
                if ";" not in linea:
                    continue
                clave, descripcion = linea.strip().split(";", 1)
                clave = clave.strip()
                descripcion = descripcion.strip()

                if clave in result:
                    print_ok(descripcion)
                    output.append(descripcion)
                else:
                    print_error(f"No cumple: {descripcion}")
                    output.append(f"No cumple: {descripcion}")
    except FileNotFoundError:
        print_error("No se encontró el archivo prop_compare.txt")
    return output


def security_analysis():
    print("\n")
    print_step("Iniciando análisis de seguridad...")
    report = {
        "rooted" : is_rooted(),
        "device_info": device_info(),
        "version_status": check_version_status(),
        "dangerous_permissions" : dangerous_permissions(),
        "prop" : get_prop(),
        "danger_ps" : ps_dump(),
        "virustotal_analysis": analizar(),
    }
    save_report(report)

def generar_pdf(data, output_file="output/reporte_seguridad_movil.pdf"):
    class PDF(FPDF):
        def header(self):
            self.set_font("Times", "B", 14)
            self.cell(0, 10, "Informe de Seguridad - Dispositivo Android", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
            self.ln(5)

        def section_title(self, title):
            self.set_font("Times", "B", 12)
            self.set_fill_color(220, 220, 220)
            self.cell(0, 10, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT, fill=True)

        def add_list(self, items):
            self.set_font("Times", "", 10)
            for item in items:
                self.multi_cell(180, 8, f"- {item}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        def permission_table(self, permissions):
            self.set_font("Times", "B", 10)
            self.set_fill_color(240, 240, 240)
            self.cell(60, 8, "Aplicación", border=1, fill=True)
            self.cell(130, 8, "Permisos peligrosos", border=1, fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.set_font("Times", "", 9)

            for app, perms in permissions.items():
                perm_str = ", ".join(
                    p.split(".")[-1].split(":")[0].replace("_", " ").title()
                    for p in perms
                )
                self.cell(60, 6, app, border=1)
                self.cell(130, 6, perm_str, border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf = PDF()
    pdf.add_page()

    if "device_info" in data:
        pdf.section_title("Información del dispositivo")
        for key, val in data["device_info"].items():
            pdf.set_font("Times", "", 10)
            pdf.cell(0, 8, f"{key.capitalize().replace('_', ' ')}: {val}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    if "version_status" in data:
        pdf.section_title("Estado de versión de seguridad")
        for key, val in data["version_status"].items():
            pdf.set_font("Times", "", 10)
            pdf.cell(0, 8, f"{key.replace('_', ' ').capitalize()}: {val}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    if "rooted" in data:
        pdf.section_title("Root")
        pdf.set_font("Times", "", 10)
        estado = "Sí" if data["rooted"] else "No"
        pdf.cell(0, 8, f"Dispositivo con acceso root: {estado}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    if "dangerous_permissions" in data:
        pdf.section_title("Permisos peligrosos")
        pdf.permission_table(data["dangerous_permissions"])
        pdf.add_page()

    if "prop" in data:
        pdf.section_title("Propiedades de seguridad")
        pdf.add_list(data["prop"])

    if "danger_ps" in data:
        pdf.section_title("Procesos sospechosos")
        pdf.add_list(data["danger_ps"])

    if "virustotal_analysis" in data:
        pdf.section_title("Resultado análisis VirusTotal")
        pdf.add_list(data["virustotal_analysis"])

    pdf.output(output_file)
    print(f"[+] PDF generado: {output_file}")

def main():
    print_banner()
    wait_device()
    security_analysis()
    print_ok("Análisis completado correctamente.\n")
    print_step("Generando informe PDF...")
    with open("output/reporte_seguridad_movil.json", "r", encoding="utf-8") as f:
        data = json.load(f)
        generar_pdf(data)

def print_banner():
    banner = r"""
  _________                                       _____              .__.__          
 /   _____/ ____   ____  __ _________   ____     /     \   _______  _|__|  |   ____  
 \_____  \_/ __ \_/ ___\|  |  \_  __ \_/ __ \   /  \ /  \ /  _ \  \/ /  |  | _/ __ \ 
 /        \  ___/\  \___|  |  /|  | \/\  ___/  /    Y    (  <_> )   /|  |  |_\  ___/ 
/_______  /\___  >\___  >____/ |__|    \___  > \____|__  /\____/ \_/ |__|____/\___  >
        \/     \/     \/                   \/          \/                         \/ 
        Análisis de Seguridad Android
"""
    print(banner)

if __name__ == "__main__":
    main()