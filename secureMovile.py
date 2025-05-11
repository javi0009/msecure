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
    print("\n")
    print_step("Listando paquetes de usuario en el dispositivo...")
    paquetes = subprocess.check_output(["adb", "shell", "pm", "list", "packages", "-3"]).decode().strip().splitlines()
    nombres = [linea.split(":")[1].strip() for linea in paquetes]
    print_ok(f"{len(nombres)} paquetes de usuario encontrados.")
    return nombres

def analyze_proc_net(proto="tcp"):
    conexiones = []
    try:
        output = subprocess.check_output(['adb', 'shell', f'cat /proc/net/{proto}']).decode().splitlines()
    except subprocess.CalledProcessError:
        print_error(f"No se pudo leer /proc/net/{proto}")
        return conexiones

    if len(output) <= 1:
        return conexiones

    for line in output[1:]: 
        fields = line.split()
        local_hex, remote_hex, state = fields[1], fields[2], fields[3]

        local_ip, local_port = hex_to_ip_port(local_hex)
        remote_ip, remote_port = hex_to_ip_port(remote_hex)

        conexiones.append({
            "proto": proto.upper(),
            "local": f"{local_ip}:{local_port}",
            "remote": f"{remote_ip}:{remote_port}",
            "state": state,
        })

    return conexiones

def hex_to_ip_port(hex_str):
    ip_hex, port_hex = hex_str.split(':')
    ip = '.'.join(str(int(ip_hex[i:i+2], 16)) for i in range(6, -2, -2))
    port = str(int(port_hex, 16))
    return ip, port

def cargar_puertos_sospechosos(ruta="utils/puertos_sospechosos.txt"):
    try:
        with open(ruta, "r") as f:
            return set(line.strip() for line in f if line.strip().isdigit())
    except FileNotFoundError:
        print_warn(f"No se encontró el archivo de puertos sospechosos: {ruta}")
        return set()

PUERTOS_SOSPECHOSOS = cargar_puertos_sospechosos()

def es_socket_en_escucha(state, local_ip):
    return state == "0A" and (local_ip == "0.0.0.0" or local_ip == "::")

def es_puerto_sospechoso(puerto):
    return puerto in PUERTOS_SOSPECHOSOS or int(puerto) > 49152

def es_ip_privada(ip):
    return (
        ip.startswith("10.") or
        ip.startswith("192.168.") or
        ip.startswith("127.") or
        (ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31)
    )

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

def analizar_conexiones_por_heuristica():
    print_step("Análisis heurístico de conexiones TCP/UDP...")

    conexiones = analyze_proc_net("tcp") + analyze_proc_net("udp")
    sospechosas = []
    ips_consultadas = {}

    for conn in conexiones:
        ip_remota, puerto_remoto = conn["remote"].split(":")
        ip_local, puerto_local = conn["local"].split(":")
        estado = conn["state"]
        motivo = None

        if not es_ip_privada(ip_remota) and conn["proto"] == "TCP" and estado == "01":
            motivo = "Conexión saliente a IP pública"
        elif es_socket_en_escucha(estado, ip_local):
            motivo = "Puerto en escucha accesible públicamente"
        elif es_puerto_sospechoso(puerto_remoto):
            motivo = f"Puerto remoto sospechoso: {puerto_remoto}"

        if motivo:
            resultado = {"motivo": motivo}

            if ip_remota not in ips_consultadas:
                time.sleep(15)  # Respetar límite de 4 req/min en la API gratuita
                detecciones, total = consultar_ip_virustotal(ip_remota)
                if detecciones is not None:
                    resultado["virustotal"] = f"{detecciones}/{total}"
                else:
                    resultado["virustotal"] = "No encontrado"
                ips_consultadas[ip_remota] = resultado["virustotal"]
            else:
                resultado["virustotal"] = ips_consultadas[ip_remota]

            sospechosas.append({**conn, **resultado})

    if not conexiones:
        print_ok("No se encontraron conexiones TCP/UDP.")
    elif not sospechosas:
        print_step(f"{len(sospechosas)} conexiones sospechosas encontradas.")
    return {
        "total_conexiones": len(conexiones),
        "sospechosas": sospechosas
    }

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
            ret.append(f"{nombre}: posible app maliciosa con detecciones de {detecciones}/{total} antivirus")
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
        "network_heuristic": analizar_conexiones_por_heuristica(),
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
                nombre_limpio = " ".join(app.split(".")[-2:]).replace("_", " ").title()
                perm_str = ", ".join(
                    p.split(".")[-1].split(":")[0].replace("_", " ").title()
                    for p in perms
                )
                self.cell(60, 6, nombre_limpio, border=1)
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

    if "network_heuristic" in data:
        pdf.section_title("Conexiones de Red Sospechosas")
        total = data["network_heuristic"].get("total_conexiones", 0)
        sospechosas = data["network_heuristic"].get("sospechosas", [])

        pdf.set_font("Times", "", 10)
        pdf.cell(0, 8, f"Total de conexiones analizadas: {total}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.cell(0, 8, f"Conexiones marcadas como sospechosas: {len(sospechosas)}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(3)

        if sospechosas:
            conexiones_formateadas = []
            for c in sospechosas:
                virustotal_info = c.get("virustotal", "No analizado")
                estado_tcp = tcp_state_human(c.get("state", ""))
                conexiones_formateadas.append(
                    f"[{c['proto']}] {c['local']} → {c['remote']} [{estado_tcp}] → {c['motivo']} [VT: {virustotal_info}]"
                )
            pdf.add_list(conexiones_formateadas)
        else:
            pdf.cell(0, 8, "No se encontraron conexiones sospechosas.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)


    pdf.output(output_file)
    print_step(f"PDF generado: {output_file}")

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