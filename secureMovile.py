import subprocess
import time
import json
import os
from dotenv import load_dotenv
from fpdf import FPDF
from fpdf.enums import XPos, YPos
from core.network_analysis import analizar_conexiones_por_heuristica
from core.utils import print_error, print_ok, print_step, print_warn, tcp_state_human
from core.adb_interface import get_prop, ps_dump, device_info, check_version_status
from core.security_checks import analizar, is_rooted, dangerous_permissions

if os.path.isdir("output"):
    print_ok("Carpeta output existe")
else:
    os.makedirs("output")
    print_step("Carpeta output creada")

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

def save_report(data, filename="output/reporte_seguridad_movil.json"):
    with open(filename, "w", encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    print_ok(f"Reporte guardado como {filename}")

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
                try:
                    texto = f"- {str(item)}".replace("\n", " ").replace("\r", " ")
                    if len(texto) > 250:
                        texto = texto[:247] + "..."
                    self.multi_cell(0, 8, texto, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                except Exception as e:
                    print(e)


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
                    f"[{c['proto']}] {c['local']} - {c['remote']} [{estado_tcp}] - {c['motivo']} [VT: {virustotal_info}]"
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