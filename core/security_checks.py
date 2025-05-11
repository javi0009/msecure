import sys
import time

from tqdm import tqdm
from .utils import print_step, print_ok, print_error, print_warn
from .vt_utils import consultar_virustotal_por_nombre
import subprocess

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

def obtener_paquetes_usuario():
    print("\n")
    print_step("Listando paquetes de usuario en el dispositivo...")
    paquetes = subprocess.check_output(["adb", "shell", "pm", "list", "packages", "-3"]).decode().strip().splitlines()
    nombres = [linea.split(":")[1].strip() for linea in paquetes]
    print_ok(f"{len(nombres)} paquetes de usuario encontrados.")
    return nombres