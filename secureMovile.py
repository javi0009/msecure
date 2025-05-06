import subprocess
import time
import json
import shutil

# Colores ANSI para terminal
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RESET = "\033[0m"
BOLD = "\033[1m"

def print_step(msg):
    print(f"{CYAN}[*] {msg}{RESET}")

def print_ok(msg):
    print(f"{GREEN}[✓] {msg}{RESET}")

def print_warn(msg):
    print(f"{YELLOW}[!] {msg}{RESET}")

def print_error(msg):
    print(f"{RED}[✗] {msg}{RESET}")

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
    print_step("Analizando permisos peligrosos de las aplicaciones...")
    result = subprocess.check_output(['adb', 'shell', 'pm', 'list', 'packages'])
    packages = [line.split(':')[1] for line in result.decode().splitlines()]

    dangerous = [
        'READ_SMS',               # Leer mensajes de texto (muy sensible)
        'RECEIVE_SMS',            # Detectar y recibir mensajes (usado por spyware)
        'RECORD_AUDIO',           # Activar micrófono y grabar audio
        'CAMERA',                 # Acceso directo a la cámara
        'ACCESS_FINE_LOCATION',   # Ubicación precisa (GPS)
        'READ_CONTACTS',          # Leer lista de contactos
        'READ_CALL_LOG',          # Leer historial de llamadas
        'PROCESS_OUTGOING_CALLS', # Detectar llamadas salientes
        'READ_PHONE_STATE',       # Obtener número, red, estado de llamadas
        'SEND_SMS'                # Enviar mensajes (riesgo de fraudes)
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

def running_services():
    print_step("Obteniendo servicios en ejecución...")
    try:
        result = subprocess.check_output(['adb', 'shell', 'dumpsys', 'activity', 'services'])
        print_ok("Servicios listados correctamente.")
        return result.decode()
    except subprocess.CalledProcessError:
        print_error("Error al obtener los servicios.")
        return "No se pudieron obtener los servicios en ejecución."

def save_report(data, filename="reporte_seguridad_movil.json"):
    with open(filename, "w", encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    print_ok(f"Reporte guardado como {filename}")

def get_prop():
    print_step("Comprobando características del sistema...")
    result = subprocess.check_output(['adb', 'shell', 'getprop']).decode()
    ret = prop_compare(result)
    return ret

def prop_compare(result):
    output = []
    if result.find("[ro.boot.verifiedbootstate]: [green]") != -1:
        print_ok("Integridad del arranque verificada")
        output.append("Integridad del arranque verificada")
    else:
        print_error("Integridad del arranque no verificada")
        output.append("Integridad del arranque no verificada")
    
    if result.find("[ro.boot.flash.locked]: [1]") != -1:
        print_ok("Bootloader bloqueado")
        output.append("Bootloader bloqueado")
    else:
        print_error("Bootloader no bloqueado, peligro")
        output.append("Bootloader no bloqueado, peligro!")

    if result.find("[ro.boot.vbmeta.device_state]: [locked]") != -1:
        print_ok("Verificación de partición activa")
        output.append("Verificación de partición activa")
    else:
        print_error("Verificaicón de partición NO activa")
        output.append("Verificación de partición NO activa")

    if result.find("[ro.debuggable]: [0]") != -1:
        print_ok("No es una build de depuración")
        output.append("No es una build de depuración")
    else:
        print_error("Es una build de depuración")
        output.append("Es una build de depuración")

    if result.find("[ro.secure]: [1]") != -1:
        print_ok("Android en modo seguro")
        output.append("Android en modo seguro")
    else:
        print_error("Android NO está en modo seguro")
        output.append("Android NO está en modo seguro")
    return output


def security_analysis():
    print_step("Iniciando análisis de seguridad...")
    report = {
        "rooted" : is_rooted(),
        "dangerous_permissions" : dangerous_permissions(),
        "running_services" : running_services(),
        "prop" : get_prop()
    }
    save_report(report)

def main():
    print_banner()
    wait_device()
    security_analysis()
    print_ok("Análisis completado correctamente.\n")

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
