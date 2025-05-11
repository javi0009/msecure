from datetime import datetime
from .utils import print_error, print_ok, print_step, print_warn
import subprocess

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