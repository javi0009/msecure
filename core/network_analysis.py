import subprocess
import time
from .vt_utils import consultar_ip_virustotal
from .utils import print_error, hex_to_ip_port, es_ip_privada, es_puerto_sospechoso, es_socket_en_escucha, print_ok, print_step, print_warn

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