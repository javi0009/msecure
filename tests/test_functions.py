import os
from secureMobile import (
    consultar_ip_virustotal,
    es_socket_en_escucha,
    es_puerto_sospechoso,
    print_step,
    print_ok,
    print_warn
)

def test_ip_virustotal():
    test_ip = "185.220.101.1"
    print_step(f"Consultando VirusTotal para IP: {test_ip}")
    detecciones, total = consultar_ip_virustotal(test_ip)

    if detecciones is not None:
        print_ok(f"Detecciones: {detecciones}/{total}")
    else:
        print_warn("No se pudo obtener información de VirusTotal.")

def test_socket_escucha_y_puerto_sospechoso():
    print_step("Simulando socket en escucha + puerto sospechoso...")

    simulada = {
        "proto": "TCP",
        "local": "0.0.0.0:55555",
        "state": "0A",
    }

    ip_local, puerto_local = simulada["local"].split(":")
    state = simulada["state"]

    if es_socket_en_escucha(state, ip_local):
        print_warn(f"Puerto en escucha accesible públicamente: {ip_local}:{puerto_local}")

    if es_puerto_sospechoso(puerto_local):
        print_warn(f"Puerto considerado sospechoso por heurística: {puerto_local}")
    else:
        print_ok(f"Puerto {puerto_local} no considerado sospechoso por umbral o lista.")

    print_ok("✔️ Simulación completada.")


if __name__ == "__main__":
    import sys
    if "ip" in sys.argv:
        test_ip_virustotal()
    elif "puerto" in sys.argv:
        test_socket_escucha_y_puerto_sospechoso()
    elif "all" in sys.argv:
        test_ip_virustotal()
        test_socket_escucha_y_puerto_sospechoso()
