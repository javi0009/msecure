
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

def tcp_state_human(state):
    estados = {
        "01": "ESTABLISHED",
        "02": "SYN_SENT",
        "03": "SYN_RECV",
        "04": "FIN_WAIT1",
        "05": "FIN_WAIT2",
        "06": "TIME_WAIT",
        "07": "CLOSE",
        "08": "CLOSE_WAIT",
        "09": "LAST_ACK",
        "0A": "LISTEN",
        "0B": "CLOSING"
    }
    return estados.get(state.upper(), f"Desconocido ({state})")

def cargar_puertos_sospechosos(ruta="utils/puertos_sospechosos.txt"):
    try:
        with open(ruta, "r") as f:
            return set(line.strip() for line in f if line.strip().isdigit())
    except FileNotFoundError:
        print_warn(f"No se encontró el archivo de puertos sospechosos: {ruta}")
        return set()

PUERTOS_SOSPECHOSOS = cargar_puertos_sospechosos()

def hex_to_ip_port(hex_str):
    ip_hex, port_hex = hex_str.split(':')
    ip = '.'.join(str(int(ip_hex[i:i+2], 16)) for i in range(6, -2, -2))
    port = str(int(port_hex, 16))
    return ip, port

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