import subprocess
import time

def wait_device():
    print("Esperando a un dispositivo...")
    while True:
        result = subprocess.check_output(['adb', 'devices']).decode()
        lines = result.strip().split('\n')[1:]
        connected = [line.split()[0] for line in lines if 'device' in line]
        if connected:
            print(f"Dispositivo detectado: {connected[0]}")
            return connected[0]
        time.sleep(2)

def is_rooted():
    try:
        print("Comprobando root...")
        output = subprocess.check_output(['adb', 'shell', 'which su'])
        return output.strip() != b''
    except subprocess.CalledProcessError:
        return False

def main():
    wait_device()
    rooted = is_rooted()
    print(rooted)

if __name__ == "__main__":
    main()
