# Msecure

Msecure es una herramienta diseñada para realizar un análisis de seguridad de un smartphone Android. Tiene las siguientes características:

- Análisis de Rooteo
- Análisis de permisos
- Análisis de aplicaciones
- Análisis de versiones
- Análisis de procesos
- Generar reporte en formato JSON
- Generar reporte en formato PDF

## Instalación

1. Tener pip instalado

```jsx
pip --version
```

Instalar pip

```jsx
apt install pip
```

1. Crear un entorno virtual con python

```jsx
python3 -m venv venv
```

1. Activar el entorno

```jsx
source venv/bin/activate #En Linux
venv\Scripts\activate #En Windows
```

1. Instalar los paquetes necesarios

```jsx
pip install -r requirements.txt
```

1. Instalar ADB (Linux)

```jsx
sudo apt update
sudo apt install android-tools-adb
```

## Uso

1. Conectar Smartphone al ordenador
2. Activar la [Depuración por USB](https://developer.android.com/studio/debug/dev-options?hl=es-419)
3. Ejecutar la herramienta

```jsx
python3 secureMovile.py
```