# ⚙️ PcServerApi Backend

[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4?logo=dotnet&logoColor=white)](https://dotnet.microsoft.com/)  
[![PowerShell](https://img.shields.io/badge/PowerShell-Scripts-5391FE?logo=powershell&logoColor=white)](https://learn.microsoft.com/powershell/)  
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Backend minimalista en **.NET 8** que permite gestionar y monitorizar servicios en un PC (ej. servidores de juegos como Minecraft, ARK, etc.).  
Expone endpoints protegidos con **JWT** para iniciar, parar, enviar comandos y consultar el estado de los servicios.  
Además incluye endpoints para **logs en vivo** y **apagado remoto del equipo**.

---

## ✨ Funcionalidades

- 🔐 **Autenticación JWT** (usuarios y roles desde `users.json`).
- 📂 **Gestión de servicios** (`services.json`):
  - Iniciar / parar servicios con scripts PowerShell.
  - Comprobar estado (`offline`, `starting`, `running`).
  - Enviar comandos al proceso (ej: `say Hola` en Minecraft).
- 📝 **Logs en vivo**:
  - Se almacenan en `C:\PcServerApi\logs\{id}.log`.
  - Acceso vía API.
- 🛑 **Apagar servicios** de forma controlada.
- ⏻ **Apagar el PC** remoto (endpoint `/system/shutdown`).
- ⚡ **CORS habilitado** para conexión desde frontend React.

---

## 📂 Archivos de configuración

### `users.json`
Define los usuarios que pueden acceder al panel:
```json
[
  {
    "Username": "admin",
    "Password": "1234",
    "Roles": ["admin", "dimensionesPerdidas"]
  }
]

### `services.json`

Define los servicios gestionados:

```json
[
  {
    "Id": "dimensionesPerdidas",
    "Name": "Minecraft Dimensiones Perdidas",
    "Path": "C:\\Users\\Fenix\\Desktop\\DimensionesPerdidas\\ServerStart.ps1",
    "Host": "127.0.0.1",
    "Port": 25565
  }
]
```

* `Id`: identificador único.
* `Name`: nombre mostrado en frontend.
* `Path`: ruta al script `.ps1` que arranca el servicio.
* `Host` / `Port`: usados para comprobar si el servicio está corriendo.

---

## 🚀 Endpoints principales

### Auth

* `POST /auth/login` → devuelve JWT

### Servicios

* `GET /services` → lista de servicios
* `POST /services/{id}/start` → inicia un servicio
* `POST /services/{id}/stop` → detiene un servicio
* `POST /services/{id}/command` → envía comando al proceso
* `GET /services/{id}/status` → estado actual
* `GET /services/{id}/logs` → últimos 200 logs

### Sistema

* `POST /system/shutdown` → apaga el PC (requiere permisos de admin en Windows)

---

## ⚙️ Requisitos

* Windows 10/11 (ejecuta PowerShell y servicios)
* [.NET 8 SDK](https://dotnet.microsoft.com/download)
* Permisos de administrador para apagar el sistema

---

## 🛠️ Instalación y ejecución

1. Clona el repositorio:

   ```bash
   git clone https://github.com/tuusuario/pcserverapi-backend.git
   cd pcserverapi-backend
   ```

2. Crea carpetas necesarias:

   ```bash
   mkdir C:\PcServerApi
   mkdir C:\PcServerApi\logs
   ```

3. Crea los archivos de configuración:

   * `C:\PcServerApi\users.json`
   * `C:\PcServerApi\services.json`

4. Ejecuta el backend:

   ```bash
   dotnet run --project PcServerApi
   ```

5. El servicio escuchará en:

   ```
   http://localhost:5000
   ```

---

## 🔒 Seguridad

* JWT firmado con clave simétrica (`appsettings` o hardcode base64).
* Los roles controlan qué servicios puede gestionar un usuario.
* Se recomienda exponer el backend sólo en LAN/VPN privada.

---

## 📌 TODO / Mejoras futuras

* [ ] Métricas de CPU/RAM de cada proceso.
* [ ] Integración con otros juegos (ARK, Valheim, Rust).
* [ ] Gestión de usuarios desde API en lugar de JSON.
* [ ] WebSocket para logs en tiempo real.

---

## 📄 Licencia

MIT © 2025 — Backend de **PcServerApi**
