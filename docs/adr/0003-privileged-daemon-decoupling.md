# ADR-003: Arquitectura Desacoplada: UI No Privilegiada y Daemon Privilegiado

## Estado
Aprobado (Fase 0)

## Contexto
La creación de interfaces de red virtuales (TUN), la modificación de las tablas de enrutamiento del kernel y la configuración de reglas de cortafuegos (Kill Switch) requieren privilegios elevados (`CAP_NET_ADMIN` / `root` en Linux, `SYSTEM` / `Administrator` en Windows).
Sin embargo, ejecutar una aplicación completa de escritorio (con frameworks gráficos como Wails, Electron, Flutter o GTK) bajo privilegios elevados viola flagrantemente el principio de mínimo privilegio (*Principle of Least Privilege*) y expone todo el sistema ante vulnerabilidades en librerías de UI o renderizado.

## Decisión
Dividir la arquitectura del cliente en dos procesos completamente desacoplados:
1. **Daemon Privilegiado (`itherad`):** Se ejecuta en segundo plano como servicio del sistema (Windows Service, systemd daemon o daemon launchd). Posee los privilegios necesarios exclusivamente para gestionar el dispositivo TUN, las reglas de firewall y el enrutamiento.
2. **Cliente de Usuario / UI No Privilegiada:** Se ejecuta en el espacio del usuario estándar sin permisos administrativos.
3. **Canal IPC Seguro:** Ambos procesos se comunican mediante mecanismos de comunicación inter-proceso locales con control de acceso estricto (Named Pipes con ACLs en Windows, Unix Domain Sockets con permisos `0600` en Linux/macOS).

## Consecuencias

### Positivas
- **Defensa en Profundidad:** El proceso expuesto al usuario y a frameworks de interfaz gráfica no puede comprometer el sistema operativo ni escalar privilegios.
- **Persistencia del Túnel:** El daemon puede mantener el túnel y el Kill Switch activos incluso si la UI se cierra, crashea o el usuario cambia de sesión.

### Negativas / Desafíos
- **Complejidad de IPC:** Requiere diseñar un protocolo de serialización (JSON-RPC o Protobuf), gestionar reconexiones de socket y controlar concurrencia entre clientes y daemon.
- **Empaquetado e Instalación:** Los instaladores de la aplicación deben registrar servicios en el sistema operativo durante la instalación.
