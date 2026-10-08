# ADR-002: Adopción de Go para el Núcleo del Cliente y Servidor

## Estado
Aprobado (Fase 0)

## Contexto
El sistema VPN debe ejecutarse tanto en servidores Linux de alto rendimiento como en múltiples sistemas operativos de escritorio (Linux, Windows, macOS) y potencialmente en plataformas móviles (Android, iOS).
Implementar la pila de red y el protocolo de manera independiente en C, Rust, Kotlin, Swift y C# multiplicaría exponencialmente el esfuerzo de mantenimiento y la probabilidad de discrepancias de seguridad o bugs de protocolo.

## Decisión
Desarrollar el núcleo de la solución (`ithera-core`) íntegramente en **Go (Golang)**:
1. El backend (`cmd/itherasrv`) y los clientes CLI/Daemon (`cmd/itheraclient`, `cmd/itheractl`) comparten directamente los paquetes internos (`internal/crypto`, `internal/device`, `internal/tun`, `internal/routing`, `internal/transport`).
2. Para plataformas móviles (Android/iOS), el core en Go puede exportarse como biblioteca compartida (C-archive/AAR/XCFramework) interactuando con las APIs nativas del SO (`VpnService` y `NEPacketTunnelProvider`).

## Consecuencias

### Positivas
- **Base de Código Unificada:** Una única implementación de la lógica de cifrado, UAPI, ofuscación y enrutamiento.
- **Rendimiento y Concurrencia:** Modelo de concurrencia nativo de Go (goroutines y canales) con pools de memoria (`sync.Pool`) para alta tasa de paquetes sin contención.
- **Seguridad de Memoria:** Ausencia de vulnerabilidades clásicas de corrupción de memoria (use-after-free, buffer overflows no controlados) inherentes a C/C++.
- **Portabilidad Cruzada:** Soporte de compilación cruzada nativo (`GOOS` y `GOARCH`).

### Negativas / Desafíos
- **Recolector de Basura (Garbage Collector):** Puede introducir pausas mínimas si no se gestionan las alocaciones de buffers mediante `sync.Pool`.
- **Límite de Memoria en Extensiones de iOS (Jetsam):** En iOS, las extensiones de túnel imponen límites estrictos (~15-35 MB). Requiere optimizar flags de compilación (`-s -w`), `GOGC=20` y limitar buffers en reposo.
