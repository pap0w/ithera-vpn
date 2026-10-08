# ADR-001: Selección de WireGuard como Protocolo Criptográfico Base

## Estado
Aprobado (Fase 0)

## Contexto
El proyecto `ithera-vpn` requiere un protocolo de túnel seguro, de alto rendimiento y eficiente en recursos para operar en entornos restringidos y dispositivos con baterías limitadas (móviles y portátiles).
Las alternativas históricas comunes son:
1. **OpenVPN:** Basado en OpenSSL, altamente configurable pero con una base de código masiva (~100,000 líneas de código en C), alto consumo de memoria, lentitud en handshakes y rendimiento deficiente en espacio de usuario.
2. **IPsec (IKEv2):** Complejo de configurar, dependiente de extensiones de kernel, problemático detrás de NATs agresivos y propenso a configuraciones erróneas.
3. **WireGuard:** Protocolo moderno basado en el *Noise Protocol Framework*, formalmente verificado, con ~4,000 líneas de código base, criptografía de última generación con parámetros fijos (sin negociación de suites criptográficas débiles), y diseñado con concepto de roaming y *connectionless UDP*.

## Decisión
Adoptar **WireGuard** como el protocolo criptográfico primario para el Data Plane de `ithera-vpn`.
- Criptografía fija: ChaCha20-Poly1305 para AEAD, Curve25519 para ECDH, BLAKE2s para hashing y SipHash24 para mitigación DoS.
- Implementación en Go utilizando `golang.zx2c4.com/wireguard` y `golang.zx2c4.com/wireguard/tun`.
- Control del dispositivo en caliente mediante la API estándar de Userspace (UAPI / `device.IpcSet`).

## Consecuencias

### Positivas
- **Máximo Throughput y Mínima Latencia:** Rendimiento cercano al límite de línea en hardware moderno.
- **Superficie de Ataque Reducida:** Menor complejidad de código implica menos superficie para vulnerabilidades críticas de memoria y lógica.
- **Roaming Transparente:** La movilidad de red (cambio de Wi-Fi a datos móviles) ocurre de forma nativa sin renegociar túneles completos.
- **Bajo Consumo de Batería:** Protocolo silencioso cuando no hay tráfico de datos.

### Negativas / Desafíos
- **Huella DPI Fija:** WireGuard tiene firmas de paquete reconocibles en su handshake inicial (148 bytes, 92 bytes, 64 bytes). Requiere capas complementarias de ofuscación (Fase 2b).
- **Protocolo Estrictamente UDP:** Redes que bloquean todo tráfico UDP saliente impiden la conexión directa. Requiere mecanismo de fallback de transporte (ADR-004).
- **Statelessness en Servidor:** Al no existir un paquete explícito de "desconexión", la gestión de sesiones y liberación de IPs (IPAM) requiere monitoreo de inactividad operativa (`last_handshake_time`).
