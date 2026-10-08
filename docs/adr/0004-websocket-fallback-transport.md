# ADR-004: Transporte Fallback sobre WebSocket/TLS

## Estado
Aprobado (Fase 0)

## Contexto
En múltiples entornos restrictivos (redes universitarias con portales cautivos, firewalls corporativos con inspección profunda L7, o redes públicas restrictivas), el tráfico UDP saliente es completamente descartado (*default-deny UDP*). En estas condiciones, WireGuard estándar es incapaz de establecer comunicación alguna.

## Decisión
Implementar un mecanismo secundario de transporte fallback que encapsula tramas WireGuard sobre conexiones **WebSocket sobre TLS 1.3 (WSS en puerto TCP 443)**:
1. Se implementa como una variante de la interfaz `conn.Bind` (`wsBind`) en `wireguard-go`.
2. Para firewalls intermedios y proxies HTTP corporativos, la conexión aparenta ser una sesión web HTTPS legítima de navegación a través del puerto 443 estándar.
3. El handshake TLS oculta la firma del protocolo WireGuard.
4. **Regla de composición:** `obfsBind` (padding UDP) y `wsBind` son mutuamente excluyentes. No se aplica `obfsBind` sobre `wsBind` porque TLS ya cifra y oculta los metadatos de capa de aplicación.

## Consecuencias

### Positivas
- **Supervivencia en Redes Hostiles:** Permite conectividad cuando UDP está 100% bloqueado o interceptado.
- **Tránsito por Proxies HTTP:** Soporte para atravesar proxies corporativos autenticados mediante el método `CONNECT` estándar de HTTP.

### Negativas / Desafíos
- **Penalización de Rendimiento (TCP-over-TCP):** El tráfico TCP encapsulado dentro del túnel TCP sufre de fenómenos de contención y *Head-of-Line blocking* ante pérdida de paquetes en el enlace físico.
- **Sobrecarga de RTT:** El establecimiento de conexión requiere handshake TCP + TLS antes del handshake WireGuard.
- **Uso Estricto como Fallback:** Debe activarse únicamente cuando el transporte UDP nativo falle o se detecte restricción total.
