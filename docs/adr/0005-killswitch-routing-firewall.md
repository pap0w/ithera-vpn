# ADR-005: Estrategia Anti-Fugas (Kill Switch) y Enrutamiento Global Seguro

## Estado
Aprobado (Fase 0)

## Contexto
Cuando un usuario activa una VPN con fines de privacidad o elusión de censura, la peor falla posible es la **exposición silenciosa de la IP real** (*data leak* o *DNS leak*).
Esto ocurre por dos motivos comunes:
1. **Reemplazo destructivo de la puerta de enlace predeterminada (`default gateway`):** Si una VPN sobrescribe la ruta por defecto (`0.0.0.0/0`), y el túnel cae inesperadamente, el sistema operativo puede restablecer la ruta física anterior, filtrando paquetes en texto plano hacia el ISP sin que el usuario lo note. Además, sobrescribir la ruta por defecto puede cortar la comunicación física hacia la IP del servidor VPN (bucle de enrutamiento).
2. **Caída abrupta del proceso VPN o transición de red:** Si el proceso del cliente se cierra inesperadamente o la red Wi-Fi cambia, el kernel continúa enrutando paquetes por interfaces físicas expuestas.

## Decisión
1. **Enrutamiento por Subredes `/1`:**
   En lugar de sustituir la ruta por defecto `0.0.0.0/0`, se instalan dos rutas de mayor especificidad:
   - `0.0.0.0/1 dev <tun>`
   - `128.0.0.0/1 dev <tun>`
   Debido a la regla de correspondencia de prefijo más largo (*Longest Prefix Match*), estas dos rutas tienen mayor prioridad sobre cualquier ruta por defecto preexistente (`/0`), capturando todo el tráfico de internet sin tocar la tabla original del sistema.
2. **Ruta Explícita de Host hacia el Gateway:**
   Se instala una ruta específica `/32` hacia la IP pública del servidor VPN a través de la interfaz física original, asegurando que el tráfico encapsulado y cifrado de WireGuard pueda salir hacia internet sin entrar en un bucle hacia la propia interfaz TUN.
3. **Kill Switch en Cortafuegos Nativo:**
   - **Linux:** Reglas `nftables` / `iptables` atómicas que descartan (*DROP*) cualquier tráfico saliente por interfaces físicas que no tenga como destino la IP del endpoint VPN en el puerto configurado.
   - **Windows:** Sub-capas en *Windows Filtering Platform (WFP)* que bloquean tráfico saliente excepto hacia la interfaz virtual de ithera o al endpoint del servidor.

## Consecuencias

### Positivas
- **Cero Fugas por Reversión de Ruta:** La tabla de enrutamiento original no se destruye ni se corrompe.
- **Protección Atómica:** El firewall a nivel del kernel protege los paquetes incluso si el daemon crashea antes de restaurar rutas.

### Negativas / Desafíos
- **Requiere Limpieza Estricta al Desconectar:** Las rutas y reglas deben ser removidas de manera atómica al desconectar conscientemente. Si el sistema se apaga de golpe, debe existir un mecanismo de recuperación (*fail-open* o herramienta de rescate `ithera-ctl reset-routes`).
