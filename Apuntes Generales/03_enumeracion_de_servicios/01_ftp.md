# FTP

## Índice

1. [Introducción al protocolo FTP y la enumeración](#1-introducción-al-protocolo-ftp-y-la-enumeración)
2. [Herramientas y proyectos utilizados](#2-herramientas-y-proyectos-utilizados)
3. [Cómo funciona FTP: canal de control y canal de datos](#3-cómo-funciona-ftp-canal-de-control-y-canal-de-datos)
4. [Despliegue del servidor FTP](#4-despliegue-del-servidor-ftp)
5. [Enumeración con Nmap](#5-enumeración-con-nmap)
6. [Ataque de fuerza bruta con Hydra](#6-ataque-de-fuerza-bruta-con-hydra)
   - [Preparación: comprobar la contraseña en el diccionario](#preparación-comprobar-la-contraseña-en-el-diccionario)
   - [Errores frecuentes al lanzar Hydra](#errores-frecuentes-al-lanzar-hydra)
   - [Ataque con éxito](#ataque-con-éxito)
7. [Acceso y verificación](#7-acceso-y-verificación)
8. [Transferencia de ficheros](#8-transferencia-de-ficheros)
9. [Escenario con usuario anónimo](#9-escenario-con-usuario-anónimo)
   - [El problema del modo pasivo tras NAT](#el-problema-del-modo-pasivo-tras-nat)
10. [Captura de credenciales en texto plano](#10-captura-de-credenciales-en-texto-plano)

---

## 1. Introducción al protocolo FTP y la enumeración

En esta clase hablaremos sobre el protocolo de transferencia de archivos (FTP) y cómo aplicar reconocimiento sobre este para recopilar información.

FTP (*File Transfer Protocol*) es un protocolo ampliamente utilizado para la transferencia de archivos en redes. Funciona bajo un modelo cliente-servidor y, en su forma clásica, transmite tanto las credenciales como los datos **en texto plano**, lo que lo convierte en un objetivo habitual durante una auditoría.

La **enumeración** del servicio FTP consiste en recopilar información relevante, como:

- La **versión** del servidor FTP (para buscar vulnerabilidades conocidas).
- La **configuración de permisos** de archivos.
- Los **usuarios y las contraseñas** (mediante ataques de fuerza bruta o *guessing*).
- Si permite **acceso anónimo** (*anonymous login*).

> **Nota:** La enumeración es una fase de reconocimiento. Cuanta más información se obtenga del servicio (versión, usuarios válidos, rutas accesibles), más fácil será encontrar un vector de explotación posterior.

---

## 2. Herramientas y proyectos utilizados

A lo largo de la clase usamos varios proyectos y herramientas:

- **Docker-FTP-Server**: contenedor que despliega un servidor FTP con un usuario y contraseña que nosotros definimos. Es el escenario principal de la práctica.
  - https://github.com/garethflowers/docker-ftp-server
- **Docker-ANON-FTP**: proyecto de *metabrainz* que despliega un contenedor FTP con **autenticación de usuarios anónimos** habilitada. Lo usamos para el segundo escenario.
  - https://github.com/metabrainz/docker-anon-ftp
- **Hydra**: herramienta de pruebas de penetración de código abierto que se utiliza para realizar ataques de fuerza bruta contra sistemas y servicios protegidos por contraseña. Es altamente personalizable y admite una amplia gama de protocolos de red, como HTTP, FTP, SSH, Telnet, SMTP, entre otros.

> **Importante:** Todas estas prácticas se realizan sobre contenedores desplegados en tu propia máquina (laboratorio controlado). Ejecutar ataques de fuerza bruta contra sistemas de terceros sin autorización es ilegal.

---

## 3. Cómo funciona FTP: canal de control y canal de datos

Antes de atacarlo conviene entender un detalle clave del protocolo, porque explica varios errores que veremos más adelante. FTP es un protocolo peculiar porque **usa dos conexiones distintas**:

| Canal              | Puerto habitual     | Para qué sirve                                                                 |
| :----------------- | :------------------ | :---------------------------------------------------------------------------- |
| **Canal de control** | `21/tcp`            | Por aquí viajan los comandos (`USER`, `PASS`, `LIST`, `RETR`…) y sus respuestas. Es la conexión que abre y usa Hydra. |
| **Canal de datos**   | `20/tcp` (activo) o un puerto del rango pasivo | Por aquí viaja el contenido real: listados de directorios, subidas y descargas de ficheros. |

En **modo pasivo** (el más habitual hoy), cuando el cliente quiere transferir datos ocurre esto:

1. El cliente envía el comando `PASV` por el canal de control.
2. El servidor abre un puerto nuevo y **le responde al cliente con la IP y el puerto** a los que debe conectarse para los datos.
3. El cliente abre una **segunda conexión** hacia esa IP y puerto.

> **Recuerda:** En FTP **siempre es el cliente quien abre las dos conexiones hacia el servidor**. Esto será importante para entender por qué, tras un NAT (como el de Docker), el servidor tiene que anunciar una IP alcanzable — de ahí la variable `PUBLIC_IP` que veremos en el despliegue.

---

## 4. Despliegue del servidor FTP

Levantamos el contenedor del proyecto `garethflowers/ftp-server` con un usuario (`martin`) y una contraseña (`abc123.`) definidos por nosotros:

```bash
┌──(kali㉿kali)-[~]
└─$ docker run \            
        --detach \
        --env FTP_PASS=abc123. \
        --env FTP_USER=martin \
        --env PUBLIC_IP=192.168.100.250 \
        --name my-ftp-server \ 
        --publish 20-21:20-21/tcp \
        --publish 40000-40009:40000-40009/tcp \
        --volume /data:/home/user \
        garethflowers/ftp-server
a0688eb53f9b745e8ed80a129aebeb2c335437f3c08388305dc7454886c6312b
```

| Parámetro | Descripción |
|-----------|-------------|
| `--detach` (`-d`) | Ejecuta el contenedor en segundo plano (modo *detached*) y devuelve el ID del contenedor. |
| `--env FTP_USER=martin` | Variable de entorno: define el nombre del usuario FTP. |
| `--env FTP_PASS=abc123.` | Variable de entorno: define la contraseña de ese usuario. |
| `--env PUBLIC_IP=192.168.100.250` | IP **pública que el servidor anuncia** al cliente para el canal de datos en modo pasivo. Debe ser una IP del servidor alcanzable por el cliente (ver nota). |
| `--name my-ftp-server` | Asigna un nombre al contenedor para poder referenciarlo cómodamente. |
| `--publish 20-21:20-21/tcp` | Publica los puertos 20 y 21 (canales de datos activo y de control) del contenedor en el host. |
| `--publish 40000-40009:40000-40009/tcp` | Publica el **rango de puertos pasivos**. Sin ellos, el canal de datos en modo pasivo no funcionaría. |
| `--volume /data:/home/user` | Monta el directorio `/data` del host dentro del contenedor en `/home/user`. Los ficheros que suba el usuario acabarán en `/data` de la máquina anfitriona. |

> **Importante — el porqué de `PUBLIC_IP`:** En modo pasivo el servidor le dice al cliente *"conéctate a ESTA IP para los datos"*. Por defecto anunciaría su **IP interna de Docker** (algo como `172.17.0.2`), que es **inalcanzable desde fuera** del host. `PUBLIC_IP` fuerza al servidor a anunciar en su lugar la IP real del host (`192.168.100.250`), a la que el cliente sí puede conectarse. El NAT de Docker reescribe las cabeceras de los paquetes, pero **no** la IP que va escrita *dentro* del mensaje FTP (`227 Entering Passive Mode`), por eso hay que indicarla a mano. Esto **no es un límite del laboratorio**: los servidores FTP reales detrás de NAT (por ejemplo, un FTP casero tras un router) se configuran exactamente igual, poniendo su IP pública, y cualquier cliente de la red puede usarlos.

Comprobamos que el contenedor está arriba y con los puertos publicados:

```bash
┌──(kali㉿kali)-[~]
└─$ docker ps
CONTAINER ID   IMAGE                      COMMAND                  CREATED              STATUS                        PORTS                                                                                                                      NAMES
a0688eb53f9b   garethflowers/ftp-server   "/docker-entrypoint.…"   About a minute ago   Up About a minute (healthy)   0.0.0.0:20-21->20-21/tcp, [::]:20-21->20-21/tcp, 0.0.0.0:40000-40009->40000-40009/tcp, [::]:40000-40009->40000-40009/tcp   my-ftp-server
```

> **Nota:** El estado `Up ... (healthy)` y los mapeos `0.0.0.0:20-21->20-21/tcp` confirman que el servicio ya escucha en el puerto 21 del host. Si intentas atacar antes de que el contenedor esté levantado, no habrá nada escuchando en el puerto 21 y las herramientas fallarán con errores de conexión.

Una vez arriba, verificamos que podemos autenticarnos con las credenciales que definimos:

```bash
┌──(kali㉿kali)-[~]
└─$ ftp martin@localhost
Trying [::1]:21 ...
Connected to localhost.
220 FTP Server
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>
```

> **Nota:** El código `230 Login successful` indica autenticación correcta. Los códigos de respuesta FTP siguen un estándar: `2xx` = éxito, `3xx` = se necesita más información (como `331 Please specify the password`), `4xx`/`5xx` = error.

---

## 5. Enumeración con Nmap

Antes (o en paralelo) al ataque de fuerza bruta, usamos Nmap para identificar la **versión** del servicio y detectar configuraciones inseguras. Empezamos con un escaneo de versión y scripts por defecto sobre el puerto 21:

```bash
┌──(kali㉿kali)-[~]
└─$ nmap -sSCV -p21 localhost          
Starting Nmap 7.99 ( https://nmap.org ) at 2026-09-22 06:59 +0200
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00022s latency).
Other addresses for localhost (not scanned): ::1

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.0.8 or later

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.92 seconds
```

| Parámetro | Descripción |
|-----------|-------------|
| `-sS` | Escaneo TCP SYN (*half-open*): rápido y discreto, no completa la conexión de tres vías. |
| `-C` | Ejecuta el conjunto de scripts NSE por defecto (equivale a `-sC` / `--script=default`). Útil para detectar configuraciones comunes. |
| `-V` | Detección de versión del servicio (equivale a `-sV`). Aquí revela `vsftpd 2.0.8 or later`. |
| `-p21` | Limita el escaneo al puerto 21 (el canal de control de FTP). |

> **Nota:** La combinación `-sSCV` es una forma abreviada de escribir `-sS -sC -sV` en un solo argumento. Identificar la versión exacta (`vsftpd`) permite buscar vulnerabilidades conocidas asociadas a ese software.

En este primer escenario **no hay usuario anónimo**, por lo que el script `ftp-anon` no reporta acceso anónimo. Nmap dispone de un script específico (`ftp-anon.nse`) que detecta precisamente esa configuración:

```bash
┌──(kali㉿kali)-[~]
└─$ locate ftp-anon.nse
/usr/share/nmap/scripts/ftp-anon.nse
```

| Comando | Descripción |
|---------|-------------|
| `locate ftp-anon.nse` | Busca en la base de datos de archivos del sistema la ruta del script NSE `ftp-anon.nse`, que comprueba si el servidor permite login anónimo. |

> **Recuerda:** `locate` consulta una base de datos indexada (rápida) en lugar de recorrer el disco. Si el archivo es muy reciente, puede que necesites actualizar el índice con `sudo updatedb`.

---

## 6. Ataque de fuerza bruta con Hydra

El objetivo es **adivinar la contraseña** del usuario `martin` usando un diccionario. Para ello empleamos Hydra contra el servicio FTP.

### Preparación: comprobar la contraseña en el diccionario

Antes de lanzar el ataque, comprobamos que la contraseña del usuario (`abc123.`) está incluida en el diccionario `rockyou.txt` (si no lo estuviera, el ataque nunca la encontraría):

```bash
┌──(kali㉿kali)-[~]
└─$ grep -F 'abc123.' /usr/share/wordlists/rockyou.txt

abc123.
abc123...
abc123..
abc123.,
123abc123.
xxx.abc123.xxx
abc123.pdk
abc123./
abc123. 
ABCabc123..._
123abc123..
```

| Parámetro | Descripción |
|-----------|-------------|
| `grep` | Busca líneas que coincidan con un patrón dentro de un archivo. |
| `-F` | Trata el patrón como **texto literal** (*fixed string*), no como expresión regular. Importante aquí porque el punto (`.`) en una regex significaría "cualquier carácter". |
| `'abc123.'` | Cadena que buscamos. |
| `/usr/share/wordlists/rockyou.txt` | Diccionario de contraseñas incluido en Kali (uno de los más usados). |

> **Nota:** Se usa `-F` para que el punto final se busque de forma literal. Sin `-F`, `grep` interpretaría `abc123.` como "abc123 seguido de cualquier carácter", devolviendo también coincidencias no deseadas.

### Errores frecuentes al lanzar Hydra

Un error muy común al empezar es lanzar Hydra **antes de que el servicio FTP esté disponible** (por ejemplo, antes de arrancar el contenedor o apuntando a un puerto donde no hay nada escuchando). En ese caso Hydra no consigue establecer conexión y muestra:

```
[ERROR] all children were disabled due too many connection errors
0 of 1 target completed, 0 valid password found
```

> **Advertencia:** Este mensaje **no es un fallo de contraseña**, sino un **fallo de conexión**: Hydra ni siquiera consigue hablar con el servicio. Los "children" son los hilos de ataque, y Hydra los deshabilita tras acumular varios errores de conexión seguidos.

Causas y comprobaciones habituales:

| Causa probable | Cómo comprobarlo / solucionarlo |
|----------------|----------------------------------|
| No hay servicio en el puerto 21 (contenedor no arrancado). | `ss -tlnp \| grep :21` — si no devuelve nada, no hay nada escuchando. Arranca el contenedor. |
| El FTP está en otra IP o puerto (contenedor/laboratorio). | Ajusta el destino: `hydra ... ftp://172.19.0.2` o el puerto con `-s 2121`. |
| El servidor corta conexiones por exceso de concurrencia. | Baja los hilos: `hydra -t 1 ...` (un solo hilo). |
| El servidor exige TLS (FTPS). | Prueba `ftps://` en lugar de `ftp://`. |

> **Recuerda:** Para diagnosticar si hay algo escuchando y si habla FTP en claro, puedes conectarte a mano con `nc -vn 127.0.0.1 21` y ver si responde con un banner `220 ...`.

### Ataque con éxito

Con el servicio ya disponible, lanzamos Hydra contra el FTP local para adivinar la contraseña del usuario `martin`:

```bash
┌──(kali㉿kali)-[~]
└─$ hydra -l martin -P /usr/share/wordlists/rockyou.txt ftp://127.0.0.1
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-09-22 07:14:54
[DATA] max 1 task per 1 server, overall 1 task, 1 login try (l:1/p:1), ~1 try per task
[DATA] attacking ftp://127.0.0.1:21/
[21][ftp] host: 127.0.0.1   login: martin   password: abc123.
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-09-22 07:14:55
```

| Parámetro | Descripción |
|-----------|-------------|
| `-l martin` | Especifica un **único login** (usuario) a probar: `martin`. Para una lista de usuarios se usaría `-L archivo.txt` (mayúscula). |
| `-P /usr/share/wordlists/rockyou.txt` | Indica el **archivo de contraseñas** (diccionario) a probar. Con `-p` (minúscula) se probaría una única contraseña. |
| `ftp://127.0.0.1` | Protocolo y destino del ataque: servicio FTP en `127.0.0.1` (puerto 21 por defecto). |

> **Nota:** La línea clave del resultado es `[21][ftp] host: 127.0.0.1 login: martin password: abc123.`, que revela la credencial encontrada. El mnemotécnico es sencillo: **minúsculas** (`-l`, `-p`) para valores únicos y **mayúsculas** (`-L`, `-P`) para listas/archivos.

---

## 7. Acceso y verificación

Con la contraseña obtenida, nos conectamos al servidor FTP para confirmar el acceso y explorar el directorio remoto:

```bash
┌──(kali㉿kali)-[~]
└─$ ftp martin@localhost
Trying [::1]:21 ...
Connected to localhost.
220 FTP Server
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> pwd
Remote directory: /
```

| Comando | Descripción |
|---------|-------------|
| `ftp martin@localhost` | Inicia una sesión FTP como usuario `martin` contra `localhost`. Solicitará la contraseña de forma interactiva. |
| `pwd` | (*print working directory*) Muestra el directorio remoto actual dentro del servidor FTP. Aquí devuelve `/`. |

> **Nota:** Una vez dentro del prompt `ftp>`, otros comandos útiles son `ls` (listar ficheros), `cd` (cambiar de directorio), `get` (descargar un fichero), `put` (subir un fichero) y `bye` (salir). El mensaje `Using binary mode` indica que las transferencias se harán en modo binario, adecuado para cualquier tipo de archivo.

---

## 8. Transferencia de ficheros

Una vez dentro de la sesión FTP, el objetivo real de una auditoría suele ser **descargar** ficheros interesantes del servidor (configuraciones, copias de seguridad, credenciales) o **subir** un fichero (por ejemplo, un webshell si el FTP sirve el mismo directorio que un servidor web). Estos son los comandos principales dentro del prompt `ftp>`:

```bash
ftp> ls
ftp> cd backups
ftp> get config.php
ftp> put shell.php
ftp> mget *.txt
ftp> bye
```

| Comando | Descripción |
|---------|-------------|
| `ls` | Lista el contenido del directorio remoto actual. |
| `cd backups` | Cambia al directorio remoto indicado. |
| `get config.php` | **Descarga** un fichero del servidor a tu máquina local. |
| `put shell.php` | **Sube** un fichero desde tu máquina al servidor (requiere permiso de escritura). |
| `mget *.txt` | Descarga **varios** ficheros de golpe (*multiple get*), admite comodines. |
| `mput *.txt` | Sube varios ficheros de golpe (*multiple put*). |
| `bye` (o `exit`) | Cierra la sesión FTP. |

> **Nota:** Con `mget`/`mput`, FTP pregunta por cada fichero por defecto. Para desactivar esa confirmación y transferir todo sin preguntar, ejecuta antes el comando `prompt` (alterna el modo interactivo).

> **Importante:** Si el directorio del FTP coincide con la raíz de un servidor web (algo habitual en configuraciones mal hechas), poder **subir** un fichero `.php` con `put` permite pasar de un simple acceso FTP a **ejecución de código** en el servidor: se sube un webshell y se accede a él desde el navegador. Es uno de los saltos más comunes de FTP a RCE.

Alternativamente, para descargar un árbol completo sin entrar en la sesión interactiva, `wget` admite el protocolo FTP con credenciales:

```bash
┌──(kali㉿kali)-[~]
└─$ wget -r ftp://martin:'abc123.'@127.0.0.1/
```

| Parámetro | Descripción |
|-----------|-------------|
| `-r` | Descarga de forma **recursiva** todo el árbol de directorios. |
| `ftp://martin:'abc123.'@127.0.0.1/` | URL con usuario y contraseña embebidos para la descarga automática. |

> **Advertencia:** Incluir la contraseña en la línea de comandos la deja registrada en el historial del shell y visible en la lista de procesos. Úsalo solo en laboratorio; en un entorno real, prefiere la sesión interactiva o un fichero `.netrc` con permisos restringidos.

---

## 9. Escenario con usuario anónimo

En este segundo escenario desplegamos un servidor que **permite el acceso anónimo**, usando el proyecto `metabrainz/docker-anon-ftp`:

```bash
docker run -d -p 20-21:20-21 -p 65500-65515:65500-65515 -v /tmp:/var/ftp:ro metabrainz/docker-anon-ftp
```

| Parámetro | Descripción |
|-----------|-------------|
| `-d` | Ejecuta el contenedor en segundo plano (*detached*). |
| `-p 20-21:20-21` | Publica los puertos de control (21) y datos activo (20). |
| `-p 65500-65515:65500-65515` | Publica el rango de puertos pasivos que usa esta imagen. |
| `-v /tmp:/var/ftp:ro` | Monta `/tmp` del host en `/var/ftp` del contenedor en modo **solo lectura** (`ro`, *read-only*). |

Al ejecutarlo, en este caso obtenemos un error porque los puertos ya estaban ocupados por el contenedor anterior:

```bash
┌──(kali㉿kali)-[~]
└─$ docker run -d -p 20-21:20-21 -p 65500-65515:65500-65515 -v /tmp:/var/ftp:ro metabrainz/docker-anon-ftp
Unable to find image 'metabrainz/docker-anon-ftp:latest' locally
latest: Pulling from metabrainz/docker-anon-ftp
2b55860d4c66: Pull complete 
8e058277d049: Pull complete 
cac814e1eefd: Pull complete 
f2da72536bda: Pull complete 
651a4bc4a4bb: Pull complete 
f8fd4a238c83: Pull complete 
edba8d639861: Pull complete 
Digest: sha256:89364620f6708a42945ddd07c2e79bdaa297b36b97b7cd920c348bf77f6c84fe
Status: Downloaded newer image for metabrainz/docker-anon-ftp:latest
933c49ca82c96a67278a5f9dd3ddea36d3d33e3f6d14cd5bfc83f48a8fe6aa99
docker: Error response from daemon: failed to set up container networking: driver failed programming external connectivity on endpoint unruffled_murdock (c7f215179784d7599df29f82f223b8ca7a119a4123be82405a2db3b266315589): Bind for :::20 failed: port is already allocated

Run 'docker run --help' for more information
```

> **Advertencia:** El error `Bind for :::20 failed: port is already allocated` indica que el puerto 20 (y por extensión 21) **ya está en uso** por el contenedor `my-ftp-server` del escenario anterior. Docker no puede mapear dos contenedores al mismo puerto del host. Para solucionarlo, hay que **detener el contenedor anterior** (`docker stop my-ftp-server`) o **mapear el nuevo a puertos distintos** en el host (por ejemplo `-p 2020-2021:20-21`).

> **Nota:** Aunque el `docker run` falla por el puerto, la imagen sí llega a descargarse (`Status: Downloaded newer image...`). Los outputs siguientes corresponden a un momento en que el contenedor anónimo sí está en marcha.

Con el servidor anónimo activo, Nmap detecta el acceso anónimo gracias al script `ftp-anon`:

```bash
┌──(kali㉿kali)-[~]
└─$ nmap -sSCV -p21 localhost
Starting Nmap 7.99 ( https://nmap.org ) at 2026-09-22 07:29 +0200
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000084s latency).
Other addresses for localhost (not scanned): ::1

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV IP 172.17.0.2 is not the same as 127.0.0.1
Service Info: Host: Welcome

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.48 seconds
```

También podemos lanzar **solo** ese script de forma dirigida, sin el resto del escaneo por defecto:

```bash
┌──(kali㉿kali)-[~]
└─$ nmap --script ftp-anon -p21 127.0.0.1
Starting Nmap 7.99 ( https://nmap.org ) at 2026-09-22 07:30 +0200
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00011s latency).

PORT   STATE SERVICE
21/tcp open  ftp
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV IP 172.17.0.2 is not the same as 127.0.0.1

Nmap done: 1 IP address (1 host up) scanned in 0.25 seconds
```

| Parámetro | Descripción |
|-----------|-------------|
| `--script ftp-anon` | Ejecuta únicamente el script NSE `ftp-anon`, que comprueba si el servidor permite login anónimo. |
| `-p21` | Limita el escaneo al puerto 21. |
| `127.0.0.1` | Objetivo del escaneo (la máquina local). |

> **Nota:** La línea `ftp-anon: Anonymous FTP login allowed (FTP code 230)` confirma que **se permite el acceso anónimo**: cualquiera puede autenticarse sin credenciales válidas. Es una mala configuración de seguridad muy frecuente.

### El problema del modo pasivo tras NAT

Fíjate en la segunda línea del resultado de Nmap:

```
|_Can't get directory listing: PASV IP 172.17.0.2 is not the same as 127.0.0.1
```

> **Importante:** Este mensaje es exactamente el problema del **modo pasivo tras el NAT de Docker** que vimos en la teoría. El login anónimo funciona (canal de control por el 21), pero al pedir el listado de directorios (canal de datos), el servidor anuncia su **IP interna de Docker** (`172.17.0.2`) en la respuesta `PASV`. Nmap, que se había conectado a `127.0.0.1`, detecta la incoherencia (`172.17.0.2` no es `127.0.0.1`) y, por seguridad, **rechaza abrir la conexión de datos** hacia una IP distinta de la del control. Por eso el listado falla aunque el login sea correcto.

> **Recuerda:** Este es justamente el motivo por el que el primer contenedor usaba `PUBLIC_IP=192.168.100.250`: para que el servidor anunciara una IP coherente y alcanzable, y el canal de datos no fallara. El contenedor anónimo de este ejemplo no tiene configurada esa variable, de ahí el error en el listado.

Aun así, el login anónimo sí funciona; podemos conectarnos y confirmarlo:

```bash
┌──(kali㉿kali)-[~]
└─$ ftp anonymous@localhost
Trying [::1]:21 ...
Connected to localhost.
220 Welcome to an awesome public FTP Server
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> pwd
Remote directory: /
```

| Comando | Descripción |
|---------|-------------|
| `ftp anonymous@localhost` | Inicia sesión FTP con el usuario especial `anonymous`. Normalmente acepta cualquier contraseña (o una vacía), por convención suele usarse una dirección de correo. |
| `pwd` | Muestra el directorio remoto actual (`/`). |

> **Nota:** El banner `220 Welcome to an awesome public FTP Server` es distinto del primer escenario (`220 FTP Server`), lo que confirma que estamos hablando con el contenedor de FTP anónimo. Aunque el login sea posible, recuerda que el listado de ficheros (`ls`) fallará por el mismo motivo del modo pasivo (`PASV IP ...`) hasta que el servidor anuncie una IP coherente.

---

## 10. Captura de credenciales en texto plano

El FTP clásico transmite el usuario y la contraseña **sin cifrar**. Esto significa que cualquiera que pueda capturar el tráfico de la red (un atacante en la misma red local, un equipo comprometido en medio, etc.) puede leer las credenciales directamente. Es una de las principales razones por las que el FTP se considera un protocolo inseguro.

Para demostrarlo en el laboratorio, podemos capturar el tráfico con `tcpdump` mientras iniciamos sesión:

```bash
┌──(kali㉿kali)-[~]
└─$ sudo tcpdump -i lo -A 'tcp port 21'
```

| Parámetro | Descripción |
|-----------|-------------|
| `-i lo` | Interfaz a escuchar. `lo` es la interfaz *loopback* (para tráfico a `localhost`); en una red real sería `eth0`, `wlan0`, etc. |
| `-A` | Muestra el contenido de los paquetes en formato **ASCII** (texto legible). |
| `'tcp port 21'` | Filtro: captura solo el tráfico del puerto 21 (canal de control de FTP). |

Mientras la captura está activa, iniciamos una sesión FTP en otra terminal. En la salida de `tcpdump` veremos aparecer, en claro, los comandos `USER` y `PASS`:

```bash
...
USER martin
...
PASS abc123.
...
```

> **Advertencia:** Ahí está el problema de seguridad: el usuario `martin` y la contraseña `abc123.` viajan **legibles** por la red. Cualquier *sniffer* (tcpdump, Wireshark) los captura sin esfuerzo.

> **Importante — la solución:** usar alternativas cifradas. **FTPS** (FTP sobre TLS) o, mejor aún, **SFTP** (transferencia de ficheros sobre SSH), que cifran toda la comunicación, incluidas las credenciales. Si un servicio solo ofrece FTP plano, es un hallazgo que reportar.

> **Recuerda:** Estas prácticas se realizan sobre el laboratorio desplegado en tu propia máquina. Capturar tráfico de redes ajenas sin autorización es ilegal.
