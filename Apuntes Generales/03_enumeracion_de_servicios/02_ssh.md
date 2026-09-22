# SSH

## Índice

1. [Introducción al protocolo SSH](#1-introducción-al-protocolo-ssh)
2. [Identificar la distribución a partir de la versión de SSH](#2-identificar-la-distribución-a-partir-de-la-versión-de-ssh)
3. [Despliegue del servidor SSH](#3-despliegue-del-servidor-ssh)
4. [Conexión y verificación de acceso](#4-conexión-y-verificación-de-acceso)
5. [Ataque de fuerza bruta con Hydra](#5-ataque-de-fuerza-bruta-con-hydra)
6. [Enumeración con Nmap](#6-enumeración-con-nmap)

---

## 1. Introducción al protocolo SSH

En esta clase exploraremos el protocolo SSH (*Secure Shell*) y cómo realizar reconocimiento para recopilar información sobre los sistemas que ejecutan este servicio.

SSH es un protocolo de administración remota que permite a los usuarios controlar y modificar sus servidores remotos a través de Internet mediante un mecanismo de autenticación seguro. Como una alternativa más segura al protocolo Telnet, que transmite información sin cifrar, SSH utiliza técnicas criptográficas para garantizar que todas las comunicaciones hacia y desde el servidor remoto estén cifradas.

SSH proporciona un mecanismo para autenticar un usuario remoto, transferir entradas desde el cliente al host y retransmitir la salida de vuelta al cliente. Esto es especialmente útil para administrar sistemas remotos de manera segura y eficiente, sin tener que estar físicamente presentes en el sitio.

A continuación se proporciona el enlace directo a la web donde copiamos el comando de `docker` para desplegar nuestro contenedor:

- **Docker Hub OpenSSH-Server**: https://hub.docker.com/r/linuxserver/openssh-server

> **Nota:** SSH suele escuchar en el puerto `22/tcp` por defecto, aunque es muy habitual cambiarlo (en esta práctica el contenedor lo expone en el `2222`). Al ser un servicio de administración remota, es uno de los objetivos más valiosos en una auditoría: un acceso válido por SSH equivale a control de la máquina.

---

## 2. Identificar la distribución a partir de la versión de SSH

Cabe destacar que, a través de la versión de SSH, también podemos identificar el *codename* de la distribución que se está ejecutando en el sistema.

Por ejemplo, si la versión del servidor SSH es `OpenSSH 8.2p1 Ubuntu 4ubuntu0.5`, podemos determinar que el sistema está ejecutando una distribución de Ubuntu. El número de versión `4ubuntu0.5` se refiere a la revisión específica del paquete de SSH en esa distribución de Ubuntu. A partir de esto, podemos identificar el *codename* de la distribución de Ubuntu, que en este caso sería **Focal** para Ubuntu 20.04.

Todas estas búsquedas las aplicamos sobre el siguiente dominio:

- **Launchpad**: https://launchpad.net/ubuntu

> **Nota:** Esta técnica se conoce como *banner grabbing*. El banner de versión que anuncia el servicio permite deducir no solo la versión de OpenSSH, sino también el sistema operativo y su versión concreta, cruzando el número de revisión del paquete con la base de datos de paquetes de la distribución (Launchpad para Ubuntu/Debian). Conocer la versión exacta del SO facilita buscar vulnerabilidades y exploits específicos.

---

## 3. Despliegue del servidor SSH

Desplegamos el contenedor del proyecto `linuxserver/openssh-server`, definiendo el usuario (`martin`) y la contraseña (`abc123.`) mediante variables de entorno:

```bash
┌──(kali㉿kali)-[~]
└─$ docker run -d \                      
  --name=openssh-server \
  --hostname=hack \                      
  -e PUID=1000 \
  -e PGID=1000 \
  -e TZ=Etc/UTC \
  -e PASSWORD_ACCESS=true \        
  -e USER_PASSWORD=abc123. \ 
  -e USER_NAME=martin \            
  -p 2222:2222 \
  -v /path/to/openssh-server/config:/config \
  --restart unless-stopped \
  lscr.io/linuxserver/openssh-server:latest
```

| Parámetro | Descripción |
|-----------|-------------|
| `-d` | Ejecuta el contenedor en segundo plano (*detached*). |
| `--name=openssh-server` | Asigna un nombre al contenedor para referenciarlo cómodamente. |
| `--hostname=hack` | Establece el *hostname* interno del contenedor (aparecerá en el prompt: `hack:~$`). |
| `-e PUID=1000` | ID de usuario (*User ID*) con el que se ejecutan los procesos dentro del contenedor. |
| `-e PGID=1000` | ID de grupo (*Group ID*) correspondiente. Junto con `PUID` alinea los permisos con los del host. |
| `-e TZ=Etc/UTC` | Zona horaria del contenedor. |
| `-e PASSWORD_ACCESS=true` | Habilita la autenticación por **contraseña** (por defecto la imagen prioriza clave pública). Necesario para esta práctica. |
| `-e USER_PASSWORD=abc123.` | Contraseña del usuario. |
| `-e USER_NAME=martin` | Nombre del usuario que se creará. |
| `-p 2222:2222` | Publica el puerto 2222 del contenedor en el puerto 2222 del host. |
| `-v /path/to/.../config:/config` | Monta un volumen de configuración persistente en `/config`. |
| `--restart unless-stopped` | Política de reinicio: el contenedor se reinicia automáticamente salvo que se pare manualmente. |
| `lscr.io/linuxserver/openssh-server:latest` | Imagen a desplegar (última versión). |

> **Importante:** El parámetro `-e PASSWORD_ACCESS=true` es imprescindible para poder realizar el ataque de fuerza bruta posterior. Si no se habilita, el servidor solo aceptaría autenticación por clave pública y Hydra no tendría un campo de contraseña que atacar.

> **Nota:** Recuerda sustituir `/path/to/openssh-server/config` por una ruta real de tu sistema si quieres que la configuración persista.

---

## 4. Conexión y verificación de acceso

Comprobamos que podemos conectarnos con las credenciales definidas. Al indicar un puerto no estándar usamos la opción `-p`:

```bash
┌──(kali㉿kali)-[~]
└─$ ssh -p 2222 martin@localhost
The authenticity of host '[localhost]:2222 ([::1]:2222)' can't be established.
ED25519 key fingerprint is: SHA256:OZSZERG1NTYAcbCAMsvmKaohN/ivcJxG2AS1nTsFtN8
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[localhost]:2222' (ED25519) to the list of known hosts.
martin@localhost's password: 
Welcome to OpenSSH Server
hack:~$ pwd
/config
hack:~$ ls
logs  ssh_host_keys  sshd  sshd.pid
```

| Comando / elemento | Descripción |
|--------------------|-------------|
| `ssh -p 2222 martin@localhost` | Inicia una conexión SSH como `martin` contra `localhost` en el puerto `2222`. |
| `-p 2222` | Especifica el puerto de destino (en SSH la `-p` es minúscula; ojo, en `docker run` la `-p` mapea puertos). |
| `pwd` | Muestra el directorio de trabajo actual dentro del servidor (`/config`). |
| `ls` | Lista el contenido del directorio actual. |

> **Nota:** La primera vez que te conectas a un host, SSH muestra `The authenticity of host ... can't be established` y su *fingerprint* (huella) de la clave. Esto ocurre porque el host aún no figura en tu archivo `~/.ssh/known_hosts`. Al responder `yes`, la huella se guarda (`Permanently added ...`) y en conexiones futuras no volverá a preguntar. Este mecanismo protege frente a ataques *man-in-the-middle*: si la clave del servidor cambiara inesperadamente, SSH te avisaría.

> **Advertencia:** Verificar la *fingerprint* antes de aceptarla es una buena práctica de seguridad. Aceptar a ciegas (`yes`) es habitual en un laboratorio, pero en un entorno real deberías contrastar la huella con la que te haya facilitado el administrador del servidor.

---

## 5. Ataque de fuerza bruta con Hydra

Al igual que con FTP, usamos Hydra para adivinar la contraseña del usuario `martin`, esta vez contra el servicio SSH:

```bash
┌──(kali㉿kali)-[~]
└─$ hydra -l martin -P /usr/share/wordlists/rockyou.txt ssh://localhost -s 2222 -t 15
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-09-22 07:43:53
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 1 task per 1 server, overall 1 task, 1 login try (l:1/p:1), ~1 try per task
[DATA] attacking ssh://localhost:2222/
[2222][ssh] host: localhost   login: martin   password: abc123.
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-09-22 07:43:53
```

| Parámetro | Descripción |
|-----------|-------------|
| `-l martin` | Un único login (usuario) a probar: `martin`. Para una lista de usuarios se usaría `-L archivo.txt` (mayúscula). |
| `-P /usr/share/wordlists/rockyou.txt` | Archivo de contraseñas (diccionario) a probar. Con `-p` (minúscula) se probaría una única contraseña. |
| `ssh://localhost` | Protocolo y objetivo del ataque: servicio SSH en `localhost`. |
| `-s 2222` | Especifica el **puerto** del servicio, necesario porque no usa el 22 por defecto. |
| `-t 15` | Número de **tareas en paralelo** (hilos). Acelera el ataque, pero un valor alto puede saturar el servicio. |

> **Advertencia:** El mensaje `[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4` indica que muchos servidores SSH limitan las conexiones simultáneas. Un `-t` demasiado alto puede provocar conexiones rechazadas, falsos negativos (contraseñas correctas que no se detectan) o incluso el bloqueo temporal por parte del servidor. En SSH conviene bajar a `-t 4` o menos.

> **Recuerda:** El mnemotécnico de Hydra: **minúsculas** (`-l`, `-p`) para valores únicos y **mayúsculas** (`-L`, `-P`) para listas/archivos. La opción `-s` fija el puerto y `-t` la concurrencia.

---

## 6. Enumeración con Nmap

Finalmente, usamos Nmap para identificar la versión del servicio SSH y el sistema operativo subyacente. En este caso escaneamos el puerto 22 estándar:

```bash
┌──(kali㉿kali)-[~]
└─$ nmap -sSCV -p22 localhost           
Starting Nmap 7.99 ( https://nmap.org ) at 2026-09-22 07:49 +0200
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00010s latency).
Other addresses for localhost (not scanned): ::1

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.2p1 Debian 5 (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.70 seconds
```

| Parámetro | Descripción |
|-----------|-------------|
| `-sS` | Escaneo TCP SYN (*half-open*): rápido y discreto, no completa la conexión de tres vías. |
| `-C` | Ejecuta los scripts NSE por defecto (equivale a `-sC`). |
| `-V` | Detección de versión del servicio (equivale a `-sV`). |
| `-p22` | Limita el escaneo al puerto 22 (el estándar de SSH). |

> **Nota:** La línea `22/tcp open ssh OpenSSH 10.2p1 Debian 5 (protocol 2.0)` es la que permite aplicar el *banner grabbing* explicado en la sección 2: revela la versión de OpenSSH, la distribución (`Debian`) y confirma el uso del protocolo SSH 2.0. El campo `Service Info: OS: Linux` y el `CPE` (*Common Platform Enumeration*) son identificadores estandarizados que ayudan a correlacionar el servicio con vulnerabilidades conocidas.

> **Recuerda:** Para escanear el contenedor de esta práctica en concreto (que expone SSH en el `2222`, no en el `22`), habría que ajustar el puerto: `nmap -sSCV -p2222 localhost`.
