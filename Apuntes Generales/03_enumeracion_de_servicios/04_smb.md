# SMB / Samba

## Índice

1. [Introducción: SMB y Samba](#1-introducción-smb-y-samba)
2. [Diferencias entre SMB y Samba](#2-diferencias-entre-smb-y-samba)
3. [Despliegue del laboratorio (CVE-2017-7494)](#3-despliegue-del-laboratorio-cve-2017-7494)
4. [Enumeración con Nmap](#4-enumeración-con-nmap)
5. [Enumeración con smbmap](#5-enumeración-con-smbmap)
6. [Interacción con smbclient](#6-interacción-con-smbclient)
7. [Montaje de recursos compartidos con CIFS](#7-montaje-de-recursos-compartidos-con-cifs)
8. [Enumeración con CrackMapExec](#8-enumeración-con-crackmapexec)

---

## 1. Introducción: SMB y Samba

SMB significa *Server Message Block*; es un protocolo de comunicación de red utilizado para compartir archivos, impresoras y otros recursos entre dispositivos de red. Es un protocolo propietario de Microsoft que se utiliza en sistemas operativos Windows.

**Samba**, por otro lado, es una implementación libre y de código abierto del protocolo SMB, que se utiliza principalmente en sistemas operativos basados en Unix y Linux. Samba proporciona una manera de compartir archivos y recursos entre dispositivos de red que ejecutan sistemas operativos diferentes, como Windows y Linux.

> **Nota:** SMB escucha habitualmente en el **puerto `445/tcp`** (SMB moderno, directo sobre TCP) y, en sistemas antiguos, en el `139/tcp` (sobre NetBIOS). Es uno de los servicios más jugosos en una auditoría interna: mal configurado, puede exponer recursos compartidos sin autenticación, credenciales y vías de ejecución remota de código.

---

## 2. Diferencias entre SMB y Samba

Aunque SMB y Samba comparten una funcionalidad similar, existen algunas diferencias notables:

| Aspecto            | SMB                                   | Samba                                          |
| :----------------- | :------------------------------------ | :--------------------------------------------- |
| Tipo               | Protocolo propietario de Microsoft    | Software libre y de código abierto             |
| Sistema operativo  | Windows                               | Unix / Linux (interoperable con Windows)       |
| Implementación     | Más completa y compleja               | Más ligera y limitada                          |
| Uso principal      | Compartición nativa en Windows        | Compartir recursos entre SO distintos          |

---

## 3. Despliegue del laboratorio (CVE-2017-7494)

Se comparte el enlace al proyecto de GitHub que utilizamos para desplegar un laboratorio de práctica con el que enumerar y explotar el servicio Samba:

- **Samba Authenticated RCE (SambaCry)**: https://github.com/vulhub/vulhub/tree/master/samba/CVE-2017-7494

Despliegue del entorno con Vulhub:

```bash
┌──(kali㉿kali)-[~]
└─$ git clone https://github.com/vulhub/vulhub.git
```

```bash
┌──(kali㉿kali)-[~]
└─$ cd vulhub/samba/CVE-2017-7494
```

```bash
┌──(kali㉿kali)-[~/vulhub/samba/CVE-2017-7494]
└─$ docker-compose up -d
```

| Comando | Descripción |
|---------|-------------|
| `git clone ...` | Descarga el repositorio de Vulhub con los laboratorios vulnerables. |
| `cd vulhub/samba/CVE-2017-7494` | Entra en el directorio del laboratorio de SambaCry. |
| `docker-compose up -d` | Levanta el contenedor Samba vulnerable en segundo plano. |

> **Nota:** CVE-2017-7494 (*SambaCry*) permite a un cliente autenticado subir una biblioteca compartida (`.so`) a un recurso escribible y lograr que el servidor la cargue y ejecute, obteniendo **ejecución remota de código**. La fase de enumeración que veremos a continuación es el paso previo: localizar recursos compartidos, permisos y credenciales.

---

## 4. Enumeración con Nmap

Antes de usar herramientas específicas de SMB, un escaneo con Nmap identifica el servicio, su versión y posibles configuraciones inseguras:

```bash
┌──(kali㉿kali)-[~]
└─$ nmap -sSCV -p139,445 localhost
```

| Parámetro | Descripción |
|-----------|-------------|
| `-sS` | Escaneo TCP SYN (*half-open*), rápido y discreto. |
| `-C` | Ejecuta los scripts NSE por defecto (equivale a `-sC`). |
| `-V` | Detección de versión del servicio (equivale a `-sV`). |
| `-p139,445` | Puertos de SMB: `139` (NetBIOS) y `445` (SMB directo). |

Nmap incluye scripts NSE específicos para SMB, muy útiles en el aula:

```bash
┌──(kali㉿kali)-[~]
└─$ nmap -p445 --script smb-protocols,smb-security-mode,smb-enum-shares localhost
```

| Script | Descripción |
|--------|-------------|
| `smb-protocols` | Enumera las versiones del protocolo SMB admitidas (SMBv1, v2, v3). Detectar `SMBv1` es un hallazgo negativo. |
| `smb-security-mode` | Muestra el modo de seguridad (si exige firma, si permite sesiones nulas). |
| `smb-enum-shares` | Intenta enumerar los recursos compartidos del servidor. |

> **Advertencia:** Que el servidor admita **SMBv1** es un riesgo importante: es la versión explotada por ataques como EternalBlue (WannaCry). Debería estar deshabilitado.

---

## 5. Enumeración con smbmap

Una de las herramientas que utilizamos para la fase de reconocimiento es **smbmap**. Es una herramienta de línea de comandos utilizada para enumerar recursos compartidos y permisos en un servidor SMB o Samba. Es muy útil para la enumeración de redes y para la identificación de posibles vulnerabilidades de seguridad.

Con smbmap puedes enumerar los recursos compartidos en un servidor SMB y obtener información detallada sobre cada recurso, como los permisos de acceso, los usuarios y grupos autorizados, y los archivos y carpetas compartidos. También puedes utilizar smbmap para identificar recursos compartidos que **no requieren autenticación**, lo que puede ser un problema de seguridad.

Parámetros comunes de smbmap:

| Parámetro | Descripción |
|-----------|-------------|
| `-H` | Dirección IP o nombre de host del servidor SMB al que conectarse. |
| `-P` | Puerto TCP de la conexión SMB. El puerto por defecto es el `445`; usar este parámetro si el servidor emplea otro. |
| `-u` | Nombre de usuario para la conexión SMB. |
| `-p` | Contraseña para la conexión SMB. |
| `-d` | Dominio al que pertenece el usuario utilizado en la conexión. |
| `-s` | Recurso compartido específico a enumerar. Si no se especifica, smbmap intenta enumerar todos. |

**Ejemplo — enumeración con sesión nula (sin credenciales):**

```bash
┌──(kali㉿kali)-[~]
└─$ smbmap -H 127.0.0.1
```

**Ejemplo — enumeración autenticada:**

```bash
┌──(kali㉿kali)-[~]
└─$ smbmap -H 127.0.0.1 -u martin -p 'abc123.'
```

**Ejemplo de salida (fragmento representativo):**

```bash
[+] IP: 127.0.0.1:445    Name: localhost
        Disk                            Permissions     Comment
        ----                            -----------     -------
        print$                          NO ACCESS       Printer Drivers
        data                            READ, WRITE     Shared data folder
        IPC$                            NO ACCESS       IPC Service
```

| Columna | Descripción |
|---------|-------------|
| `Disk` | Nombre del recurso compartido. |
| `Permissions` | Permisos del usuario sobre ese recurso: `NO ACCESS`, `READ ONLY` o `READ, WRITE`. |
| `Comment` | Descripción del recurso. |

> **Importante:** Un recurso con permisos `READ, WRITE` (como `data` en el ejemplo) es clave para SambaCry: al ser escribible, permite subir la biblioteca maliciosa. smbmap ayuda precisamente a **localizar recursos escribibles** que sirvan de vector.

> **Recuerda:** Ojo con las dos `-p`/`-P`: en smbmap `-p` (minúscula) es la **contraseña** y `-P` (mayúscula) es el **puerto**. Es al revés que en otras herramientas, así que conviene tenerlo presente.

smbmap permite a administradores de sistemas y auditores de seguridad verificar rápidamente la configuración de permisos de los recursos compartidos, lo que ayuda a identificar posibles vulnerabilidades y a tomar medidas para remediarlas.

---

## 6. Interacción con smbclient

Otra de las herramientas que se ven en esta clase es **smbclient**. A diferencia de smbmap (centrada en enumeración), smbclient proporciona una interfaz de línea de comandos para **interactuar** con los recursos compartidos SMB y Samba: permite la descarga y subida de archivos, la navegación por el sistema de archivos remoto, entre otras funcionalidades.

Parámetros comunes de smbclient:

| Parámetro | Descripción |
|-----------|-------------|
| `-L` | Enumera (lista) los recursos compartidos disponibles en el servidor SMB o Samba. |
| `-U` | Especifica el nombre de usuario (y contraseña) para la autenticación. |
| `-c` | Especifica un comando que se ejecutará en el servidor (modo no interactivo). |
| `-N` | No solicita contraseña (útil para probar sesiones nulas / anónimas). |

**Ejemplo — listar recursos compartidos sin autenticación:**

```bash
┌──(kali㉿kali)-[~]
└─$ smbclient -L //127.0.0.1/ -N
```

**Ejemplo — conectarse a un recurso concreto con credenciales:**

```bash
┌──(kali㉿kali)-[~]
└─$ smbclient //127.0.0.1/data -U martin
```

Una vez dentro del prompt interactivo (`smb: \>`), se usan comandos propios:

```bash
smb: \> ls
smb: \> get archivo.txt
smb: \> put exploit.so
smb: \> exit
```

| Comando | Descripción |
|---------|-------------|
| `ls` | Lista el contenido del recurso compartido. |
| `get archivo.txt` | Descarga un fichero del servidor a tu máquina. |
| `put exploit.so` | Sube un fichero desde tu máquina al recurso (requiere permiso de escritura). |
| `exit` | Cierra la sesión. |

> **Nota:** El comando `smbclient -L //127.0.0.1/ -N` con `-N` (*no password*) sirve para comprobar si el servidor permite **sesiones nulas**, es decir, listar recursos sin credenciales. Si funciona, es una mala configuración de seguridad muy habitual.

La lista completa de parámetros y sus descripciones se pueden encontrar en la documentación oficial de la herramienta.

---

## 7. Montaje de recursos compartidos con CIFS

Además de interactuar con `smbclient` (parecido a un cliente FTP), podemos **montar** un recurso compartido directamente en el sistema de archivos de Linux, de modo que aparezca como una carpeta más y podamos usarlo con `cd`, `ls`, `cp`, editores, etc.

**CIFS** (*Common Internet File System*) es un dialecto antiguo del protocolo SMB (concretamente SMB 1.0). Hoy los términos "SMB" y "CIFS" se usan casi como sinónimos. En Linux el nombre ha quedado asociado al **controlador del kernel** que monta estos recursos (`cifs`), por eso el montaje se hace con `-t cifs` **aunque por debajo se negocie SMB2 o SMB3**.

> **Nota:** Usar `-t cifs` no significa forzar el inseguro SMB1: el cliente y el servidor negocian la versión más alta que ambos admitan. Si necesitas fijar una versión concreta, se hace con la opción `vers=` (por ejemplo `vers=3.0`).

Primero creamos el directorio donde "engancharemos" el recurso remoto (punto de montaje):

```bash
┌──(kali㉿kali)-[~]
└─$ sudo mkdir -p /mnt/mounted
```

Después montamos el recurso compartido:

```bash
┌──(kali㉿kali)-[~]
└─$ sudo mount -t cifs //127.0.0.1/myshare /mnt/mounted -o username=martin
```

| Elemento | Descripción |
|----------|-------------|
| `mount` | Comando de Linux para montar un sistema de archivos en un punto del árbol de directorios. |
| `-t cifs` | Tipo de sistema de archivos: `cifs` (el cliente SMB del kernel Linux). |
| `//127.0.0.1/myshare` | Recurso remoto a montar: `//servidor/nombre_del_recurso`. |
| `/mnt/mounted` | Punto de montaje local: la carpeta donde aparecerá el contenido remoto. |
| `-o username=martin` | Opciones de montaje (`-o`). Aquí, el usuario para autenticarse. Pedirá la contraseña de forma interactiva. |

> **Importante:** El montaje requiere privilegios, de ahí `sudo`. En muchos sistemas necesitarás instalar antes el paquete de utilidades CIFS: `sudo apt install cifs-utils`. Sin él, `mount` devolverá el error `mount: /mnt/mounted: wrong fs type, bad option, bad superblock...`.

Opciones (`-o`) más habituales:

| Opción | Descripción |
|--------|-------------|
| `username=martin` | Usuario para la autenticación SMB. |
| `password=abc123.` | Contraseña. **Evita ponerla en la línea de comandos** (queda en el historial); es más seguro que la pida de forma interactiva o usar un fichero de credenciales. |
| `guest` | Monta como invitado, sin contraseña (para recursos anónimos). |
| `vers=3.0` | Fuerza la versión del protocolo SMB (`1.0`, `2.0`, `2.1`, `3.0`…). |
| `credentials=/ruta/fichero` | Lee usuario y contraseña de un fichero (más seguro que escribirlos en el comando). |
| `ro` / `rw` | Monta en solo lectura (`ro`) o lectura-escritura (`rw`). |

Una vez montado, el recurso remoto se usa como cualquier carpeta local:

```bash
┌──(kali㉿kali)-[~]
└─$ ls /mnt/mounted
┌──(kali㉿kali)-[~]
└─$ cp /mnt/mounted/archivo.txt ~/
```

Para **desmontar** el recurso cuando terminemos:

```bash
┌──(kali㉿kali)-[~]
└─$ sudo umount /mnt/mounted
```

| Comando | Descripción |
|---------|-------------|
| `umount /mnt/mounted` | Desmonta el recurso (ojo: el comando es `umount`, sin la "n"). |

> **Nota:** Ejemplo con fichero de credenciales, la forma recomendada. Se crea un fichero (por ejemplo `~/.smbcreds`) con el contenido `username=martin` / `password=abc123.` / `domain=WORKGROUP`, se protege con `chmod 600 ~/.smbcreds` y se monta con `-o credentials=/home/kali/.smbcreds`. Así la contraseña no queda registrada en el historial del shell ni visible en la lista de procesos.

> **Diferencia clave con smbclient:** `smbclient` te da una sesión tipo FTP (comandos `get`/`put`), mientras que `mount -t cifs` **integra el recurso en el sistema de archivos**, permitiéndote usar todas las herramientas de Linux directamente sobre él. Para SambaCry, montar un recurso escribible facilita colocar la biblioteca `.so` maliciosa como si copiaras un fichero normal.

---

## 8. Enumeración con CrackMapExec

Otra de las herramientas que utilizamos para enumerar el servicio Samba es **CrackMapExec** (también conocida como **CME**). Es una herramienta de pruebas de penetración de línea de comandos que se utiliza para realizar auditorías de seguridad en entornos de Active Directory. CME se basa en las bibliotecas de Python *impacket* y es compatible con Windows, Linux y macOS.

CME puede utilizarse para diversas tareas de auditoría, como enumerar usuarios y grupos, buscar contraseñas débiles, detectar sistemas vulnerables y buscar vectores de ataque. Además, permite ejecutar ataques de diccionario de contraseñas, ataques de *Pass-the-Hash* y explotar vulnerabilidades conocidas en sistemas Windows. Cuenta con una amplia variedad de módulos y opciones de configuración, lo que la convierte en una herramienta muy flexible que automatiza muchas tareas de auditoría comunes.

Se comparte el enlace directo a la Wiki para instalar la herramienta:

- **CrackMapExec**: https://wiki.porchetta.industries/getting-started/installation/installation-on-unix

**Ejemplo — enumeración básica del servicio SMB:**

```bash
┌──(kali㉿kali)-[~]
└─$ crackmapexec smb 127.0.0.1
```

**Ejemplo — enumeración de recursos compartidos con credenciales:**

```bash
┌──(kali㉿kali)-[~]
└─$ crackmapexec smb 127.0.0.1 -u martin -p 'abc123.' --shares
```

| Parámetro | Descripción |
|-----------|-------------|
| `smb` | Protocolo objetivo (CME soporta también `ssh`, `winrm`, `ldap`, etc.). |
| `127.0.0.1` | IP o rango de objetivos. |
| `-u martin` | Usuario para la autenticación. |
| `-p 'abc123.'` | Contraseña para la autenticación. |
| `--shares` | Enumera los recursos compartidos y los permisos del usuario sobre ellos. |

**Ejemplo — ataque de diccionario (fuerza bruta de credenciales):**

```bash
┌──(kali㉿kali)-[~]
└─$ crackmapexec smb 127.0.0.1 -u usuarios.txt -p /usr/share/wordlists/rockyou.txt
```

> **Nota:** Cuando se pasan **archivos** a `-u` y `-p`, CME prueba todas las combinaciones usuario/contraseña, funcionando como herramienta de fuerza bruta (similar a Hydra, pero orientada a entornos Windows/AD).

> **Importante:** CrackMapExec ya no recibe mantenimiento activo; su sucesor es **NetExec** (`nxc`), que mantiene una sintaxis prácticamente idéntica (`nxc smb 127.0.0.1 -u ... -p ... --shares`). Si CME no está disponible en tu Kali, usa `nxc` en su lugar.

> **Recuerda:** Todas estas prácticas se realizan sobre el laboratorio desplegado en tu propia máquina. Enumerar o atacar servidores de terceros sin autorización explícita es ilegal.
