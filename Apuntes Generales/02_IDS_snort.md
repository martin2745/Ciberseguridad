# 02 IDS snort

## Índice

- [Sistemas de Detección de Intrusos en Red (NIDS)](#sistemas-de-detección-de-intrusos-en-red-nids)
- [Herramientas de código abierto: Snort y Suricata](#herramientas-de-código-abierto-snort-y-suricata)
- [Funcionamiento y aplicación práctica](#funcionamiento-y-aplicación-práctica)
- [Objetivos](#objetivos)
- [Laboratorio](#laboratorio)
- [Práctica Snort: Detección de SSH y Ping](#práctica-snort-detección-de-ssh-y-ping)
  - [1. Creación de regla para detectar conexiones SSH entrantes](#1-creación-de-regla-para-detectar-conexiones-ssh-entrantes)
  - [2. Creación del usuario practica que tratará de conectarse por SSH](#2-creación-del-usuario-practica-que-tratará-de-conectarse-por-ssh)
  - [2. Creación de regla para detectar conexiones Ping entrantes](#2-creación-de-regla-para-detectar-conexiones-ping-entrantes)
- [Alerta sobre ataque SYN Flood](#alerta-sobre-ataque-syn-flood)
- [Consolidación de conocimientos](#consolidación-de-conocimientos)

---

## Sistemas de Detección de Intrusos en Red (NIDS)

Actualmente, el notable aumento en la cantidad de ciberataques dirigidos a empresas e infraestructuras críticas requiere el uso de múltiples herramientas para securizar nuestros sistemas. Entre estas herramientas destacan los **Sistemas de Detección de Intrusos en Red** (NIDS, por sus siglas en inglés).

Estas herramientas buscan identificar de forma anticipada anomalías que puedan indicar el inicio de un ciberataque, con el fin de **prevenirlo o mitigarlo** con la mayor rapidez posible. Los NIDS son capaces de analizar el tráfico de red en tiempo real **sin interrumpir el flujo de datos**, ya que funcionan generalmente de manera pasiva, supervisando tanto el tráfico entrante y saliente como el tráfico local.

---

## Herramientas de código abierto: Snort y Suricata

**Snort** y **Suricata** son dos de las herramientas de código abierto más utilizadas en este ámbito.

Snort permite analizar el tráfico de red en tiempo real y registrar paquetes de datos. Además, puede actuar como un **Sistema de Prevención de Intrusos (IPS)**. Utiliza un lenguaje basado en reglas que combina métodos de inspección por firmas, protocolos y anomalías para detectar actividades potencialmente maliciosas.

Su popularidad se debe, en gran parte, a la extensa base de reglas desarrolladas, mantenidas y actualizadas por la comunidad de usuarios de Snort .

Entre las principales utilidades de Snort se encuentran:

- El **rastreo de paquetes** (_Sniffer_).
- El **registro de paquetes** para la depuración del tráfico de red (_Packet Logger_).
- Las **funciones de sistema de prevención de intrusiones en red (NIDS)**.

---

## Funcionamiento y aplicación práctica

En el modo NIDS, Snort solo registrará los paquetes que se consideren maliciosos, utilizando las características preestablecidas para ello a través de sus reglas.

La acción que ejecuta Snort también se define en las reglas establecidas por el **administrador de red**. Dichas reglas son fáciles de implementar, lo que permite diferenciar la actividad regular de Internet de la actividad anómala o maliciosa.

En este estudio se abordarán la **creación de variables y reglas en Snort** y su **ejecución en los modos sniffer e IDS** . Dentro de las reglas se trabajará la detección de diversos ataques mediante el uso de la herramienta `hping3`, instalada por defecto en **Kali Linux**, que será nuestra máquina atacante.

---

## Objetivos

1. Entender el funcionamiento de las reglas preestablecidas en Snort.
2. Manejar el archivo y los mecanismos para la configuración de Snort.
3. Crear nuevas variables y reglas con fines específicos en Snort.
4. Analizar, sintetizar y organizar la información dentro del área de Ciberseguridad.

---

## Laboratorio

Para esta práctica vamos a hacer uso de una máquina kali y una máquina linux con snort. Estas dos máquinas estarán en una red Nat.

---

## Práctica Snort: Detección de SSH y Ping

### 1. **Creación de regla para detectar conexiones SSH entrantes**

- Crear una regla de Snort que alerte cada vez que otra máquina (como Kali) se conecta por SSH a tu VM con Snort.
- El mensaje de alerta debe ser: "¡Tunombre!: detectada una conexión SSH ENTRANTE".
- Ignorar el estado de la conexión (no usar el flag established).

**Recordatorio de los pasos clave:**

- Coloca la regla dentro del directorio de reglas de Snort (habitualmente `/etc/snort/rules/`).
- Incluye esa regla en el archivo `snort.conf` usando `include`.

**Resolución:**

Nos posicionamos en la ruta`/etc/snort` donde está toda la información de configuración para snort.

```bash
root@ui1:~# cd /etc/snort/
root@ui1:/etc/snort# ls -l
total 324
-rw-r--r-- 1 root root    3757 ago  8  2012 classification.config
-rw-r--r-- 1 root root   82469 ago  8  2012 community-sid-msg.map
-rw-r--r-- 1 root root       0 oct 19  2015 database.conf
-rw-r--r-- 1 root root   29597 ago  8  2012 gen-msg.map
-rw-r--r-- 1 root root       0 oct  3  2018 grep
-rw-r--r-- 1 root root       0 oct  3  2018 log
-rw-r--r-- 1 root root       0 oct  3  2018 log2
-rw-r--r-- 1 root root     687 ago  8  2012 reference.config
drwxr-xr-x 2 root root    4096 oct  3  2018 rules
-rw-r----- 1 root snort  26484 oct 14 17:32 snort.conf
-rw------- 1 root root     804 oct 19  2015 snort.debian.conf
-rw-r--r-- 1 root root    2335 ago  8  2012 threshold.conf
-rw-r--r-- 1 root root  160606 ago  8  2012 unicode.map
```

La carpeta `/etc/snort/` contiene los archivos principales de configuración y operación para Snort en Linux, incluyendo parámetros, reglas y referencias necesarias para su funcionamiento correcto.

#### Archivos y carpetas más relevantes

- **snort.conf**: archivo principal donde se define la configuración global de Snort, incluyendo las rutas a las reglas.
- **rules/**: directorio que almacena los archivos de reglas personalizadas y oficiales que Snort utiliza para analizar el tráfico.
- **classification.config**: mapea las categorías de alertas y ayuda a clasificar los eventos detectados por las reglas.
- **reference.config**: vincula alertas a referencias externas (por ejemplo: CVEs, boletines de seguridad).
- **threshold.conf**: permite configurar umbrales para limitar la generación de alertas repetidas por eventos idénticos (rate limiting).
- **community-sid-msg.map**, **gen-msg.map**: archivos de mapeo y mensaje para los identificadores (SID) de reglas y tipos de eventos detectados.
- **snort.debian.conf**: configuración específica para el paquete Debian/Ubuntu, usada en el arranque con el servicio.

#### Carpetas y archivos auxiliares

- **log, log2, grep**: normalmente utilizados para almacenamiento temporal o procesamiento de logs durante la operación o pruebas.
- **database.conf**: archivo preparado para configuración de base de datos si se usa registro de eventos en un sistema externo.
- **unicode.map**: necesario para interpretar correctamente ciertos contenidos de tráfico de red con codificaciones unicode.

#### Editar fichero de configuración

Como buena práctica es común realizar previamente una copia del fichero de configuración y posteriormete proceder con la edición del archivo.

```bash
root@ui1:/etc/snort# cp -pv snort.conf snort.conf_VIEJO
«snort.conf» -> «snort.conf_VIEJO»
root@ui1:/etc/snort# ls -l snort.con*
-rw-r----- 1 root snort 26484 oct 22 09:14 snort.conf
-rw-r----- 1 root snort 26484 oct 22 09:14 snort.conf_VIEJO
```

Una vez realizada la copia procedemos a editar el fichero de configuración donde tendremos que editar las variables **HOME_NET** y **EXTERNAL_NET** para que sea la IP de la VM Snort o el rango de tu red local a vigilar:

```bash
###################################################
# Step #1: Set the network variables.  For more information, see README.variables
###################################################

# Setup the network addresses you are protecting
ipvar HOME_NET 198.0.2.7

# Set up the external network addresses. Leave as "any" in most situations
#ipvar EXTERNAL_NET any
ipvar EXTERNAL_NET !$HOME_NET
```

Si queremos ver si la configuración del archivo es exitosa realizamos lo siguiente:

```bash
root@ui1:/etc/snort# snort -T -c /etc/snort/snort.conf
...
Snort successfully validated the configuration!
Snort exiting
```

A continuación vamos a crear un archivo para la regla SSH en la ruta `/etc/snort/rules` y añadir el fichero de reglas a la configuración del IDS en el punto 7.

```bash
root@ui1:/etc/snort# cat rules/ssh_entrante.rules
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"¡Martin!: detectada una conexión SSH ENTRANTE"; sid:1000010; rev:1;)
```

```bash
root@ui1:/etc/snort# grep ssh_entrante.rules snort.conf
include $RULE_PATH/ssh_entrante.rules
```

**Explicación de la regla:**

- `alert`: tipo de acción, genera alerta.
- `tcp $EXTERNAL_NET any -> $HOME_NET 22`: cualquier IP/puerto origen, hacia mi equipo en puerto 22 (por defecto SSH).
- `msg`: mensaje personalizado que aparecerá en la alerta.
- `sid`: identificador único de la regla.
- `rev`: número de revisión (en caso de modificar la regla en el futuro).

### 2. **Creación del usuario practica que tratará de conectarse por SSH**

Creamos el usuario practica.

```bash
root@ui1:/etc/snort# adduser
adduser: Sólo se permiten uno o dos nombres.
root@ui1:/etc/snort# adduser practica
Añadiendo el usuario `practica' ...
Añadiendo el nuevo grupo `practica' (1000) ...
Añadiendo el nuevo usuario `practica' (1000) con grupo `practica' ...
Creando el directorio personal `/home/practica' ...
Copiando los ficheros desde `/etc/skel' ...
Introduzca la nueva contraseña de UNIX:
Vuelva a escribir la nueva contraseña de UNIX:
passwd: contraseña actualizada correctamente
Cambiando la información de usuario para practica
Introduzca el nuevo valor, o pulse INTRO para usar el valor predeterminado
        Nombre completo []: practica
        Número de habitación []:
        Teléfono del trabajo []:
        Teléfono de casa []:
        Otro []:
¿Es correcta la información? [S/n] s
root@ui1:/etc/snort# grep practica /etc/passwd
practica:x:1000:1000:practica,,,:/home/practica:/bin/bash
```

Por defecto, Snort guarda los logs en el directorio `/etc/snort/log`. Este directorio debe existir o crearse para que Snort pueda almacenar ahí las notificaciones, eventos o logs del sistema. Los logs se pueden consultar en esa ruta después de haber ejecutado Snort con las reglas configuradas, como en tu caso para capturar tráfico SSH.

Los archivos que tienes en `/var/log/snort/` corresponden a diferentes tipos de logs generados por Snort:

- alert: Este archivo contiene las alertas generadas por Snort en texto claro, con los eventos detectados según las reglas configuradas. Es el log principal para monitorear incidencias de intrusión.
- snort.log.\*: Son archivos binarios de logs en formato pcap que contienen capturas de paquetes detalladas. Se guardan con un timestamp en el nombre y pueden abrirse con herramientas de análisis de paquetes como Wireshark o tcpdump para examinar el tráfico capturado.
- tcpdump.log.\*: Son también archivos de captura de paquetes (pcap) generados por Snort en modo tcpdump. Pueden usarse para análisis forense de tráfico, guardando segmentos específicos capturados por Snort.

```bash
root@ui1:/etc/snort# ls -l /var/log/snort/
total 376
-rw-r--r-- 1 root adm 305217 oct 22 10:37 alert
-rw------- 1 root adm  47266 oct 22 10:35 snort.log.1761121943
-rw------- 1 root adm  18128 oct 22 10:37 snort.log.1761122200
-rw------- 1 root adm    920 oct 22 10:07 tcpdump.log.1761120440
```

En esta práctica vamos a partir de que `/var/log/snort` está completamente vacío. Podemos ejecutar snort con el siguiente comando para que detecte el tráfico entrante por la interfaz indicada.

```bash
root@ui1:~# snort -i eth0 -b -l /var/log/snort -c /etc/snort/snort.conf
```

El comando `snort` utiliza la siguiente configuración para su ejecución:

| Parámetro | Descripción |
|-----------|-------------|
| `-i eth0` | Escucha el tráfico en la interfaz de red eth0. |
| `-b`      | Guarda los paquetes capturados en archivos binarios (pcap). |
| `-l /var/log/snort` | Guarda los archivos (pcap y alertas) en el directorio `/var/log/snort`. |
| `-c /etc/snort/snort.conf` | Usa la configuración y reglas definidas en ese archivo para detectar y registrar alertas. |

Si desde la kali accedemos a la máquina snort podemos comprobar que se crea los ficheros de log con la información del tráfico y vemos como se ha detectado un acceso desde la máquina kali (198.0.2.4/24) a la máquina snort al puerto 22 (198.0.2.7).

```bash
┌──(kali㉿kali)-[~]
└─$ ssh practica@198.0.2.7
practica@198.0.2.7's password:
Linux ui1 3.2.0-4-486 #1 Debian 3.2.93-1 i686

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Wed Oct 22 14:10:05 2025 from 198.0.2.4

practica@ui1:~$ su -
Contraseña:

root@ui1:~# ls /var/log/snort/
alert  snort.log.1761134953

root@ui1:~# tail /var/log/snort/alert
***AP*** Seq: 0xE84B77AB  Ack: 0x58E0E3E2  Win: 0x1E9  TcpLen: 32
TCP Options (3) => NOP NOP TS: 3567599193 86214

[**] [1:1000010:1] ¡Martin!: detectada una conexión SSH ENTRANTE [**]
[Priority: 0]
10/22-14:11:11.513464 198.0.2.4:39108 -> 198.0.2.7:22
TCP TTL:64 TOS:0x10 ID:25807 IpLen:20 DgmLen:52 DF
***A**** Seq: 0xE84B77D3  Ack: 0x58E0E40A  Win: 0x1E9  TcpLen: 32
TCP Options (3) => NOP NOP TS: 3567599196 86280
```

> **Nota:** El archivo snort.log.1761134953 puede ser visto por herramientas como _tcpdump_ con su parámetro _-r_ o por wireshark (previamente estableciendo la extensión del paquete como .pcap).

### 2. **Creación de regla para detectar conexiones Ping entrantes**

Tenemos que crear otra regla diferente para el filtrado de paquetes ICMP cuando se lleva a cabo un comando ping.

```bash
root@ui1:/etc/snort/rules# cat ping_entrante.rules
alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"¡Martín!: alguien está haciendo ping"; sid:1000011; rev:1;)
root@ui1:/etc/snort/rules# cat -n ../snort.conf | grep ping_
   645  include $RULE_PATH/ping_entrante.rules
```

La norma de Snort es una regla personalizada para detectar paquetes ICMP (como los generados por el comando ping) desde hosts externos hacia la red interna, generando una alerta con mensaje específico.

```bash
alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"¡Martín!: alguien está haciendo ping"; sid:1000011; rev:1;)
```

- **alert:** Acción a realizar. Cuando esta regla se cumple, Snort genera una alerta y registra el evento.
- **icmp:** Aplica la regla al protocolo ICMP (usado, por ejemplo, por ping).
- **$EXTERNAL_NET any -> $HOME_NET any:** Detecta tráfico ICMP originado en cualquier host externo (variable `$EXTERNAL_NET`) y dirigido a cualquier host interno (variable `$HOME_NET`). Los puertos se indican como `any` porque ICMP no utiliza puertos, pero la sintaxis obliga a ponerlos.
- **(msg:"¡Martín!: alguien está haciendo ping"; ...):** Opciones de la regla. Aquí se especifica el mensaje personalizado que aparecerá en la alerta.
- **sid:1000011;** Identificador único de la regla. Es obligatorio.

Si nosotros tratamos de conectarnos a nuestra máquina objetivo podemos ver como se almacena información de los ping detectados.

```bash
┌──(kali㉿kali)-[~]
└─$ ping -c 3 198.0.2.7
PING 198.0.2.7 (198.0.2.7) 56(84) bytes of data.
64 bytes from 198.0.2.7: icmp_seq=1 ttl=64 time=0.858 ms
64 bytes from 198.0.2.7: icmp_seq=2 ttl=64 time=0.788 ms
64 bytes from 198.0.2.7: icmp_seq=3 ttl=64 time=0.775 ms

--- 198.0.2.7 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2001ms
rtt min/avg/max/mdev = 0.775/0.807/0.858/0.036 ms

┌──(kali㉿kali)-[~]
└─$ ssh practica@198.0.2.7
practica@198.0.2.7's password:
Linux ui1 3.2.0-4-486 #1 Debian 3.2.93-1 i686

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Oct 23 23:53:46 2025 from 198.0.2.4

practica@ui1:~$ head -30 /var/log/snort/alert
[**] [1:1000010:1] ¡Martin!: detectada una conexión SSH ENTRANTE [**]
[Priority: 0]
10/23-23:52:16.567134 198.0.2.2:6754 -> 198.0.2.7:22
TCP TTL:255 TOS:0x0 ID:2558 IpLen:20 DgmLen:40
***A**** Seq: 0x12F5D  Ack: 0x95E9A61C  Win: 0x8000  TcpLen: 20

[**] [1:366:7] ICMP PING *NIX [**]
[Classification: Misc activity] [Priority: 3]
10/23-23:52:32.198962 198.0.2.4 -> 198.0.2.7
ICMP TTL:64 TOS:0x0 ID:49352 IpLen:20 DgmLen:84 DF
Type:8  Code:0  ID:9396   Seq:1  ECHO

[**] [1:1000011:1] ¡Martín!: alguien está haciendo ping [**]
[Priority: 0]
10/23-23:52:32.198962 198.0.2.4 -> 198.0.2.7
ICMP TTL:64 TOS:0x0 ID:49352 IpLen:20 DgmLen:84 DF
Type:8  Code:0  ID:9396   Seq:1  ECHO
```

---

## Alerta sobre ataque SYN Flood

- a) Configure en Snort una regla para detectar ataques del tipo SYN Flood, con el mensaje "Tunombre: Recibimos un ataque por SYN Flood!".
- b) Para realizar el ataque, utilice el comando desde la Kali «hping3» montando el ataque en cuestión. Documente el ataque.
- c) Lance Snort e ilustre cómo detecta el ataque y cómo se muestra la IP de la máquina que ataca.
- d) ¿Qué tipo de tráfico genera un ataque SYN flood?

Un ataque **SYN Flood** es un tipo de ataque de denegación de servicio (DoS) que explota el proceso de establecimiento de conexión TCP (three-way handshake). El atacante envía muchas peticiones SYN a un servidor, pero nunca completa la conexión, llenando la lista de conexiones pendientes y evitando que clientes legítimos accedan al servicio.

Vamos a realizar todos los pasos. En primer lugar configuramos la regla de Snort y la añadimos al fichero de configuración. Posteriormente ejecutamos Snort y lanzamos el ataque SYN Flood.

```bash
root@ui1:/etc/snort/rules# cat synflood_ataque.rules
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"¡Martín!: Recibimos un ataque por SYN Flood!"; sid:1000012; rev:1;)
root@ui1:/etc/snort/rules# cat -n ../snort.conf | grep synflood_ataque.rules
   646  include $RULE_PATH/synflood_ataque.rules
```

**Explicación paso a paso:**

- `alert tcp ...`: Aplica a todo el tráfico TCP.
- `flags:S;` : Solo a paquetes con el flag SYN activado y SIN ACK ni otros flags.
- `msg:"Tunombre: Recibimos un ataque por SYN Flood!";` : Mensaje de aviso, cámbialo por tu nombre.
- `sid:1000001;` : Un número identificador único de la regla.

Podemos ver que la máquina objetivo tiene el puerto 22 abierto por lo que haremos el ataque SYN Flood sobre este puerto.

```bash
┌──(kali㉿kali)-[~]
└─$ nmap -sS -vv 198.0.2.7
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-10-24 00:25 CEST
Initiating ARP Ping Scan at 00:25
Scanning 198.0.2.7 [1 port]
Completed ARP Ping Scan at 00:25, 0.04s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 00:25
Completed Parallel DNS resolution of 1 host. at 00:25, 13.00s elapsed
Initiating SYN Stealth Scan at 00:25
Scanning 198.0.2.7 [1000 ports]
Discovered open port 22/tcp on 198.0.2.7
Completed SYN Stealth Scan at 00:25, 0.10s elapsed (1000 total ports)
Nmap scan report for 198.0.2.7
Host is up, received arp-response (0.0010s latency).
Scanned at 2025-10-24 00:25:33 CEST for 0s
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
MAC Address: 08:00:27:CE:D0:4B (Oracle VirtualBox virtual NIC)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 13.24 seconds
           Raw packets sent: 1001 (44.028KB) | Rcvd: 1001 (40.032KB)
```

Ejecutamos el ataque SYN Flood haciendo uso de `hping3`.

```bash
┌──(kali㉿kali)-[~]
└─$ sudo hping3 -S -p 22 --flood 198.0.2.7
...
```

| Parámetro | Descripción |
|-----------|-------------|
| `-S`      | Solo SYN. |
| `-p 22`   | Destino puerto 22 ya que es el único puerto abierto detectado por `nmap`. |
| `--flood` | Genera paquetes lo más rápido posible. |

```bash
┌──(kali㉿kali)-[~]
└─$ ssh -l root 198.0.2.7
root@198.0.2.7's password:
Linux ui1 3.2.0-4-486 #1 Debian 3.2.93-1 i686

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Oct 24 00:29:27 2025 from 198.0.2.4
root@ui1:~# cat /var/log/snort/alert
[**] [1:1000012:1] ¡Martín!: Recibimos un ataque por SYN Flood! [**]
[Priority: 0]
10/24-00:31:54.869906 198.0.2.4:62643 -> 198.0.2.7:22
TCP TTL:64 TOS:0x0 ID:13987 IpLen:20 DgmLen:40
******S* Seq: 0x5EF3CCB5  Ack: 0x5D3C6434  Win: 0x200  TcpLen: 20
```

Un SYN flood genera muchos paquetes TCP con sólo el flag SYN activado, saturando la cola de conexiones semicompletadas del servidor y prohibiendo el acceso de usuarios legítimos.

---

## Consolidación de conocimientos

1. ¿Qué aprendiste sobre la importancia de la visibilidad del tráfico en la seguridad de red?

A modo de reflexión, la práctica con Snort permite comprender cómo el análisis manual del tráfico revela la importancia de la visibilidad y la detección temprana de amenazas en la red. Sin embargo, al trasladar este enfoque al entorno profesional, se observa que la correcta gestión de Snort requiere su integración como un servicio permanente, automatizado y robusto capaz de operar en modo IDS o IPS, según las necesidades, para garantizar la continuidad y eficiencia de la protección.​

En producción, la colaboración de Snort con otros sistemas como firewalls o plataformas SIEM resulta clave para lograr una defensa escalable, centralizada y adaptativa. No basta solo con la detección manual; la automatización, el monitoreo constante y la respuesta activa son esenciales para proteger la infraestructura de red frente a amenazas modernas, sin sacrificar rendimiento ni disponibilidad operativa.​

2. Realiza una tabla resumen de los principales aspectos de esta herramienta teniendo en cuenta:

- Elementos básicos de Snort.
- Modos de operación de Snort y formas de realizar el lanzamiento.
- Elementos de la configuración de Snort.
- Archivos de reglas, sintaxis y opciones.
- Paso a paso de su uso en uno de los casos estudiados (conciso y preciso = repetible).

| Aspecto                           | Detalle clave                                                                                                                                                                                                     |
| --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Elementos básicos de Snort**    | Motor de análisis de paquetes, archivos de configuración, archivos de reglas, sistema de alertas.                                                                                                                 |
| **Modos de operación**            | Sniffer: solo monitorea tráfico.<br>Packet Logger: guarda tráfico para análisis.<br>IDS/IPS: detecta y/o bloquea amenazas.<br>Se puede lanzar por comando directo o como servicio.                                |
| **Elementos de configuración**    | Archivo `snort.conf`, inclusión de archivos de reglas personalizados, selección de interfaz, variables de red (`HOME_NET`, `EXTERNAL_NET`).                                                                       |
| **Archivos de reglas y sintaxis** | Sintaxis: `alert protocol src_ip src_port -> dst_ip dst_port (options)`.<br>Opciones comunes: `msg`, `flags`, `sid`.<br>Ejemplo: `alert tcp any any -> any 80 (flags:S; msg:"SYN flood detected";)`               |
| **Paso a paso en caso SYN flood** | 1. Crear una regla y guardarla en un archivo.<br>2. Incluirla en `snort.conf`.<br>3. Lanzar Snort con interfaz adecuada.<br>4. Generar tráfico con `hping3`.<br>5. Observar alertas en consola o archivos de log. |
