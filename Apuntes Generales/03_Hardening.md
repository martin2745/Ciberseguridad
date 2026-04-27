# 03 Hardening en Linux

## Índice

- [Objetivos](#objetivos)
- [Indicaciones](#indicaciones)
- [PARTE I. Hardening de una máquina local utilizando la herramienta Lynis](#parte-i-hardening-de-una-máquina-local-utilizando-la-herramienta-lynis)
  - [1. Creación y gestión de usuario](#1-creación-y-gestión-de-usuario)
  - [2. Instalar y configurar OpenSSH](#2-instalar-y-configurar-openssh)
  - [3. Auditoría básica inicial con Lynis](#3-auditoría-básica-inicial-con-lynis)
  - [4. Resolver sugerencias detectadas por Lynis](#4-resolver-sugerencias-detectadas-por-lynis)
  - [5. Comprobación final de resultados](#5-comprobación-final-de-resultados)

---

El bastionado o «hardening» es un proceso continuo que se basa en aplicar las configuraciones correctas junto con una serie de medidas para securizar nuestros sistemas y redes. La auditoría constituye un aspecto importante del bastionado de sistemas, ya que permite detectar posibles configuraciones erróneas o servicios no protegidos. Entre las herramientas de auditoría en Linux tenemos Lynis, que es una herramienta de código abierto. Lynis tiene un conjunto automatizado de «scripts» desarrollados para probar un sistema Linux. Esta herramienta permite realizar un extenso análisis de salud de los sistemas para reforzar su bastionado.

En este estudio de caso, realizaremos el «hardening» de una máquina Linux para mejorar su seguridad. Utilizaremos una máquina virtual con Ubuntu 20.04, lo que les permitirá experimentar de forma segura sin afectar tu equipo real. Al final, entenderán cómo analizar un sistema, aplicar recomendaciones de hardening y verificar los cambios.

---

## Objetivos

1. Demostrar el uso de una herramienta de auditoría de seguridad (Lynis) para el bastionado de sistemas Linux y compararla con una similar en Windows.
2. Analizar, sintetizar y organizar la información dentro del área de seguridad informática.
3. Documentar el informe utilizando las referencias y citas correctamente según la norma IEEE.

---

## Indicaciones

Se empleará la VM Ubuntu 20.04 con una interfaz de red conectada en NAT.

1. En VirtualBox, importa la máquina virtual.
2. Nombra la máquina (por ejemplo, «Ubuntu-Hardening»).
3. Inicia sesión en la terminal con las credenciales usuario/usuario.
4. Escala privilegios de administrador e instala la herramienta Lynis (si tienes alguna dificultad, utiliza el gestor de paquetes Synaptic).

   Desde sudo, ejecuta:

   - `apt update`
   - `apt install lynis -y`

Para realizar el trabajo se deben responder las siguientes «Cuestiones» que computan los 10 puntos, repartidos en tres partes (revisar la bibliografía de este estudio de caso).

---

## PARTE I. Hardening de una máquina local utilizando la herramienta Lynis

### 1. Creación y gestión de usuario

- Cree un usuario (`tunombre`) y establezca la caducidad de su contraseña utilizando el comando `chage` con los parámetros adecuados:

```bash
usuario@ubuntu-20:~$ sudo apt install -y whois && sudo useradd -m -d /home/martin -s /bin/bash -p $(mkpasswd 'abc123.') -G sudo martin
[sudo] contraseña para usuario:
Leyendo lista de paquetes... Hecho
Creando árbol de dependencias
Leyendo la información de estado... Hecho
El paquete indicado a continuación se instaló de forma automática y ya no es necesario.
  libfprint-2-tod1
Utilice «sudo apt autoremove» para eliminarlo.
Se instalarán los siguientes paquetes NUEVOS:
  whois
0 actualizados, 1 nuevos se instalarán, 0 para eliminar y 686 no actualizados.
Se necesita descargar 44,7 kB de archivos.
Se utilizarán 279 kB de espacio de disco adicional después de esta operación.
Des:1 http://es.archive.ubuntu.com/ubuntu focal/main amd64 whois amd64 5.5.6 [44,7 kB]
Descargados 44,7 kB en 1s (42,4 kB/s)
Seleccionando el paquete whois previamente no seleccionado.
(Leyendo la base de datos ... 194716 ficheros o directorios instalados actualmente.)
Preparando para desempaquetar .../archives/whois_5.5.6_amd64.deb ...
Desempaquetando whois (5.5.6) ...
Configurando whois (5.5.6) ...
Procesando disparadores para man-db (2.9.1-1) ...
Scanning processes...
Scanning linux images...

Running kernel seems to be up-to-date.

No services need to be restarted.

No containers need to be restarted.

No user sessions are running outdated binaries.
usuario@ubuntu-20:~$ tail -1 /etc/passwd
martin:x:1001:1001::/home/martin:/bin/bash
usuario@ubuntu-20:~$ su - martin
Contraseña:
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

martin@ubuntu-20:~$ groups
martin sudo
```

- Establecer fecha de caducidad de la contraseña.

```bash
usuario@ubuntu-20:~$ sudo chage -M 30 martin
usuario@ubuntu-20:~$ sudo chage -l martin
Último cambio de contraseña                                     : dic 01, 2025
La contraseña caduca                                    : dic 31, 2025
Contraseña inactiva                                     : nunca
La cuenta caduca                                                : nunca
Número de días mínimo entre cambio de contraseña                : 0
Número de días máximo entre cambio de contraseña                : 30
Número de días de aviso antes de que caduque la contraseña      : 7
```

- Deshabilitar la cuenta tras 10 días desde la fecha de caducidad.

```bash
usuario@ubuntu-20:~$ sudo chage -I 10 martin
usuario@ubuntu-20:~$ sudo chage -l martin
Último cambio de contraseña                                     : dic 01, 2025
La contraseña caduca                                    : dic 31, 2025
Contraseña inactiva                                     : ene 10, 2026
La cuenta caduca                                                : nunca
Número de días mínimo entre cambio de contraseña                : 0
Número de días máximo entre cambio de contraseña                : 30
Número de días de aviso antes de que caduque la contraseña      : 7
```

- Establecer el número mínimo de días antes de cambiar la contraseña.

```bash
usuario@ubuntu-20:~$ sudo chage -m 5 martin
usuario@ubuntu-20:~$ sudo chage -l martin
Último cambio de contraseña                                     : dic 01, 2025
La contraseña caduca                                    : dic 31, 2025
Contraseña inactiva                                     : ene 10, 2026
La cuenta caduca                                                : nunca
Número de días mínimo entre cambio de contraseña                : 5
Número de días máximo entre cambio de contraseña                : 30
Número de días de aviso antes de que caduque la contraseña      : 7
```

- Establecer el número máximo de días antes de cambiar la contraseña.

```bash
usuario@ubuntu-20:~$ sudo chage -M 20 martin
usuario@ubuntu-20:~$ sudo chage -l martin
Último cambio de contraseña                                     : dic 01, 2025
La contraseña caduca                                    : dic 21, 2025
Contraseña inactiva                                     : dic 31, 2025
La cuenta caduca                                                : nunca
Número de días mínimo entre cambio de contraseña                : 5
Número de días máximo entre cambio de contraseña                : 20
Número de días de aviso antes de que caduque la contraseña      : 7
```

- Establecer días de aviso de expiración.

```bash
usuario@ubuntu-20:~$ sudo chage -W 10 martin
usuario@ubuntu-20:~$ sudo chage -l martin
Último cambio de contraseña                                     : dic 01, 2025
La contraseña caduca                                    : dic 21, 2025
Contraseña inactiva                                     : dic 31, 2025
La cuenta caduca                                                : nunca
Número de días mínimo entre cambio de contraseña                : 5
Número de días máximo entre cambio de contraseña                : 20
Número de días de aviso antes de que caduque la contraseña      : 10
```

- Mostrar información de la edad de la cuenta usando el parámetro `-l`.

```bash
usuario@ubuntu-20:~$ sudo chage -l martin
Último cambio de contraseña                                     : dic 01, 2025
La contraseña caduca                                    : dic 21, 2025
Contraseña inactiva                                     : dic 31, 2025
La cuenta caduca                                                : nunca
Número de días mínimo entre cambio de contraseña                : 5
Número de días máximo entre cambio de contraseña                : 20
Número de días de aviso antes de que caduque la contraseña      : 10
```

### 2. Instalar y configurar OpenSSH

- Si no está instalado, ejecute:

```bash
$ sudo apt update
$ sudo apt install openssh-server -y
$ sudo systemctl enable --now ssh
```

### 3. Auditoría básica inicial con Lynis

- Ejecutar la auditoría básica como root:

```bash
$ sudo lynis audit system > /home/tunombre/lynis_inicial.txt 2>&1
```

- Realizar captura de pantalla del “Hardening Index” y guardarla como `capturaInicial.png`.

```bash
usuario@ubuntu-20:~$ sudo apt update && sudo apt install -y lynis
```

A continuación, ejecutamos la herramienta para realizar la primera auditoría del sistema:

```bash
root@ubuntu-20:~# lynis audit system > /home/martin/lynis_inicial.txt 2>&1
```

Tras la ejecución, podemos verificar que se ha generado el reporte correctamente:

```bash
usuario@ubuntu-20:~$ su - martin
Contraseña:
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

martin@ubuntu-20:~$ ls -l
total 32
-rw-r--r-- 1 root root 32483 dic  1 10:49 lynis_inicial.txt
```

Finalmente, examinamos el contenido del reporte para detectar problemas:

```bash
martin@ubuntu-20:~$ cat lynis_inicial.txt

[ Lynis 2.6.2 ]

################################################################################
  Lynis comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
  welcome to redistribute it under the terms of the GNU General Public License.
  See the LICENSE file for details about using this software.

  2007-2018, CISOfy - https://cisofy.com/lynis/
  Enterprise support available (compliance, plugins, interface and tools)
################################################################################


[+] Initializing program
------------------------------------
  - Detecting OS...                                           [ DONE ]
  - Checking profiles...                                      [ DONE ]
  - Detecting language and localization                       [ es ]

  ---------------------------------------------------
  Program version:           2.6.2
  Operating system:          Linux
  Operating system name:     Ubuntu Linux
  Operating system version:  20.04
  Kernel version:            5.4.0
  Hardware platform:         x86_64
  Hostname:                  ubuntu-20
  ---------------------------------------------------
  Profiles:                  /etc/lynis/default.prf
  Log file:                  /var/log/lynis.log
  Report file:               /var/log/lynis-report.dat
  Report version:            1.0
  Plugin directory:          /etc/lynis/plugins
  ---------------------------------------------------
  Auditor:                   [Not Specified]
  Language:                  es
  Test category:             all
  Test group:                all
  ---------------------------------------------------
  - Program update status...                                  [ WARNING ]

      ===============================================================================
        Lynis Actualización disponible
      ===============================================================================

        Current version is more than 4 months old

        Current version : 262   Latest version : 316

        Please update to the latest version.
        New releases include additional features, bug fixes, tests, and baselines.

        Download the latest version:

        Packages (DEB/RPM) -  https://packages.cisofy.com
        Website (TAR)      -  https://cisofy.com/downloads/
        GitHub (source)    -  https://github.com/CISOfy/lynis

      ===============================================================================


[+] System Tools
------------------------------------
  - Scanning available tools...
  - Checking system binaries...

[+] Plugins (fase 1)
------------------------------------
 Nota: los plugins contienen pruebas más extensivas y toman más tiempo

  - Plugin: debian
    [
[+] Debian Tests
------------------------------------
  - Checking for system binaries that are required by Debian Tests...
    - Checking /bin...                                        [ FOUND ]
    - Checking /sbin...                                       [ FOUND ]
    - Checking /usr/bin...                                    [ FOUND ]
    - Checking /usr/sbin...                                   [ FOUND ]
    - Checking /usr/local/bin...                              [ FOUND ]
    - Checking /usr/local/sbin...                             [ FOUND ]
  - Authentication:
    - PAM (Pluggable Authentication Modules):
      - libpam-tmpdir                                         [ Not Installed ]
      - libpam-usb                                            [ Not Installed ]
  - File System Checks:
    - DM-Crypt, Cryptsetup & Cryptmount:
  - Software:
    - apt-listbugs                                            [ Not Installed ]
    - apt-listchanges                                         [ Not Installed ]
    - checkrestart                                            [ Not Installed ]
    - needrestart                                             [ Installed ]
    - debsecan                                                [ Not Installed ]
    - debsums                                                 [ Not Installed ]
    - fail2ban                                                [ Not Installed ]
]

[+] Boot and services
------------------------------------
  - Service Manager                                           [ SysV Init ]
  - Checking UEFI boot                                        [ DESACTIVADO ]
  - Checking presence GRUB2                                   [ ENCONTRADO ]
    - Checking for password protection                        [ PELIGRO ]
  - Check running services (systemctl)                        [ HECHO ]
        Result: found 34 running services
  - Check enabled services at boot (systemctl)                [ HECHO ]
        Result: found 60 enabled services
  - Check startup files (permissions)                         [ OK ]
  - Checking sulogin in rescue.service                        [ NO ENCONTRADO ]

[+] Kernel
------------------------------------
  - Checking default run level                                [ RUNLEVEL 5 ]
  - Checking CPU support (NX/PAE)
    CPU support: PAE and/or NoeXecute supported               [ ENCONTRADO ]
  - Checking kernel version and release                       [ HECHO ]
  - Checking kernel type                                      [ HECHO ]
  - Checking loaded kernel modules                            [ HECHO ]
      Found 48 active modules
  - Checking Linux kernel configuration file                  [ ENCONTRADO ]
  - Checking default I/O kernel scheduler                     [ NO ENCONTRADO ]
  - Checking for available kernel update                      [ DESCONOCIDO ]
  - Checking core dumps configuration                         [ DESACTIVADO ]
    - Checking setuid core dumps configuration                [ PROTECTED ]
  - Check if reboot is needed                                 [ NO ]

[+] Memoria y  Procesos
------------------------------------
  - Checking /proc/meminfo                                    [ ENCONTRADO ]
  - Searching for dead/zombie processes                       [ OK ]
  - Searching for IO waiting processes                        [ OK ]

[+] Users, Groups and Authentication
------------------------------------
  - Administrator accounts                                    [ OK ]
  - Unique UIDs                                               [ OK ]
  - Consistency of group files (grpck)                        [ OK ]
  - Unique group IDs                                          [ OK ]
  - Unique group names                                        [ OK ]
  - Password file consistency                                 [ OK ]
  - Query system users (non daemons)                          [ HECHO ]
  - NIS+ authentication support                               [ NOT ENABLED ]
  - NIS authentication support                                [ NOT ENABLED ]
  - sudoers file                                              [ ENCONTRADO ]
    - Check sudoers file permissions                          [ OK ]
  - PAM password strength tools                               [ SUGERENCIA ]
  - PAM configuration files (pam.conf)                        [ ENCONTRADO ]
  - PAM configuration files (pam.d)                           [ ENCONTRADO ]
  - PAM modules                                               [ ENCONTRADO ]
  - LDAP module in PAM                                        [ NO ENCONTRADO ]
  - Accounts without expire date                              [ OK ]
  - Accounts without password                                 [ OK ]
  - Checking user password aging (minimum)                    [ DESACTIVADO ]
  - User password aging (maximum)                             [ DESACTIVADO ]
  - Checking expired passwords                                [ OK ]
  - Checking Linux single user mode authentication            [ PELIGRO ]
  - Determining default umask
    - umask (/etc/profile)                                    [ NO ENCONTRADO ]
    - umask (/etc/login.defs)                                 [ SUGERENCIA ]
  - LDAP authentication support                               [ NOT ENABLED ]
  - Logging failed login attempts                             [ ENABLED ]

[+] Shells
------------------------------------
  - Checking shells from /etc/shells
    Result: found 7 shells (valid shells: 7).
    - Session timeout settings/tools                          [ NONE ]
  - Checking default umask values
    - Checking default umask in /etc/bash.bashrc              [ NONE ]
    - Checking default umask in /etc/profile                  [ NONE ]

[+] File systems
------------------------------------
  - Checking mount points
    - Checking /home mount point                              [ SUGERENCIA ]
    - Checking /tmp mount point                               [ SUGERENCIA ]
    - Checking /var mount point                               [ SUGERENCIA ]
  - Query swap partitions (fstab)                             [ OK ]
  - Testing swap partitions                                   [ OK ]
  - Testing /proc mount (hidepid)                             [ SUGERENCIA ]
  - Checking for old files in /tmp                            [ OK ]
  - Checking /tmp sticky bit                                  [ OK ]
  - Checking /var/tmp sticky bit                              [ OK ]
  - ACL support root file system                              [ ENABLED ]
  - Mount options of /                                        [ NON DEFAULT ]
  - Disable kernel support of some filesystems
    - Discovered kernel modules: cramfs freevxfs hfs hfsplus jffs2 udf

[+] USB Devices
------------------------------------
  - Checking usb-storage driver (modprobe config)             [ NOT DISABLED ]
  - Checking USB devices authorization                        [ DESACTIVADO ]
  - Checking USBGuard                                         [ NO ENCONTRADO ]

[+] Storage
------------------------------------
  - Checking firewire ohci driver (modprobe config)           [ DESACTIVADO ]

[+] NFS
------------------------------------
  - Check running NFS daemon                                  [ NO ENCONTRADO ]

[+] Name services
------------------------------------
  - Checking /etc/resolv.conf options                         [ ENCONTRADO ]
  - Searching DNS domain name                                 [ ENCONTRADO ]
      Domain name: 04-desktop-amd64.jesusamieiro.com
  - Checking /etc/hosts
    - Checking /etc/hosts (duplicates)                        [ OK ]
    - Checking /etc/hosts (hostname)                          [ OK ]
    - Checking /etc/hosts (localhost)                         [ OK ]
    - Checking /etc/hosts (localhost to IP)                   [ OK ]

[+] Ports and packages
------------------------------------
  - Searching package managers
    - Searching dpkg package manager                          [ ENCONTRADO ]
      - Querying package manager
    - Query unpurged packages                                 [ ENCONTRADO ]
  - Checking security repository in sources.list file         [ OK ]
  - Checking APT package database                             [ OK ]
  - Checking vulnerable packages                              [ PELIGRO ]
  - Checking upgradeable packages                             [ OMITIDO ]
  - Checking package audit tool                               [ INSTALLED ]
    Found: apt-get

[+] Networking
------------------------------------
  - Checking IPv6 configuration                               [ ENABLED ]
      Configuration method                                    [ AUTO ]
      IPv6 only                                               [ NO ]
  - Checking configured nameservers
    - Testing nameservers
        Nameserver: 127.0.0.53                                [ OK ]
    - Minimal of 2 responsive nameservers                     [ PELIGRO ]
  - Checking default gateway                                  [ HECHO ]
  - Getting listening ports (TCP/UDP)                         [ HECHO ]
      * Found 17 ports
  - Checking promiscuous interfaces                           [ OK ]
  - Checking waiting connections                              [ OK ]
  - Checking status DHCP client                               [ NOT ACTIVE ]
  - Checking for ARP monitoring software                      [ NO ENCONTRADO ]

[+] Printers and Spools
------------------------------------
  - Checking cups daemon                                      [ CORRIENDO ]
  - Checking CUPS configuration file                          [ OK ]
    - File permissions                                        [ PELIGRO ]
  - Checking CUPS addresses/sockets                           [ ENCONTRADO ]
  - Checking lp daemon                                        [ NO ESTÁ CORRIENDO ]

[+] Software: e-mail and messaging
------------------------------------

[+] Software: firewalls
------------------------------------
  - Checking iptables kernel module                           [ ENCONTRADO ]
    - Checking iptables policies of chains                    [ ENCONTRADO ]
    - Checking for empty ruleset                              [ PELIGRO ]
    - Checking for unused rules                               [ OK ]
  - Checking host based firewall                              [ ACTIVE ]

[+] Software: webserver
------------------------------------
  - Checking Apache                                           [ NO ENCONTRADO ]
  - Checking nginx                                            [ NO ENCONTRADO ]

[+] SSH Support
------------------------------------
  - Checking running SSH daemon                               [ ENCONTRADO ]
    - Searching SSH configuration                             [ ENCONTRADO ]
    - SSH option: AllowTcpForwarding                          [ SUGERENCIA ]
    - SSH option: ClientAliveCountMax                         [ SUGERENCIA ]
    - SSH option: ClientAliveInterval                         [ OK ]
    - SSH option: Compression                                 [ SUGERENCIA ]
    - SSH option: FingerprintHash                             [ OK ]
    - SSH option: GatewayPorts                                [ OK ]
    - SSH option: IgnoreRhosts                                [ OK ]
    - SSH option: LoginGraceTime                              [ OK ]
    - SSH option: LogLevel                                    [ SUGERENCIA ]
    - SSH option: MaxAuthTries                                [ SUGERENCIA ]
    - SSH option: MaxSessions                                 [ SUGERENCIA ]
    - SSH option: PermitRootLogin                             [ SUGERENCIA ]
    - SSH option: PermitUserEnvironment                       [ OK ]
    - SSH option: PermitTunnel                                [ OK ]
    - SSH option: Port                                        [ SUGERENCIA ]
    - SSH option: PrintLastLog                                [ OK ]
    - SSH option: Protocol                                    [ NO ENCONTRADO ]
    - SSH option: StrictModes                                 [ OK ]
    - SSH option: TCPKeepAlive                                [ SUGERENCIA ]
    - SSH option: UseDNS                                      [ OK ]
    - SSH option: UsePrivilegeSeparation                      [ NO ENCONTRADO ]
    - SSH option: VerifyReverseMapping                        [ NO ENCONTRADO ]
    - SSH option: X11Forwarding                               [ SUGERENCIA ]
    - SSH option: AllowAgentForwarding                        [ SUGERENCIA ]
    - SSH option: AllowUsers                                  [ NO ENCONTRADO ]
    - SSH option: AllowGroups                                 [ NO ENCONTRADO ]

[+] SNMP Support
------------------------------------
  - Checking running SNMP daemon                              [ NO ENCONTRADO ]

[+] Databases
------------------------------------
    No database engines found

[+] LDAP Services
------------------------------------
  - Checking OpenLDAP instance                                [ NO ENCONTRADO ]

[+] PHP
------------------------------------
  - Checking PHP                                              [ NO ENCONTRADO ]

[+] Squid Support
------------------------------------
  - Checking running Squid daemon                             [ NO ENCONTRADO ]

[+] Logging and files
------------------------------------
  - Checking for a running log daemon                         [ OK ]
    - Checking Syslog-NG status                               [ NO ENCONTRADO ]
    - Checking systemd journal status                         [ ENCONTRADO ]
    - Checking Metalog status                                 [ NO ENCONTRADO ]
    - Checking RSyslog status                                 [ ENCONTRADO ]
    - Checking RFC 3195 daemon status                         [ NO ENCONTRADO ]
    - Checking minilogd instances                             [ NO ENCONTRADO ]
  - Checking logrotate presence                               [ OK ]
  - Checking log directories (static list)                    [ HECHO ]
  - Checking open log files                                   [ HECHO ]
  - Checking deleted files in use                             [ FILES FOUND ]

[+] Insecure services
------------------------------------
  - Checking inetd status                                     [ NOT ACTIVE ]

[+] Banners and identification
------------------------------------
  - /etc/issue                                                [ ENCONTRADO ]
    - /etc/issue contents                                     [ WEAK ]
  - /etc/issue.net                                            [ ENCONTRADO ]
    - /etc/issue.net contents                                 [ WEAK ]

[+] Scheduled tasks
------------------------------------
  - Checking crontab/cronjob                                  [ HECHO ]

[+] Accounting
------------------------------------
  - Checking accounting information                           [ NO ENCONTRADO ]
  - Checking sysstat accounting data                          [ NO ENCONTRADO ]
  - Checking auditd                                           [ NO ENCONTRADO ]

[+] Time and Synchronization
------------------------------------
  - NTP daemon found: ntpd                                    [ ENCONTRADO ]
  - NTP daemon found: systemd (timesyncd)                     [ ENCONTRADO ]
  - Checking for a running NTP daemon or client               [ OK ]
  - Checking valid association ID's                           [ ENCONTRADO ]
  - Checking high stratum ntp peers                           [ OK ]
  - Checking unreliable ntp peers                             [ ENCONTRADO ]
  - Checking selected time source                             [ OK ]
  - Checking time source candidates                           [ OK ]
  - Checking falsetickers                                     [ OK ]
  - Checking NTP version                                      [ ENCONTRADO ]

[+] Cryptography
------------------------------------
  - Checking for expired SSL certificates [0/4]               [ NONE ]

[+] Virtualization
------------------------------------

[+] Containers
------------------------------------

[+] Security frameworks
------------------------------------
  - Checking presence AppArmor                                [ ENCONTRADO ]
    - Checking AppArmor status                                [ ENABLED ]
  - Checking presence SELinux                                 [ NO ENCONTRADO ]
  - Checking presence grsecurity                              [ NO ENCONTRADO ]
  - Checking for implemented MAC framework                    [ OK ]

[+] Software: file integrity
------------------------------------
  - Checking file integrity tools
  - Checking presence integrity tool                          [ NO ENCONTRADO ]

[+] Software: System tooling
------------------------------------
  - Checking automation tooling
  - Automation tooling                                        [ NO ENCONTRADO ]
  - Checking for IDS/IPS tooling                              [ NONE ]

[+] Software: Malware
------------------------------------

[+] File Permissions
------------------------------------
  - Starting file permissions check

[+] Home directories
------------------------------------
  - Checking shell history files                              [ OK ]

[+] Kernel Hardening
------------------------------------
  - Comparing sysctl key pairs with scan profile
    - fs.protected_hardlinks (exp: 1)                         [ OK ]
    - fs.protected_symlinks (exp: 1)                          [ OK ]
    - fs.suid_dumpable (exp: 0)                               [ DIFFERENT ]
    - kernel.core_uses_pid (exp: 1)                           [ DIFFERENT ]
    - kernel.ctrl-alt-del (exp: 0)                            [ OK ]
    - kernel.dmesg_restrict (exp: 1)                          [ DIFFERENT ]
    - kernel.kptr_restrict (exp: 2)                           [ DIFFERENT ]
    - kernel.randomize_va_space (exp: 2)                      [ OK ]
    - kernel.sysrq (exp: 0)                                   [ DIFFERENT ]
    - kernel.yama.ptrace_scope (exp: 1 2 3)                   [ OK ]
    - net.ipv4.conf.all.accept_redirects (exp: 0)             [ DIFFERENT ]
    - net.ipv4.conf.all.accept_source_route (exp: 0)          [ OK ]
    - net.ipv4.conf.all.bootp_relay (exp: 0)                  [ OK ]
    - net.ipv4.conf.all.forwarding (exp: 0)                   [ OK ]
    - net.ipv4.conf.all.log_martians (exp: 1)                 [ DIFFERENT ]
    - net.ipv4.conf.all.mc_forwarding (exp: 0)                [ OK ]
    - net.ipv4.conf.all.proxy_arp (exp: 0)                    [ OK ]
    - net.ipv4.conf.all.rp_filter (exp: 1)                    [ DIFFERENT ]
    - net.ipv4.conf.all.send_redirects (exp: 0)               [ DIFFERENT ]
    - net.ipv4.conf.default.accept_redirects (exp: 0)         [ DIFFERENT ]
    - net.ipv4.conf.default.accept_source_route (exp: 0)      [ DIFFERENT ]
    - net.ipv4.conf.default.log_martians (exp: 1)             [ DIFFERENT ]
    - net.ipv4.icmp_echo_ignore_broadcasts (exp: 1)           [ OK ]
    - net.ipv4.icmp_ignore_bogus_error_responses (exp: 1)     [ OK ]
    - net.ipv4.tcp_syncookies (exp: 1)                        [ OK ]
    - net.ipv4.tcp_timestamps (exp: 0 1)                      [ OK ]
    - net.ipv6.conf.all.accept_redirects (exp: 0)             [ DIFFERENT ]
    - net.ipv6.conf.all.accept_source_route (exp: 0)          [ OK ]
    - net.ipv6.conf.default.accept_redirects (exp: 0)         [ DIFFERENT ]
    - net.ipv6.conf.default.accept_source_route (exp: 0)      [ OK ]

[+] Hardening
------------------------------------
    - Installed compiler(s)                                   [ ENCONTRADO ]
    - Installed malware scanner                               [ NO ENCONTRADO ]

[+] Pruebas personalizadas
------------------------------------
  - Running custom tests...                                   [ NONE ]

[+] Plugins (fase 2)
------------------------------------

================================================================================

  -[ Lynis 2.6.2 Results ]-

  Warnings (5):
  ----------------------------
  ! Version of Lynis is very old and should be updated [LYNIS]
      https://cisofy.com/controls/LYNIS/

  ! No password set for single mode [AUTH-9308]
      https://cisofy.com/controls/AUTH-9308/

  ! Found one or more vulnerable packages. [PKGS-7392]
      https://cisofy.com/controls/PKGS-7392/

  ! Couldn't find 2 responsive nameservers [NETW-2705]
      https://cisofy.com/controls/NETW-2705/

  ! iptables module(s) loaded, but no rules active [FIRE-4512]
      https://cisofy.com/controls/FIRE-4512/

  Suggestions (51):
  ----------------------------
  * Install libpam-tmpdir to set $TMP and $TMPDIR for PAM sessions [CUST-0280]
      https://your-domain.example.org/controls/CUST-0280/

  * Install libpam-usb to enable multi-factor authentication for PAM sessions [CUST-0285]
      https://your-domain.example.org/controls/CUST-0285/

  * Install apt-listbugs to display a list of critical bugs prior to each APT installation. [CUST-0810]
      https://your-domain.example.org/controls/CUST-0810/

  * Install apt-listchanges to display any significant changes prior to any upgrade via APT. [CUST-0811]
      https://your-domain.example.org/controls/CUST-0811/

  * Install debian-goodies so that you can run checkrestart after upgrades to determine which services are using old versions of libraries and need restarting. [CUST-0830]
      https://your-domain.example.org/controls/CUST-0830/

  * Install debsecan to generate lists of vulnerabilities which affect this installation. [CUST-0870]
      https://your-domain.example.org/controls/CUST-0870/

  * Install debsums for the verification of installed package files against MD5 checksums. [CUST-0875]
      https://your-domain.example.org/controls/CUST-0875/

  * Install fail2ban to automatically ban hosts that commit multiple authentication errors. [DEB-0880]
      https://cisofy.com/controls/DEB-0880/

  * Set a password on GRUB bootloader to prevent altering boot configuration (e.g. boot in single user mode without password) [BOOT-5122]
      https://cisofy.com/controls/BOOT-5122/

  * Protect rescue.service by using sulogin [BOOT-5260]
      https://cisofy.com/controls/BOOT-5260/

  * Determine why /vmlinuz is missing on this Debian/Ubuntu system. [KRNL-5788]
    - Details  : /vmlinuz
      https://cisofy.com/controls/KRNL-5788/

  * Check the output of apt-cache policy manually to determine why output is empty [KRNL-5788]
      https://cisofy.com/controls/KRNL-5788/

  * Install a PAM module for password strength testing like pam_cracklib or pam_passwdqc [AUTH-9262]
      https://cisofy.com/controls/AUTH-9262/

  * Configure minimum password age in /etc/login.defs [AUTH-9286]
      https://cisofy.com/controls/AUTH-9286/

  * Configure maximum password age in /etc/login.defs [AUTH-9286]
      https://cisofy.com/controls/AUTH-9286/

  * Set password for single user mode to minimize physical access attack surface [AUTH-9308]
      https://cisofy.com/controls/AUTH-9308/

  * Default umask in /etc/login.defs could be more strict like 027 [AUTH-9328]
      https://cisofy.com/controls/AUTH-9328/

  * To decrease the impact of a full /home file system, place /home on a separated partition [FILE-6310]
      https://cisofy.com/controls/FILE-6310/

  * To decrease the impact of a full /tmp file system, place /tmp on a separated partition [FILE-6310]
      https://cisofy.com/controls/FILE-6310/

  * To decrease the impact of a full /var file system, place /var on a separated partition [FILE-6310]
      https://cisofy.com/controls/FILE-6310/

  * Disable drivers like USB storage when not used, to prevent unauthorized storage or data theft [STRG-1840]
      https://cisofy.com/controls/STRG-1840/

  * Purge old/removed packages (1 found) with aptitude purge or dpkg --purge command. This will cleanup old configuration files, cron jobs and startup scripts. [PKGS-7346]
      https://cisofy.com/controls/PKGS-7346/

  * Install debsums utility for the verification of packages with known good database. [PKGS-7370]
      https://cisofy.com/controls/PKGS-7370/

  * Update your system with apt-get update, apt-get upgrade, apt-get dist-upgrade and/or unattended-upgrades [PKGS-7392]
      https://cisofy.com/controls/PKGS-7392/

  * Install package apt-show-versions for patch management purposes [PKGS-7394]
      https://cisofy.com/controls/PKGS-7394/

  * Check your resolv.conf file and fill in a backup nameserver if possible [NETW-2705]
      https://cisofy.com/controls/NETW-2705/

  * Consider running ARP monitoring software (arpwatch,arpon) [NETW-3032]
      https://cisofy.com/controls/NETW-3032/

  * Access to CUPS configuration could be more strict. [PRNT-2307]
      https://cisofy.com/controls/PRNT-2307/

  * Consider hardening SSH configuration [SSH-7408]
    - Details  : AllowTcpForwarding (YES --> NO)
      https://cisofy.com/controls/SSH-7408/

  * Consider hardening SSH configuration [SSH-7408]
    - Details  : ClientAliveCountMax (3 --> 2)
      https://cisofy.com/controls/SSH-7408/

  * Consider hardening SSH configuration [SSH-7408]
    - Details  : Compression (YES --> (DELAYED|NO))
      https://cisofy.com/controls/SSH-7408/

  * Consider hardening SSH configuration [SSH-7408]
    - Details  : LogLevel (INFO --> VERBOSE)
      https://cisofy.com/controls/SSH-7408/

  * Consider hardening SSH configuration [SSH-7408]
    - Details  : MaxAuthTries (6 --> 2)
      https://cisofy.com/controls/SSH-7408/

  * Consider hardening SSH configuration [SSH-7408]
    - Details  : MaxSessions (10 --> 2)
      https://cisofy.com/controls/SSH-7408/

  * Consider hardening SSH configuration [SSH-7408]
    - Details  : PermitRootLogin (WITHOUT-PASSWORD --> NO)
      https://cisofy.com/controls/SSH-7408/

  * Consider hardening SSH configuration [SSH-7408]
    - Details  : Port (22 --> )
      https://cisofy.com/controls/SSH-7408/

  * Consider hardening SSH configuration [SSH-7408]
    - Details  : TCPKeepAlive (YES --> NO)
      https://cisofy.com/controls/SSH-7408/

  * Consider hardening SSH configuration [SSH-7408]
    - Details  : X11Forwarding (YES --> NO)
      https://cisofy.com/controls/SSH-7408/

  * Consider hardening SSH configuration [SSH-7408]
    - Details  : AllowAgentForwarding (YES --> NO)
      https://cisofy.com/controls/SSH-7408/

  * Check what deleted files are still in use and why. [LOGG-2190]
      https://cisofy.com/controls/LOGG-2190/

  * Add a legal banner to /etc/issue, to warn unauthorized users [BANN-7126]
      https://cisofy.com/controls/BANN-7126/

  * Add legal banner to /etc/issue.net, to warn unauthorized users [BANN-7130]
      https://cisofy.com/controls/BANN-7130/

  * Enable process accounting [ACCT-9622]
      https://cisofy.com/controls/ACCT-9622/

  * Enable sysstat to collect accounting (no results) [ACCT-9626]
      https://cisofy.com/controls/ACCT-9626/

  * Enable auditd to collect audit information [ACCT-9628]
      https://cisofy.com/controls/ACCT-9628/

  * Check ntpq peers output for unreliable ntp peers and correct/replace them [TIME-3120]
      https://cisofy.com/controls/TIME-3120/

  * Install a file integrity tool to monitor changes to critical and sensitive files [FINT-4350]
      https://cisofy.com/controls/FINT-4350/

  * Determine if automation tools are present for system management [TOOL-5002]
      https://cisofy.com/controls/TOOL-5002/

  * One or more sysctl values differ from the scan profile and could be tweaked [KRNL-6000]
    - Solution : Change sysctl value or disable test (skip-test=KRNL-6000:<sysctl-key>)
      https://cisofy.com/controls/KRNL-6000/

  * Harden compilers like restricting access to root user only [HRDN-7222]
      https://cisofy.com/controls/HRDN-7222/

  * Harden the system by installing at least one malware scanner, to perform periodic file system scans [HRDN-7230]
    - Solution : Install a tool like rkhunter, chkrootkit, OSSEC
      https://cisofy.com/controls/HRDN-7230/

  Follow-up:
  ----------------------------
  - Show details of a test (lynis show details TEST-ID)
  - Check the logfile for all details (less /var/log/lynis.log)
  - Read security controls texts (https://cisofy.com)
  - Use --upload to upload data to central system (Lynis Enterprise users)

================================================================================

  Lynis security scan details:

  Hardening index : 53 [##########          ]
  Tests performed : 227
  Plugins enabled : 1

  Components:
  - Firewall               [V]
  - Malware scanner        [X]

  Lynis Modules:
  - Compliance Status      [?]
  - Security Audit         [V]
  - Vulnerability Scan     [V]

  Files:
  - Test and debug information      : /var/log/lynis.log
  - Report data                     : /var/log/lynis-report.dat

================================================================================
  Notice: Lynis Actualización disponible
  Versión actual : 262    Latest version : 316
================================================================================

  Lynis 2.6.2

  Auditing, system hardening, and compliance for UNIX-based systems
  (Linux, macOS, BSD, and others)

  2007-2018, CISOfy - https://cisofy.com/lynis/
  Enterprise support available (compliance, plugins, interface and tools)

================================================================================

  [TIP]: Enhance Lynis audits by adding your settings to custom.prf (see /etc/lynis/default.prf for all settings)
```

### 4. Resolver sugerencias detectadas por Lynis

- De las [SUGGESTION], resolver:
  - Las relacionadas con el módulo PAM: `[AUTH-9262]`, `[AUTH-9286]`, `[AUTH-9286]`.
  - La relacionada con herramientas de monitoreo de ARP: `[NETW-3032]`.
  - Todo lo indicado para el hardening de SSH.
  - Instalar un escáner de malware como “chkrootkit”: `[HRDN-7230]`.

#### Módulo PAM (AUTH-9262, AUTH-9286)

- **AUTH-9262**: Instala un módulo PAM para la verificación de fortaleza de contraseñas, como `pam_cracklib` o `pam_passwdqc`. Puedes instalarlo con:

```bash
sudo apt install libpam-cracklib
```

Luego, edita `/etc/pam.d/common-password` y asegúrate de que la línea incluya:

```bash
password requisite pam_cracklib.so retry=3 minlen=8 difok=3
```

- `retry=3`: Permite hasta 3 intentos para introducir una contraseña que cumpla los requisitos antes de cancelar el proceso.
- `minlen=8`: Obliga a que la contraseña tenga al menos 8 caracteres.
- `difok=3`: Requiere que la nueva contraseña difiera de la anterior en al menos 3 caracteres.

Esto obligará a que las contraseñas sean más seguras.

- **AUTH-9286**: Configura la edad mínima y máxima de las contraseñas en `/etc/login.defs`. Añade o modifica las siguientes líneas:

```bash
# Password aging controls:
#
#       PASS_MAX_DAYS   Maximum number of days a password may be used.
#       PASS_MIN_DAYS   Minimum number of days allowed between password changes.
#       PASS_WARN_AGE   Number of days warning given before a password expires.
#
PASS_MAX_DAYS   20
PASS_MIN_DAYS   5
PASS_WARN_AGE   10
```

Esto obligará a que los usuarios cambien sus contraseñas periódicamente y no puedan cambiarlas demasiado rápido.

#### Monitoreo de ARP (NETW-3032)

- **NETW-3032**: Instala y configura una herramienta de monitoreo de ARP, como `arpwatch` o `arpon`. Por ejemplo, para instalar `arpwatch`:

```bash
sudo apt install arpwatch
sudo systemctl enable arpwatch
sudo systemctl start arpwatch
```

Esto te permitirá detectar cambios sospechosos en la tabla ARP y prevenir ataques como ARP spoofing.

#### Hardening de SSH

- Asegúrate de que `/etc/ssh/sshd_config` tenga estas configuraciones recomendadas:

```bash
PermitRootLogin no
MaxAuthTries 2
MaxSessions 2
AllowTcpForwarding no
Compression delayed
LogLevel VERBOSE
TCPKeepAlive no
X11Forwarding no
AllowAgentForwarding no
```

Reinicia el servicio SSH después de los cambios:

```bash
sudo systemctl restart ssh
```

Estas opciones mejoran la seguridad del acceso remoto.

#### Escáner de Malware (HRDN-7230)

- **HRDN-7230**: Instala un escáner de malware como `chkrootkit`. Ejecuta:

```bash
sudo apt install chkrootkit
```

Luego, realiza un escaneo manual con:

```bash
sudo chkrootkit
```

Puedes programar escaneos periódicos usando cron. Esto ayudará a detectar rootkits y malware en tu sistema.

### 5. Comprobación final de resultados

- Ejecutar Lynis nuevamente para comprobar la efectividad de las soluciones aplicadas.
- Realizar una nueva captura de pantalla del Hardening Index (`capturaFinal.png`).

Despues de realizar todos los pasos podemos ver lo siguiente:

```bash
  Lynis security scan details:

  Hardening index : 62 [############        ]
  Tests performed : 227
  Plugins enabled : 1

  Components:
  - Firewall               [V]
  - Malware scanner        [V]

  Lynis Modules:
  - Compliance Status      [?]
  - Security Audit         [V]
  - Vulnerability Scan     [V]

  Files:
  - Test and debug information      : /var/log/lynis.log
  - Report data                     : /var/log/lynis-report.dat
```

Hemos mejorado el nivel de hardening de nuestra máquina de 53 a 62 por lo que nuestro sistema es más robusto ahora.
