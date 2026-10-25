# rpcbind (puerto 111) — Metasploitable 2

> Práctica de laboratorio: aplicar únicamente sobre tu propia máquina Metasploitable 2 (`192.168.100.9`), aislada de Internet. Documento de la serie [Reconocimiento y Metasploit](./01_reconocimiento_y_metasploit.md).

**Qué es:** `rpcbind` (portmapper) es el "directorio" de los servicios **RPC**: cuando un cliente quiere hablar con NFS, mountd, etc., primero pregunta aquí en qué puerto están. **Puerto 111**.

**Cómo se explota:** por sí mismo no da acceso; es la **puerta de enumeración** que revela, sobre todo, el servicio **NFS** (ver [13_nfs.md](./13_nfs.md)).

## Explotación manual (sin Metasploit)

```bash
rpcinfo -p 192.168.100.9        # lista todos los servicios RPC y sus puertos
```

## Explotación con Metasploit

```bash
use auxiliary/scanner/nfs/nfsmount    # enumera exportaciones NFS vía rpcbind
set RHOSTS 192.168.100.9
run
```
