# DNS — BIND 9.4.2 (puerto 53) — Metasploitable 2

> Práctica de laboratorio: aplicar únicamente sobre tu propia máquina Metasploitable 2 (`192.168.100.9`), aislada de Internet. Documento de la serie [Reconocimiento y Metasploit](./01_reconocimiento_y_metasploit.md).

**Qué es:** DNS traduce nombres de dominio a direcciones IP. Lo sirve **ISC BIND 9.4.2** en el **puerto 53**.

**Cómo se explota:** esta versión no tiene un RCE sencillo en el laboratorio; su interés es de **reconocimiento**: averiguar la versión y probar una **transferencia de zona** (si está mal configurada, vuelca todos los registros del dominio).

## Explotación manual (sin Metasploit)

```bash
# Versión del servidor DNS
dig version.bind chaos txt @192.168.100.9

# Intento de transferencia de zona (sustituye <dominio> por el que descubras)
dig axfr @192.168.100.9 <dominio>
```

## Explotación con Metasploit

```bash
use auxiliary/gather/dns_info
set DOMAIN <dominio>
run
# (también auxiliary/scanner/dns/... para enumeración)
```
