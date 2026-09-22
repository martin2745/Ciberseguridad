# CMS — Joomla

## Índice

1. [Introducción a Joomla](#1-introducción-a-joomla)
2. [Despliegue del laboratorio (CVE-2015-8562)](#2-despliegue-del-laboratorio-cve-2015-8562)
3. [Reconocimiento inicial](#3-reconocimiento-inicial)
4. [Enumeración con JoomScan](#4-enumeración-con-joomscan)
5. [Enumeración con Nmap](#5-enumeración-con-nmap)

---

## 1. Introducción a Joomla

En esta clase veremos cómo enumerar el gestor de contenido **Joomla**. Joomla es un sistema de gestión de contenidos (CMS) de código abierto que se utiliza para crear sitios web y aplicaciones en línea. Es muy popular debido a su facilidad de uso y flexibilidad, lo que lo convierte en una opción habitual para sitios web empresariales, gubernamentales y de organizaciones sin ánimo de lucro.

Joomla es altamente personalizable y cuenta con una gran cantidad de extensiones disponibles, lo que permite a los usuarios añadir funcionalidades adicionales a sus sitios web sin necesidad de conocimientos de programación avanzados. Joomla también cuenta con una comunidad activa de desarrolladores y usuarios que comparten sus conocimientos y recursos para mejorar el CMS.

> **Nota:** Al igual que WordPress, la mayoría de los problemas de seguridad de Joomla provienen de **extensiones de terceros** y de versiones del núcleo sin actualizar. La enumeración busca identificar la versión de Joomla, sus componentes/extensiones y posibles rutas y ficheros sensibles.

---

## 2. Despliegue del laboratorio (CVE-2015-8562)

Se comparte el enlace del proyecto que desplegaremos en Docker para auditar un Joomla:

- **CVE-2015-8562**: https://github.com/vulhub/vulhub/tree/master/joomla/CVE-2015-8562

> **Nota:** Han actualizado el proyecto de GitHub: ahora simplemente lo despliegas con `docker-compose up -d` y no hace falta realizar el proceso de instalación, ya viene todo instalado por defecto.

Despliegue del entorno con Vulhub:

```bash
┌──(kali㉿kali)-[~]
└─$ git clone https://github.com/vulhub/vulhub.git
```

```bash
┌──(kali㉿kali)-[~]
└─$ cd vulhub/joomla/CVE-2015-8562
```

```bash
┌──(kali㉿kali)-[~/vulhub/joomla/CVE-2015-8562]
└─$ docker-compose up -d
```

| Comando | Descripción |
|---------|-------------|
| `git clone ...` | Descarga el repositorio de Vulhub. |
| `cd vulhub/joomla/CVE-2015-8562` | Entra en el directorio del laboratorio. |
| `docker-compose up -d` | Levanta el contenedor Joomla vulnerable en segundo plano. |

> **Nota:** CVE-2015-8562 es una vulnerabilidad crítica de **ejecución remota de código** en Joomla 1.5 a 3.4.5, provocada por una deserialización insegura del valor de la cabecera `User-Agent`. La enumeración previa nos permitirá confirmar que la versión desplegada es vulnerable.

---

## 3. Reconocimiento inicial

Para confirmar que el objetivo es un Joomla y averiguar su versión, hay varios ficheros reveladores. El más fiable es `administrator/manifests/files/joomla.xml`:

```bash
┌──(kali㉿kali)-[~]
└─$ curl -s http://localhost/administrator/manifests/files/joomla.xml | grep -i version
```

**Ejemplo de salida (fragmento representativo):**

```bash
<version>3.4.5</version>
```

| Elemento | Descripción |
|----------|-------------|
| `curl -s` | Descarga el contenido de forma silenciosa. |
| `administrator/manifests/files/joomla.xml` | Fichero de manifiesto que declara la versión exacta del núcleo de Joomla. |
| `grep -i version` | Filtra la línea que contiene la versión. |

Otro fichero clásico es `README.txt`, que suele indicar la rama de versión:

```bash
┌──(kali㉿kali)-[~]
└─$ curl -s http://localhost/README.txt | head -n 5
```

> **Nota:** La presencia del directorio `/administrator/` (el panel de administración de Joomla) es una señal inequívoca de que estamos ante este CMS.

---

## 4. Enumeración con JoomScan

Una de las herramientas que usamos en esta clase es **JoomScan**. Es una herramienta de línea de comandos diseñada específicamente para escanear sitios web que utilizan Joomla y buscar posibles vulnerabilidades y debilidades de seguridad.

JoomScan utiliza una variedad de técnicas de enumeración para identificar información sobre el sitio: la versión de Joomla utilizada, los componentes y módulos instalados, y posibles ficheros sensibles. También emplea una base de datos de vulnerabilidades conocidas para buscar problemas en la instalación.

Está mantenida por OWASP. En Kali suele venir instalada; si no, se descarga del proyecto oficial:

- **JoomScan (OWASP)**: https://github.com/OWASP/joomscan

Si necesitas instalarla manualmente:

```bash
┌──(kali㉿kali)-[~]
└─$ git clone https://github.com/OWASP/joomscan.git
```

```bash
┌──(kali㉿kali)-[~]
└─$ cd joomscan
```

La sintaxis básica para escanear un sitio de Joomla es:

```bash
┌──(kali㉿kali)-[~]
└─$ joomscan --url http://localhost
```

Si la ejecutas desde el código fuente clonado, se invoca con Perl:

```bash
┌──(kali㉿kali)-[~/joomscan]
└─$ perl joomscan.pl -u http://localhost
```

| Parámetro | Descripción |
|-----------|-------------|
| `--url` / `-u http://localhost` | URL del sitio Joomla a escanear. |
| `perl joomscan.pl` | Forma de invocarlo cuando se ejecuta el script directamente (JoomScan está escrito en Perl). |
| `--enumerate-components` | (Opcional) Fuerza la enumeración de todos los componentes instalados. |

**Ejemplo de salida (fragmento representativo):**

```bash
    OWASP JoomScan
    Version : 0.0.7
--------------------------------------------
[+] URL: http://localhost/
[+] Detecting Joomla Version
[++] Joomla 3.4.5

[+] Core Joomla Vulnerability
[++] Target Joomla core is vulnerable to Remote Code Execution (CVE-2015-8562)

[+] Checking Directory Listing
[++] directory has directory listing:
     http://localhost/administrator/components/

[+] Checking apache info/status files
[++] Readme file found:
     http://localhost/README.txt
```

| Sección de la salida | Qué indica |
|----------------------|------------|
| `Detecting Joomla Version` | Versión del núcleo detectada. |
| `Core Joomla Vulnerability` | Vulnerabilidades conocidas del núcleo para esa versión (aquí, la RCE del laboratorio). |
| `Checking Directory Listing` | Directorios con listado abierto (fuga de información). |
| `Readme file found` | Ficheros informativos accesibles que ayudan a confirmar la versión. |

> **Importante:** La línea `vulnerable to Remote Code Execution (CVE-2015-8562)` confirma que la versión desplegada es explotable. En el informe hay que anotar la versión, el CVE y la evidencia (la propia salida de JoomScan).

Es importante tener en cuenta que JoomScan no es una herramienta infalible y puede generar falsos positivos o falsos negativos. Por lo tanto, conviene utilizarla junto con otras herramientas y técnicas para tener una imagen completa de la seguridad del Joomla auditado.

---

## 5. Enumeración con Nmap

Como complemento, Nmap dispone de un script NSE específico para Joomla y de utilidades genéricas de HTTP:

```bash
┌──(kali㉿kali)-[~]
└─$ nmap -p80 --script http-joomla-brute,http-enum localhost
```

| Script | Descripción |
|--------|-------------|
| `http-joomla-brute` | Realiza fuerza bruta contra el panel de administración de Joomla. |
| `http-enum` | Enumera rutas y ficheros comunes (paneles, backups, directorios conocidos). |

> **Nota:** `http-enum` es genérico pero muy útil en cualquier servicio web: revela paneles de administración, ficheros de copia de seguridad y directorios interesantes que sirven como punto de partida para una auditoría más profunda.

> **Recuerda:** Todas estas prácticas se realizan sobre el laboratorio desplegado en tu propia máquina. Escanear sitios de terceros sin autorización explícita es ilegal.
