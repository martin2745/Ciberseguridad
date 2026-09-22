# HTTP / HTTPS

## Índice

1. [Introducción a HTTP y HTTPS](#1-introducción-a-http-y-https)
2. [Diferencias entre HTTP y HTTPS](#2-diferencias-entre-http-y-https)
3. [Inspección del certificado SSL/TLS con OpenSSL](#3-inspección-del-certificado-ssltls-con-openssl)
4. [Análisis de la configuración SSL/TLS: sslyze y sslscan](#4-análisis-de-la-configuración-ssltls-sslyze-y-sslscan)
5. [Enumeración con Nmap](#5-enumeración-con-nmap)
6. [Descubrimiento de directorios y ficheros](#6-descubrimiento-de-directorios-y-ficheros)
   - [gobuster](#gobuster)
   - [ffuf](#ffuf)
   - [Nikto](#nikto)
7. [Caso práctico: la vulnerabilidad Heartbleed (CVE-2014-0160)](#7-caso-práctico-la-vulnerabilidad-heartbleed-cve-2014-0160)
   - [Despliegue del laboratorio vulnerable](#despliegue-del-laboratorio-vulnerable)
   - [Detección de Heartbleed](#detección-de-heartbleed)

---

## 1. Introducción a HTTP y HTTPS

HTTP (*Hypertext Transfer Protocol*) es un protocolo de comunicación utilizado para la transferencia de datos en la World Wide Web. Se emplea para transferir contenido de texto, imágenes, vídeos, hipervínculos, etc. El puerto predeterminado para HTTP es el **puerto 80**.

HTTPS (*Hypertext Transfer Protocol Secure*) es una versión segura de HTTP que utiliza SSL/TLS para cifrar la comunicación entre el cliente y el servidor. Utiliza el **puerto 443** por defecto. La principal diferencia entre HTTP y HTTPS es que HTTPS emplea una capa de seguridad adicional para cifrar los datos, lo que los hace más seguros durante la transferencia.

> **Nota:** En una auditoría, el servicio web es casi siempre el que más superficie de ataque expone (aplicaciones, paneles de administración, APIs…). Por eso su enumeración es tan importante: identificar el servidor, sus tecnologías, sus rutas y —en HTTPS— la calidad de su configuración criptográfica.

---

## 2. Diferencias entre HTTP y HTTPS

| Característica        | HTTP                          | HTTPS                                            |
| :------------------- | :---------------------------- | :----------------------------------------------- |
| Puerto por defecto   | `80/tcp`                      | `443/tcp`                                        |
| Cifrado              | Ninguno (texto plano)         | SSL/TLS                                           |
| Integridad de datos  | No garantizada                | Garantizada por TLS                              |
| Autenticación del servidor | No                      | Sí, mediante **certificado digital**             |
| Riesgo de *sniffing* | Alto (todo es legible)        | Bajo (tráfico cifrado)                           |

> **Importante:** En HTTP todo viaja en claro, incluidas las credenciales enviadas en formularios. Capturar tráfico HTTP con un *sniffer* (como Wireshark) permite leer directamente usuarios y contraseñas. Es una de las razones por las que HTTPS es hoy el estándar.

---

## 3. Inspección del certificado SSL/TLS con OpenSSL

Una de las herramientas que vemos en esta clase para inspeccionar el certificado SSL es **OpenSSL**. OpenSSL es una biblioteca de software libre y de código abierto que se utiliza para implementar protocolos de seguridad en línea, como TLS (*Transport Layer Security*) y SSL (*Secure Sockets Layer*). Proporciona una implementación de estos protocolos para permitir que las aplicaciones se comuniquen de manera segura y cifrada a través de la red.

El comando principal que usamos con esta herramienta es el siguiente:

```bash
┌──(kali㉿kali)-[~]
└─$ openssl s_client -connect ejemplo.com:443
```

| Parámetro | Descripción |
|-----------|-------------|
| `s_client` | Cliente TLS/SSL de prueba. Establece una conexión segura y muestra todos los detalles de la negociación. |
| `-connect ejemplo.com:443` | Host y puerto al que conectarse (`443` es el puerto HTTPS por defecto). |

Con este comando podemos inspeccionar el certificado SSL de un servidor web. Se conecta al servidor en el puerto 443 y muestra información detallada sobre el certificado SSL, como su validez, la fecha de caducidad, el tipo de cifrado, etc.

**Ejemplo de salida (fragmento representativo):**

```bash
CONNECTED(00000003)
depth=2 C = US, O = DigiCert Inc, CN = DigiCert Global Root CA
verify return:1
---
Certificate chain
 0 s:CN = ejemplo.com
   i:C = US, O = DigiCert Inc, CN = DigiCert TLS RSA SHA256 2020 CA1
---
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
---
```

> **Nota:** El bloque `Certificate chain` muestra la cadena de confianza (del certificado del sitio hasta la CA raíz), y `Protocol`/`Cipher` indican la versión de TLS y el algoritmo de cifrado negociados. Para salir de la sesión interactiva de `s_client`, pulsa `Ctrl+C` o escribe `Q` y Enter.

Algunas variantes útiles para el aula:

```bash
# Ver solo las fechas de validez del certificado
┌──(kali㉿kali)-[~]
└─$ echo | openssl s_client -connect ejemplo.com:443 2>/dev/null | openssl x509 -noout -dates
```

```bash
# Especificar el nombre de host (SNI), necesario en servidores con varios dominios
┌──(kali㉿kali)-[~]
└─$ openssl s_client -connect ejemplo.com:443 -servername ejemplo.com
```

| Parámetro / elemento | Descripción |
|----------------------|-------------|
| `echo \|` | Envía una entrada vacía para que la conexión se cierre sola y no quede a la espera interactiva. |
| `x509 -noout -dates` | Procesa el certificado y muestra únicamente (`-noout`) sus fechas de emisión y caducidad (`-dates`). |
| `-servername ejemplo.com` | Envía la extensión **SNI** (*Server Name Indication*), imprescindible cuando un mismo servidor aloja varios dominios HTTPS. |

> **Recuerda:** Un certificado caducado, autofirmado o que no corresponde al dominio es un hallazgo relevante en una auditoría: puede indicar mala gestión o facilitar ataques de suplantación.

---

## 4. Análisis de la configuración SSL/TLS: sslyze y sslscan

Otras herramientas que vemos en esta clase son **sslyze** y **sslscan**.

- **sslyze** es una herramienta de análisis de seguridad SSL que se utiliza para evaluar la configuración SSL de un servidor. Proporciona información detallada sobre el cifrado utilizado, los protocolos admitidos y los certificados SSL.
- **sslscan** es otra herramienta de análisis de seguridad SSL que se utiliza para evaluar la configuración SSL de un servidor. Proporciona información detallada sobre los protocolos SSL/TLS admitidos, el cifrado utilizado y los certificados SSL.

La principal diferencia entre ambas es que **sslyze** se enfoca en una evaluación de seguridad más **exhaustiva** de los protocolos y configuraciones SSL/TLS (incluye comprobaciones de vulnerabilidades concretas), mientras que **sslscan** se enfoca en la **identificación rápida** de los protocolos SSL/TLS admitidos por el servidor y los cifrados utilizados.

| Herramienta | Enfoque | Uso típico |
| :---------- | :------ | :--------- |
| `sslscan`   | Identificación rápida de protocolos y cifrados admitidos | Primera foto de qué acepta el servidor |
| `sslyze`    | Análisis exhaustivo + comprobación de vulnerabilidades | Auditoría en profundidad de la configuración |

Ejemplo de uso de **sslscan** contra un servidor:

```bash
┌──(kali㉿kali)-[~]
└─$ sslscan ejemplo.com
```

**Ejemplo de salida (fragmento representativo):**

```bash
  SSL/TLS Protocols:
SSLv2     disabled
SSLv3     disabled
TLSv1.0   disabled
TLSv1.1   disabled
TLSv1.2   enabled
TLSv1.3   enabled

  Supported Server Cipher(s):
Preferred TLSv1.3  256 bits  TLS_AES_256_GCM_SHA384
Accepted  TLSv1.2  256 bits  ECDHE-RSA-AES256-GCM-SHA384
```

> **Nota:** Que aparezcan como `enabled` protocolos antiguos (`SSLv2`, `SSLv3`, `TLSv1.0`, `TLSv1.1`) es un hallazgo negativo: están obsoletos y son vulnerables. Una configuración segura solo debería admitir `TLSv1.2` y `TLSv1.3`.

Ejemplo de uso de **sslyze** con comprobaciones concretas:

```bash
┌──(kali㉿kali)-[~]
└─$ sslyze --certinfo --tlsv1_2 --heartbleed ejemplo.com
```

| Parámetro | Descripción |
|-----------|-------------|
| `--certinfo` | Analiza y valida el certificado del servidor. |
| `--tlsv1_2` | Comprueba los cifrados admitidos en TLS 1.2. |
| `--heartbleed` | Comprueba específicamente si el servidor es vulnerable a Heartbleed (ver sección 6). |

La identificación de la información arrojada por las herramientas de análisis SSL/TLS es de suma importancia, ya que nos permite detectar vulnerabilidades en la configuración de un servidor y tomar medidas para proteger nuestra información confidencial.

---

## 5. Enumeración con Nmap

Nmap también permite auditar el servicio HTTP/HTTPS mediante sus scripts NSE. Para ver el certificado y los cifrados admitidos:

```bash
┌──(kali㉿kali)-[~]
└─$ nmap -p443 --script ssl-cert,ssl-enum-ciphers ejemplo.com
```

| Parámetro | Descripción |
|-----------|-------------|
| `-p443` | Limita el escaneo al puerto HTTPS. |
| `--script ssl-cert` | Muestra los datos del certificado SSL (titular, emisor, validez). |
| `--script ssl-enum-ciphers` | Enumera los protocolos y suites de cifrado admitidos, con una nota de calidad (A–F) para cada uno. |

Para enumerar rápidamente un servicio HTTP (título de la página, cabeceras, tecnologías):

```bash
┌──(kali㉿kali)-[~]
└─$ nmap -sSCV -p80,443 ejemplo.com
```

> **Nota:** Los scripts por defecto (`-sC`) incluyen `http-title` (título de la web) y `http-server-header` (software del servidor), que ayudan a hacerse una idea inicial del objetivo sin abrir el navegador.

Otra herramienta muy usada para enumerar tecnologías web es `whatweb`:

```bash
┌──(kali㉿kali)-[~]
└─$ whatweb https://ejemplo.com
```

| Comando | Descripción |
|---------|-------------|
| `whatweb https://ejemplo.com` | Identifica el servidor web, el CMS, los frameworks, las librerías JavaScript y otras tecnologías empleadas por el sitio. |

---

## 6. Descubrimiento de directorios y ficheros

Los servidores web casi nunca enlazan todo su contenido desde la portada. Rutas de administración, ficheros de copia de seguridad, paneles ocultos o directorios olvidados suelen existir sin estar enlazados. El **descubrimiento de contenido** (*content discovery* o *directory brute forcing*) consiste en probar una lista de nombres habituales contra el servidor y quedarse con los que responden.

> **Nota:** La técnica se basa en el **código de respuesta HTTP**: `200` (existe), `301`/`302` (redirección, suele existir), `403` (prohibido, pero *existe*) y `404` (no existe). Encontrar un `403` es interesante: el recurso está ahí, solo que protegido.

### gobuster

`gobuster` prueba nombres de un diccionario contra el servidor y reporta los que existen:

```bash
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://localhost -w /usr/share/wordlists/dirb/common.txt
```

| Parámetro | Descripción |
|-----------|-------------|
| `dir` | Modo de descubrimiento de **directorios y ficheros**. |
| `-u http://localhost` | URL objetivo. |
| `-w /usr/share/wordlists/dirb/common.txt` | Diccionario de nombres a probar (*wordlist*). |
| `-x php,txt,bak` | (Opcional) Extensiones a añadir a cada palabra (busca `admin.php`, `admin.txt`…). |

**Ejemplo de salida (fragmento representativo):**

```bash
===============================================================
Gobuster v3.6
===============================================================
/.htaccess            (Status: 403) [Size: 278]
/admin                (Status: 301) [Size: 313] [--> http://localhost/admin/]
/index.php            (Status: 200) [Size: 10701]
/robots.txt           (Status: 200) [Size: 45]
/backup               (Status: 301) [Size: 314] [--> http://localhost/backup/]
===============================================================
```

> **Importante:** Rutas como `/admin` (panel), `/backup` (posibles copias con datos sensibles) o `/robots.txt` (que a menudo lista rutas que el administrador quiere ocultar de los buscadores) son puntos de partida excelentes. `robots.txt` es, irónicamente, una fuente de rutas interesantes para el atacante.

### ffuf

`ffuf` (*Fuzz Faster U Fool*) es una alternativa muy rápida basada en la palabra `FUZZ`, que marca dónde se prueba cada término del diccionario:

```bash
┌──(kali㉿kali)-[~]
└─$ ffuf -u http://localhost/FUZZ -w /usr/share/wordlists/dirb/common.txt
```

| Parámetro | Descripción |
|-----------|-------------|
| `-u http://localhost/FUZZ` | URL con la palabra clave `FUZZ` en el punto a fuzzear. |
| `-w ...` | Diccionario. |
| `-mc 200,301,403` | (Opcional) *Match codes*: mostrar solo estos códigos de respuesta. |
| `-fc 404` | (Opcional) *Filter codes*: ocultar estos códigos. |

> **Nota:** La gran ventaja de `ffuf` es que la palabra `FUZZ` puede ir en **cualquier parte** de la petición: en la ruta, en un parámetro (`?id=FUZZ`), en una cabecera o incluso en el nombre de un subdominio. Es una navaja suiza del *fuzzing* web.

### Nikto

`nikto` es un escáner de vulnerabilidades web que, además de descubrir ficheros, comprueba configuraciones inseguras y vulnerabilidades conocidas:

```bash
┌──(kali㉿kali)-[~]
└─$ nikto -h http://localhost
```

| Parámetro | Descripción |
|-----------|-------------|
| `-h http://localhost` | *Host* objetivo a analizar. |

**Ejemplo de salida (fragmento representativo):**

```bash
+ Server: Apache/2.4.29 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-Content-Type-Options header is not set.
+ /admin/: This might be interesting...
+ OSVDB-3233: /icons/README: Apache default file found.
```

> **Advertencia:** Nikto es **ruidoso** (genera muchísimas peticiones y queda registrado en los logs del servidor). Es perfecto para un laboratorio o una auditoría autorizada, pero no es sigiloso. Sus hallazgos típicos son cabeceras de seguridad ausentes (`X-Frame-Options`, `X-Content-Type-Options`), ficheros por defecto y rutas interesantes.

---

## 7. Caso práctico: la vulnerabilidad Heartbleed (CVE-2014-0160)

**Heartbleed** es una vulnerabilidad de seguridad que afecta a la biblioteca OpenSSL y permite a los atacantes acceder a la memoria de un servidor vulnerable. Si un servidor web es vulnerable a Heartbleed y lo detectamos a través de estas herramientas, significa que un atacante podría potencialmente acceder a información confidencial, como claves privadas, nombres de usuario y contraseñas, etc.

> **Importante:** Heartbleed explota un fallo en la extensión *Heartbeat* de TLS. El atacante pide al servidor que le devuelva más bytes de los que envió, y el servidor responde con fragmentos de su propia memoria, donde pueden encontrarse claves privadas o credenciales. Lo grave es que **no deja rastro** en los logs y no requiere autenticación.

### Despliegue del laboratorio vulnerable

Se proporciona el enlace al proyecto de GitHub donde desplegamos el laboratorio vulnerable a Heartbleed:

- **CVE-2014-0160**: https://github.com/vulhub/vulhub/tree/master/openssl/CVE-2014-0160

Descarga y despliegue del entorno con Vulhub:

```bash
┌──(kali㉿kali)-[~]
└─$ git clone https://github.com/vulhub/vulhub.git
```

```bash
┌──(kali㉿kali)-[~]
└─$ cd vulhub/openssl/CVE-2014-0160
```

```bash
┌──(kali㉿kali)-[~/vulhub/openssl/CVE-2014-0160]
└─$ docker-compose up -d
```

| Comando | Descripción |
|---------|-------------|
| `git clone ...` | Descarga el repositorio de Vulhub con todos los laboratorios vulnerables. |
| `cd vulhub/openssl/CVE-2014-0160` | Entra en el directorio del laboratorio de Heartbleed. |
| `docker-compose up -d` | Levanta el contenedor vulnerable en segundo plano (`-d`, *detached*). |

> **Nota:** El laboratorio expone un servidor con una versión de OpenSSL vulnerable escuchando por HTTPS (habitualmente en el `443`). Consulta el `README.md` del laboratorio para confirmar el puerto exacto en tu despliegue.

### Detección de Heartbleed

La forma más directa de comprobar la vulnerabilidad es con el script NSE de Nmap `ssl-heartbleed`:

```bash
┌──(kali㉿kali)-[~]
└─$ nmap -p443 --script ssl-heartbleed localhost
```

**Ejemplo de salida cuando el servidor ES vulnerable:**

```bash
PORT    STATE SERVICE
443/tcp open  https
| ssl-heartbleed:
|   VULNERABLE:
|   The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library
|     State: VULNERABLE
|     Risk factor: High
|_    References: https://cvedetails.com/cve/2014-0160/
```

| Parámetro | Descripción |
|-----------|-------------|
| `-p443` | Puerto HTTPS a comprobar. |
| `--script ssl-heartbleed` | Script NSE que comprueba específicamente la vulnerabilidad Heartbleed (CVE-2014-0160). |

También podemos confirmarlo con sslyze:

```bash
┌──(kali㉿kali)-[~]
└─$ sslyze --heartbleed localhost
```

> **Advertencia:** El bloque `VULNERABLE / State: VULNERABLE / Risk factor: High` confirma que el servidor puede filtrar memoria. En un caso real, el siguiente paso sería avisar y aplicar la mitigación de inmediato.

> **Importante — contramedidas de Heartbleed:** (1) actualizar OpenSSL a una versión parcheada (1.0.1g o superior); (2) **regenerar las claves privadas y reemitir los certificados**, ya que podrían haber sido filtrados; y (3) **revocar los certificados antiguos** y forzar el cambio de contraseñas de los usuarios como precaución.

> **Recuerda:** Todas estas prácticas se realizan sobre laboratorios desplegados en tu propia máquina. Escanear o explotar servidores de terceros sin autorización explícita es ilegal.
