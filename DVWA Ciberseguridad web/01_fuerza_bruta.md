# Fuerza bruta en DVWA con Burp Suite

## Índice

1. [Ataques de fuerza bruta — conceptos previos](#1-ataques-de-fuerza-bruta--conceptos-previos)
   - [Modos de ataque](#11-modos-de-ataque)
2. [Interceptación de tráfico con proxy](#2-interceptación-de-tráfico-con-proxy)
3. [Configuración de FoxyProxy](#3-configuración-de-foxyproxy)
4. [Burp Suite — introducción y configuración](#4-burp-suite--introducción-y-configuración)
   - [Sección Proxy](#41-sección-proxy)
   - [HTTP History](#42-http-history)
   - [Interceptación de HTTPS](#43-interceptación-de-https)
   - [Sección Target y Target Scope](#44-sección-target-y-target-scope)
5. [Ataque de fuerza bruta en DVWA — nivel low](#5-ataque-de-fuerza-bruta-en-dvwa--nivel-low)
   - [Análisis de la petición con Burp Suite](#51-análisis-de-la-petición-con-burp-suite)
   - [Burp Suite Repeater](#52-burp-suite-repeater)
   - [Burp Suite Intruder — configuración del ataque](#53-burp-suite-intruder--configuración-del-ataque)
   - [Análisis del código fuente — nivel low](#54-análisis-del-código-fuente--nivel-low)
6. [Nivel de seguridad medium](#6-nivel-de-seguridad-medium)

---

## 1. Ataques de fuerza bruta — conceptos previos

Los formularios de autenticación web, donde se introduce un nombre de usuario y una contraseña, constituyen la forma más habitual de gestionar el acceso a una aplicación. Este mecanismo es susceptible de ser atacado probando diferentes pares usuario-contraseña hasta encontrar una combinación válida. El proceso, repetitivo por naturaleza, puede automatizarse usando herramientas especializadas junto con diccionarios (*wordlists*) que contienen miles o millones de entradas, como los de [SecLists](https://github.com/danielmiessler/SecLists) o `rockyou.txt`.

Un ejemplo de formulario de autenticación típico sería el siguiente:

```html
<form action="login.php" method="post">
    <fieldset>
        <label for="user">Username</label>
        <input type="text" class="loginInput" size="20" name="username"><br />
        <label for="pass">Password</label>
        <input type="password" class="loginInput" AUTOCOMPLETE="off" size="20" name="password"><br />
        <br />
        <p class="submit"><input type="submit" value="Login" name="Login"></p>
    </fieldset>
    <input type='hidden' name='user_token' value='884431d22c7b5b526f87fac04ad59449' />
</form>
```

Al enviar este formulario, el navegador genera una petición `POST` que puede observarse con Burp Suite:

```
POST /dvwa/login.php HTTP/1.1
Host: 10.0.2.100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 88
Origin: http://10.0.2.100
Connection: close
Referer: http://10.0.2.100/dvwa/login.php
Cookie: security=low; PHPSESSID=722h1rtd5hid3mu60b3kotnvbg
Upgrade-Insecure-Requests: 1

username=admin&password=password&Login=Login&user_token=884431d22c7b5b526f87fac04ad59449
```

> **Nota:** Observar la estructura de la petición es fundamental antes de lanzar cualquier ataque. Identificar los campos del formulario (`username`, `password`, `Login`), el método HTTP utilizado (`GET` o `POST`) y las cookies de sesión activas son los datos imprescindibles para configurar correctamente las herramientas de ataque.

---

### 1.1 Modos de ataque

Dependiendo de la herramienta utilizada, los ataques de fuerza bruta contra formularios web pueden adoptar distintas estrategias. La siguiente tabla resume los cuatro modos más habituales:

| Modo | Descripción | Caso de uso |
|------|-------------|-------------|
| **Sniper** | Prueba cada entrada del diccionario en una única posición fijada. El resto de parámetros permanecen constantes. | Usuario conocido, se prueba un diccionario de contraseñas. |
| **Battering Ram** | Introduce la misma palabra en todas las posiciones a la vez. | Pruebas donde se quiere comprobar el mismo valor en múltiples parámetros simultáneamente. |
| **Pitchfork** | Usa varios diccionarios a la vez, tomando un elemento de cada uno en paralelo. Los diccionarios deben tener el mismo número de entradas. | *Credential stuffing*: probar combinaciones usuario-contraseña conocidas o habituales. |
| **Cluster Bomb** | Usa varios diccionarios a la vez probando todas las combinaciones posibles entre ellos. | Ataque exhaustivo cuando se desconoce tanto el usuario como la contraseña. |

Los siguientes ejemplos ilustran el comportamiento de cada modo usando un usuario `admin` y un diccionario de contraseñas con tres entradas: `abc123`, `abc123.`, `abc123..`

**Sniper** — ataca únicamente el campo contraseña con el usuario `admin` fijo:

| Nº de petición | Prueba |
|---------------|--------|
| 1 | `username=admin&password=abc123` |
| 2 | `username=admin&password=abc123.` |
| 3 | `username=admin&password=abc123..` |

**Battering Ram** — introduce la misma palabra en todos los campos a la vez (diccionario: `admin`, `martin`, `paula`):

| Nº de petición | Prueba |
|---------------|--------|
| 1 | `username=admin&password=admin` |
| 2 | `username=martin&password=martin` |
| 3 | `username=paula&password=paula` |

**Pitchfork** — diccionario de usuarios: `admin`, `martin`, `paula`; diccionario de contraseñas: `abc123`, `password`, `toor`:

| Nº de petición | Prueba |
|---------------|--------|
| 1 | `username=admin&password=abc123` |
| 2 | `username=martin&password=password` |
| 3 | `username=paula&password=toor` |

**Cluster Bomb** — con los mismos diccionarios del ejemplo anterior genera 9 combinaciones (3 usuarios × 3 contraseñas):

| Nº de petición | Prueba |
|---------------|--------|
| 1 | `username=admin&password=abc123` |
| 2 | `username=admin&password=password` |
| 3 | `username=admin&password=toor` |
| 4 | `username=martin&password=abc123` |
| 5 | `username=martin&password=password` |
| 6 | `username=martin&password=toor` |
| 7 | `username=paula&password=abc123` |
| 8 | `username=paula&password=password` |
| 9 | `username=paula&password=toor` |

> **Nota:** El modo *Sniper* es el más habitual en ataques de contraseña cuando el usuario es conocido. *Cluster Bomb* es el más exhaustivo pero también el más lento, ya que el número de peticiones crece multiplicativamente con el tamaño de cada diccionario.

---

## 2. Interceptación de tráfico con proxy

Un proxy de interceptación es una herramienta que se sitúa entre el navegador web y el servidor, permitiendo al auditor revisar, modificar y reenviar el tráfico HTTP/HTTPS. **Burp Suite** y **OWASP ZAP** son los dos proxies más utilizados en auditorías web, y ambos vienen preinstalados en Kali Linux.

> **Recuerda:** El flujo de trabajo con un proxy de interceptación es: navegador → proxy → servidor web. El proxy captura las peticiones antes de que lleguen al servidor, y las respuestas antes de que lleguen al navegador.

---

## 3. Configuración de FoxyProxy

Para que Burp Suite acceda al tráfico del navegador, es necesario configurar Firefox para que envíe las comunicaciones a través del proxy. **FoxyProxy** es una extensión que permite cambiar rápidamente la configuración del proxy del navegador, alternando entre conexión directa al servidor y conexión a través de Burp Suite.

**Instalación:** acceder a la página de la extensión en Firefox y pulsar *Agregar a Firefox*.

Una vez instalada, aparecerá el icono de FoxyProxy en la barra superior del navegador, dando acceso a las opciones de configuración.

**Configuración del reenvío a Burp Suite:** en la sección `Proxies` → `Add` se define la entrada para Burp Suite. Burp Suite escucha por defecto en `127.0.0.1` puerto `8080/tcp`. Se puede configurar manualmente o seleccionar la plantilla `Burp` si está disponible:

| Campo | Valor |
|-------|-------|
| Hostname | `127.0.0.1` |
| Puerto | `8080` |
| Tipo | `HTTP` |

Una vez guardada la entrada, desde el menú desplegable de FoxyProxy se puede elegir en cada momento si navegar directamente o a través de Burp Suite.

> **Importante:** Recuerda activar el proxy en FoxyProxy antes de empezar a capturar tráfico con Burp Suite, y desactivarlo cuando no se necesite para evitar que el navegador quede sin conexión si Burp Suite no está corriendo.

---

## 4. Burp Suite — introducción y configuración

La versión instalada en Kali Linux es **Burp Suite Community Edition**. Aunque no incluye todas las funcionalidades de la versión profesional (como las capacidades avanzadas de *Intruder* o el escáner activo), sigue siendo una herramienta completa y ampliamente utilizada para realizar auditorías web.

---

### 4.1 Sección Proxy

La interceptación del tráfico se controla desde la sección `Proxy`. Esta sección tiene dos estados principales:

- **Intercept is off:** Burp Suite captura el tráfico de fondo sin retenerlo. Las peticiones y respuestas son accesibles en la subsección `HTTP History`.
- **Intercept is on:** Burp Suite intercepta el tráfico y lo retiene. El auditor debe autorizar cada petición una a una para que la comunicación entre el navegador y el servidor continúe fluyendo.
  - Con `Forward` se autoriza la petición hacia el servidor.
  - Con `Drop` se descarta la petición.

> **Advertencia:** Es importante controlar en todo momento el estado de la interceptación. Si `Intercept is on` y se olvida autorizar las peticiones, el navegador parecerá no cargar ninguna página, ya que el tráfico queda retenido en el interceptador a la espera de ser autorizado.

---

### 4.2 HTTP History

En la subsección `Proxy` → `HTTP History` son accesibles todas las comunicaciones capturadas por Burp Suite, tanto las peticiones como las respuestas.

Tanto las peticiones como las respuestas pueden visualizarse en distintos modos:

- **Pretty:** resaltado de sintaxis para facilitar la lectura.
- **Raw:** texto plano sin formato.
- **Hex:** representación hexadecimal.
- **Render:** en el caso de las respuestas, renderiza la página como si fuera un navegador, lo que permite ver el resultado visual de la respuesta HTTP.

> **Nota:** El modo *Render* es especialmente útil para verificar rápidamente el resultado de una petición sin necesidad de enviarla al navegador.

---

### 4.3 Interceptación de HTTPS

Al interceptar tráfico HTTPS, el navegador detecta que el certificado digital recibido no corresponde al servidor web con el que quiere comunicarse, sino a Burp Suite, y genera un error de seguridad. Esto ocurre porque Burp Suite actúa como un intermediario (*man in the middle*) para poder cifrar y descifrar las comunicaciones, pero el navegador no reconoce su certificado.

La solución es instalar el certificado digital de Burp Suite en el navegador como una autoridad de certificación de confianza:

**Paso 1 — Descargar el certificado:** con Burp Suite corriendo y FoxyProxy activo, acceder en el navegador a `http://burp`. Aparecerá la página de Burp Suite Community Edition con un botón `CA Certificate` para descargarlo.

**Paso 2 — Instalar el certificado en Firefox:** ir a `Settings` → `Privacy & Security` → `Certificates` → `View Certificates` → pestaña `Authorities` → `Import`, y seleccionar el archivo descargado. En el diálogo que aparece, marcar la opción *Trust this CA to identify websites* y confirmar.

A partir de este momento, Burp Suite interceptará el tráfico HTTPS sin generar errores en el navegador.

> **Advertencia:** El certificado de Burp Suite solo debe instalarse en navegadores o perfiles usados exclusivamente para auditorías en entornos controlados. Instalarlo en un perfil de uso cotidiano implicaría que Burp Suite podría interceptar tráfico sensible (banca, correo, etc.) si el proxy está activo.

---

### 4.4 Sección Target y Target Scope

En la sección `Target` se puede acceder a los diferentes sitios web visitados y visualizar la estructura del sitio (páginas y carpetas) junto con las peticiones asociadas.

Para evitar ruido y centrarse únicamente en la aplicación de interés, es recomendable definir el **Target Scope**, que limita el tráfico capturado y mostrado por Burp Suite al sitio web objetivo. Se accede desde `Target` → `Scope` o desde el botón `Settings`:

- En la sección **Target scope** → *Include in scope* → `Add`, se añade el prefijo de la URL objetivo, por ejemplo `http://10.0.2.100/dvwa`.
- En **Out-of-scope request handling** se puede configurar Burp Suite para descartar automáticamente las peticiones que queden fuera del scope definido.

> **Nota:** Definir el Target Scope reduce el volumen de tráfico en `HTTP History` y facilita enormemente el análisis, especialmente en aplicaciones con muchos recursos externos (scripts, fuentes, analytics, etc.).

---

## 5. Ataque de fuerza bruta en DVWA — nivel low

**Objetivo:** descubrir la contraseña del usuario `admin` mediante un ataque de fuerza bruta contra el formulario de autenticación de la sección *Brute Force* de DVWA con el nivel de seguridad configurado en `Low`.

Acceder a DVWA, establecer el nivel de seguridad en `Low` en la sección `DVWA Security`, y navegar a la sección `Brute Force`.

---

### 5.1 Análisis de la petición con Burp Suite

Con Burp Suite corriendo y FoxyProxy activo, se configura Burp Suite en modo `Intercept is on` y se envía un intento de autenticación erróneo, por ejemplo `admin` / `abc123`, para capturar y analizar la petición.

La petición capturada tiene la siguiente estructura:

```
GET /dvwa/vulnerabilities/brute/?username=admin&password=abc123&Login=Login HTTP/1.1
Host: 10.0.2.100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Referer: http://10.0.2.100/dvwa/vulnerabilities/brute/
Cookie: security=low; PHPSESSID=408knot3dl1jrvpni3h57d2krv
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```

De esta petición se extraen los datos clave para el ataque:

| Dato | Valor |
|------|-------|
| Método | `GET` |
| URL del formulario | `/dvwa/vulnerabilities/brute/` |
| Campo usuario | `username` |
| Campo contraseña | `password` |
| Campo submit | `Login` |
| Cookie de sesión | `security=low; PHPSESSID=408knot3dl1jrvpni3h57d2krv` |

La respuesta ante un intento fallido contiene el texto `Username and/or password incorrect`, que se usará como indicador de fallo en la configuración del ataque.

> **Importante:** La cookie `PHPSESSID` es única por sesión. Si la sesión expira durante el ataque, las peticiones serán redirigidas al login principal y los resultados serán incorrectos. Es necesario mantener la sesión activa durante todo el ataque.

---

### 5.2 Burp Suite Repeater

**Repeater** permite modificar y reenviar peticiones al objetivo de forma manual para evaluar la respuesta de la aplicación ante los cambios realizados. Es útil para probar contraseñas concretas o verificar el comportamiento de la aplicación ante variaciones específicas antes de lanzar un ataque automatizado.

**Paso 1 — Enviar la petición a Repeater:** en `HTTP History` o en la vista de interceptación, hacer clic derecho sobre la petición de interés y seleccionar `Send to Repeater` (`Ctrl+R`).

**Paso 2 — Modificar la petición:** en la sección `Repeater` aparecerá la petición capturada. Modificar el valor del parámetro `password` en la URL con el valor a probar, por ejemplo `password=Abc123`.

**Paso 3 — Enviar y analizar la respuesta:** pulsar el botón `Send` y analizar la respuesta de la aplicación en el panel de la derecha. Si la respuesta contiene `Username and/or password incorrect`, la contraseña es incorrecta. Si aparece `Welcome to the password protected area`, la autenticación ha sido exitosa.

> **Nota:** Repeater es una herramienta potente para validar el comportamiento de la aplicación, pero no está pensada para automatizar cientos o miles de intentos. Para eso se usa *Intruder*.

---

### 5.3 Burp Suite Intruder — configuración del ataque

**Intruder** permite automatizar el envío de peticiones modificando dinámicamente los valores de los parámetros indicados. Se va a usar para lanzar un ataque de fuerza bruta en modo *Sniper* contra el campo contraseña.

> **Advertencia:** La versión Community Edition de Burp Suite tiene activado un *time throttle* que introduce un retardo artificial entre peticiones en Intruder, lo que ralentiza significativamente los ataques con diccionarios grandes. Para ataques de mayor envergadura es preferible usar Hydra.

**Paso 1 — Enviar la petición a Intruder:** en `HTTP History` o en la vista de interceptación, hacer clic derecho sobre la petición capturada del formulario de autenticación y seleccionar `Send to Intruder` (`Ctrl+I`).

**Paso 2 — Configurar posiciones del payload:** en la sección `Intruder`, seleccionar el tipo de ataque `Sniper attack`. A continuación, pulsar `Clear §` para eliminar las posiciones configuradas automáticamente por Burp Suite, y seleccionar manualmente el valor del parámetro `password` en la petición para marcarlo como posición del payload con el botón `Add §`:

```
GET /dvwa/vulnerabilities/brute/?username=admin&password=§abc123§&Login=Login HTTP/1.1
```

**Paso 3 — Configurar el payload:** en la pestaña `Payloads`, seleccionar como `Payload type` el tipo `Simple list` y cargar una lista de contraseñas con `Load`. En este ejemplo se usa `2020-200_most_used_passwords.txt` de SecLists, disponible en Kali Linux en:

```
/usr/share/wordlists/seclists/Passwords/CommonCredentials/2020-200_most_used_passwords.txt
```

**Paso 4 — Configurar Grep - Match:** en la pestaña `Settings`, localizar la sección `Grep - Match`. Pulsar `Clear` para eliminar las entradas existentes y añadir con `Add` la cadena de fallo:

```
Username and/or password incorrect
```

Esto hace que Intruder marque con un flag las respuestas que contengan esa cadena, facilitando la identificación visual del intento exitoso (el que no esté marcado).

**Paso 5 — Lanzar el ataque:** pulsar `Start attack`. En la ventana de resultados se puede observar que todos los intentos tienen el flag `Username and/or password incorrect` activado excepto el correspondiente a la contraseña correcta. Además, el campo `Length` de la respuesta exitosa será diferente al del resto (en este caso, unos 4807 bytes frente a los 4763 bytes de los intentos fallidos).

> **Nota:** Los parámetros más útiles para distinguir entre intentos exitosos y fallidos son: la presencia o ausencia de una cadena de texto conocida (`Grep - Match`), el tamaño de la respuesta (`Length`), y el código de estado HTTP (`Status code`). Revisar siempre más de uno para confirmar el resultado.

---

### 5.4 Análisis del código fuente — nivel low

Una vez obtenida la contraseña, DVWA permite revisar el código PHP que controla la autenticación pulsando el botón `View Source` en la esquina inferior derecha de la sección *Brute Force*:

```php
<?php

if( isset( $_GET[ 'Login' ] ) ) {
    // Get username
    $user = $_GET[ 'username' ];

    // Get password
    $pass = $_GET[ 'password' ];
    $pass = md5( $pass );

    // Check the database
    $query  = "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';";
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

    if( $result && mysqli_num_rows( $result ) == 1 ) {
        // Get users details
        $row     = mysqli_fetch_assoc( $result );
        $avatar  = $row["avatar"];

        // Login successful
        echo "<p>Welcome to the password protected area {$user}</p>";
        echo "<img src=\"{$avatar}\" />";
    }
    else {
        // Login failed
        echo "<pre><br />Username and/or password incorrect.</pre>";
    }

    ((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}
?>
```

El código revela que el programador no implementó ninguna medida de seguridad contra la fuerza bruta:

- Recoge el usuario directamente de la petición `GET` en `$user` sin ninguna validación ni sanitización.
- Recoge la contraseña en claro en `$pass` y la convierte a MD5 antes de consultarla en la base de datos.
- Realiza una consulta SQL directa concatenando los valores del usuario en la cadena de consulta, lo que hace al formulario también vulnerable a inyección SQL.
- No implementa ningún mecanismo de limitación de intentos, retardo entre peticiones, ni bloqueo de cuenta.

> **Advertencia:** La ausencia total de controles en el nivel *low* hace que el formulario sea trivialmente atacable tanto por fuerza bruta como por inyección SQL. El uso de `md5` para almacenar contraseñas tampoco es seguro, ya que existen bases de datos de hashes MD5 precomputados (*rainbow tables*) que permiten revertirlos fácilmente.

---

## 6. Nivel de seguridad medium

En el nivel de seguridad `medium`, el programador introduce un retardo artificial sobre los intentos de autenticación fallidos mediante la función `sleep()`. Esta medida ralentiza los ataques de fuerza bruta al imponer una espera entre cada intento fallido:

```php
<?php

if( isset( $_GET[ 'Login' ] ) ) {
    // Get username
    $user = $_GET[ 'username' ];

    // Get password
    $pass = $_GET[ 'password' ];
    $pass = md5( $pass );

    // Check the database
    $query  = "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';";
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

    if( $result && mysqli_num_rows( $result ) == 1 ) {
        // Get users details
        $row     = mysqli_fetch_assoc( $result );
        $avatar  = $row["avatar"];

        // Login successful
        echo "<p>Welcome to the password protected area {$user}</p>";
        echo "<img src=\"{$avatar}\" />";
    }
    else {
        // Login failed
        sleep( 2 );
        echo "<pre><br />Username and/or password incorrect.</pre>";
    }

    ((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}
?>
```

El impacto de este retardo es visible al comparar los tiempos de ataque entre niveles:

| Nivel | Retardo por intento fallido | Tiempo aproximado para 200 contraseñas |
|-------|-----------------------------|----------------------------------------|
| `low` | Sin retardo | ~1 segundo |
| `medium` | 2 segundos | ~21 segundos |

> **Nota:** El retardo artificial es una medida de defensa simple pero efectiva contra herramientas con bajo paralelismo. Sin embargo, no es suficiente por sí sola — un atacante puede aumentar el número de hilos paralelos para compensarlo, o cambiar a una herramienta como Hydra que gestiona mejor el paralelismo. Las defensas más robustas combinan retardo con bloqueo de cuenta temporal tras un número de intentos fallidos, o con CAPTCHA.
