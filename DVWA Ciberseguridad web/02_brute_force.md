# Brute force en DVWA con Burp Suite

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
   - [Análisis del código fuente — nivel medium](#61-análisis-del-código-fuente--nivel-medium)
7. [Nivel de seguridad high](#7-nivel-de-seguridad-high)
8. [Medidas de prevención](#8-medidas-de-prevención)
9. [Ataque de fuerza bruta con Hydra](#9-ataque-de-fuerza-bruta-con-hydra)
10. [Ejercicio práctico - Ataque de fuerza bruta](#10-ejercicio-práctico---ataque-de-fuerza-bruta)

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

```bash
POST /dvwa/login.php HTTP/1.1
Host: 192.168.100.4
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 88
Origin: http://192.168.100.4
Connection: close
Referer: http://192.168.100.4/dvwa/login.php
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

Una herramienta fundamental para un auditor web es el **proxy**, que se sitúa entre el navegador del auditor y el servidor web objetivo. Al interceptar el tráfico, el auditor puede revisar la información intercambiada y modificarla antes de que llegue al servidor o de vuelta al cliente.

El flujo es el siguiente:

```
Navegador (Kali) <--> PROXY (Burp Suite) <--> Servidor web (DVWA en Ubuntu Server)
```

**Burp Suite** y **OWASP ZAP** son dos ejemplos de proxys ampliamente usados en auditorías web y vienen preinstalados en Kali Linux.

> **Recuerda:** En el escenario de laboratorio, el servidor DVWA corre en la máquina Ubuntu Server con IP `192.168.100.4`, y Burp Suite se ejecuta en Kali Linux. Todo el tráfico entre el navegador Firefox (Kali) y DVWA pasa a través del proxy de Burp Suite en `127.0.0.1:8080`.

---

## 3. Configuración de FoxyProxy

Para que Burp Suite pueda interceptar el tráfico del navegador Firefox, es necesario redirigir las comunicaciones a través del proxy de Burp. La forma más cómoda de hacerlo es mediante la extensión **FoxyProxy**, que permite cambiar la configuración del proxy del navegador con un solo clic sin necesidad de modificar los ajustes del sistema operativo.

Hay otras alternativas para redirigir el tráfico a Burp Suite:

- Usar el navegador incorporado en la propia interfaz de Burp Suite.
- Configurar directamente el proxy en las opciones de red del navegador.
- Instalar el plugin FoxyProxy (opción más cómoda para alternar rápidamente entre navegación directa y a través de Burp).

**Instalación:** acceder a la página de la extensión en Firefox y pulsar **Agregar a Firefox**. Una vez instalada, aparecerá el icono de FoxyProxy en la barra superior derecha.

**Configuración del proxy hacia Burp Suite:**

1. Abrir las opciones de FoxyProxy pulsando su icono.
2. Ir a la sección **Proxies → Add**.
3. Seleccionar la plantilla **Burp** o introducir los valores manualmente:

| Campo | Valor |
|-------|-------|
| Hostname | `127.0.0.1` |
| Puerto | `8080` |

4. Guardar la configuración con **Save**.

A partir de ese momento, desde el menú desplegable de FoxyProxy se puede elegir entre navegar directamente o redirigir el tráfico a través de Burp Suite seleccionando la entrada **Burp**.

> **Nota:** Burp Suite escucha por defecto en `127.0.0.1:8080/tcp`. Si este puerto está ocupado, se puede cambiar desde **Settings → Tools → Proxy → Proxy listeners**.

---

## 4. Burp Suite — introducción y configuración

**Burp Suite** es una plataforma integrada para realizar auditorías de seguridad en aplicaciones web. La versión instalada en Kali Linux es la **Community Edition**, que, aunque no incluye todas las funcionalidades de la versión profesional (como el escáner automático de vulnerabilidades), sigue siendo una herramienta muy completa para auditorías manuales.

Sus módulos principales son:

| Módulo | Función |
|--------|---------|
| **Proxy** | Intercepta y modifica el tráfico entre el navegador y el servidor. |
| **Target** | Organiza los sitios visitados en una estructura de árbol con sus peticiones. |
| **Intruder** | Automatiza ataques de fuerza bruta y fuzzing sobre parámetros HTTP. |
| **Repeater** | Permite reenviar y modificar peticiones individuales de forma manual. |
| **Decoder** | Codifica y decodifica datos en formatos como Base64, URL, HTML, etc. |
| **Comparer** | Compara dos peticiones o respuestas para detectar diferencias. |

---

### 4.1 Sección Proxy

La interceptación del tráfico se controla desde la sección **Proxy**. Existen dos estados posibles:

| Estado | Comportamiento |
|--------|---------------|
| **Intercept is off** | Burp Suite captura el tráfico en segundo plano sin bloquearlo. Las peticiones fluyen libremente y pueden consultarse en *HTTP History*. |
| **Intercept is on** | Burp Suite detiene cada petición a la espera de que el auditor la autorice o la descarte manualmente. |

Cuando la interceptación está activa, el auditor dispone de dos opciones para cada petición retenida:

- **Forward** — autoriza la petición para que continúe hacia el servidor.
- **Drop** — descarta la petición; el servidor nunca la recibirá.

> **Advertencia:** Si el navegador parece no cargar ninguna página, comprobar el estado de la interceptación. Es frecuente que Burp Suite esté reteniendo peticiones en modo *Intercept is on* sin que el auditor se haya dado cuenta, dejando el tráfico bloqueado a la espera de autorización.

---

### 4.2 HTTP History

En la subsección **Proxy → HTTP History** se puede consultar el historial completo de comunicaciones capturadas: tanto las peticiones enviadas por el navegador como las respuestas devueltas por el servidor.

Cada entrada del historial muestra información resumida: método HTTP (`GET`/`POST`), URL, código de estado, longitud de la respuesta y tipo MIME. Al seleccionar una entrada, se despliegan el detalle completo de la petición y la respuesta en los distintos modos de visualización:

| Modo | Descripción |
|------|-------------|
| **Pretty** | Formato con resaltado de sintaxis, más legible. |
| **Raw** | Texto plano tal como viaja por la red. |
| **Hex** | Representación hexadecimal, útil para analizar datos binarios. |
| **Render** | Renderiza la respuesta como si fuera un navegador, mostrando la página visualmente. |

---

### 4.3 Interceptación de HTTPS

Al interceptar tráfico HTTPS, el navegador detecta que el certificado digital recibido no es el del servidor web real sino el de Burp Suite, y genera un error de seguridad. Esto ocurre porque Burp realiza un **ataque man-in-the-middle** sobre la comunicación cifrada: descifra el tráfico, lo expone al auditor y vuelve a cifrarlo antes de reenviarlo.

Para evitar este error, es necesario instalar el certificado de Burp Suite como una **autoridad de certificación de confianza** en Firefox:

1. Con Burp activo y FoxyProxy redirigiendo el tráfico, acceder en el navegador a `http://burp`.
2. Descargar el certificado pulsando el botón **CA Certificate**.
3. En Firefox, ir a **Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import**.
4. Seleccionar el certificado descargado y marcar la opción **Trust this CA to identify websites**.
5. Pulsar **OK**.

A partir de este momento, Burp Suite interceptará el tráfico HTTPS sin mostrar errores en el navegador, apareciendo **PortSwigger CA** como nueva autoridad de certificación en la lista de Firefox.

> **Importante:** Este certificado solo debe instalarse en el navegador del entorno de auditoría. Instalarlo en un navegador de uso cotidiano supone un riesgo de seguridad, ya que cualquier proxy con esa clave podría descifrar las comunicaciones cifradas.

---

### 4.4 Sección Target y Target Scope

La sección **Target** proporciona una vista organizada de todos los sitios web visitados durante la sesión, mostrando una **estructura en árbol** con las páginas, carpetas y peticiones HTTP asociadas a cada una.

Para evitar capturar tráfico irrelevante (actualizaciones del navegador, telemetría, etc.) y centrarse únicamente en la aplicación objetivo, se recomienda configurar el **Target Scope**:

1. Ir a **Target → Scope** o al botón **Settings**.
2. En la sección **Include in scope**, pulsar **Add** e introducir la URL base de DVWA:

```
http://192.168.100.4/dvwa
```

3. En **Out-of-scope request handling**, seleccionar **Drop all out-of-scope requests**.

| Opción | Efecto |
|--------|--------|
| Include in scope | Solo se procesan las URLs que coincidan con el prefijo indicado. |
| Drop all out-of-scope requests | El tráfico externo al scope es descartado automáticamente. |

> **Nota:** Limitar el scope reduce el ruido en *HTTP History* y facilita la identificación de peticiones relevantes durante la auditoría.

---

## 5. Ataque de fuerza bruta en DVWA — nivel low

**Objetivo:** descubrir la contraseña del usuario `admin` mediante un ataque de fuerza bruta contra el formulario de autenticación de la sección *Brute Force* de DVWA con el nivel de seguridad configurado en `Low`.

Acceder a DVWA, establecer el nivel de seguridad en `Low` en la sección `DVWA Security`, y navegar a la sección `Brute Force`.

---

### 5.1 Análisis de la petición con Burp Suite

Con Burp Suite corriendo y FoxyProxy activo, se configura Burp Suite en modo `Intercept is on` y se envía un intento de autenticación erróneo, por ejemplo `admin` / `abc123`, para capturar y analizar la petición.

La petición capturada tiene la siguiente estructura:

```bash
GET /dvwa/vulnerabilities/brute/?username=admin&password=abc123&Login=Login HTTP/1.1
Host: 192.168.100.4
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Referer: http://192.168.100.4/dvwa/vulnerabilities/brute/
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

![Petición y respuesta](./imagenes/brute%20force/01.png)

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

```bash
GET /dvwa/vulnerabilities/brute/?username=admin&password=§abc123§&Login=Login HTTP/1.1
```

**Paso 3 — Configurar el payload:** en la pestaña `Payloads`, seleccionar como `Payload type` el tipo `Simple list` y cargar una lista de contraseñas con `Load`. En este ejemplo se usa `2020-200_most_used_passwords.txt` de SecLists, disponible en Kali Linux en:

```bash
/usr/share/wordlists/seclists/Passwords/CommonCredentials/2020-200_most_used_passwords.txt
```

> **Nota:** La versión gratuita de Burp Suite no permite el uso de diccionarios cargados desde listas externas de gran tamaño de forma eficiente. Para ataques con diccionarios grandes se recomienda usar Hydra.

![Configuración del ataque](./imagenes/brute%20force/02.png)

**Paso 4 — Configurar Grep - Match:** en la pestaña `Settings`, localizar la sección `Grep - Match`. Pulsar `Clear` para eliminar las entradas existentes y añadir con `Add` la cadena de fallo:

```bash
Username and/or password incorrect
```

Esto hace que Intruder marque con un flag las respuestas que contengan esa cadena, facilitando la identificación visual del intento exitoso (el que no esté marcado).

![Configuración del Grep - Match](./imagenes/brute%20force/03.png)

**Paso 5 — Lanzar el ataque:** pulsar `Start attack`. En la ventana de resultados se puede observar que todos los intentos tienen el flag `Username and/or password incorrect` activado excepto el correspondiente a la contraseña correcta. Además, el campo `Length` de la respuesta exitosa será diferente al del resto.

> **Nota:** Los parámetros más útiles para distinguir entre intentos exitosos y fallidos son: la presencia o ausencia de una cadena de texto conocida (`Grep - Match`), el tamaño de la respuesta (`Length`), y el código de estado HTTP (`Status code`). Revisar siempre más de uno para confirmar el resultado.

![Resultado del ataque](./imagenes/brute%20force/04.png)

El ataque finaliza al encontrar la contraseña correcta, en este caso `admin:password`.

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

En el nivel de seguridad `medium`, el programador introduce un retardo artificial sobre los intentos de autenticación fallidos mediante la función `sleep()`. Esta medida ralentiza los ataques de fuerza bruta al imponer una espera entre cada intento fallido.

El retardo puede verificarse desde la terminal de Kali con `curl` y el comando `time`:

```bash
kali@kali:~$ time curl -s -b "security=medium; PHPSESSID=408knot3dl1jrvpni3h57d2krv" 'http://192.168.100.4/dvwa/vulnerabilities/brute/?username=admin&password=123411&Login=Login'
<!DOCTYPE html>
...
real 0m2,057s
user 0m0,014s
sys 0m0,009s
```

> **Nota:** Es necesario indicar en `curl` la opción `-b` con el valor de la cookie, previamente obtenido capturando y analizando una solicitud con Burp Suite o con las herramientas del desarrollador del navegador.

Para comprobar si el retardo es fijo o aleatorio, se puede enviar una secuencia de peticiones:

```bash
kali@kali:~$ for i in {1..10}; do time curl -s -b "security=medium; PHPSESSID=408knot3dl1jrvpni3h57d2krv" 'http://192.168.100.4/dvwa/vulnerabilities/brute/?username=admin&password=123411&Login=Login' -o /dev/null ; done
real 0m2,024s
...
real 0m2,027s
...
```

El resultado confirma que se trata de un **retardo fijo de 2 segundos**, lo que hace predecible el tiempo total del ataque. El impacto de este retardo es visible al comparar los tiempos de ataque entre niveles:

| Nivel | Retardo por intento fallido | Tiempo aproximado para 200 contraseñas |
|-------|-----------------------------|----------------------------------------|
| `low` | Sin retardo | ~1 segundo |
| `medium` | 2 segundos fijos | ~21 segundos |

> **Nota:** El retardo artificial es una medida de defensa simple pero efectiva contra herramientas con bajo paralelismo. Sin embargo, no es suficiente por sí sola: un atacante puede aumentar el número de hilos paralelos para compensarlo, o cambiar a una herramienta como Hydra que gestiona mejor el paralelismo. Las defensas más robustas combinan retardo con bloqueo de cuenta temporal tras un número de intentos fallidos.

---

### 6.1 Análisis del código fuente — nivel medium

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

La única diferencia respecto al nivel *low* es la llamada a `sleep(2)` en el bloque de fallo, que introduce un retardo fijo de 2 segundos en cada intento erróneo. El resto del código es idéntico: sin sanitización de entradas, sin limitación de intentos y sin bloqueo de cuenta.

> **Nota:** Aunque el nivel *medium* introduce `mysqli_real_escape_string()` para sanear las entradas (no visible en este fragmento pero sí en la fuente completa), ello solo mitiga parcialmente la inyección SQL. La vulnerabilidad a fuerza bruta sigue presente, únicamente ralentizada.

---

## 7. Nivel de seguridad high

En el nivel de seguridad `high`, el programador combina dos mecanismos de protección adicionales respecto al nivel *medium*:

- **Retardo variable:** en lugar de un retardo fijo de 2 segundos, se aplica `sleep(rand(2, 4))`, que introduce una espera aleatoria de entre 2 y 4 segundos en cada intento fallido. Esto dificulta la estimación del tiempo total del ataque y complica ciertas técnicas de temporización.
- **Tokens CSRF:** el formulario incorpora un campo oculto `user_token` con un valor único, secreto e impredecible generado por el servidor para cada sesión. El cliente debe incluir el token correcto en cada petición; de lo contrario, esta es rechazada.

```html
<input type='hidden' name='user_token' value='c31562fc5d76ce2f388bdf16f8871249' />
```

El token CSRF tiene dos efectos sobre los ataques automatizados: obliga a obtener un token válido antes de cada petición, lo que requiere parsear la respuesta HTML anterior para extraerlo y añadirlo a la siguiente petición. Esto complica enormemente la automatización con herramientas básicas y requiere lógica adicional en el script de ataque.

> **Nota:** Los tokens CSRF no están diseñados específicamente para prevenir la fuerza bruta, sino para prevenir ataques de falsificación de petición entre sitios. Sin embargo, al hacer que cada petición necesite un valor único extraído del HTML de la respuesta anterior, añaden una capa de dificultad práctica para los ataques automatizados.

---

## 8. Medidas de prevención

Las medidas de seguridad recomendadas para proteger formularios de autenticación frente a ataques de fuerza bruta son las siguientes:

- **Bloqueo de cuenta temporal:** tras un número determinado de intentos fallidos (por ejemplo 3 o 5), bloquear la cuenta durante un período de tiempo (`$lockout_time`). El nivel *Impossible* de DVWA implementa un bloqueo de 15 minutos tras 3 fallos con la variable `$total_failed_login`.
- **Limitación de velocidad (*rate limiting*):** introducir un retardo entre intentos fallidos (`sleep()`) y limitar el número de intentos permitidos por dirección IP o cuenta de usuario dentro de un período de tiempo.
- **Políticas de contraseñas seguras:** exigir contraseñas con longitud mínima, combinación de caracteres y renovación periódica.
- **Autenticación multifactor (MFA):** exigir al usuario una segunda forma de autenticación además del par usuario/contraseña, como un código de un solo uso enviado al dispositivo móvil.
- **CAPTCHA:** uso de desafíos para distinguir entre usuarios humanos y bots automatizados.
- **Registro y vigilancia:** supervisión continua de los intentos de inicio de sesión para detectar actividades inusuales o sospechosas.
- **Firewalls de aplicaciones web (WAF):** configurados para detectar y bloquear patrones propios de ataques de fuerza bruta en tiempo real.
- **Consultas parametrizadas (*prepared statements*):** para proteger la base de datos frente a inyección SQL, que a menudo coexiste con formularios vulnerables a fuerza bruta.

---

## 9. Ataque de fuerza bruta con Hydra

**Hydra** es una herramienta de línea de comandos para ataques de fuerza bruta que soporta una gran variedad de protocolos: FTP, SSH, HTTP, HTTPS, SMB, RDP, entre muchos otros. A diferencia de Burp Suite Intruder en su versión Community, **no aplica limitación de velocidad**, lo que la hace más eficiente para diccionarios grandes.

Hydra viene preinstalada en Kali Linux. Las opciones del comando pueden consultarse con:

```bash
hydra -h
```

Para lanzar el ataque contra el formulario de DVWA se necesita la siguiente información, obtenida previamente con Burp Suite:

| Dato | Valor |
|------|-------|
| Usuario objetivo | `admin` |
| Wordlist | `2020-200_most_used_passwords.txt` |
| URL del formulario | `http://192.168.100.4/dvwa/vulnerabilities/brute/` |
| Método del formulario | `GET` |
| Campos del formulario | `username`, `password`, `Login` |
| Cookie de sesión | `PHPSESSID=u50vbil75pgsn9qgrj7q929sp8; security=low` |
| Cadena de fallo | `Username and/or password incorrect` |

**Comando para el nivel low:**

```bash
hydra -l admin -P 2020-200_most_used_passwords.txt 'http-get-form://192.168.100.4/dvwa/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:H=Cookie:PHPSESSID=u50vbil75pgsn9qgrj7q929sp8; security=low:F=Username and/or password incorrect' -V -t 5 -I -e nsr
```

Los parámetros más relevantes del comando:

| Parámetro | Descripción |
|-----------|-------------|
| `-l admin` | Nombre de usuario fijo para el ataque. |
| `-P 2020-200_most_used_passwords.txt` | Fichero con la lista de contraseñas a probar. |
| `http-get-form` | Indica que se ataca un formulario que usa el método `GET`. |
| `username=^USER^&password=^PASS^&Login=Login` | Campos del formulario. `^USER^` y `^PASS^` son sustituidos por Hydra en cada intento. |
| `:H=Cookie:PHPSESSID=...` | Cookie de sesión necesaria para que las peticiones sean válidas. |
| `:F=Username and/or password incorrect` | Cadena que indica fallo de autenticación. Hydra descarta los intentos que contengan esta frase. |
| `-V` | Modo verbose: muestra cada intento usuario/contraseña en pantalla. |
| `-t 5` | Número de conexiones paralelas por objetivo. |
| `-I` | Ignora el fichero de recuperación de sesiones anteriores. |
| `-e nsr` | Prueba contraseña vacía (`n`), el propio usuario como contraseña (`s`) y el usuario al revés (`r`), además del diccionario. |

Hydra también acepta una sintaxis alternativa equivalente:

```bash
hydra -l admin -P 2020-200_most_used_passwords.txt -I 192.168.100.4 http-get-form "/dvwa/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:H=Cookie:PHPSESSID=u50vbil75pgsn9qgrj7q929sp8; security=low:F=Username and/or password incorrect" -V -t 5 -I -e nsr
```

**Resultado esperado:**

```bash
[80][http-get-form] host: 192.168.100.4   login: admin   password: password
1 of 1 target successfully completed, 1 valid password found
```

**Comparación de tiempos según el nivel de seguridad:**

Ejecutando el mismo ataque con `security=medium` en la cookie, el retardo de 2 segundos por intento fallido eleva el tiempo total del ataque de aproximadamente 1 segundo a 21 segundos para un diccionario de 200 entradas.

| Nivel | Tiempo aproximado (200 contraseñas, 5 hilos) |
|-------|----------------------------------------------|
| `low` | ~1 segundo |
| `medium` | ~21 segundos |

> **Advertencia:** Hydra y herramientas similares solo deben usarse en entornos de laboratorio controlados o en sistemas sobre los que se tiene autorización expresa. El uso no autorizado contra sistemas reales es ilegal.

## 10. Ejercicio práctico - Ataque de fuerza bruta

Si nosotros accedemos como admin veremos lo siguiente:

![Acceso como admin](./imagenes/brute%20force/05.png)

Si nosotros vemos la imagen vemos que está en la ruta `http://192.168.100.4/dvwa/hackable/users/admin.jpg` por lo que si eliminamos el final y buscamos por `http://192.168.100.4/dvwa/hackable/users/` veremos que nos muestra todas las imágenes de los usuarios:

![Imagenes de todos los usuarios](./imagenes/brute%20force/06.png)

El objetivo de esta práctica es hacer un ataque de fuerza bruta de tipo **Cluster Bomb** o **Bomba de racimo** para poder encontrar cual es el usuario y la contraseña que se utiliza en el formulario de login.