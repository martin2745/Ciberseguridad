# CMS — Magento

## Índice

1. [Introducción a Magento](#1-introducción-a-magento)
2. [Despliegue del laboratorio (Magento 2.2 SQLi)](#2-despliegue-del-laboratorio-magento-22-sqli)
3. [Reconocimiento inicial](#3-reconocimiento-inicial)
4. [Enumeración con MageScan](#4-enumeración-con-magescan)
5. [La vulnerabilidad: SQL Injection](#5-la-vulnerabilidad-sql-injection)
   - [Concepto](#concepto)
   - [Explotación y Cookie Hijacking](#explotación-y-cookie-hijacking)

---

## 1. Introducción a Magento

En esta clase veremos cómo enumerar el gestor de contenido **Magento**. Magento es una plataforma de comercio electrónico de código abierto que se utiliza para construir tiendas en línea de alta calidad y escalables. Es una de las plataformas más populares para el comercio electrónico y es utilizada por grandes marcas como Nike, Coca-Cola y Ford.

Sin embargo, con la popularidad de Magento también ha surgido la preocupación por la seguridad. Al gestionar **datos de pago y datos personales** de clientes, es un objetivo especialmente atractivo para los atacantes, y las brechas en tiendas Magento pueden tener un impacto económico y legal muy alto.

> **Nota:** A diferencia de un blog en WordPress, aquí lo que está en juego son carritos, cuentas de clientes y, sobre todo, información de pago. Por eso el enfoque de la auditoría es tan sensible: cualquier fuga puede afectar a datos financieros.

---

## 2. Despliegue del laboratorio (Magento 2.2 SQLi)

Se comparte el enlace al laboratorio que desplegaremos en Docker para configurar el Magento vulnerable:

- **Magento 2.2 SQL Injection**: https://github.com/vulhub/vulhub/tree/master/magento/2.2-sqli

Despliegue del entorno con Vulhub:

```bash
┌──(kali㉿kali)-[~]
└─$ git clone https://github.com/vulhub/vulhub.git
```

```bash
┌──(kali㉿kali)-[~]
└─$ cd vulhub/magento/2.2-sqli
```

```bash
┌──(kali㉿kali)-[~/vulhub/magento/2.2-sqli]
└─$ docker-compose up -d
```

| Comando | Descripción |
|---------|-------------|
| `git clone ...` | Descarga el repositorio de Vulhub. |
| `cd vulhub/magento/2.2-sqli` | Entra en el directorio del laboratorio. |
| `docker-compose up -d` | Levanta el contenedor Magento vulnerable en segundo plano. |

> **Nota:** El arranque de Magento puede tardar bastante (es una aplicación pesada). Da unos minutos al contenedor antes de acceder. Consulta el `README.md` del laboratorio para ver el puerto y la ruta vulnerable exactos.

---

## 3. Reconocimiento inicial

Para confirmar que el objetivo es Magento, hay varias señales características:

```bash
┌──(kali㉿kali)-[~]
└─$ curl -s -I http://localhost/ | grep -i "set-cookie\|x-magento"
```

| Elemento | Descripción |
|----------|-------------|
| `-I` | Descarga solo las cabeceras HTTP. |
| `Set-Cookie` | Magento genera cookies muy reconocibles (por ejemplo, la cookie de sesión `PHPSESSID` junto a otras propias de la tienda). |

Otros ficheros y rutas reveladores:

```bash
┌──(kali㉿kali)-[~]
└─$ curl -s http://localhost/magento_version
```

| Ruta | Descripción |
|------|-------------|
| `/magento_version` | En Magento 2 devuelve la edición y versión (si no está deshabilitada). |
| `/static/version*` | Rutas de recursos estáticos con formato propio de Magento. |
| `/admin` | Panel de administración por defecto. |

> **Nota:** La presencia de rutas como `/static/`, `/pub/`, `/checkout/` o `/customer/account/` es muy indicativa de una tienda Magento.

---

## 4. Enumeración con MageScan

Una de las herramientas que veremos en esta clase es **MageScan**, una herramienta de escaneo de vulnerabilidades específica para Magento. Puede detectar vulnerabilidades comunes, incluyendo problemas con permisos de archivos, errores de configuración y vulnerabilidades conocidas en extensiones populares de Magento.

- **MageScan**: https://github.com/steverobbins/magescan

Se distribuye como un fichero `.phar` (un ejecutable de PHP empaquetado). Descarga:

```bash
┌──(kali㉿kali)-[~]
└─$ wget https://github.com/steverobbins/magescan/releases/download/v1.12.9/magescan.phar
```

Su sintaxis y modo de uso son bastante sencillos. Ejemplo de escaneo completo:

```bash
┌──(kali㉿kali)-[~]
└─$ php magescan.phar scan:all http://localhost
```

| Elemento | Descripción |
|----------|-------------|
| `php` | Intérprete de PHP con el que se ejecuta la herramienta. |
| `magescan.phar` | Archivo ejecutable empaquetado de MageScan. |
| `scan:all` | Comando que realiza un escaneo exhaustivo de todas las comprobaciones disponibles. |
| `http://localhost` | URL del sitio objetivo que se escaneará. |

**Ejemplo de salida (fragmento representativo):**

```bash
Magento Information
+----------+------------------+
| Edition  | Community        |
| Version  | 2.2.0            |
+----------+------------------+

Unreachable Path Check
+-------------------------------+-----------------+--------+
| Path                          | Response        | Status |
+-------------------------------+-----------------+--------+
| app/etc/env.php               | 403 Forbidden   | Pass   |
| .git/config                   | 200 OK          | Fail   |
+-------------------------------+-----------------+--------+
```

| Sección de la salida | Qué indica |
|----------------------|------------|
| `Magento Information` | Edición y versión detectadas. |
| `Unreachable Path Check` | Comprueba si ficheros sensibles están accesibles. Un `Fail` (como `.git/config` respondiendo `200 OK`) es un hallazgo grave: fuga de información. |

> **Advertencia:** Un fichero como `.git/config` o `app/etc/env.php` accesible es crítico: `env.php` contiene credenciales de la base de datos y claves de cifrado. Anota siempre estos `Fail` en el informe.

---

## 5. La vulnerabilidad: SQL Injection

### Concepto

Una de las técnicas que explotaremos sobre este gestor de contenidos es la famosa **SQL Injection** (inyección SQL). Esta vulnerabilidad se produce cuando los datos de entrada no son debidamente validados y se pueden insertar comandos SQL maliciosos en la consulta a la base de datos.

Un ataque de inyección SQL exitoso puede permitir al atacante obtener información confidencial, como credenciales de usuario o datos de pago, o incluso modificar o ejecutar comandos en la base de datos del sitio web.

> **Importante:** La causa raíz siempre es la misma: la aplicación **construye una consulta SQL concatenando entrada del usuario sin sanear**. Si la entrada se tratara como un dato (consultas parametrizadas / *prepared statements*) en lugar de como parte del código SQL, el ataque no sería posible.

### Explotación y Cookie Hijacking

En el caso del Magento que desplegamos, explotaremos una inyección SQL con el objetivo de obtener una **cookie de sesión**, que posteriormente utilizaremos para llevar a cabo un ataque de **Cookie Hijacking**. Este tipo de ataque nos permitirá, como atacantes, asumir la identidad del usuario legítimo y acceder a sus funciones, que en este caso será el **administrador**.

El flujo del ataque es el siguiente:

1. Localizar el parámetro vulnerable a inyección SQL.
2. Extraer, mediante la inyección, el valor de sesión del administrador almacenado en la base de datos.
3. Sustituir nuestra cookie de sesión por la del administrador en el navegador.
4. Acceder al panel como administrador sin conocer su contraseña.

Para automatizar la detección y explotación de la inyección usamos **sqlmap**:

```bash
┌──(kali㉿kali)-[~]
└─$ sqlmap -u "http://localhost/catalog/product_frontend_action/synchronize" --data='...' --level=5 --risk=3 --dbms=mysql
```

| Parámetro | Descripción |
|-----------|-------------|
| `-u "..."` | URL del endpoint vulnerable. |
| `--data='...'` | Datos enviados por POST (el cuerpo de la petición donde va el parámetro vulnerable). |
| `--level=5` | Nivel de exhaustividad de las pruebas (1–5); más alto prueba más puntos de inyección. |
| `--risk=3` | Nivel de "riesgo" de las pruebas (1–3); más alto usa payloads más agresivos. |
| `--dbms=mysql` | Indica el gestor de base de datos, lo que acelera y afina la explotación. |

Una vez extraída la sesión del administrador, realizamos el **Cookie Hijacking** sustituyendo el valor de la cookie en el navegador. En la consola del navegador (DevTools → Console) se haría, conceptualmente:

```javascript
document.cookie = "admin=VALOR_DE_SESION_ROBADO; path=/";
```

| Elemento | Descripción |
|----------|-------------|
| `document.cookie` | Propiedad del navegador que permite leer y escribir cookies del sitio actual. |
| `admin=VALOR_...` | Nombre y valor de la cookie de sesión del administrador obtenida por la inyección. |
| `path=/` | Ámbito de la cookie (todo el sitio). |

> **Importante:** Al recargar la página con la cookie del administrador ya establecida, el servidor nos reconoce como ese usuario: hemos suplantado su sesión (**Session/Cookie Hijacking**) sin necesidad de su contraseña.

> **Advertencia — contramedidas:** (1) usar **consultas parametrizadas** para eliminar la inyección de raíz; (2) marcar las cookies de sesión como `HttpOnly` y `Secure` para dificultar su robo y uso; (3) asociar la sesión a factores adicionales (IP, *user-agent*) y (4) mantener Magento actualizado con los parches de seguridad.

> **Recuerda:** Todas estas prácticas se realizan sobre el laboratorio desplegado en tu propia máquina. Explotar inyecciones SQL o suplantar sesiones en sitios de terceros sin autorización explícita es un delito.
