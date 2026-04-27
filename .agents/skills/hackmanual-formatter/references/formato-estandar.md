# Formato Estándar — Manual de Explotación de Máquina

Plantilla de referencia con ejemplos reales extraídos de manuales validados.
Usar como guía al aplicar el skill `hackmanual-formatter`.

---

## Plantilla completa de documento

```markdown
# Máquina <Nombre> - <Plataforma>

**Plataforma:** [Máquina <Nombre>](<URL del reto>)
**Dificultad:** <Fácil | Media | Difícil>
**SO:** <Linux | Windows> (<Distribución y versión>)
**Autor del reto:** <nombre o — si desconocido>
**Técnicas:** <Técnica1>, <Técnica2>, <Técnica3>

---

## Índice

1. [Configuración del laboratorio](#1-configuración-del-laboratorio)
2. [Reconocimiento — Escaneo de red](#2-reconocimiento--escaneo-de-red)
   - [Descubrimiento de hosts](#descubrimiento-de-hosts)
   - [Escaneo de puertos](#escaneo-de-puertos)
3. [Enumeración de servicios](#3-enumeración-de-servicios)
4. [Análisis de vulnerabilidades](#4-análisis-de-vulnerabilidades)
5. [Explotación](#5-explotación)
6. [Post-explotación](#6-post-explotación)
7. [Escalada de privilegios](#7-escalada-de-privilegios)
8. [Resumen de vulnerabilidades](#8-resumen-de-vulnerabilidades)

---
```

---

## Cabecera de metadatos

**Ejemplo real:**

```markdown
# Máquina Pipy - HackMyVM

**Plataforma:** [Máquina Pipy](https://hackmyvm.eu/machines/machine.php?vm=Pipy)
**Dificultad:** Media
**SO:** Linux (Ubuntu 22.04.3 LTS)
**Autor del reto:** ruycr4ft
**Técnicas:** RCE (CVE-2023-27372), Enumeración HTTP, Reverse Shell, Escalada de privilegios (CVE-2023-4911)
```

**Cómo inferir los valores:**
- `Nombre` y `Plataforma`: del título del documento o del contexto.
- `Dificultad`: si no aparece explícitamente, inferir por el número de pasos y técnicas.
- `SO`: buscar en outputs de `nmap` (`Service Info: OS:`, `OS details:`, `lsb_release -a`).
- `Técnicas`: enumerar todas las técnicas nombradas en el texto (LFI, RCE, Path Hijacking, etc.).

---

## Sección de reconocimiento

### Descubrimiento de hosts — con `arp-scan`

```markdown
### Descubrimiento de hosts

Iniciamos identificando la IP de la víctima en la red local mediante un escaneo ARP:

```bash
arp-scan -I eth0 192.168.100.0/24
```

| IP                | MAC Address       | Fabricante        |
| :---------------- | :---------------- | :---------------- |
| **192.168.100.9** | 08:00:27:0c:8f:a4 | Oracle VirtualBox |

> La IP **192.168.100.9** corresponde a la máquina objetivo <Nombre>.
```

### Descubrimiento de hosts — con `nmap` ping scan

```markdown
### Ping Scan — Descubrimiento de hosts

```bash
sudo nmap -n -sn 192.168.100.0/24
```

> La IP **192.168.100.X** corresponde a la máquina objetivo <Nombre>.
```

### Escaneo de puertos con tabla de parámetros

```markdown
### Escaneo de puertos

```bash
sudo nmap -n -Pn -sS -p- 192.168.100.X
```

| Parámetro | Descripción |
|-----------|-------------|
| `-Pn`     | Omite el ping previo (asume host activo) |
| `-sS`     | TCP SYN scan (stealth): no completa el handshake |
| `-p-`     | Escanea todos los puertos del 1 al 65535 |

**Salida:**
```bash
<output aquí>
```

Puertos abiertos: **22/tcp (SSH)** y **80/tcp (HTTP)**.
```

---

## Tablas de parámetros — referencia por herramienta

### nmap — parámetros habituales

| Parámetro        | Descripción                                              |
|------------------|----------------------------------------------------------|
| `-p-`            | Escanea todos los puertos del 1 al 65535                 |
| `-sS`            | TCP SYN scan (stealth): no completa el handshake         |
| `-sV`            | Detección de versión del servicio                        |
| `-sC`            | Ejecuta scripts NSE por defecto                          |
| `-O`             | Detección de sistema operativo                           |
| `-Pn`            | Omite el ping previo (asume host activo)                 |
| `-n`             | No resuelve nombres DNS                                  |
| `--min-rate`     | Mínimo de paquetes por segundo                           |
| `-vvv`           | Verbosidad máxima                                        |

### gobuster — parámetros habituales

| Parámetro  | Descripción                                        |
|------------|----------------------------------------------------|
| `dir`      | Modo enumeración de directorios                    |
| `-u`       | URL objetivo                                       |
| `-w`       | Wordlist a utilizar                                |
| `-x`       | Extensiones a probar (ej: `.php,.html`)            |
| `-t`       | Número de hilos concurrentes                       |

### ffuf — parámetros habituales

| Parámetro       | Descripción                                        |
|-----------------|----------------------------------------------------|
| `-u ... /FUZZ`  | URL con marcador de posición                       |
| `-w`            | Wordlist a utilizar                                |
| `-e`            | Extensiones a probar                               |
| `-ic`           | Ignora líneas comentadas del wordlist              |

---

## Callouts estándar por situación

```markdown
> La IP **X.X.X.X** corresponde a la máquina objetivo <Nombre>.

> El servidor ejecuta el CMS **<Nombre> versión X.X.X** sobre PHP.

> **CVE-XXXX-XXXXX** — <descripción breve de la vulnerabilidad y su impacto>.

> Credenciales de <servicio> en **texto plano**: usuario `X`, contraseña `Y`.

> **¡Máquina comprometida!** Tenemos acceso como usuario `<usuario>`.

> **¡Escalada completada!** Somos `root`.

> **¡Flag de root obtenida!** <descripción breve de cómo se llegó hasta ella>.
```

---

## Sección de explotación — estructura tipo

```markdown
## N. Explotación — <Nombre de la técnica>

### Paso 1: <Descripción breve>

<Explicación de qué se hace y por qué.>

```bash
<comando>
```

### Paso 2: <Descripción breve>

```bash
<comando>
```

**Salida:**

```bash
<output relevante>
```

### Resultado: <descripción del acceso obtenido>

```bash
<prompt de shell obtenido>
```

> **¡<Logro conseguido>!** <Descripción del nivel de acceso.>
```

---

## Sección de escalada de privilegios — estructura tipo

```markdown
## N. Escalada de privilegios — <Técnica>

### Identificación del vector

<Explicación de cómo se identifica el vector de escalada.>

```bash
<comando de reconocimiento>
```

**Salida:**

```bash
<output>
```

> <Conclusión sobre la vulnerabilidad encontrada.>

### Explotación

<Explicación paso a paso.>

```bash
<comandos de explotación>
```

> **¡Escalada completada!** Somos `root`.
```

---

## Sección final — Resumen de vulnerabilidades

```markdown
## N. Resumen de vulnerabilidades

| # | Vulnerabilidad | CVE | Criticidad | Impacto |
|---|---------------|-----|------------|---------|
| 1 | <Nombre> | CVE-XXXX-XXXXX | Crítica (CVSS 9.8) | <Impacto> |
| 2 | <Nombre> | — | Alta | <Impacto> |
| 3 | <Nombre> | CVE-XXXX-XXXXX | Alta (CVSS 7.8) | <Impacto> |
```

**Criterios de criticidad orientativos:**

| Criticidad | CVSS     | Ejemplo típico                                |
|------------|----------|-----------------------------------------------|
| Crítica    | 9.0–10.0 | RCE no autenticado                            |
| Alta       | 7.0–8.9  | LFI, escalada de privilegios local, SSRF      |
| Media      | 4.0–6.9  | Credenciales débiles, enumeración de usuarios |
| Baja       | 0.1–3.9  | Divulgación de información menor              |

---

## Sección final — Contramedidas

```markdown
## Contramedidas recomendadas

1. **<Nombre del control>**: <descripción de la medida>.
2. **<Nombre del control>**: <descripción de la medida>.
```

**Ejemplos de contramedidas frecuentes:**
- Actualizar el software/CMS a la última versión parcheada.
- Sanitizar y validar parámetros de entrada en aplicaciones web.
- No almacenar credenciales en texto plano; usar gestores de secretos.
- Usar rutas absolutas en scripts ejecutados con privilegios elevados.
- Aplicar el principio de mínimo privilegio a usuarios y procesos.
- Eliminar permisos innecesarios en reglas de `sudo` (`SETENV`, `NOPASSWD`).
- Deshabilitar la autenticación por contraseña en SSH; usar solo claves.

---

## Sección final — Herramientas utilizadas

```markdown
## Herramientas utilizadas

| Herramienta    | Uso                                                        |
|----------------|------------------------------------------------------------|
| `nmap`         | Escaneo de puertos, detección de servicios y OS            |
| `gobuster`     | Fuzzing de directorios y archivos web                      |
| `ffuf`         | Fuzzing de directorios y archivos web                      |
| `curl`         | Análisis de cabeceras HTTP                                 |
| `whatweb`      | Fingerprinting de tecnologías web                          |
| `searchsploit` | Búsqueda de exploits públicos                              |
| `netcat (nc)`  | Listener para Reverse Shell                                |
| `python3`      | Servidor HTTP temporal y ejecución de exploits             |
| `ssh`          | Acceso remoto a la máquina objetivo                        |
| `ssh2john`     | Extracción del hash de claves privadas SSH                 |
| `john`         | Cracking de hashes mediante diccionario                    |
| `hashcat`      | Cracking de hashes por GPU                                 |
| `mysql`        | Acceso a base de datos MariaDB/MySQL                       |
| `wget`         | Descarga de ficheros vía HTTP                              |
| `gcc`          | Compilación de exploits en C                               |
| `arp-scan`     | Descubrimiento de hosts en la red local                    |
| `bash -p`      | Shell privilegiada tras explotación de bit SUID            |
```

Incluir únicamente las herramientas que aparecen en los bloques de código del documento.
