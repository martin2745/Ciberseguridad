---
name: hackmanual-formatter
description: Formatea y estandariza manuales de explotación de máquinas CTF/HackMyVM/HackTheBox en un formato profesional y homogéneo. Úsalo cuando el usuario proporcione un documento markdown (.md) con notas o pasos de un writeup de máquina y quiera darle formato de manual profesional. También debe activarse cuando el usuario mencione: 'formatear manual', 'dar formato a writeup', 'estandarizar documento de máquina', 'aplicar formato CTF', 'formatear explotación', o cuando adjunte un .md con bloques de código de comandos de hacking (nmap, gobuster, nc, ssh, etc.) y pida que se le dé formato o se transforme en un manual. Este skill es especialmente útil cuando el usuario tiene múltiples writeups que quiere unificar bajo un formato común.
---

# HackManual Formatter

Skill para transformar notas o writeups en bruto de máquinas CTF en manuales de explotación profesionales, homogéneos y reutilizables, siguiendo un formato de referencia establecido.

## Flujo de trabajo

### 1. Lectura y análisis previo

Antes de aplicar ningún cambio, leer ambos archivos:

- **Documento de entrada**: el `.md` que el usuario quiere formatear
- **Documento de referencia**: si el usuario proporciona uno, usarlo como plantilla; si no, usar el formato estándar definido en `references/formato-estandar.md`

Identificar y anotar mentalmente:
- Secciones presentes y ausentes respecto al formato estándar
- Bloques de código existentes (se respetarán íntegramente)
- Datos disponibles para la cabecera (plataforma, dificultad, SO, técnicas…)
- Tablas ya existentes vs. las que hay que crear
- Typos o errores evidentes en URLs o nombres de comandos

**Antes de aplicar cambios, explicar al usuario los cambios que se van a realizar.** Esperar confirmación.

---

### 2. Cambios a aplicar (en orden)

Aplicar todos los cambios siguientes. Ver `references/formato-estandar.md` para plantillas concretas de cada elemento.

#### 2.1 Cabecera de metadatos
Añadir al inicio del documento si no existe:

```markdown
# Máquina <Nombre> - <Plataforma>

**Plataforma:** [Máquina <Nombre>](<URL>)
**Dificultad:** <Fácil | Media | Difícil>
**SO:** <Linux | Windows> (<Distribución y versión si se conoce>)
**Autor del reto:** <nombre o — si desconocido>
**Técnicas:** <lista separada por comas de técnicas usadas>
```

Inferir los valores a partir del contenido del documento. Si algún dato no se puede inferir, usar `—`.

#### 2.2 Índice con anclas
Generar un índice numerado con enlaces internos en Markdown a todas las secciones y subsecciones relevantes, justo después de la cabecera y antes del primer `---`.

#### 2.3 Separadores horizontales (`---`)
Colocar un `---` tras la cabecera, tras el índice, y entre cada sección principal (`## N. ...`).

#### 2.4 Tablas de parámetros para comandos clave
Para los comandos con múltiples flags (`nmap`, `gobuster`, `ffuf`, `hydra`, `sqlmap`…), añadir una tabla inmediatamente después del bloque de código explicando cada parámetro:

| Parámetro | Descripción |
|-----------|-------------|
| `-X`      | Explicación |

#### 2.5 Callouts con `>`
Añadir blockquotes (`>`) tras bloques de código o análisis para resaltar:
- IP identificada como objetivo
- Vulnerabilidades descubiertas
- Credenciales obtenidas
- Accesos conseguidos
- Flags obtenidas

#### 2.6 Texto narrativo entre bloques de código
Si hay bloques de código consecutivos sin explicación entre ellos, añadir una frase de transición que explique qué se está haciendo y por qué.

#### 2.7 Corrección de typos evidentes
Corregir únicamente errores claros en URLs, nombres de herramientas o rutas de archivo. No modificar el contenido técnico ni los bloques de código.

#### 2.8 Nota sobre casos especiales o repetición de pasos
Si el documento menciona un paso que puede variar o repetirse (ej: comportamiento de caché de John the Ripper), formatearlo como callout `>` con etiqueta **Nota:**.

#### 2.9 Sección de Resumen de vulnerabilidades (añadir al final si no existe)
```markdown
## N. Resumen de vulnerabilidades

| # | Vulnerabilidad | CVE | Criticidad | Impacto |
|---|---------------|-----|------------|---------|
```
Rellenar con las vulnerabilidades identificadas a lo largo del documento.

#### 2.10 Sección de Contramedidas (añadir al final si no existe)
Lista numerada con recomendaciones específicas para cada vulnerabilidad encontrada.

#### 2.11 Tabla de herramientas utilizadas (añadir al final si no existe)
```markdown
## Herramientas utilizadas

| Herramienta | Uso |
|-------------|-----|
```
Inferir las herramientas a partir de los bloques de código presentes en el documento.

---

### 3. Reglas de oro — NUNCA hacer esto

- **NUNCA modificar el contenido de un bloque de código.** Los comandos, outputs y código fuente son sagrados.
- **NUNCA inventar** datos de cabecera, CVEs, IPs o credenciales que no estén en el documento.
- **NUNCA cambiar** la estructura lógica o el orden de las secciones originales.
- **NUNCA eliminar** información técnica del documento original.
- No añadir secciones vacías si no hay datos suficientes para rellenarlas.

---

## Referencia rápida de secciones estándar

Consultar `references/formato-estandar.md` para ver la plantilla completa con ejemplos de cada sección.
