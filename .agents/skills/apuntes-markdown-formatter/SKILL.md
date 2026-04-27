---
name: apuntes-markdown-formatter
description: Formatea, corrige y mejora apuntes técnicos en Markdown de cualquier temática (ciberseguridad, redes, sistemas, programación, etc.) convirtiéndolos en documentos profesionales, homogéneos y pedagógicamente enriquecidos. Úsalo cuando el usuario adjunte o proporcione un archivo .md con apuntes técnicos y pida mejorar la organización, añadir índice, corregir errores, mejorar explicaciones o estandarizar el formato. También debe activarse cuando el usuario mencione: 'mejorar apuntes', 'formatear markdown', 'organizar documento', 'añadir índice', 'corregir apuntes', 'mejorar explicaciones', 'dar formato a mis notas', o cuando adjunte cualquier .md con bloques de código y pida aplicar mejoras. Este skill es especialmente útil cuando el usuario tiene múltiples documentos de apuntes que quiere unificar bajo un formato común.
---

# Apuntes Markdown Formatter

Skill para transformar apuntes técnicos en bruto en documentos Markdown profesionales, homogéneos y pedagógicamente enriquecidos, sin eliminar ni reducir el contenido original.

---

## Flujo de trabajo

### 1. Lectura y análisis previo

Antes de aplicar ningún cambio, leer el documento completo e identificar:

- Secciones presentes y su estructura jerárquica (`#`, `##`, `###`, etc.)
- Bloques de código existentes — se respetarán íntegramente
- Errores ortográficos, de acentuación o de expresión evidentes
- Explicaciones teóricas que puedan ampliarse con información relevante
- Comandos o instrucciones clave que merezcan una tabla de parámetros
- Notas o advertencias que deberían destacarse visualmente con callouts
- Bloques de código consecutivos sin texto de transición entre ellos

**Antes de aplicar cambios, exponer al usuario el plan de modificaciones.** Esperar confirmación antes de proceder.

---

### 2. Cambios a aplicar (en orden)

#### 2.1 Índice numerado con anclas

Generar un índice con enlaces internos Markdown a todas las secciones y subsecciones relevantes, insertado justo después del título principal (`# ...`) y antes del primer `---`.

Formato:

```markdown
## Índice

1. [Introducción](#1-introducción)
2. [Configuración básica](#2-configuración-básica)
   - [Subsección A](#subsección-a)
   - [Subsección B](#subsección-b)
3. [Uso avanzado](#3-uso-avanzado)
```

#### 2.2 Separadores horizontales (`---`)

Colocar un `---` tras el índice y entre cada sección principal (`## ...`) para mejorar la legibilidad.

#### 2.3 Corrección ortográfica y de expresión

Corregir únicamente:
- Errores de acentuación (ej: `deberiamos` → `deberíamos`)
- Errores ortográficos evidentes en texto narrativo
- Errores tipográficos en nombres de comandos, rutas o URLs cuando sean inequívocos

**NUNCA modificar el contenido de bloques de código.**

#### 2.4 Ampliación de explicaciones teóricas

Ampliar las explicaciones teóricas existentes con información adicional relevante. **Nunca reducir ni eliminar el contenido original.**

Criterios para ampliar:
- Si una explicación describe un concepto sin mencionar su propósito práctico → añadir contexto de uso
- Si se menciona una herramienta, protocolo o componente sin detallar su funcionamiento → ampliar brevemente
- Si hay una comparativa implícita → hacerla explícita
- Si falta contexto de seguridad o de buenas prácticas relevante → añadirlo

#### 2.5 Tablas de parámetros para comandos clave

Para comandos con múltiples flags o parámetros importantes, añadir una tabla inmediatamente **después** del bloque de código:

| Parámetro | Descripción |
|-----------|-------------|
| `-X`      | Explicación breve |

Aplicar cuando el bloque de código contenga un comando con 3 o más flags/opciones que no estén explicadas en el texto circundante.

#### 2.6 Callouts con `>`

Añadir blockquotes (`>`) para destacar información crítica tras bloques de código o explicaciones:

```markdown
> **Nota:** Información complementaria útil para entender el punto.

> **Advertencia:** Riesgos de seguridad o configuraciones peligrosas.

> **Importante:** Pasos obligatorios o consecuencias de omisión.

> **Recuerda:** Conceptos previos necesarios para entender el punto actual.
```

Tipos de callout y cuándo usarlos:
- `> **Nota:**` — información adicional útil pero no crítica
- `> **Advertencia:**` — riesgos de seguridad o uso incorrecto
- `> **Importante:**` — pasos que no deben omitirse
- `> **Recuerda:**` — conceptos previos o dependencias

#### 2.7 Texto de transición entre bloques de código consecutivos

Si hay dos o más bloques de código seguidos sin explicación entre ellos, añadir una frase de transición que explique qué hace el siguiente bloque y por qué.

#### 2.8 Formateo de comandos y rutas inline

Los comandos, rutas, nombres de archivo, parámetros y términos técnicos concretos que aparezcan en el texto narrativo deben ir siempre formateados como código inline con backticks:

- Correcto: `systemctl restart apache2`, `/etc/hosts`, opción `--verbose`
- Incorrecto: systemctl restart apache2 (sin backticks en texto narrativo)

#### 2.9 Estandarización de notas existentes

Las notas existentes en el documento con formatos variados (`_*Nota*_:`, `**Nota:**`, texto plano, etc.) deben estandarizarse al formato callout `>`:

```markdown
> **Nota:** Contenido de la nota.
```

---

### 3. Reglas de oro — NUNCA hacer esto

- **NUNCA modificar el contenido de un bloque de código.** Los comandos, outputs y configuraciones son sagrados.
- **NUNCA eliminar** información técnica o explicaciones del documento original.
- **NUNCA reducir** el contenido de una explicación para "simplificarla".
- **NUNCA cambiar** el orden lógico ni la estructura de secciones originales.
- **NUNCA inventar** rutas, comandos, parámetros o comportamientos que no estén documentados o sean incorrectos.
- **NUNCA añadir** una cabecera de metadatos (plataforma, SO, técnicas, versión, etc.) al inicio del documento.
- No añadir secciones de resumen, contramedidas ni herramientas al final del documento.
- No añadir secciones vacías si no hay datos suficientes para rellenarlas.
- No usar iconos ni emojis en ninguna parte del documento.

---

### 4. Nomenclatura del archivo de salida

Conservar el nombre del archivo original.

---

### 5. Confirmación final

Tras generar el documento, informar al usuario de forma concisa:
- Correcciones ortográficas aplicadas (si las hay)
- Secciones donde se amplió contenido
- Tablas de parámetros añadidas
- Callouts insertados
