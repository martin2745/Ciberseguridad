# ingreslock — bindshell (puerto 1524) — Metasploitable 2

> Práctica de laboratorio: aplicar únicamente sobre tu propia máquina Metasploitable 2 (`192.168.100.9`), aislada de Internet. Documento de la serie [Reconocimiento y Metasploit](./01_reconocimiento_y_metasploit.md).

**Qué es:** el puerto **1524** aparece como "ingreslock", pero en Metasploitable es en realidad una **puerta trasera**: una *shell de root* escuchando directamente, sin autenticación.

**Cómo se explota:** no hay que explotar nada; basta con **conectarse** al puerto y ya tienes una consola de root. Es el caso más directo de todos.

## Explotación manual (sin Metasploit)

```bash
telnet 192.168.100.9 1524
# aparece directamente un prompt de root:
id            # uid=0(root)
whoami        # root
```

**Explotación con Metasploit:** no existe un módulo específico porque no hace falta; es una conexión directa. Si lo quisieras gestionar como sesión en Metasploit, podrías capturar la shell con un *handler* genérico, pero lo natural es el `telnet` anterior.
