# Resumen de contramedidas — Metasploitable 2

> Documento de la serie [Reconocimiento y Metasploit](./01_reconocimiento_y_metasploit.md).

Las mismas técnicas que abren la máquina en cada uno de los servicios de esta serie indican cómo cerrarla. De forma general:

- **Actualizar y parchear** todo el software; eliminar versiones troyanizadas (vsftpd 2.3.4, UnrealIRCd 3.2.8.1) y obtenerlo solo de **fuentes oficiales**, verificando firmas y *hashes*.
- **Desactivar servicios inseguros o innecesarios**: Telnet, r-services (rexec/rlogin/rsh), X11 por red, puertas traseras (1524), DRb expuesto. Cuanto menos expongas, menor superficie de ataque.
- **Credenciales robustas**: eliminar contraseñas por defecto o vacías (MySQL root, VNC, PostgreSQL), exigir contraseñas fuertes y limitar intentos (p. ej. *fail2ban*) para frenar la fuerza bruta.
- **Cifrado**: sustituir Telnet/FTP/rlogin por **SSH/SFTP**; no exponer VNC sin túnel cifrado.
- **Configuración segura de servicios**: en Samba, no usar `username map script` inseguro; en NFS, **no exportar `/`** ni usar `no_root_squash`, y restringir por IP; en Tomcat, quitar o proteger el Manager y cambiar credenciales.
- **Mínimo privilegio**: que los servicios **no corran como root**, de modo que un fallo no entregue el control total.
- **Red y monitorización**: cortafuegos cerrando todo lo no imprescindible, segmentación de red, y un **IDS/IPS** más revisión de *logs* para detectar conexiones o comportamientos anómalos.

---

> **Recordatorio final:** practica solo sobre tu Metasploitable 2 en una red aislada. El objetivo de esta serie de apuntes es **entender** cómo surgen las vulnerabilidades para saber **defenderse** de ellas.
