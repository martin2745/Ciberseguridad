# Post-explotación: credenciales débiles y cracking — Metasploitable 2

> Práctica de laboratorio: aplicar únicamente sobre tu propia máquina Metasploitable 2 (`192.168.100.9`), aislada de Internet. Documento de la serie [Reconocimiento y Metasploit](./01_reconocimiento_y_metasploit.md).

Una vez dentro (sobre todo como root), uno de los primeros objetivos es hacerse con las **credenciales** de todos los usuarios para moverse o mantener el acceso. En Linux, las contraseñas cifradas están en `/etc/shadow` (solo legible por root) y los usuarios en `/etc/passwd`.

```bash
# Desde una shell de root en el objetivo, copia ambos archivos a Kali.
# En Kali, combínalos y crackéalos con John the Ripper:
unshadow passwd.txt shadow.txt > hashes.txt
john hashes.txt
john --show hashes.txt       # ver las contraseñas ya descifradas
```

Credenciales débiles conocidas de Metasploitable 2 (útiles para verificar logins):

| Usuario | Contraseña |
|---|---|
| msfadmin | msfadmin |
| user | user |
| postgres | postgres |
| sys | batman |
| klog | 123456789 |
| service | service |

> **Subir a Meterpreter:** si conseguiste una *shell* normal y quieres las funciones de Meterpreter, en Metasploit puedes mejorarla con:
> ```bash
> background           # deja la shell en segundo plano
> sessions -u 1        # mejora la sesión 1 a Meterpreter
> sessions -i 2        # entra en la nueva sesión Meterpreter
> ```
