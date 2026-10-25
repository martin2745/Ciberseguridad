# Repositorio de Ciberseguridad y Hacking Ético

## ¿Qué es la Ciberseguridad?
La **ciberseguridad** es el conjunto de prácticas, tecnologías y procesos diseñados para proteger ordenadores, servidores, dispositivos móviles, sistemas electrónicos, redes y datos contra ataques maliciosos, daños o accesos no autorizados. Su objetivo principal es garantizar la confidencialidad, integridad y disponibilidad de la información en un entorno digital.

## ¿Qué es el Hacking?
El **hacking** es el conjunto de técnicas y conocimientos utilizados para comprender en profundidad, explorar y, a menudo, identificar y explotar vulnerabilidades en sistemas informáticos, redes o aplicaciones. Originalmente, el término se refería a la resolución creativa de problemas técnicos, aunque comúnmente se asocia con eludir medidas de seguridad.

## ¿Qué es el Hacking Ético?
El **hacking ético** consiste en aplicar las técnicas y herramientas de hacking de forma legal, autorizada y estructurada. El objetivo de un hacker ético (o *white-hat hacker*) es evaluar la seguridad de los sistemas para identificar vulnerabilidades y reportarlas a los propietarios. Esto permite corregir los fallos antes de que atacantes malintencionados puedan explotarlos, mejorando así la postura de seguridad de la organización.

## Contenido del repositorio
Este repositorio está diseñado como un espacio de aprendizaje y documentación sobre diversas áreas de la ciberseguridad. Aquí podrás encontrar:
- **Apuntes generales:** Guías teóricas y prácticas sobre herramientas de seguridad.
- **Entornos de pruebas web:** Documentación sobre el despliegue y uso de aplicaciones vulnerables por diseño, como DVWA, para practicar la explotación web.
- **Máquinas comprometidas (Writeups):** Resoluciones detalladas paso a paso de máquinas de plataformas de entrenamiento, abarcando desde el reconocimiento inicial hasta la escalada de privilegios.
- **Otros recursos:** Material complementario sobre herramientas y técnicas concretas (IDS, hardening, explotación y fuerza bruta).

---

### Kali Linux

- [00 - Instalación de Kali Linux](./Kali%20Linux/00_instalacion.md)

### Apuntes generales de hacking ético y ciberseguridad

- [00 - Conceptos básicos de redes](./Apuntes%20Generales/00_conceptos_basicos.md)
- [01 - Reconocimiento de servicios y acceso](./Apuntes%20Generales/01_Reconocimiento_de_servicios_y_acceso.md)
- [02 - Configuración de laboratorios con Docker](./Apuntes%20Generales/02_configuracion_laboratorios_con_docker.md)

#### Enumeración de servicios

- [01 - FTP](./Apuntes%20Generales/03_enumeracion_de_servicios/01_ftp.md)
- [02 - SSH](./Apuntes%20Generales/03_enumeracion_de_servicios/02_ssh.md)
- [03 - HTTP / HTTPS](./Apuntes%20Generales/03_enumeracion_de_servicios/03_http.md)
- [04 - SMB / Samba](./Apuntes%20Generales/03_enumeracion_de_servicios/04_smb.md)
- [05 - CMS WordPress](./Apuntes%20Generales/03_enumeracion_de_servicios/05_cms_wordpress.md)
- [06 - CMS Joomla](./Apuntes%20Generales/03_enumeracion_de_servicios/06_cms_joomla.md)
- [07 - CMS Drupal](./Apuntes%20Generales/03_enumeracion_de_servicios/07_cms_drupal.md)
- [08 - CMS Magento](./Apuntes%20Generales/03_enumeracion_de_servicios/08_cms_magento.md)

### Otros recursos

- [01 - IDS Snort](./Otros%20Recursos/01_IDS_snort.md)
- [02 - Hardening en Linux](./Otros%20Recursos/02_Hardening.md)
- [03 - Metasploit Framework](./Otros%20Recursos/03_Metasploit_Framework.md)
- [04 - Hydra para fuerza bruta contra formularios web](./Otros%20Recursos/04_Hydra.md)

### Máquina DVWA para práctica de ciberseguridad web

- [00 - Instalación de DVWA](./DVWA%20Ciberseguridad%20web/00_instalacion.md)
- [01 - Uso de Burp Suite](./DVWA%20Ciberseguridad%20web/01_burpsuite.md)
- [02 - Fuerza Bruta](./DVWA%20Ciberseguridad%20web/02_brute_force.md)
- [03 - Inyección de comandos](./DVWA%20Ciberseguridad%20web/03_command_injection.md)
- [04 - File Inclusion](./DVWA%20Ciberseguridad%20web/04_file_inclusion.md)
- [05 - File Upload](./DVWA%20Ciberseguridad%20web/05_file_upload_vulnerability.md)
- [06 - SQL Injection](./DVWA%20Ciberseguridad%20web/06_sql_injection.md)
- [07 - Blind SQL injection](./DVWA%20Ciberseguridad%20web/07_blind_sqli.md)
- [08 - XSS reflected](./DVWA%20Ciberseguridad%20web/08_reflected_xss.md)
- [09 - XSS stored](./DVWA%20Ciberseguridad%20web/09_stored_xss.md)

### Máquinas comprometidas

#### Metasploitable2

- [00 - Instalación de Metasploitable 2](./Máquinas%20comprometidas/Metasploitable2/00_instalacion.md)
- [01 - Reconocimiento y Metasploit](./Máquinas%20comprometidas/Metasploitable2/01_reconocimiento_y_metasploit.md)
- [02 - FTP (vsftpd 2.3.4)](./Máquinas%20comprometidas/Metasploitable2/02_ftp.md)
- [03 - SSH (OpenSSH 4.7p1)](./Máquinas%20comprometidas/Metasploitable2/03_ssh.md)
- [04 - Telnet](./Máquinas%20comprometidas/Metasploitable2/04_telnet.md)
- [05 - SMTP (Postfix)](./Máquinas%20comprometidas/Metasploitable2/05_smtp.md)
- [06 - DNS (BIND 9.4.2)](./Máquinas%20comprometidas/Metasploitable2/06_dns.md)
- [07 - HTTP (Apache + apps web)](./Máquinas%20comprometidas/Metasploitable2/07_http.md)
- [08 - rpcbind](./Máquinas%20comprometidas/Metasploitable2/08_rpcbind.md)
- [09 - Samba (SMB 3.0.20)](./Máquinas%20comprometidas/Metasploitable2/09_samba.md)
- [10 - Servicios r (exec/login/shell)](./Máquinas%20comprometidas/Metasploitable2/10_servicios_r.md)
- [11 - Java RMI](./Máquinas%20comprometidas/Metasploitable2/11_java_rmi.md)
- [12 - ingreslock (bindshell)](./Máquinas%20comprometidas/Metasploitable2/12_ingreslock.md)
- [13 - NFS](./Máquinas%20comprometidas/Metasploitable2/13_nfs.md)
- [14 - ProFTPD 1.3.1](./Máquinas%20comprometidas/Metasploitable2/14_proftpd.md)
- [15 - MySQL 5.0.51a](./Máquinas%20comprometidas/Metasploitable2/15_mysql.md)
- [16 - distccd](./Máquinas%20comprometidas/Metasploitable2/16_distccd.md)
- [17 - PostgreSQL 8.3](./Máquinas%20comprometidas/Metasploitable2/17_postgresql.md)
- [18 - VNC](./Máquinas%20comprometidas/Metasploitable2/18_vnc.md)
- [19 - X11](./Máquinas%20comprometidas/Metasploitable2/19_x11.md)
- [20 - UnrealIRCd](./Máquinas%20comprometidas/Metasploitable2/20_unrealircd.md)
- [21 - Apache Tomcat / Coyote](./Máquinas%20comprometidas/Metasploitable2/21_tomcat.md)
- [22 - DRb (Ruby distribuido)](./Máquinas%20comprometidas/Metasploitable2/22_drb.md)
- [23 - Post-explotación](./Máquinas%20comprometidas/Metasploitable2/23_post_explotacion.md)
- [24 - Resumen de contramedidas](./Máquinas%20comprometidas/Metasploitable2/24_contramedidas.md)

##### Tareas

- [01 - Enunciado: Fuerza bruta sobre SMB, FTP y SSH](./Máquinas%20comprometidas/Metasploitable2/tareas/01_enunciado_fuerza_bruta_smb_ftp_ssh.md)
- [01 - Solución: Fuerza bruta sobre SMB, FTP y SSH](./Máquinas%20comprometidas/Metasploitable2/tareas/01_solucion_fuerza_bruta_smb_ftp_ssh.md)

#### HackMyVM

- [01 - Pipy](./Máquinas%20comprometidas/HackMyVM/01_pipy.md)
- [02 - Friendly](./Máquinas%20comprometidas/HackMyVM/02_friendly.md)
- [03 - Friendly2](./Máquinas%20comprometidas/HackMyVM/03_friendly2.md)
- [04 - Friendly3](./Máquinas%20comprometidas/HackMyVM/04_friendly3.md)

#### Vulhub

- [Kibana - CVE-2018-17246](./Máquinas%20comprometidas/Vulhub/kibana/CVE-2018-17246/writeup.md)
- [ImageMagick - CVE-2016-3714 (ImageTragick)](./Máquinas%20comprometidas/Vulhub/imagemagick/CVE-2016-3714/writeup.md)
