# Tarea — Fuerza bruta sobre SMB, FTP y SSH (Metasploitable 2)

> **Práctica de laboratorio.** El objetivo de esta tarea es realizar ataques de fuerza bruta (diccionario) contra varios servicios de red de una máquina vulnerable de laboratorio, partiendo de las recomendaciones de un informe de vulnerabilidades. Se trabaja íntegramente en un entorno aislado y controlado, destinado exclusivamente al aprendizaje de técnicas de auditoría de seguridad. Realizar estos mismos ataques contra sistemas de terceros sin autorización expresa y por escrito es ilegal.

## Índice

1. [Entorno de laboratorio](#1-entorno-de-laboratorio)
2. [Apartado 1 — Diccionarios de usuarios y contraseñas (SMB)](#2-apartado-1--diccionarios-de-usuarios-y-contraseñas-smb)
3. [Apartado 2 — Fuerza bruta sobre FTP (4 hilos)](#3-apartado-2--fuerza-bruta-sobre-ftp-4-hilos)
4. [Apartado 3 (opcional) — Fuerza bruta sobre SSH](#4-apartado-3-opcional--fuerza-bruta-sobre-ssh)

---

## 1. Entorno de laboratorio

| Elemento | Descripción |
|---|---|
| **Máquina atacante** | Kali Linux, con las herramientas de pentesting necesarias (`Hydra`, `nmap`, cliente FTP y SSH). |
| **Máquina objetivo** | Metasploitable 2, una distribución Debian deliberadamente vulnerable publicada con fines educativos. |
| **Red** | Ambas máquinas en la misma red local aislada (red solo-anfitrión / interna de la máquina virtual). |

---

## 2. Apartado 1 — Diccionarios de usuarios y contraseñas (SMB)

Siguiendo las recomendaciones del informe de vulnerabilidades, elabora una lista de posibles usuarios y posibles contraseñas para atacar el servicio **SMB**. Puedes consultar en Internet credenciales por defecto para ese servicio y otras habituales en máquinas Debian.

Diccionarios de contraseñas hay muchos disponibles en Internet, y Kali dispone de varios, pero para este ejemplo, con el fin de no demorarse, vale uno de pequeño tamaño. En todo caso, para comprobar que se encuentran credenciales válidas, recuerda añadir el usuario principal de la máquina **`msfadmin` / `msfadmin`**.

El resultado serán dos archivos:

- `usuarios.txt`
- `dicionario.txt`

---

## 3. Apartado 2 — Fuerza bruta sobre FTP (4 hilos)

Realiza el ataque de fuerza bruta sobre el servicio **FTP** con 4 hilos en paralelo. Opción: `-t 4`.

---

## 4. Apartado 3 (opcional) — Fuerza bruta sobre SSH

- Realiza el ataque de fuerza bruta sobre el servicio **SSH**.
- El servicio SSH de la máquina objetivo (Metasploitable 2) emplea una versión muy antigua de OpenSSH, que solo admite algoritmos criptográficos obsoletos. Las versiones modernas de Kali Linux desactivan por defecto estos algoritmos débiles, por lo que será necesario ajustar la configuración para completar el ataque.
- Comprueba el acceso vía SSH desde Kali a la máquina Metasploitable 2 con las credenciales encontradas.

Para habilitar algoritmos obsoletos, edita `/etc/ssh/ssh_config`:

```
Host 192.168.1.XXX
    KexAlgorithms +diffie-hellman-group1-sha1
    HostKeyAlgorithms +ssh-rsa
    PubkeyAcceptedAlgorithms +ssh-rsa
    MACs +hmac-md5,hmac-sha1
```

Comando para conectarse a la máquina objetivo:

```bash
ssh -oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa msfadmin@192.168.1.XXX
```

> **Nota:** Sustituye `192.168.1.XXX` por la IP real de tu máquina Metasploitable 2 en tu laboratorio.
