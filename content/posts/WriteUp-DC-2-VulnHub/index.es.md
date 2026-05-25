---
title: "WriteUp: DC-2 | VulnHub"
date: 2026-03-25
draft: false
tags:
  - Linux
  - Web
  - WordPress
  - CMS
  - Caido
  - CeWL
  - Git
categories:
  - WriteUps
author: MaxisFront
description: "VulnHub DC:1 Machine | Desafío creado por: DCAU | Serie: DC"
image: WordPress_Logo.png
hideReadingTime: false
---
> Todos los derechos reservados a la organización WordPress

{{< alert info >}}

> Resumen

- Enumeración de usuarios con `Caido`
- Descubrimiento de claves a través de `CeWL`
- Reutilización de credenciales para el servicio `SSH`
- Aprovechamiento de SUID del comando `git`
- Recomendaciones de seguridad para prevenir y mitigar las vulnerabilidades de esta máquina.

{{< /alert>}}

  
#### Habilidades Empleadas

  
- Enumeración de puertos y enumeración de CMS
- Búsqueda y uso de CVEs Críticos
- Uso de comandos básicos basados en GNU/Linux
- Aprovechamiento de SUID vulnerables

#### Herramientas Utilizadas

- arp-scan
- Ping
- Nmap
- Caido
- WPScan
- CeWL
- SSH
- Git

---

## Escaneo y Análisis de Vulnerabilidades

  
Primeramente analizamos nuestra red local a través del comando `arp-scan`, especificando nuestra interfaz de red:
  

``` bash
arp-scan -I eth3 -l
```

>- `arp-scan`: Permite identificar equipos conectados a la misma red que el host.
>
>- `-I (interface)`: Especificamos la interfaz de red donde se enviarán solicitudes para identificar dispositivos.
>
>- `-l (--localnet)`: Descubrimiento de dispositivos en nuestra subred local.


![Arp-Scan output](images/1_dc2-arp-scan.png)


La dirección IP de interés es la `192.168.1.176`. Realizamos una prueba de conectividad a través de `ping` para observar si es posible entablar una comunicación entre equipos:


``` bash
ping -c1 -R 192.168.1.176
```


>- `ping`: Envía un paquete ICMP para verificar si un equipo está activo.
>
>- `-c1`: Especificamos que solo se envíe un paquete y se espere a recibirlo.
>
>- `-R (Record Route)`: El resultado muestra los nodos por los que atravesó un paquete.
  
![Testing connection through Ping](images/2_dc2-ping-traceroute.png)  


  La ruta de la traza ICMP es exitosa. Así pues, el valor del TTL es igual a `64`, lo cual **_podría_** indicar que estamos frente a un OS `Linux/Unix`.

---

### Reconocimiento de Puertos


Enumeramos los `65535` puertos del sistema a través de la herramienta `Nmap` (Network Mapper) para intentar identificar puertos TCP abiertos:


``` bash
nmap -p- --min-rate 5000 -Pn -n -oN nmap-scan 192.168.1.176
```

> - `-p-`: Nmap escanea los 65535 puertos TCP de un host.
>
> - `--min-rate`: Se envían como mínimo X cantidad de paquetes por segundo.
>
> - `-Pn (No Ping)`: Omisión del descubrimiento de host mediante ping (Asumiendo que el host está activo).
>
> - `-n (Sin resolución DNS)`: Omisión de resolución de DNS inversa (Se evita solicitar el nombre del host a partir de su IP).
>
> - `-oN`: Exportar los resultados en formato Nmap (Casi igual que el resultado en la CLI)


> <= Importante =>
> Dentro de entornos empresariales es preferible evitar el envío de paquetes `TCP, ICMP o UDP` en grandes cantidades, pues esto puede provocar un ataque `DoS` accidental o ser bloqueados por sistemas de monitorización.

![Escaneo de puertos con Nmap](images/3_dc2-nmap-scam.png)
  
### Enumeración de Puertos

Observamos los puertos `80 (http) y el 7744 (raqmon-pdu)`. Ahora, podemos centrar la enumeración en estos puertos utilizando la flag `-sV`, donde `Nmap` - tras haber entablado una comunicación con un puerto - analice las respuestas para determinar la versión del servicio que hay detrás.

  Los puertos `80 (HTTP)` y el `7744 (SSH)` se encuentran activos. A partir de este punto podemos enumerar los servicios a través de `Nmap`. 

``` bash
nmap -sCV -80,7744 -oN ports-enumeration 192.168.1.176
```

> - `-sCV`: Enumeración de los servicios de cada puerto, potenciado a través de scripts de reconocimiento por defecto.
  

![Ports enumeration with their services](images/4_dc2-ports-enumeration.png)  
  

Tras un análisis de la enumeración de puertos, podemos agrupar los resultados en la siguiente tabla:

  
| Puerto | Servicio |                    Versión                     |                                                                       Notas                                                                       |
| :----: | :------: | :--------------------------------------------: | :-----------------------------------------------------------------------------------------------------------------------------------------------: |
|   80   |   HTTP   | Apache httpd 2.4.10 ((Debian)) Debian 5+deb8u7 | Se identifica un `CMS` (WordPress, en este caso) con un servicio Apache `2.4.10`. Por otro lado, se identifica un equipo con `Debian 8 - jessie`. |
|  7744  |   SSH    |  OpenSSH 6.7p1 Debian 5+deb8u7 (protocol 2.0)  |                      Versión desactualizada propensa al **CVE-2018-15473**, aunque `para este equipo existen otros métodos`.                      |
  
> Herramientas como `whatweb` (Comando) o `Wappalyzer` (Extensión del navegador) son de gran utilidad cuando deseamos conocer únicamente las tecnologías que hay en un servicio http.


A partir de la tabla podemos definir posibles vectores de ataques:
 
> - Puerto 80 (HTTP): El `CMS` es un `WordPress  4.7.10` propenso al `CVE-2019-20041`, enumeración de usuarios a través del archivo `/wp-json/wp/v2/users`, así como enumeración de vulnerabilidades a través de herramientas automatizadas como `WPScan`.
>
> - Puerto 7744 (SSH): Servicio `OpenSSH` desactualizado, siendo usado posiblemente por un `Debian 8` (jessie). Posible enumeración de usuarios a través del `CVE-2018-15473`, aunque para esta máquina es posible obtener acceso mediante una enumeración web (A través de herramientas como `Caido` y `CeWL`.

### Enumeración Web

  
Previo a acceder a la web sin fallos, se mapea la IP de la máquina a la página dc-2 de manera temporal, modificando el archivo `/etc/hosts` para solucionar la dirección de la página:


![Adding dc-2 to the /etc/hosts file](images/5_dc2-map-etc-hosts.png)

Antes de acceder a través del navegador, realizamos una enumeración de direcciones dentro de la página web:


![Using gobuster to enumerate URL paths](images/6_dc2-gobuster-urls.png)

Observamos que dentro de las direcciones identificadas existe `/wp-admin`, por lo que accedemos a través del navegador para visualizar el panel de administración.

![Wordpress Administration Panel](images/7_dc2-admin-panel.png)

Se identificó la existencia del usuario `admin`, pero sin otros usuarios o contraseñas no es posible acceder al panel. Por ello se decidió utilizar `curl` para enumerar los usuarios del sistema:

```bash
for i in {0..10}; do curl -si "http://dc-2/?author=$i" | grep "author/"; done
```

![Enumerating users through the Curl command](images/8_dc2-curl-users-enumeration.png)

> Otra manera de enumerar posibles usuarios es consultando la dirección `/?rest_route=/wp/v2/users/`, aprovechándonos de la `REST API` de WordPress, incluida a partir de la versión `4.7.0`.
>
> Se debe destacar que la `REST API` solo expondrá a los usuarios con por lo menos 1 publicación, saltándose el resto.

Tras finalmente haber enumerado a los usuarios existentes en la página, ahora debemos descubrir de algún modo las claves de los usuarios.


---

Los ataques por diccionario suelen tener tener mayor eficacia que diccionarios genéricos. Esta premisa se basa en que los trabajadores y usuarios suelen crear contraseñas basadas en su contexto (Consumo de productos, hobbies, herramientas de trabajo, etc.).

> Acorde al paper "Context-Based Password Cracking for Digital Investigation" , se sugiere que los diccionarios personalizados (Información contextual) pueden mejorar la eficacia de un ataque hasta en un 50% en algunos casos. Esto frente a métodos de crakeo tradicionales. 
> 
> Fuente: [Context-Based Password Cracking for Digital Investigation](https://forensicsandsecurity.com/papers/PhDThesis-ContextBasedPasswordCrackingForDigitalInvestigation.pdf)

Por todo ello, se decidió generar un diccionario personalizado basado en el contenido de la página `dc-2`, utilizando la herramienta `CeWL`.

```bash
cewl -w custom_password_dictionary.txt http://dc-2/
```

> - `CeWL`: Custom Wordlist Generator genera diccionarios por medio del web crawling, siendo capaz de extraer palabras únicas, números de teléfono y correos electrónicos.

## Explotación

A partir de este punto nos enfocamos en intentar acceder a través de diversos métodos al sistema del equipo `DC-2`.

### Web

Tras obtener el diccionario, utilizamos una herramienta como `hydra` o `Caido` para automatizar la fase de prueba de credenciales:

![User enumeration through the 'Caido' tool](images/9_dc2-enum-users-jerry-and-tom.png)

>- `Caido`: Herramienta para auditorías web. Intercepta, modifica y gestiona tráfico HTTP/HTTPS en tiempo real.
>- `HTTPQL`: Lenguaje de consultas utilizado por Caido. Permite consultas con operadores lógicos (AND u OR), facilitando tareas como filtrado de respuestas del servidor.

Podemos observar que `Caido` recibió el código de respuesta `302 (Found)` para 2 consultas, las cuales fueron `tom` : `parturient`  y `jerry` : `adipiscing`.

Utilizando las credenciales obtenidas, logramos acceder al panel de administración.

![WordPress administration panel successful access](images/10_dc2-administration-panel-as-jerry.png)

A pesar de tener acceso al panel, no se lograron identificar _plugins_ desactualizados, información confidencial o avisos del administrador del sistema.

### SSH

En diversos entornos de trabajo es común la reutilización de credenciales. Por ello, retomando el hecho de que durante la enumeración de puertos vimos que el servicio `SSH` se encontraba corriendo en el puerto `7744`, intentamos acceder con los usuarios y contraseñas previas.

``` bash
ssh tom@192.168.1.176 
```

> - `SSH`: Secure Shell es un servicio de acceso remoto a servidores y dispositivos de manera segura

![SSH access with tom credentials](images/11_dc2-ssh-user-tom.png)

Al intentar ejecutar comandos como `groups` o `sudo -l` nos marca un error `-rbash: ... command not found`. Esto indica que nos encontramos frente una `restricted bash`, caracterizada por tener una cantidad limitada de comandos, acceso limitado a carpetas y no poder modificar su `.bashrc`.

Podemos verificar esto viendo el tipo de `Shell` de nuestra sesión, así como ver los comandos a los que estamos encapsulados:

```bash
echo $SHELL
ls -R -la usr/bin # Carpeta dentro del "/home" del usuario
```

![Verification of rbash and listing our commands](images/12_dc2-symbolic-links-identification.png)
Es posible observar que de la mayoría de los `symlinks` presentes (Equivalentes a un `acceso directo en Windows`) pueden dar paso a escapar de la `rbash` (`vi, less y scp`). En este caso utilizamos `vi` para cambiar la variable `SHELL` y solicitar una `bash`:

```shell
# > Ejecutar vi y presionar ESC
:set shell=/bin/bash
:shell
export PATH=/bin:/usr/bin:$PATH
```

Al checar el valor nuevamente de `SHELL`, observamos que nuestra sesión ahora utiliza una `bash sin restricciones`, así como que tenemos acceso a todos comandos del sistema.

Al ejecutar `sudo -l` observamos que `tom` no se encuentra dentro del grupo `sudoers`. A pesar de ello, previamente durante la explotación web descubrimos que existía el usuario `jerry`. Probamos a cambiar de usuario:

```bash
su jerry # Contraseña: adipiscing
```

Observamos nuevamente una reutilización de credenciales. Ahora intentamos listar -si es que existen- los comandos que podemos ejecutar con permisos de root:

![Command that Jerry can run as sudo](images/13_dc2-command-as-sudo.png)

Observamos que el usuario `jerry` tiene permisos de administrador para ejecutar el comando `git`, una herramienta utilizada para control de versiones.

Una manera rápida de elevar privilegios a través de `git` es siguiendo un formato similar al que utilizamos con `vi`:

```bash
sudo git -p help config # Abrirá un paginado
!/bin/bash
```

> - `-p help config`: Git lanza un paginador como el usuario root (Como `less`) para visualizar la ayuda detallada para el comando config.


![Bash session as the user root](images/14_dc2-privilege-escalation.png)


Ahora tenemos una sesión de bash como el usuario `root`. Como última comprobación, probamos a leer la flag que se encuentra en el directorio `/root`:

> Congratulatons!!!
>
> A special thanks to all those who sent me tweets
> and provided me with feedback - it's all greatly
> appreciated.
>
> If you enjoyed this CTF, send me a tweet via @DCAU7.


## Impacto

El atacante con permisos de un usuario común como `tom` o `jerry` tiene capacidades de:

> - Acceso y permisos de lectura en carpetas como `/www/html`.
> - Capacidad de lectura del archivo `wp-config.php`. 
> - Acceso a la base de datos de WordPress, con capacidad de modificar tablas como `wp_users`.
> - Capacidad de enumerar otros sistemas de la red y de realizar movimiento lateral.


El atacante con permisos de administrador obtiene las capacidades de:

> - Crear, modificar o eliminar usuarios, entablar persistencia entre sesiones y controlar el tráfico del servidor.
> - Modificación total de archivos del sistema `Linux`.
> - Modificar o eliminar el sistema `WordPress` del servidor.

---

## Resumen


La máquina `DC-2` presentó una serie de vulnerabilidades críticas (**No todas expuestas en este WriteUp**) que permitieron técnicas como `User enumeration` y `Dictionary Attack`, así como `Credential Reuse` en el servicio `SSH`, entre otras más. Por ello, a continuación se expondrán los descubrimientos, su gravedad y pautas para evitar esta clase de fallas de seguridad.

### Descubrimientos

> Reutilización de Credenciales

| ID  |          **Vulnerabilidad**           |                  **Gravedad**                  |                                                                 Descripción                                                                 |
| :-: | :-----------------------------------: | :--------------------------------------------: | :-----------------------------------------------------------------------------------------------------------------------------------------: |
| MF1 | CWE-1391: Uso de credenciales débiles | {{< exptag "critica">}} Crítica {{</exptag >}} | Reutilización de credenciales entre el servicio `Web` y `SSH`, permitiendo al atacante acceder al servidor y saltar entre usuarios locales. |

{{< alert error >}} 
Medidas inmediatas

> - Evitar el uso de claves basadas en productos de la empresa como lo es la página web o contenido dentro de esta.
> - No reutilizar credenciales bajo ninguna circunstancia.
> - Cambiar periódicamente las credenciales de los usuarios (Tanto en el servicio `Web` como en el `SSH`).

{{< /alert>}}


> Ejecución de git como sudo

| ID  |             **Vulnerabilidad**             |                  **Gravedad**                  |                                                        Descripción                                                        |
| :-: | :----------------------------------------: | :--------------------------------------------: | :-----------------------------------------------------------------------------------------------------------------------: |
| MF2 | CWE-269: Gestión inadecuada de privilegios | {{< exptag "critica">}} Crítica {{</exptag >}} | El usuario `jerry` posee la capacidad de escalar privilegios a través del binario `git` por medio de la flag `--paginate` |

{{< alert error >}} 
Medidas inmediatas:

> Para mitigar las capacidades de un atacante de poder escalar privilegios, se insta a:
>
>- Establecer permisos restrictivos para el comando `git` dentro del archivo `/etc/sudoers`, permitiendo únicamente el uso de `sudo` para comandos como `git pull`.
>- Si se requieren permisos para la modificación de archivos dentro de `/var/www/`, cambiar el dueño del directorio a usuarios especiales como `www-data`.

> Para remediar la capacidad de un atacante para escalar privilegios, se insta a utilizar herramientas automatizadas aisladas con permisos especiales, evitando que un usuario tenga que realizar tareas de forma manual.

{{< /alert>}}


> Panel de Administración

| ID  |                        **Vulnerabilidad**                        |               **Gravedad**               |                                                                         Descripción                                                                          |
| :-: | :--------------------------------------------------------------: | :--------------------------------------: | :----------------------------------------------------------------------------------------------------------------------------------------------------------: |
| MF3 | CWE-307: Falta de control de intentos de autenticación excesivos | {{< exptag "alta">}} Alta {{</exptag >}} | El panel de administración de WordPress no tiene un límite definido de intentos de autenticación, permitiendo automatizados de autenticación indefinidamente |


{{< alert error >}} 
Medidas inmediatas:

> - Establecer un método `2FA` para reducir el alcance de ataques dirigidos.
> - Implementar un `WAF` (Web application firewall) para monitorear y bloquear tráfico `HTTP/HTTPS` sospechoso.
>-  Establecer una política de bloqueo de IPs temporal o permanente.

{{< /alert>}}


> Enumeración de usuarios

| ID  |                          **Vulnerabilidad**                          |                **Gravedad**                |                                                            Descripción                                                            |
| :-: | :------------------------------------------------------------------: | :----------------------------------------: | :-------------------------------------------------------------------------------------------------------------------------------: |
| MF4 | CWE-200: Exposición de información sensible a un actor no autorizado | {{< exptag "media">}} Media {{</exptag >}} | La versión `4.7.0` de WordPress permite la enumeración de usuarios a través de la API REST en la URL `/wp-json/wp/v2/users`  <br> |


{{< alert error >}} 
Medidas inmediatas:

> - Restringir el acceso a la `API REST` a usuarios no privilegiados, o bien, deshabilitar los `endpoints` que permiten acceder a la información de los usuarios.
> - Bloquear la enumeración de usuarios a través de la URL `/?author=ID`.

{{< /alert>}}







