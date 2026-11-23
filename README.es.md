<div align="center">

<img src="docs/img/logo.svg" width="88" alt="nbuddyn">

# nbuddyn

**La cabina que le falta a tu n8n autoalojado.**<br>
Puertas abiertas, fallas silenciosas y lo que está por romperse, en una sola página. Solo lectura, mínimo y tuyo.

[English](README.md) · **Español** · [Português](README.pt.md)

[![CI](https://github.com/diegoparras/nbuddyn/actions/workflows/ci.yml/badge.svg)](https://github.com/diegoparras/nbuddyn/actions/workflows/ci.yml)
[![Versión](https://img.shields.io/github/v/release/diegoparras/nbuddyn?color=F5B83D&label=versi%C3%B3n)](https://github.com/diegoparras/nbuddyn/releases)
[![Licencia: MIT](https://img.shields.io/badge/licencia-MIT-F5B83D.svg)](LICENSE)
![Plataformas](https://img.shields.io/badge/imagen-amd64%20%7C%20arm64-555)
![Hecho en Rust](https://img.shields.io/badge/hecho%20en-Rust-555)

<a href="docs/img/tour.mp4"><img src="docs/img/tour.gif" width="820" alt="Un recorrido de un minuto por nbuddyn"></a>

<sub>Un recorrido de un minuto, grabado sobre la demo incluida. Todos los datos que se ven son inventados.</sub>

</div>

> [!IMPORTANT]
> nbuddyn es un proyecto independiente, de la comunidad. **No tiene afiliación con n8n GmbH, ni su aval ni su patrocinio.**
> No contiene código de n8n y no desbloquea ni elude ninguna función licenciada de n8n. Ver [Sin afiliación con n8n](#sin-afiliación-con-n8n).

## Por qué

n8n es muy bueno ejecutando workflows. Es más callado a la hora de gobernarlos: qué
webhooks puede llamar cualquiera, qué workflows fallan sin que nadie se entere, dónde
quedó pegada una clave dentro de un nodo, si los workers están vivos.

nbuddyn se instala al lado de tu n8n, lee su base de datos y su Redis, y responde esas
preguntas con un puntaje y una lista de qué hacer primero.

- **Solo lectura.** Pone su sesión de base de datos en modo lectura antes de la primera consulta. No puede modificar tu n8n.
- **Mínimo.** Un único binario estático escrito en Rust. La imagen pesa pocos MB y una instancia típica usa menos de 30 MB de memoria.
- **Privado.** Sin telemetría, sin cuenta, sin nube. Nada sale de tu servidor salvo las alertas que configures o el aviso de versiones nuevas de n8n, si lo encendés.
- **Tres idiomas.** Inglés, español y portugués, se cambian desde la página.

## Probalo en 30 segundos

No hace falta tener n8n. Esto arranca nbuddyn contra un n8n inventado, con los problemas que tienen los reales:

```bash
docker run --rm -p 8787:8787 ghcr.io/diegoparras/nbuddyn:latest demo
```

Abrí <http://localhost:8787> y entrá con `demo` / `demo`.

## Qué te da

| | |
|---|---|
| [![Resumen](docs/img/overview-es.png)](docs/img/overview-es.png) **Resumen.** Un puntaje, seis luces y qué hacer primero. | [![Hallazgos](docs/img/findings.png)](docs/img/findings.png) **Hallazgos.** Cada uno dice qué hacer, qué tan seguro está nbuddyn, y enlaza al workflow. |
| [![Clúster](docs/img/cluster.png)](docs/img/cluster.png) **Clúster.** La cola, los workers, los procesadores de webhooks, los task runners y Redis. | [![Actividad](docs/img/activity.png)](docs/img/activity.png) **Actividad.** Qué cambió entre una revisión y la siguiente, y quién lo guardó. |
| [![Historial](docs/img/history.png)](docs/img/history.png) **Historial.** Ejecuciones y puntaje por día, aunque n8n ya las haya borrado. | [![Credenciales](docs/img/credentials.png)](docs/img/credentials.png) **Credenciales.** Qué workflows se romperían si rotaras una. Nunca el secreto. |

<sub>Capturas tomadas sobre la demo incluida. Todos los datos que se ven son inventados. La página se ve igual en español; acá la mayoría está en inglés.</sub>

**Qué revisa**

- **Puertas abiertas:** servidores MCP, chats, webhooks y formularios sin autenticación.
- **Fallas silenciosas:** workflows que fallan seguido, ejecuciones trabadas hace horas, workflows activos sin workflow de error, workflows que dejaron de correr.
- **Secretos:** claves escritas dentro de nodos (se informa el tipo, nunca el valor), llamadas sin cifrar, usuarios sin doble factor.
- **Cola y clúster:** sin workers, versiones de n8n mezcladas, cola que se acumula, Redis a punto de descartar trabajos, task runners que no responden.
- **Orden:** nodos eliminados en n8n 3, credenciales sin uso, nodos que ejecutan comandos del sistema.

**Qué más hace**

- **Alertas** por Telegram o a cualquier webhook (Slack funciona tal cual) cuando algo cambia, nunca el informe entero otra vez.
- **Varios n8n** desde un solo nbuddyn: producción y pruebas, o uno por cliente.
- **Tus reglas:** definí qué tan grave es cada chequeo acá, aceptá un hallazgo con un motivo, hacé que las aceptaciones venzan.
- **Usuarios, roles e inicio de sesión único** (OpenID Connect), con registro de auditoría.
- **Un endpoint MCP**, para que un asistente de IA pregunte por tu n8n en lenguaje natural. También de solo lectura.

La lista completa está en la [referencia](docs/reference.md) (en inglés).

## Instalación

Necesitás dos cosas: dónde está la base de datos de n8n y una contraseña para el login propio de nbuddyn.

**Tu n8n usa Postgres.** Creá una vez un usuario de solo lectura (el SQL está en la
[guía](docs/install.es.md#1-crear-un-usuario-de-solo-lectura-solo-postgres)) y después:

```bash
docker run -d --name nbuddyn -p 8787:8787 \
  -e NBUDDYN_DATABASE_URL=postgres://nbuddyn:elegi-una-clave@n8n_postgres:5432/n8n \
  -e NBUDDYN_PASSWORD=elegi-una-clave-de-acceso \
  -v nbuddyn_data:/data \
  ghcr.io/diegoparras/nbuddyn:latest
```

**Tu n8n usa SQLite** (lo que usa n8n cuando no le configurás una base):

```bash
docker run -d --name nbuddyn -p 8787:8787 \
  -v n8n_data:/n8n:ro \
  -v nbuddyn_data:/data \
  -e NBUDDYN_DATABASE_URL=sqlite:/n8n/database.sqlite \
  -e NBUDDYN_PASSWORD=elegi-una-clave-de-acceso \
  ghcr.io/diegoparras/nbuddyn:latest
```

Abrí <http://localhost:8787> y entrá con el usuario `nbuddyn`. Todo lo demás se configura desde la página, en **Ajustes**.

Guías paso a paso:

| | |
|---|---|
| [Docker](docs/install.es.md#docker) | Un comando, como arriba. |
| [Docker Compose](docs/install.es.md#docker-compose) | Archivos listos en [`deploy/`](deploy). |
| [Easypanel](docs/install.es.md#easypanel) | Clic por clic. |
| [Portainer, Coolify, Dokploy y otros](docs/install.es.md#otros-paneles) | Cualquier cosa que corra una imagen Docker. |
| [Desde el código](docs/install.es.md#desde-el-código) | `cargo build --release`. |

## ¿Es seguro ponerlo al lado de producción?

- **Solo lee.** Con Postgres, dale un usuario que pueda leer únicamente las columnas que necesita: no puede leer credenciales guardadas, hashes de contraseñas ni datos de ejecuciones.
- Corre como usuario sin privilegios, en una imagen que tiene un binario y nada más: sin shell, sin gestor de paquetes.
- Los secretos que guarda (contraseñas de base y de Redis, el token de Telegram) van cifrados en disco.
- Las imágenes están firmadas y traen su lista de componentes. Cómo verificarlas está en [SECURITY.md](SECURITY.md).
- El [modelo de amenazas](docs/THREAT-MODEL.md) detalla qué protege cada entrada y qué queda abierto a sabiendas.

Todavía no se hizo una auditoría de seguridad independiente.

## Qué no hace

nbuddyn mira; no arregla ni bloquea. Nunca escribe en n8n, así que no puede desactivar
por vos un workflow riesgoso. No mira dentro de las ejecuciones ni de las credenciales,
y no revisa qué hace un workflow con sus datos. El puntaje resume lo que puede ver. Es
un radar, no una auditoría.

## Compatibilidad

nbuddyn está pensado para **n8n 3 en adelante**. Cada cambio se prueba contra un n8n 3.3
real, con SQLite y con Postgres. También se corre contra n8n 1.123 y 2.48, pero no es
para lo que está hecho, y algunos chequeos (workers, procesadores de webhooks) necesitan
n8n 3. nbuddyn lee la base de datos propia de n8n, que n8n puede cambiar entre
versiones; después de actualizar n8n, `nbuddyn check` te dice si todo se sigue pudiendo leer.

## Documentación

- [Guía de instalación](docs/install.es.md)
- [Referencia](docs/reference.md) (en inglés): cada chequeo, cada ajuste, alertas, inicio de sesión único, MCP
- [Política de seguridad](SECURITY.md) y [modelo de amenazas](docs/THREAT-MODEL.md) (en inglés)
- [Historial de cambios](CHANGELOG.md) (en inglés)
- [Cómo contribuir](CONTRIBUTING.md)

## Sin afiliación con n8n

nbuddyn es un proyecto independiente de código abierto. No tiene afiliación con n8n GmbH,
ni su aval, ni su patrocinio, ni su soporte. "n8n" es una marca de n8n GmbH y se usa acá
únicamente para decir con qué funciona nbuddyn.

nbuddyn no contiene código de n8n. No modifica n8n, y no desbloquea ni elude ninguna
función de los planes pagos de n8n: no enciende nada dentro de n8n. Lee la base de datos
y el Redis de un n8n que alojás vos, con el acceso que vos le das.

Parte de lo que muestra nbuddyn se parece a cosas que n8n ofrece en sus planes pagos,
como la vista de workers, un historial más largo de ejecuciones y los eventos de
auditoría. nbuddyn arma su propia vista, más simple y desde afuera, y no las sustituye.
Si necesitás esas funciones dentro de n8n, con el soporte de n8n detrás, contratalas a n8n.

Para ayuda con n8n, andá a los [canales propios de n8n](https://n8n.io).

## Licencia

[MIT](LICENSE). Libre para usar, modificar y compartir, en casa o en el trabajo. Las
bibliotecas con las que está hecho nbuddyn conservan sus propias licencias de código abierto.
