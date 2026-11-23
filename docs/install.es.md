# Instalar nbuddyn

[English](install.md) · **Español** · [Português](install.pt.md)

Diez minutos de punta a punta. nbuddyn es un contenedor chico que corre al lado de tu n8n.

- [Antes de empezar](#antes-de-empezar)
- [1. Crear un usuario de solo lectura (solo Postgres)](#1-crear-un-usuario-de-solo-lectura-solo-postgres)
- [2. Ponerlo a correr](#2-ponerlo-a-correr): [Docker](#docker) · [Docker Compose](#docker-compose) · [Easypanel](#easypanel) · [Otros paneles](#otros-paneles) · [Desde el código](#desde-el-código)
- [3. Primer vistazo](#3-primer-vistazo)
- [Actualizar](#actualizar)
- [Si algo sale mal](#si-algo-sale-mal)

¿Querés mirarlo antes? `docker run --rm -p 8787:8787 ghcr.io/diegoparras/nbuddyn:latest demo`
arranca un n8n inventado. Entrá con `demo` / `demo`.

## Antes de empezar

nbuddyn está pensado para **n8n 3 en adelante**.

Necesitás saber una sola cosa: **qué base de datos usa tu n8n.**

- Si nunca le configuraste una, es **SQLite**: un archivo llamado `database.sqlite` dentro de la carpeta de datos de n8n.
- Si tu n8n tiene `DB_TYPE=postgresdb` en su configuración, es **Postgres**.

nbuddyn tiene que poder llegar a esa base, así que corrélo en el mismo servidor (y en la
misma red de Docker) que n8n.

## 1. Crear un usuario de solo lectura (solo Postgres)

Si tu n8n usa SQLite, salteá este paso.

Conectate a la base de n8n con cualquier herramienta de SQL y ejecutá esto una sola vez.
Cambiá la clave, y usá solo letras y números para no tener que escaparla después:

```sql
CREATE ROLE nbuddyn LOGIN PASSWORD 'elegi-una-clave';
GRANT SELECT (id, name, active, "isArchived", nodes, settings) ON workflow_entity TO nbuddyn;
GRANT SELECT (id, name, type) ON credentials_entity TO nbuddyn;
GRANT SELECT (id, "workflowId", status, "startedAt", "createdAt", "deletedAt") ON execution_entity TO nbuddyn;
GRANT SELECT (disabled, "mfaEnabled") ON "user" TO nbuddyn;
```

Este usuario solo puede leer las columnas que nbuddyn necesita. No puede leer
credenciales guardadas, hashes de contraseñas ni datos de ejecuciones, y no puede
escribir nada.

Opcional, para dos extras (quién guardó cada workflow y cuánto tardaron las ejecuciones):

```sql
GRANT SELECT ("versionId") ON workflow_entity TO nbuddyn;
GRANT SELECT ("versionId", authors) ON workflow_history TO nbuddyn;
GRANT SELECT ("stoppedAt") ON execution_entity TO nbuddyn;
```

## 2. Ponerlo a correr

Cualquier forma de correr nbuddyn necesita las mismas tres cosas:

| Qué | Valor |
|---|---|
| La imagen | `ghcr.io/diegoparras/nbuddyn:latest` |
| El puerto | `8787` |
| Un volumen en | `/data` (ahí viven el historial, los ajustes y los usuarios) |

Y estas variables:

| Variable | Qué poner |
|---|---|
| `NBUDDYN_DATABASE_URL` | Postgres: `postgres://nbuddyn:elegi-una-clave@HOST:5432/n8n`<br>SQLite: `sqlite:/n8n/database.sqlite` |
| `NBUDDYN_PASSWORD` | La contraseña con la que vas a entrar a nbuddyn. |
| `NBUDDYN_SECRET_KEY` | Recomendada. 32 caracteres o más; cifra los secretos que guarda nbuddyn. Generala con `openssl rand -hex 32` y guardala. |
| `NBUDDYN_LANG` | Opcional. `en`, `es` o `pt`. |

Todo lo demás (la dirección de n8n, Redis, task runners, alertas, más instancias de n8n)
se configura después desde la página. La [referencia](reference.md#every-setting) (en
inglés) lista todas las variables.

### Docker

Postgres:

```bash
docker run -d --name nbuddyn --restart unless-stopped -p 8787:8787 \
  --network RED_DE_TU_N8N \
  -e NBUDDYN_DATABASE_URL=postgres://nbuddyn:elegi-una-clave@n8n_postgres:5432/n8n \
  -e NBUDDYN_PASSWORD=elegi-una-clave-de-acceso \
  -e NBUDDYN_SECRET_KEY=pega-aca-la-clave-larga-y-aleatoria \
  -v nbuddyn_data:/data \
  ghcr.io/diegoparras/nbuddyn:latest
```

`n8n_postgres` es el nombre de tu contenedor de Postgres. `docker network ls` muestra
tus redes y `docker inspect n8n_postgres` muestra en cuál está.

SQLite:

```bash
docker run -d --name nbuddyn --restart unless-stopped -p 8787:8787 \
  -v n8n_data:/n8n:ro \
  -v nbuddyn_data:/data \
  -e NBUDDYN_DATABASE_URL=sqlite:/n8n/database.sqlite \
  -e NBUDDYN_PASSWORD=elegi-una-clave-de-acceso \
  -e NBUDDYN_SECRET_KEY=pega-aca-la-clave-larga-y-aleatoria \
  ghcr.io/diegoparras/nbuddyn:latest
```

`n8n_data` es el volumen que tu n8n monta en `/home/node/.n8n`. El `:ro` lo deja en solo
lectura: nbuddyn no podría cambiar los archivos de n8n aunque quisiera.

### Docker Compose

Hay dos archivos listos en [`deploy/`](../deploy):

- [`compose.postgres.yml`](../deploy/compose.postgres.yml)
- [`compose.sqlite.yml`](../deploy/compose.sqlite.yml)

Bajá el que corresponda, cambiá las claves que trae adentro y arrancalo:

```bash
docker compose -f compose.postgres.yml up -d
```

Para sumar nbuddyn al compose que ya tiene tu n8n, copiá ahí el servicio `nbuddyn` y el
volumen `nbuddyn_data`. Así comparte la red de n8n sin hacer nada más.

### Easypanel

1. Abrí el proyecto donde está tu n8n y tocá **+ Service → App**. Ponele `nbuddyn`.
2. **Source → Docker Image.** Imagen: `ghcr.io/diegoparras/nbuddyn:latest`. Guardar.
3. **Environment.** Pegá esto con tus valores y guardá:

   ```
   NBUDDYN_DATABASE_URL=postgres://nbuddyn:elegi-una-clave@PROYECTO_SERVICIO:5432/n8n
   NBUDDYN_PASSWORD=elegi-una-clave-de-acceso
   NBUDDYN_SECRET_KEY=pega-aca-la-clave-larga-y-aleatoria
   NBUDDYN_LANG=es
   ```

   Dentro de Easypanel un servicio se alcanza como `proyecto_servicio`. Si el proyecto es
   `acme` y el servicio de Postgres es `n8n-db`, el host es `acme_n8n-db`.
4. **Mounts → Add Volume Mount.** Nombre `data`, ruta `/data`.
5. **Domains.** Agregá un dominio (o usá el que ofrece Easypanel) y poné el puerto `8787`.
6. Tocá **Deploy**. Abrí el dominio y entrá con el usuario `nbuddyn`.

Para crear el usuario de solo lectura del paso 1, abrí el servicio de Postgres en
Easypanel, abrí su consola, ejecutá `psql -U postgres -d n8n` y pegá el SQL.

**Si tu n8n en Easypanel usa SQLite**, nbuddyn tiene que ver la carpeta de datos de n8n.
En el servicio de nbuddyn andá a **Mounts → Add Bind Mount**:

- Host path: `/var/lib/docker/volumes/PROYECTO_SERVICIO_VOLUMEN/_data`
- Mount path: `/n8n`

`PROYECTO_SERVICIO_VOLUMEN` son los nombres del proyecto, el servicio y el volumen de n8n
unidos con `_`: para el proyecto `acme`, el servicio `n8n` y el volumen `data`, es
`acme_n8n_data`. Después poné `NBUDDYN_DATABASE_URL=sqlite:/n8n/database.sqlite` y
desplegá.

### Otros paneles

Portainer, Coolify, Dokploy, CapRover, Dockge y los demás corren una imagen Docker, y
nbuddyn no necesita nada especial. Se llamen como se llamen en tu panel, completá:

- **Imagen:** `ghcr.io/diegoparras/nbuddyn:latest`
- **Puerto:** `8787`
- **Volumen persistente:** en `/data`
- **Variables de entorno:** la tabla de [Ponerlo a correr](#2-ponerlo-a-correr)
- **Red:** la misma que la base de datos de n8n

Si el panel pide un chequeo de salud: `GET /healthz` en el puerto 8787.

Estos paneles no fueron probados uno por uno. Si el tuyo necesita algo distinto,
[abrí un issue](https://github.com/diegoparras/nbuddyn/issues).

### Desde el código

Con [Rust](https://rustup.rs) instalado:

```bash
git clone https://github.com/diegoparras/nbuddyn
```

```bash
cd nbuddyn && cargo build --release
```

```bash
NBUDDYN_DATABASE_URL=postgres://nbuddyn:elegi-una-clave@localhost:5432/n8n \
NBUDDYN_PASSWORD=elegi-una-clave-de-acceso \
NBUDDYN_DATA_DIR=./data \
./target/release/nbuddyn
```

O armá la imagen vos: `docker build -t nbuddyn .`

## 3. Primer vistazo

Entrá con el usuario `nbuddyn` y la contraseña que elegiste. La primera revisión tarda
unos segundos. Después abrí el menú (arriba a la derecha) y andá a **Ajustes**:

1. **Dirección de n8n.** Donde abrís n8n en el navegador. Cada hallazgo pasa a tener un enlace a su workflow.
2. **Redis de n8n**, si tu n8n corre en modo cola. Esto enciende los chequeos de la cola y de los workers. Los workers y los procesadores de webhooks se descubren solos.
3. **Task runners**, uno por línea, si los corrés como contenedores aparte.
4. **Alertas.** Un bot de Telegram o un webhook, con un botón para mandar una prueba.

Poné nbuddyn detrás de https antes de abrirlo a internet: su informe lista tus puntos débiles.

## Actualizar

Bajá la imagen nueva y volvé a arrancar el contenedor. Tu historial y tus ajustes están
en el volumen `/data` y se conservan.

```bash
docker pull ghcr.io/diegoparras/nbuddyn:latest
```

```bash
docker compose up -d
```

En Easypanel, tocá **Deploy** otra vez. Para quedarte en una versión elegida, usá una
etiqueta como `ghcr.io/diegoparras/nbuddyn:0.20.0` en lugar de `latest`.

Después de actualizar **n8n**, verificá que nbuddyn lo siga pudiendo leer:

```bash
docker run --rm --network RED_DE_TU_N8N \
  -e NBUDDYN_DATABASE_URL=postgres://nbuddyn:elegi-una-clave@n8n_postgres:5432/n8n \
  ghcr.io/diegoparras/nbuddyn:latest check
```

## Si algo sale mal

| Qué ves | Qué hacer |
|---|---|
| El contenedor se detiene enseguida | Leé su log. nbuddyn dice qué variable falta o está mal. |
| No puede conectarse a la base | nbuddyn y la base no están en la misma red, o el nombre del host está mal. |
| Permiso denegado en una tabla | Falta un `GRANT` del paso 1. `nbuddyn check` imprime exactamente cuál ejecutar. |
| SQLite: "can only be read this way while n8n is running" | Arrancá n8n. El archivo solo se puede leer mientras n8n corre. |
| No se pueden guardar los ajustes | No hay un volumen montado en `/data`. |
| La página Clúster está vacía | Falta el Redis de n8n en Ajustes, o tu n8n no está en modo cola. |

¿Seguís trabado? [Abrí un issue](https://github.com/diegoparras/nbuddyn/issues) con el
log. Sacá las contraseñas antes.
