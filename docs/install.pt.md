# Instalar o nbuddyn

[English](install.md) · [Español](install.es.md) · **Português**

Dez minutos do início ao fim. O nbuddyn é um contêiner pequeno que roda ao lado do seu n8n.

- [Antes de começar](#antes-de-começar)
- [1. Criar um usuário somente leitura (só Postgres)](#1-criar-um-usuário-somente-leitura-só-postgres)
- [2. Colocar para rodar](#2-colocar-para-rodar): [Docker](#docker) · [Docker Compose](#docker-compose) · [Easypanel](#easypanel) · [Outros painéis](#outros-painéis) · [A partir do código](#a-partir-do-código)
- [3. Primeiro olhar](#3-primeiro-olhar)
- [Atualizar](#atualizar)
- [Se algo der errado](#se-algo-der-errado)

Quer só dar uma olhada antes? `docker run --rm -p 8787:8787 ghcr.io/diegoparras/nbuddyn:latest demo`
inicia um n8n inventado. Entre com `demo` / `demo`.

## Antes de começar

O nbuddyn é feito para o **n8n 3 em diante**.

Você precisa saber uma única coisa: **qual banco de dados o seu n8n usa.**

- Se você nunca configurou um, é **SQLite**: um arquivo chamado `database.sqlite` dentro da pasta de dados do n8n.
- Se o seu n8n tem `DB_TYPE=postgresdb` na configuração, é **Postgres**.

O nbuddyn precisa alcançar esse banco, então rode-o no mesmo servidor (e na mesma rede
do Docker) que o n8n.

## 1. Criar um usuário somente leitura (só Postgres)

Se o seu n8n usa SQLite, pule esta etapa.

Conecte-se ao banco do n8n com qualquer ferramenta de SQL e execute isto uma única vez.
Troque a senha, e use apenas letras e números para não precisar escapá-la depois:

```sql
CREATE ROLE nbuddyn LOGIN PASSWORD 'escolha-uma-senha';
GRANT SELECT (id, name, active, "isArchived", nodes, settings) ON workflow_entity TO nbuddyn;
GRANT SELECT (id, name, type) ON credentials_entity TO nbuddyn;
GRANT SELECT (id, "workflowId", status, "startedAt", "createdAt", "deletedAt") ON execution_entity TO nbuddyn;
GRANT SELECT (disabled, "mfaEnabled") ON "user" TO nbuddyn;
```

Esse usuário só consegue ler as colunas de que o nbuddyn precisa. Não consegue ler
credenciais guardadas, hashes de senhas nem dados de execuções, e não consegue escrever nada.

Opcional, para dois extras (quem salvou cada workflow e quanto tempo as execuções levaram):

```sql
GRANT SELECT ("versionId") ON workflow_entity TO nbuddyn;
GRANT SELECT ("versionId", authors) ON workflow_history TO nbuddyn;
GRANT SELECT ("stoppedAt") ON execution_entity TO nbuddyn;
```

## 2. Colocar para rodar

Qualquer forma de rodar o nbuddyn precisa das mesmas três coisas:

| O quê | Valor |
|---|---|
| A imagem | `ghcr.io/diegoparras/nbuddyn:latest` |
| A porta | `8787` |
| Um volume em | `/data` (ali ficam o histórico, as configurações e os usuários) |

E destas variáveis:

| Variável | O que colocar |
|---|---|
| `NBUDDYN_DATABASE_URL` | Postgres: `postgres://nbuddyn:escolha-uma-senha@HOST:5432/n8n`<br>SQLite: `sqlite:/n8n/database.sqlite` |
| `NBUDDYN_PASSWORD` | A senha com a qual você vai entrar no nbuddyn. |
| `NBUDDYN_SECRET_KEY` | Recomendada. 32 caracteres ou mais; criptografa os segredos que o nbuddyn guarda. Gere com `openssl rand -hex 32` e guarde-a. |
| `NBUDDYN_LANG` | Opcional. `en`, `es` ou `pt`. |

Todo o resto (o endereço do n8n, Redis, task runners, alertas, mais instâncias do n8n) é
configurado depois, na página. A [referência](reference.md#every-setting) (em inglês)
lista todas as variáveis.

### Docker

Postgres:

```bash
docker run -d --name nbuddyn --restart unless-stopped -p 8787:8787 \
  --network REDE_DO_SEU_N8N \
  -e NBUDDYN_DATABASE_URL=postgres://nbuddyn:escolha-uma-senha@n8n_postgres:5432/n8n \
  -e NBUDDYN_PASSWORD=escolha-uma-senha-de-acesso \
  -e NBUDDYN_SECRET_KEY=cole-aqui-a-chave-longa-e-aleatoria \
  -v nbuddyn_data:/data \
  ghcr.io/diegoparras/nbuddyn:latest
```

`n8n_postgres` é o nome do seu contêiner do Postgres. `docker network ls` mostra as suas
redes e `docker inspect n8n_postgres` mostra em qual ele está.

SQLite:

```bash
docker run -d --name nbuddyn --restart unless-stopped -p 8787:8787 \
  -v n8n_data:/n8n:ro \
  -v nbuddyn_data:/data \
  -e NBUDDYN_DATABASE_URL=sqlite:/n8n/database.sqlite \
  -e NBUDDYN_PASSWORD=escolha-uma-senha-de-acesso \
  -e NBUDDYN_SECRET_KEY=cole-aqui-a-chave-longa-e-aleatoria \
  ghcr.io/diegoparras/nbuddyn:latest
```

`n8n_data` é o volume que o seu n8n monta em `/home/node/.n8n`. O `:ro` deixa somente
leitura: o nbuddyn não conseguiria alterar os arquivos do n8n nem se quisesse.

### Docker Compose

Há dois arquivos prontos em [`deploy/`](../deploy):

- [`compose.postgres.yml`](../deploy/compose.postgres.yml)
- [`compose.sqlite.yml`](../deploy/compose.sqlite.yml)

Baixe o que serve para você, troque as senhas que vêm dentro e inicie:

```bash
docker compose -f compose.postgres.yml up -d
```

Para adicionar o nbuddyn ao compose que o seu n8n já tem, copie para lá o serviço
`nbuddyn` e o volume `nbuddyn_data`. Assim ele compartilha a rede do n8n sem mais nada.

### Easypanel

1. Abra o projeto onde está o seu n8n e clique em **+ Service → App**. Dê o nome `nbuddyn`.
2. **Source → Docker Image.** Imagem: `ghcr.io/diegoparras/nbuddyn:latest`. Salve.
3. **Environment.** Cole isto com os seus valores e salve:

   ```
   NBUDDYN_DATABASE_URL=postgres://nbuddyn:escolha-uma-senha@PROJETO_SERVICO:5432/n8n
   NBUDDYN_PASSWORD=escolha-uma-senha-de-acesso
   NBUDDYN_SECRET_KEY=cole-aqui-a-chave-longa-e-aleatoria
   NBUDDYN_LANG=pt
   ```

   Dentro do Easypanel um serviço é alcançado como `projeto_servico`. Se o projeto é
   `acme` e o serviço do Postgres é `n8n-db`, o host é `acme_n8n-db`.
4. **Mounts → Add Volume Mount.** Nome `data`, caminho `/data`.
5. **Domains.** Adicione um domínio (ou use o que o Easypanel oferece) e defina a porta `8787`.
6. Clique em **Deploy**. Abra o domínio e entre com o usuário `nbuddyn`.

Para criar o usuário somente leitura da etapa 1, abra o serviço do Postgres no
Easypanel, abra o console dele, execute `psql -U postgres -d n8n` e cole o SQL.

**Se o seu n8n no Easypanel usa SQLite**, o nbuddyn precisa enxergar a pasta de dados do
n8n. No serviço do nbuddyn vá em **Mounts → Add Bind Mount**:

- Host path: `/var/lib/docker/volumes/PROJETO_SERVICO_VOLUME/_data`
- Mount path: `/n8n`

`PROJETO_SERVICO_VOLUME` são os nomes do projeto, do serviço e do volume do n8n unidos
com `_`: para o projeto `acme`, o serviço `n8n` e o volume `data`, é `acme_n8n_data`.
Depois defina `NBUDDYN_DATABASE_URL=sqlite:/n8n/database.sqlite` e faça o deploy.

### Outros painéis

Portainer, Coolify, Dokploy, CapRover, Dockge e os demais rodam uma imagem Docker, e o
nbuddyn não precisa de nada especial. Seja qual for o nome no seu painel, preencha:

- **Imagem:** `ghcr.io/diegoparras/nbuddyn:latest`
- **Porta:** `8787`
- **Volume persistente:** em `/data`
- **Variáveis de ambiente:** a tabela de [Colocar para rodar](#2-colocar-para-rodar)
- **Rede:** a mesma do banco de dados do n8n

Se o painel pedir uma verificação de saúde: `GET /healthz` na porta 8787.

Esses painéis não foram testados um a um. Se o seu precisar de algo diferente,
[abra uma issue](https://github.com/diegoparras/nbuddyn/issues).

### A partir do código

Com o [Rust](https://rustup.rs) instalado:

```bash
git clone https://github.com/diegoparras/nbuddyn
```

```bash
cd nbuddyn && cargo build --release
```

```bash
NBUDDYN_DATABASE_URL=postgres://nbuddyn:escolha-uma-senha@localhost:5432/n8n \
NBUDDYN_PASSWORD=escolha-uma-senha-de-acesso \
NBUDDYN_DATA_DIR=./data \
./target/release/nbuddyn
```

Ou construa a imagem você mesmo: `docker build -t nbuddyn .`

## 3. Primeiro olhar

Entre com o usuário `nbuddyn` e a senha que você escolheu. A primeira varredura leva
alguns segundos. Depois abra o menu (no canto superior direito) e vá em **Configurações**:

1. **Endereço do n8n.** Onde você abre o n8n no navegador. Cada achado passa a ter um link para o workflow.
2. **Redis do n8n**, se o seu n8n roda em modo fila. Isso liga as verificações da fila e dos workers. Os workers e os processadores de webhooks são descobertos sozinhos.
3. **Task runners**, um por linha, se você os roda como contêineres separados.
4. **Alertas.** Um bot do Telegram ou um webhook, com um botão para enviar um teste.

Coloque o nbuddyn atrás de https antes de abri-lo para a internet: o relatório dele lista os seus pontos fracos.

## Atualizar

Baixe a imagem nova e inicie o contêiner de novo. O seu histórico e as suas
configurações estão no volume `/data` e são mantidos.

```bash
docker pull ghcr.io/diegoparras/nbuddyn:latest
```

```bash
docker compose up -d
```

No Easypanel, clique em **Deploy** outra vez. Para ficar em uma versão escolhida, use
uma tag como `ghcr.io/diegoparras/nbuddyn:0.18.0` em vez de `latest`.

Depois de atualizar o **n8n**, confira se o nbuddyn ainda consegue lê-lo:

```bash
docker run --rm --network REDE_DO_SEU_N8N \
  -e NBUDDYN_DATABASE_URL=postgres://nbuddyn:escolha-uma-senha@n8n_postgres:5432/n8n \
  ghcr.io/diegoparras/nbuddyn:latest check
```

## Se algo der errado

| O que você vê | O que fazer |
|---|---|
| O contêiner para logo em seguida | Leia o log dele. O nbuddyn diz qual variável falta ou está errada. |
| Não consegue conectar ao banco | O nbuddyn e o banco não estão na mesma rede, ou o nome do host está errado. |
| Permissão negada em uma tabela | Falta um `GRANT` da etapa 1. `nbuddyn check` imprime exatamente qual executar. |
| SQLite: "can only be read this way while n8n is running" | Inicie o n8n. O arquivo só pode ser lido enquanto o n8n roda. |
| Não dá para salvar as configurações | Não há um volume montado em `/data`. |
| A página Cluster está vazia | Falta o Redis do n8n em Configurações, ou o seu n8n não está em modo fila. |

Ainda travado? [Abra uma issue](https://github.com/diegoparras/nbuddyn/issues) com o
log. Tire as senhas antes.
