<div align="center">

<img src="docs/img/logo.svg" width="88" alt="nbuddyn">

# nbuddyn

**A cabine que falta no seu n8n auto-hospedado.**<br>
Portas abertas, falhas silenciosas e o que está prestes a quebrar, em uma única página. Somente leitura, mínimo e seu.

[English](README.md) · [Español](README.es.md) · **Português**

[![CI](https://github.com/diegoparras/nbuddyn/actions/workflows/ci.yml/badge.svg)](https://github.com/diegoparras/nbuddyn/actions/workflows/ci.yml)
[![Versão](https://img.shields.io/github/v/release/diegoparras/nbuddyn?color=F5B83D&label=vers%C3%A3o)](https://github.com/diegoparras/nbuddyn/releases)
[![Licença: MIT](https://img.shields.io/badge/licen%C3%A7a-MIT-F5B83D.svg)](LICENSE)
![Plataformas](https://img.shields.io/badge/imagem-amd64%20%7C%20arm64-555)
![Feito em Rust](https://img.shields.io/badge/feito%20em-Rust-555)

<a href="docs/img/tour.mp4"><img src="docs/img/tour.gif" width="820" alt="Um passeio de um minuto pelo nbuddyn"></a>

<sub>Um passeio de um minuto, gravado na demo incluída. Todos os dados exibidos são inventados.</sub>

</div>

> [!IMPORTANT]
> O nbuddyn é um projeto independente, da comunidade. **Não tem afiliação com a n8n GmbH, nem o seu aval ou patrocínio.**
> Não contém código do n8n e não desbloqueia, substitui nem contorna nenhum recurso licenciado do n8n. Veja [Sem afiliação com o n8n](#sem-afiliação-com-o-n8n).

## Por quê

O n8n é muito bom em executar workflows. É mais calado na hora de governá-los: quais
webhooks qualquer pessoa pode chamar, quais workflows falham sem ninguém saber, onde uma
chave ficou colada dentro de um nó, se os workers estão vivos.

O nbuddyn fica ao lado do seu n8n, lê o banco de dados e o Redis dele, e responde essas
perguntas com uma pontuação e uma lista do que fazer primeiro.

- **Somente leitura.** Coloca a sessão do banco em modo leitura antes da primeira consulta. Não pode alterar o seu n8n.
- **Mínimo.** Um único binário estático escrito em Rust. A imagem tem poucos MB e uma instância típica usa menos de 30 MB de memória.
- **Privado.** Sem telemetria, sem conta, sem nuvem. Nada sai do seu servidor, a não ser os alertas que você configurar.
- **Três idiomas.** Inglês, espanhol e português, trocáveis na própria página.

## Experimente em 30 segundos

Não precisa ter n8n. Isto inicia o nbuddyn contra um n8n inventado, com os problemas que os reais têm:

```bash
docker run --rm -p 8787:8787 ghcr.io/diegoparras/nbuddyn:latest demo
```

Abra <http://localhost:8787> e entre com `demo` / `demo`.

## O que você recebe

| | |
|---|---|
| [![Resumo](docs/img/overview-pt.png)](docs/img/overview-pt.png) **Resumo.** Uma pontuação, seis luzes e o que fazer primeiro. | [![Achados](docs/img/findings.png)](docs/img/findings.png) **Achados.** Cada um diz o que fazer, o quanto o nbuddyn tem certeza, e leva ao workflow. |
| [![Cluster](docs/img/cluster.png)](docs/img/cluster.png) **Cluster.** A fila, os workers, os processadores de webhooks, os task runners e o Redis. | [![Atividade](docs/img/activity.png)](docs/img/activity.png) **Atividade.** O que mudou entre uma varredura e a seguinte, e quem salvou. |
| [![Histórico](docs/img/history.png)](docs/img/history.png) **Histórico.** Execuções e pontuação por dia, mesmo depois que o n8n as apaga. | [![Credenciais](docs/img/credentials.png)](docs/img/credentials.png) **Credenciais.** Quais workflows quebrariam se você trocasse uma. Nunca o segredo. |

<sub>Capturas feitas na demo incluída. Todos os dados exibidos são inventados. A página fica igual em português; aqui a maioria está em inglês.</sub>

**O que ele verifica**

- **Portas abertas:** servidores MCP, chats, webhooks e formulários sem autenticação.
- **Falhas silenciosas:** workflows que falham repetidamente, execuções travadas há horas, workflows ativos sem workflow de erro, workflows que pararam de rodar.
- **Segredos:** chaves escritas dentro de nós (informa o tipo, nunca o valor), chamadas sem criptografia, usuários sem autenticação em dois fatores.
- **Fila e cluster:** sem workers, versões do n8n misturadas, fila acumulando, Redis prestes a descartar trabalhos, task runners que não respondem.
- **Organização:** nós removidos no n8n 3, credenciais sem uso, nós que executam comandos do sistema.

**O que mais ele faz**

- **Alertas** pelo Telegram ou para qualquer webhook (o Slack funciona direto) quando algo muda, nunca o relatório inteiro de novo.
- **Vários n8n** em um só nbuddyn: produção e homologação, ou um por cliente.
- **Suas regras:** defina a gravidade de cada verificação aqui, aceite um achado com um motivo, faça as aceitações expirarem.
- **Usuários, papéis e login único** (OpenID Connect), com registro de auditoria.
- **Um endpoint MCP**, para um assistente de IA perguntar sobre o seu n8n em linguagem natural. Também somente leitura.

A lista completa está na [referência](docs/reference.md) (em inglês).

## Instalação

Você precisa de duas coisas: onde está o banco de dados do n8n e uma senha para o login próprio do nbuddyn.

**Seu n8n usa Postgres.** Crie uma vez um usuário somente leitura (o SQL está no
[guia](docs/install.pt.md#1-criar-um-usuário-somente-leitura-só-postgres)) e depois:

```bash
docker run -d --name nbuddyn -p 8787:8787 \
  -e NBUDDYN_DATABASE_URL=postgres://nbuddyn:escolha-uma-senha@n8n_postgres:5432/n8n \
  -e NBUDDYN_PASSWORD=escolha-uma-senha-de-acesso \
  -v nbuddyn_data:/data \
  ghcr.io/diegoparras/nbuddyn:latest
```

**Seu n8n usa SQLite** (o padrão quando o n8n não recebe um banco):

```bash
docker run -d --name nbuddyn -p 8787:8787 \
  -v n8n_data:/n8n:ro \
  -v nbuddyn_data:/data \
  -e NBUDDYN_DATABASE_URL=sqlite:/n8n/database.sqlite \
  -e NBUDDYN_PASSWORD=escolha-uma-senha-de-acesso \
  ghcr.io/diegoparras/nbuddyn:latest
```

Abra <http://localhost:8787> e entre com o usuário `nbuddyn`. Todo o resto é configurado na página, em **Configurações**.

Guias passo a passo:

| | |
|---|---|
| [Docker](docs/install.pt.md#docker) | Um comando, como acima. |
| [Docker Compose](docs/install.pt.md#docker-compose) | Arquivos prontos em [`deploy/`](deploy). |
| [Easypanel](docs/install.pt.md#easypanel) | Clique a clique. |
| [Portainer, Coolify, Dokploy e outros](docs/install.pt.md#outros-painéis) | Qualquer coisa que rode uma imagem Docker. |
| [A partir do código](docs/install.pt.md#a-partir-do-código) | `cargo build --release`. |

## É seguro colocar ao lado da produção?

- **Só lê.** Com Postgres, dê a ele um usuário que leia apenas as colunas necessárias: ele não consegue ler credenciais guardadas, hashes de senhas nem dados de execuções.
- Roda como usuário sem privilégios, em uma imagem que contém um binário e nada mais: sem shell, sem gerenciador de pacotes.
- Os segredos que ele guarda (senhas do banco e do Redis, o token do Telegram) ficam criptografados em disco.
- As imagens são assinadas e trazem a lista de componentes. Como verificar está em [SECURITY.md](SECURITY.md).
- O [modelo de ameaças](docs/THREAT-MODEL.md) detalha o que protege cada entrada e o que fica aberto de propósito.

Ainda não foi feita uma auditoria de segurança independente.

## O que ele não faz

O nbuddyn observa; não corrige nem bloqueia. Nunca escreve no n8n, então não pode
desativar por você um workflow arriscado. Não olha dentro das execuções nem das
credenciais, e não revisa o que um workflow faz com os dados. A pontuação resume o que
ele consegue ver. É um radar, não uma auditoria.

## Compatibilidade

O nbuddyn é feito para o **n8n 3 em diante**. Cada mudança é testada contra um n8n 3.3
real, com SQLite e com Postgres. Ele também é executado contra o n8n 1.123 e 2.48, mas
não é para isso que foi feito, e algumas verificações (workers, processadores de
webhooks) precisam do n8n 3. O nbuddyn lê o banco de dados do próprio n8n, que o n8n pode mudar entre
versões; depois de atualizar o n8n, `nbuddyn check` diz se tudo ainda pode ser lido.

## Documentação

- [Guia de instalação](docs/install.pt.md)
- [Referência](docs/reference.md) (em inglês): cada verificação, cada ajuste, alertas, login único, MCP
- [Política de segurança](SECURITY.md) e [modelo de ameaças](docs/THREAT-MODEL.md) (em inglês)
- [Histórico de mudanças](CHANGELOG.md) (em inglês)
- [Como contribuir](CONTRIBUTING.md)

## Sem afiliação com o n8n

O nbuddyn é um projeto independente de código aberto. Não tem afiliação com a n8n GmbH,
nem o seu aval, patrocínio ou suporte. "n8n" é uma marca da n8n GmbH e é usada aqui
apenas para dizer com o que o nbuddyn funciona.

O nbuddyn não contém código do n8n. Não modifica o n8n e não desbloqueia, substitui nem
contorna nenhum recurso dos planos pagos do n8n. Ele lê o banco de dados e o Redis de um
n8n que você mesmo hospeda, com o acesso que você concede. Para ajuda com o n8n, procure
os [canais do próprio n8n](https://n8n.io).

## Licença

[MIT](LICENSE). Livre para usar, modificar e compartilhar, em casa ou no trabalho. As
bibliotecas com as quais o nbuddyn é feito mantêm as suas próprias licenças de código aberto.
