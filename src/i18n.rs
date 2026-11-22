//! English, Spanish and Portuguese. Every user-facing string lives here.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    En,
    Es,
    Pt,
}

impl Lang {
    /// Accepts codes such as `es`, `es-AR` or `pt_BR`. Unknown values fall back to English.
    pub fn parse(code: &str) -> Self {
        match code.trim().to_ascii_lowercase().get(..2) {
            Some("es") => Lang::Es,
            Some("pt") => Lang::Pt,
            _ => Lang::En,
        }
    }

    pub fn code(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::Es => "es",
            Lang::Pt => "pt",
        }
    }

    fn pick(self, en: &'static str, es: &'static str, pt: &'static str) -> &'static str {
        match self {
            Lang::En => en,
            Lang::Es => es,
            Lang::Pt => pt,
        }
    }
}

/// Every check the radar can report, in the order they are documented.
#[cfg(test)]
pub const CHECKS: &[&str] = &[
    "open_ai_entry",
    "repeated_failures",
    "stuck_execution",
    "hardcoded_secret",
    "public_entry_no_auth",
    "no_error_workflow",
    "plaintext_http",
    "no_mfa",
    "removed_node_v3",
    "env_access",
    "unused_credential",
    "command_execution",
    "redis_eviction",
    "redis_memory_high",
    "queue_backlog",
    "no_workers",
    "version_mismatch",
    "runner_down",
];

/// Heading for a group of `count` findings of one check, such as
/// "5 MCP servers or chats without authentication".
pub fn group_title(lang: Lang, check: &str, count: usize) -> String {
    // Instance-wide conditions read the same however many findings carry them.
    let same = |text: &'static str| (text, text);
    let (one, many) = match check {
        "open_ai_entry" => (
            lang.pick(
                "An MCP server or chat without authentication",
                "Un servidor MCP o chat sin autenticación",
                "Um servidor MCP ou chat sem autenticação",
            ),
            lang.pick(
                "{n} MCP servers or chats without authentication",
                "{n} servidores MCP o chats sin autenticación",
                "{n} servidores MCP ou chats sem autenticação",
            ),
        ),
        "public_entry_no_auth" => (
            lang.pick(
                "A webhook or form without authentication",
                "Un webhook o formulario sin autenticación",
                "Um webhook ou formulário sem autenticação",
            ),
            lang.pick(
                "{n} webhooks or forms without authentication",
                "{n} webhooks o formularios sin autenticación",
                "{n} webhooks ou formulários sem autenticação",
            ),
        ),
        "hardcoded_secret" => (
            lang.pick(
                "A secret written inside a node",
                "Una clave escrita dentro de un nodo",
                "Uma chave escrita dentro de um nó",
            ),
            lang.pick(
                "{n} secrets written inside nodes",
                "{n} claves escritas dentro de nodos",
                "{n} chaves escritas dentro de nós",
            ),
        ),
        "no_error_workflow" => (
            lang.pick(
                "An active workflow tells nobody when it fails",
                "Un workflow activo no avisa cuando falla",
                "Um workflow ativo não avisa quando falha",
            ),
            lang.pick(
                "{n} active workflows tell nobody when they fail",
                "{n} workflows activos no avisan cuando fallan",
                "{n} workflows ativos não avisam quando falham",
            ),
        ),
        "repeated_failures" => (
            lang.pick(
                "A workflow keeps failing",
                "Un workflow falla una y otra vez",
                "Um workflow falha repetidamente",
            ),
            lang.pick(
                "{n} workflows keep failing",
                "{n} workflows fallan una y otra vez",
                "{n} workflows falham repetidamente",
            ),
        ),
        "stuck_execution" => (
            lang.pick(
                "An execution stuck for over an hour",
                "Una ejecución trabada hace más de una hora",
                "Uma execução travada há mais de uma hora",
            ),
            lang.pick(
                "{n} executions stuck for over an hour",
                "{n} ejecuciones trabadas hace más de una hora",
                "{n} execuções travadas há mais de uma hora",
            ),
        ),
        "removed_node_v3" => (
            lang.pick(
                "A node removed in n8n 3",
                "Un nodo eliminado en n8n 3",
                "Um nó removido no n8n 3",
            ),
            lang.pick(
                "{n} nodes removed in n8n 3",
                "{n} nodos eliminados en n8n 3",
                "{n} nós removidos no n8n 3",
            ),
        ),
        "plaintext_http" => (
            lang.pick(
                "An unencrypted call to an external host",
                "Una llamada sin cifrar a un destino externo",
                "Uma chamada sem criptografia a um destino externo",
            ),
            lang.pick(
                "{n} unencrypted calls to external hosts",
                "{n} llamadas sin cifrar a destinos externos",
                "{n} chamadas sem criptografia a destinos externos",
            ),
        ),
        "no_mfa" => (
            lang.pick(
                "Users without two-factor authentication",
                "Usuarios sin doble factor",
                "Usuários sem autenticação de dois fatores",
            ),
            lang.pick(
                "Users without two-factor authentication",
                "Usuarios sin doble factor",
                "Usuários sem autenticação de dois fatores",
            ),
        ),
        "env_access" => (
            lang.pick(
                "A node reads server environment variables",
                "Un nodo lee variables de entorno del servidor",
                "Um nó lê variáveis de ambiente do servidor",
            ),
            lang.pick(
                "{n} nodes read server environment variables",
                "{n} nodos leen variables de entorno del servidor",
                "{n} nós leem variáveis de ambiente do servidor",
            ),
        ),
        "unused_credential" => (
            lang.pick(
                "A credential no workflow uses",
                "Una credencial que ningún workflow usa",
                "Uma credencial que nenhum workflow usa",
            ),
            lang.pick(
                "{n} credentials no workflow uses",
                "{n} credenciales que ningún workflow usa",
                "{n} credenciais que nenhum workflow usa",
            ),
        ),
        "command_execution" => (
            lang.pick(
                "A node runs system commands",
                "Un nodo ejecuta comandos del sistema",
                "Um nó executa comandos do sistema",
            ),
            lang.pick(
                "{n} nodes run system commands",
                "{n} nodos ejecutan comandos del sistema",
                "{n} nós executam comandos do sistema",
            ),
        ),
        "redis_eviction" => same(lang.pick(
            "Redis may drop jobs from the queue",
            "Redis puede descartar trabajos de la cola",
            "O Redis pode descartar trabalhos da fila",
        )),
        "redis_memory_high" => same(lang.pick(
            "Redis is almost out of memory",
            "Redis está casi sin memoria",
            "O Redis está quase sem memória",
        )),
        "queue_backlog" => same(lang.pick(
            "Executions are piling up in the queue",
            "Las ejecuciones se acumulan en la cola",
            "As execuções estão se acumulando na fila",
        )),
        "no_workers" => same(lang.pick(
            "No worker is running",
            "No hay ningún worker en marcha",
            "Nenhum worker está em execução",
        )),
        "version_mismatch" => same(lang.pick(
            "The cluster is running mixed n8n versions",
            "El cluster corre versiones distintas de n8n",
            "O cluster está rodando versões diferentes do n8n",
        )),
        "runner_down" => (
            lang.pick(
                "A task runner is not answering",
                "Un runner no responde",
                "Um runner não responde",
            ),
            lang.pick(
                "{n} task runners are not answering",
                "{n} runners no responden",
                "{n} runners não respondem",
            ),
        ),
        _ => ("", ""),
    };
    if count == 1 {
        one.to_owned()
    } else {
        many.replace("{n}", &count.to_string())
    }
}

/// What to do about a check.
pub fn advice(lang: Lang, check: &str) -> &'static str {
    match check {
        "open_ai_entry" => lang.pick(
            "Anyone who learns the address can use those tools with your accounts. Add authentication on each trigger node.",
            "Quien conozca la dirección puede usar esas herramientas con tus cuentas. Agregá autenticación en cada nodo disparador.",
            "Quem conhecer o endereço pode usar essas ferramentas com as suas contas. Adicione autenticação em cada nó de gatilho.",
        ),
        "public_entry_no_auth" => lang.pick(
            "Anyone who learns the address can call them. Add authentication on the trigger node, or validate the caller inside the workflow.",
            "Cualquiera que conozca la dirección puede llamarlos. Agregá autenticación en el nodo disparador, o validá a quien llama dentro del workflow.",
            "Qualquer pessoa que conheça o endereço pode chamá-los. Adicione autenticação no nó de gatilho, ou valide quem chama dentro do workflow.",
        ),
        "hardcoded_secret" => lang.pick(
            "Move them to n8n credentials so they are stored encrypted and do not travel with the workflow.",
            "Pasalas a credenciales de n8n para que se guarden cifradas y no viajen con el workflow.",
            "Mova-as para credenciais do n8n para que fiquem criptografadas e não viajem com o workflow.",
        ),
        "no_error_workflow" => lang.pick(
            "One error workflow that sends you a message is enough; assign it to all of them.",
            "Alcanza con un solo workflow de error que te mande un mensaje; asignalo a todos.",
            "Basta um único workflow de erro que envie uma mensagem; atribua-o a todos.",
        ),
        "repeated_failures" => lang.pick(
            "Open the latest failed execution to see which node breaks. An expired credential is a common cause.",
            "Abrí la última ejecución fallida para ver qué nodo se rompe. Una credencial vencida es una causa frecuente.",
            "Abra a última execução com falha para ver qual nó quebra. Uma credencial expirada é uma causa comum.",
        ),
        "stuck_execution" => lang.pick(
            "Check that workers and task runners are alive, then stop the execution if it will not finish.",
            "Revisá que los workers y los runners estén vivos, y detené la ejecución si no va a terminar.",
            "Verifique se os workers e os runners estão ativos, e pare a execução se ela não for terminar.",
        ),
        "removed_node_v3" => lang.pick(
            "The workflow fails when it runs. Replace each node with its current equivalent.",
            "El workflow falla al ejecutarse. Reemplazá cada nodo por su equivalente actual.",
            "O workflow falha ao executar. Substitua cada nó pelo equivalente atual.",
        ),
        "plaintext_http" => lang.pick(
            "Data travels readable over the network. Use https:// where the destination supports it.",
            "Los datos viajan legibles por la red. Usá https:// donde el destino lo admita.",
            "Os dados trafegam legíveis pela rede. Use https:// onde o destino suportar.",
        ),
        "no_mfa" => lang.pick(
            "Enable it under Settings > Personal, especially for owner accounts.",
            "Activalo en Settings > Personal, sobre todo en las cuentas dueñas.",
            "Ative em Settings > Personal, principalmente nas contas proprietárias.",
        ),
        "env_access" => lang.pick(
            "They stop working when environment access is blocked, and can expose server secrets when it is not.",
            "Dejan de funcionar si el acceso al entorno está bloqueado, y pueden exponer claves del servidor si no lo está.",
            "Deixam de funcionar se o acesso ao ambiente estiver bloqueado, e podem expor chaves do servidor se não estiver.",
        ),
        "unused_credential" => lang.pick(
            "Delete the ones nothing else needs. Credentials used by n8n itself, such as the assistant's, also appear here.",
            "Borrá las que nada más necesite. Las que usa el propio n8n, como las del asistente, también aparecen acá.",
            "Exclua as que nada mais precisa. As usadas pelo próprio n8n, como as do assistente, também aparecem aqui.",
        ),
        "command_execution" => lang.pick(
            "Expected for some workflows. Make sure only trusted people can edit them.",
            "Es esperable en algunos workflows. Asegurate de que solo gente de confianza pueda editarlos.",
            "É esperado em alguns workflows. Garanta que só pessoas de confiança possam editá-los.",
        ),
        "redis_eviction" => lang.pick(
            "Its memory policy lets it delete keys when it fills up, and queued executions are keys. Set maxmemory-policy to noeviction.",
            "Su política de memoria le permite borrar claves cuando se llena, y las ejecuciones en cola son claves. Poné maxmemory-policy en noeviction.",
            "A política de memória permite apagar chaves quando enche, e as execuções na fila são chaves. Defina maxmemory-policy como noeviction.",
        ),
        "redis_memory_high" => lang.pick(
            "Raise its memory limit or find what is filling it before it starts refusing or dropping data.",
            "Subile el límite de memoria o buscá qué lo está llenando, antes de que empiece a rechazar o descartar datos.",
            "Aumente o limite de memória ou descubra o que o está enchendo, antes que comece a recusar ou descartar dados.",
        ),
        "queue_backlog" => lang.pick(
            "Workers are not keeping up. Check that they are alive and consider more workers or higher concurrency.",
            "Los workers no dan abasto. Revisá que estén vivos y considerá más workers o más concurrencia.",
            "Os workers não estão dando conta. Verifique se estão ativos e considere mais workers ou mais concorrência.",
        ),
        "no_workers" => lang.pick(
            "Queued executions will wait until a worker starts. Check the worker services.",
            "Las ejecuciones en cola van a esperar hasta que arranque un worker. Revisá los servicios de workers.",
            "As execuções na fila vão esperar até um worker iniciar. Verifique os serviços de workers.",
        ),
        "version_mismatch" => lang.pick(
            "Main, workers and webhook processors must run the same version. Finish the update on the ones left behind.",
            "Main, workers y webhooks tienen que correr la misma versión. Terminá la actualización en los que quedaron atrás.",
            "Main, workers e webhooks precisam rodar a mesma versão. Conclua a atualização nos que ficaram para trás.",
        ),
        "runner_down" => lang.pick(
            "Code nodes on its worker will fail or wait until it is back. Check that runner's service and its logs.",
            "Los nodos Code de su worker van a fallar o quedar esperando hasta que vuelva. Revisá el servicio de ese runner y sus logs.",
            "Os nós Code do worker dele vão falhar ou ficar esperando até ele voltar. Verifique o serviço desse runner e os logs.",
        ),
        _ => "",
    }
}

/// The one sentence that sums up the instance, in the voice of the cockpit.
pub fn headline(lang: Lang, urgent: usize, other: usize) -> String {
    let template = match (urgent, other) {
        (0, 0) => lang.pick(
            "Your n8n is flying clean. Nothing to report.",
            "Tu n8n vuela limpio. Nada para reportar.",
            "O seu n8n voa limpo. Nada a relatar.",
        ),
        (0, 1) => lang.pick(
            "Your n8n is flying steady, with one point to review.",
            "Tu n8n vuela estable, con un punto para revisar.",
            "O seu n8n voa estável, com um ponto para revisar.",
        ),
        (0, _) => lang.pick(
            "Your n8n is flying steady, with {m} points to review.",
            "Tu n8n vuela estable, con {m} puntos para revisar.",
            "O seu n8n voa estável, com {m} pontos para revisar.",
        ),
        (1, _) => lang.pick(
            "Your n8n is flying, but with one red light on.",
            "Tu n8n vuela, pero con una luz roja encendida.",
            "O seu n8n voa, mas com uma luz vermelha acesa.",
        ),
        _ => lang.pick(
            "Your n8n is flying, but with {n} red lights on.",
            "Tu n8n vuela, pero con {n} luces rojas encendidas.",
            "O seu n8n voa, mas com {n} luzes vermelhas acesas.",
        ),
    };
    template
        .replace("{n}", &urgent.to_string())
        .replace("{m}", &other.to_string())
}

/// A second line naming the most urgent groups, built from their titles.
pub fn lead(lang: Lang, urgent_titles: &[String]) -> String {
    let lower_first = |s: &str| {
        let mut chars = s.chars();
        match chars.next() {
            Some(first) => first.to_lowercase().collect::<String>() + chars.as_str(),
            None => String::new(),
        }
    };
    match urgent_titles {
        [] => String::new(),
        [only] => format!(
            "{} {}.",
            lang.pick("Most urgent:", "Lo más urgente:", "Mais urgente:"),
            lower_first(only)
        ),
        [first, second, ..] => format!(
            "{} {} {} {}.",
            lang.pick("Most urgent:", "Lo más urgente:", "Mais urgente:"),
            lower_first(first),
            lang.pick("and", "y", "e"),
            lower_first(second)
        ),
    }
}

/// Labels for the web page, sent with every report so the page holds no text of its own.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct UiText {
    pub tagline: &'static str,
    pub sweep: &'static str,
    pub export: &'static str,
    pub zone_risk: &'static str,
    pub zone_caution: &'static str,
    pub zone_ok: &'static str,
    pub gauge: &'static str,
    pub light_doors: &'static str,
    pub light_failures: &'static str,
    pub light_silent: &'static str,
    pub light_secrets: &'static str,
    pub light_queue: &'static str,
    pub light_runners: &'static str,
    pub runners: &'static str,
    pub queue_waiting: &'static str,
    pub queue_active: &'static str,
    pub workers: &'static str,
    pub webhooks: &'static str,
    pub redis_memory: &'static str,
    pub no_limit: &'static str,
    pub cluster_unavailable: &'static str,
    pub ok: &'static str,
    pub urgent: &'static str,
    pub important: &'static str,
    pub minor: &'static str,
    pub info: &'static str,
    pub total_urgent: &'static str,
    pub total_important: &'static str,
    pub total_minor: &'static str,
    pub workflows_reviewed: &'static str,
    pub nodes_reviewed: &'static str,
    pub more: &'static str,
    pub show: &'static str,
    pub inactive: &'static str,
    pub read_only: &'static str,
    pub unavailable: &'static str,
    pub language: &'static str,
    pub history: &'static str,
    pub days: &'static str,
    pub runs_title: &'static str,
    pub score_title: &'static str,
    pub runs_total: &'static str,
    pub runs_ok: &'static str,
    pub runs_failed: &'static str,
    pub runs_canceled: &'static str,
    pub failure_rate: &'static str,
    pub col_workflow: &'static str,
    pub col_runs: &'static str,
    pub col_failed: &'static str,
    pub col_rate: &'static str,
    pub col_last: &'static str,
    pub col_day: &'static str,
    pub col_score: &'static str,
    pub table_by_day: &'static str,
    pub history_since: &'static str,
    pub history_note: &'static str,
    pub history_empty: &'static str,
    pub history_unavailable: &'static str,
    pub settings: &'static str,
    pub set_n8n_url: &'static str,
    pub help_n8n_url: &'static str,
    pub set_lang: &'static str,
    pub set_interval_seconds: &'static str,
    pub help_interval_seconds: &'static str,
    pub set_timezone: &'static str,
    pub help_timezone: &'static str,
    pub set_history_days: &'static str,
    pub help_history_days: &'static str,
    pub set_runner_urls: &'static str,
    pub help_runner_urls: &'static str,
    pub set_redis_url: &'static str,
    pub help_redis_url: &'static str,
    pub env_only: &'static str,
    pub env_database: &'static str,
    pub env_mcp: &'static str,
    pub on: &'static str,
    pub off: &'static str,
    pub save: &'static str,
    pub cancel: &'static str,
    pub invalid: &'static str,
    pub save_failed: &'static str,
    pub settings_readonly: &'static str,
    pub accept: &'static str,
    pub accept_note: &'static str,
    pub confirm: &'static str,
    pub accepted: &'static str,
    pub accepted_help: &'static str,
    pub restore: &'static str,
    pub open_in_n8n: &'static str,
}

pub fn ui_text(lang: Lang) -> UiText {
    UiText {
        tagline: lang.pick(
            "Flight report for n8n",
            "Informe de vuelo de n8n",
            "Relatório de voo do n8n",
        ),
        sweep: lang.pick("Last sweep", "Último barrido", "Última varredura"),
        export: lang.pick("Export PDF", "Exportar PDF", "Exportar PDF"),
        zone_risk: lang.pick("Risk zone", "Zona de riesgo", "Zona de risco"),
        zone_caution: lang.pick("Caution", "Precaución", "Atenção"),
        zone_ok: lang.pick("On course", "En ruta", "Em rota"),
        gauge: lang.pick(
            "Score gauge",
            "Indicador de puntaje",
            "Indicador de pontuação",
        ),
        light_doors: lang.pick("Doors", "Puertas", "Portas"),
        light_failures: lang.pick("Failures", "Fallos", "Falhas"),
        light_silent: lang.pick("No alert", "Sin aviso", "Sem aviso"),
        light_secrets: lang.pick("Secrets", "Claves", "Chaves"),
        light_queue: lang.pick("Queue", "Cola", "Fila"),
        light_runners: "Runners",
        runners: lang.pick("runners alive", "runners vivos", "runners ativos"),
        queue_waiting: lang.pick(
            "waiting in queue",
            "en espera en la cola",
            "em espera na fila",
        ),
        queue_active: lang.pick("running now", "ejecutándose ahora", "em execução agora"),
        workers: lang.pick("workers alive", "workers vivos", "workers ativos"),
        webhooks: lang.pick(
            "webhook processors alive",
            "webhooks vivos",
            "webhooks ativos",
        ),
        redis_memory: lang.pick("Redis memory", "memoria de Redis", "memória do Redis"),
        no_limit: lang.pick("no limit", "sin límite", "sem limite"),
        cluster_unavailable: lang.pick(
            "Could not read Redis, so the queue and the cluster are not shown",
            "No se pudo leer Redis, así que no se muestran la cola ni el cluster",
            "Não foi possível ler o Redis, então a fila e o cluster não são mostrados",
        ),
        ok: "OK",
        urgent: lang.pick("Urgent", "Urgente", "Urgente"),
        important: lang.pick("Important", "Importante", "Importante"),
        minor: lang.pick("Minor", "Menor", "Menor"),
        info: lang.pick("Good to know", "Para saber", "Para saber"),
        total_urgent: lang.pick("urgent", "urgentes", "urgentes"),
        total_important: lang.pick("important", "importantes", "importantes"),
        total_minor: lang.pick("minor", "menores", "menores"),
        workflows_reviewed: lang.pick(
            "workflows reviewed",
            "workflows revisados",
            "workflows revisados",
        ),
        nodes_reviewed: lang.pick("nodes reviewed", "nodos revisados", "nós revisados"),
        more: lang.pick("more", "más", "mais"),
        show: lang.pick("Show", "Ver", "Ver"),
        inactive: lang.pick("inactive", "inactivo", "inativo"),
        read_only: lang.pick(
            "nbuddyn only reads. It never changes your n8n.",
            "nbuddyn solo lee. Nunca modifica tu n8n.",
            "nbuddyn apenas lê. Nunca altera o seu n8n.",
        ),
        unavailable: lang.pick(
            "Could not read the n8n database yet",
            "Todavía no se pudo leer la base de n8n",
            "Ainda não foi possível ler o banco do n8n",
        ),
        language: lang.pick("Language", "Idioma", "Idioma"),
        history: lang.pick("History", "Historial", "Histórico"),
        days: lang.pick("days", "días", "dias"),
        runs_title: lang.pick(
            "Executions per day",
            "Ejecuciones por día",
            "Execuções por dia",
        ),
        score_title: lang.pick("Score per day", "Puntaje por día", "Pontuação por dia"),
        runs_total: lang.pick("executions", "ejecuciones", "execuções"),
        runs_ok: lang.pick("succeeded", "terminaron bien", "terminaram bem"),
        runs_failed: lang.pick("failed", "fallaron", "falharam"),
        runs_canceled: lang.pick("canceled", "canceladas", "canceladas"),
        failure_rate: lang.pick("failure rate", "de fallos", "de falhas"),
        col_workflow: lang.pick("Workflow", "Workflow", "Workflow"),
        col_runs: lang.pick("Executions", "Ejecuciones", "Execuções"),
        col_failed: lang.pick("Failed", "Fallaron", "Falharam"),
        col_rate: lang.pick("Failure rate", "% de fallos", "% de falhas"),
        col_last: lang.pick("Last run", "Última vez", "Última vez"),
        col_day: lang.pick("Day", "Día", "Dia"),
        col_score: lang.pick("Score", "Puntaje", "Pontuação"),
        table_by_day: lang.pick("Table by day", "Tabla por día", "Tabela por dia"),
        history_since: lang.pick(
            "nbuddyn remembers since",
            "nbuddyn recuerda desde",
            "nbuddyn lembra desde",
        ),
        history_note: lang.pick(
            "n8n deletes old executions. These totals stay.",
            "n8n borra las ejecuciones viejas. Estos totales quedan.",
            "O n8n apaga as execuções antigas. Estes totais ficam.",
        ),
        history_empty: lang.pick(
            "No executions in these days",
            "Sin ejecuciones en estos días",
            "Sem execuções nestes dias",
        ),
        history_unavailable: lang.pick(
            "The history could not be updated",
            "No se pudo actualizar el historial",
            "Não foi possível atualizar o histórico",
        ),
        settings: lang.pick(
            "Settings",
            "Ajustes",
            "Configurações",
        ),
        set_n8n_url: lang.pick(
            "n8n address",
            "Dirección de n8n",
            "Endereço do n8n",
        ),
        help_n8n_url: lang.pick(
            "Where you open n8n in the browser, such as https://n8n.example.com. Each finding then links to its workflow.",
            "Donde abrís n8n en el navegador, por ejemplo https://n8n.ejemplo.com. Cada hallazgo pasa a tener un enlace a su workflow.",
            "Onde você abre o n8n no navegador, como https://n8n.exemplo.com. Cada achado passa a ter um link para o workflow.",
        ),
        set_lang: lang.pick(
            "Default language",
            "Idioma por defecto",
            "Idioma padrão",
        ),
        set_interval_seconds: lang.pick(
            "Seconds between scans",
            "Segundos entre barridos",
            "Segundos entre varreduras",
        ),
        help_interval_seconds: lang.pick(
            "From 10 to 86400.",
            "De 10 a 86400.",
            "De 10 a 86400.",
        ),
        set_timezone: lang.pick(
            "Time zone",
            "Zona horaria",
            "Fuso horário",
        ),
        help_timezone: lang.pick(
            "Decides where a day ends, such as America/Argentina/Buenos_Aires. Empty uses the database's.",
            "Decide dónde termina un día, por ejemplo America/Argentina/Buenos_Aires. Vacío usa la de la base.",
            "Decide onde um dia termina, como America/Sao_Paulo. Vazio usa o do banco.",
        ),
        set_history_days: lang.pick(
            "Days of history to keep",
            "Días de historial a guardar",
            "Dias de histórico a guardar",
        ),
        help_history_days: lang.pick(
            "From 1 to 3650.",
            "De 1 a 3650.",
            "De 1 a 3650.",
        ),
        set_runner_urls: lang.pick(
            "Task runners",
            "Runners",
            "Runners",
        ),
        help_runner_urls: lang.pick(
            "One per line, as host or host:port. Empty turns this check off.",
            "Uno por línea, como host o host:puerto. Vacío apaga este chequeo.",
            "Um por linha, como host ou host:porta. Vazio desliga esta verificação.",
        ),
        set_redis_url: lang.pick(
            "n8n's Redis",
            "Redis de n8n",
            "Redis do n8n",
        ),
        help_redis_url: lang.pick(
            "As redis://:password@host:6379. The password is never shown here. Empty turns the queue checks off.",
            "Como redis://:clave@host:6379. La clave nunca se muestra acá. Vacío apaga los chequeos de la cola.",
            "Como redis://:senha@host:6379. A senha nunca é mostrada aqui. Vazio desliga as verificações da fila.",
        ),
        env_only: lang.pick(
            "Set in the environment",
            "Se configuran en el entorno",
            "Definidos no ambiente",
        ),
        env_database: lang.pick(
            "n8n database",
            "Base de n8n",
            "Banco do n8n",
        ),
        env_mcp: lang.pick(
            "MCP access",
            "Acceso MCP",
            "Acesso MCP",
        ),
        on: lang.pick(
            "on",
            "encendido",
            "ligado",
        ),
        off: lang.pick(
            "off",
            "apagado",
            "desligado",
        ),
        save: lang.pick(
            "Save",
            "Guardar",
            "Salvar",
        ),
        cancel: lang.pick(
            "Cancel",
            "Cancelar",
            "Cancelar",
        ),
        invalid: lang.pick(
            "Not valid",
            "No es válido",
            "Não é válido",
        ),
        save_failed: lang.pick(
            "Could not save",
            "No se pudo guardar",
            "Não foi possível salvar",
        ),
        settings_readonly: lang.pick(
            "Nothing can be saved: nbuddyn has no data directory it can use.",
            "No se puede guardar nada: nbuddyn no tiene un directorio de datos que pueda usar.",
            "Nada pode ser salvo: o nbuddyn não tem um diretório de dados que possa usar.",
        ),
        accept: lang.pick(
            "Accept",
            "Aceptar",
            "Aceitar",
        ),
        accept_note: lang.pick(
            "Why is this fine? (optional)",
            "¿Por qué está bien así? (opcional)",
            "Por que está bem assim? (opcional)",
        ),
        confirm: lang.pick(
            "Confirm",
            "Confirmar",
            "Confirmar",
        ),
        accepted: lang.pick(
            "Accepted",
            "Aceptados",
            "Aceitos",
        ),
        accepted_help: lang.pick(
            "Someone decided these are fine as they are. They do not count in the score.",
            "Alguien decidió que están bien así. No cuentan en el puntaje.",
            "Alguém decidiu que estão bem assim. Não contam na pontuação.",
        ),
        restore: lang.pick(
            "Show again",
            "Volver a mostrar",
            "Mostrar de novo",
        ),
        open_in_n8n: lang.pick(
            "Open in n8n",
            "Abrir en n8n",
            "Abrir no n8n",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LANGS: [Lang; 3] = [Lang::En, Lang::Es, Lang::Pt];

    #[test]
    fn language_codes_are_parsed_leniently() {
        assert_eq!(Lang::parse("es-AR"), Lang::Es);
        assert_eq!(Lang::parse("PT_br"), Lang::Pt);
        assert_eq!(Lang::parse("fr"), Lang::En);
        assert_eq!(Lang::parse(""), Lang::En);
    }

    #[test]
    fn every_check_has_a_title_and_advice_in_every_language() {
        for check in CHECKS {
            let singles: Vec<String> = LANGS.iter().map(|l| group_title(*l, check, 1)).collect();
            let advices: Vec<&str> = LANGS.iter().map(|l| advice(*l, check)).collect();
            for (single, advice) in singles.iter().zip(&advices) {
                assert!(!single.is_empty(), "{check} has no title");
                assert!(!advice.is_empty(), "{check} has no advice");
            }
            assert_ne!(
                singles[0], singles[1],
                "{check} title not translated to Spanish"
            );
            assert_ne!(
                advices[0], advices[2],
                "{check} advice not translated to Portuguese"
            );
        }
    }

    #[test]
    fn group_titles_count_their_findings() {
        assert_eq!(
            group_title(Lang::Es, "open_ai_entry", 5),
            "5 servidores MCP o chats sin autenticación"
        );
        assert_eq!(
            group_title(Lang::En, "open_ai_entry", 1),
            "An MCP server or chat without authentication"
        );
        for lang in LANGS {
            for check in CHECKS {
                assert!(
                    !group_title(lang, check, 7).contains("{n}"),
                    "{check} left a placeholder"
                );
            }
        }
    }

    #[test]
    fn headline_follows_the_state_of_the_instance() {
        assert_eq!(
            headline(Lang::Es, 6, 40),
            "Tu n8n vuela, pero con 6 luces rojas encendidas."
        );
        assert_eq!(
            headline(Lang::Es, 1, 0),
            "Tu n8n vuela, pero con una luz roja encendida."
        );
        assert_eq!(
            headline(Lang::En, 0, 3),
            "Your n8n is flying steady, with 3 points to review."
        );
        assert_eq!(
            headline(Lang::Pt, 0, 0),
            "O seu n8n voa limpo. Nada a relatar."
        );
    }

    #[test]
    fn lead_names_up_to_two_urgent_groups() {
        let titles = vec![
            "5 servidores MCP o chats sin autenticación".to_owned(),
            "Un workflow falla una y otra vez".to_owned(),
            "Otra cosa".to_owned(),
        ];
        assert_eq!(
            lead(Lang::Es, &titles),
            "Lo más urgente: 5 servidores MCP o chats sin autenticación y un workflow falla una y otra vez."
        );
        assert_eq!(
            lead(Lang::En, &titles[..1]),
            "Most urgent: 5 servidores MCP o chats sin autenticación."
        );
        assert_eq!(lead(Lang::Pt, &[]), "");
    }
}
