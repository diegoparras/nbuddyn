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
    "no_main",
    "version_mismatch",
    "runner_down",
    "stale_workflow",
    "n8n_outdated",
];

/// Heading of the new findings in an alert.
pub fn alert_new(lang: Lang, count: usize) -> String {
    match (lang, count) {
        (Lang::En, 1) => "1 new finding:".into(),
        (Lang::En, n) => format!("{n} new findings:"),
        (Lang::Es, 1) => "1 hallazgo nuevo:".into(),
        (Lang::Es, n) => format!("{n} hallazgos nuevos:"),
        (Lang::Pt, 1) => "1 achado novo:".into(),
        (Lang::Pt, n) => format!("{n} achados novos:"),
    }
}

pub fn alert_resolved(lang: Lang, count: usize) -> String {
    match (lang, count) {
        (Lang::En, n) => format!("Resolved ({n}):"),
        (Lang::Es, 1) => "Resuelto (1):".into(),
        (Lang::Es, n) => format!("Resueltos ({n}):"),
        (Lang::Pt, 1) => "Resolvido (1):".into(),
        (Lang::Pt, n) => format!("Resolvidos ({n}):"),
    }
}

pub fn alert_changes(lang: Lang, count: usize) -> String {
    format!(
        "{} ({count}):",
        lang.pick(
            "Workflow changes",
            "Cambios en workflows",
            "Mudanças em workflows"
        )
    )
}

pub fn alert_more(lang: Lang, count: usize) -> String {
    match lang {
        Lang::En => format!("and {count} more"),
        Lang::Es => format!("y {count} más"),
        Lang::Pt => format!("e mais {count}"),
    }
}

pub fn alert_score(lang: Lang) -> &'static str {
    lang.pick("Score", "Puntaje", "Pontuação")
}

pub fn alert_unreachable(lang: Lang) -> &'static str {
    lang.pick(
        "nbuddyn cannot read this n8n. It keeps trying.",
        "nbuddyn no puede leer este n8n. Sigue intentando.",
        "O nbuddyn não consegue ler este n8n. Continua tentando.",
    )
}

pub fn alert_back(lang: Lang) -> &'static str {
    lang.pick(
        "nbuddyn can read this n8n again.",
        "nbuddyn volvió a leer este n8n.",
        "O nbuddyn voltou a ler este n8n.",
    )
}

pub fn alert_test(lang: Lang) -> &'static str {
    lang.pick(
        "Test message: alerts are reaching this chat.",
        "Mensaje de prueba: las alertas están llegando a este chat.",
        "Mensagem de teste: os alertas estão chegando a este chat.",
    )
}

/// Why a finding of this check may not be a problem. Empty for checks that
/// report facts: something nbuddyn counted or could not reach.
pub fn caveat(lang: Lang, check: &str) -> &'static str {
    match check {
        "open_ai_entry" | "public_entry_no_auth" => lang.pick(
            "nbuddyn sees the trigger's setting, not what happens after it. If the workflow checks who is calling in its first nodes, or a proxy in front of n8n does, this is fine: accept it.",
            "nbuddyn ve la configuración del disparador, no lo que pasa después. Si el workflow valida a quien llama en sus primeros nodos, o lo hace un proxy delante de n8n, está bien: aceptalo.",
            "O nbuddyn vê a configuração do gatilho, não o que acontece depois. Se o workflow valida quem chama nos primeiros nós, ou um proxy na frente do n8n faz isso, está tudo bem: aceite.",
        ),
        "hardcoded_secret" => lang.pick(
            "Found by its shape: text that looks like a key. It can be an example, a public identifier or a test value.",
            "Se detecta por la forma: un texto que parece una clave. Puede ser un ejemplo, un identificador público o un valor de prueba.",
            "Detectado pelo formato: um texto que parece uma chave. Pode ser um exemplo, um identificador público ou um valor de teste.",
        ),
        "plaintext_http" => lang.pick(
            "nbuddyn guesses which hosts are internal by their name. A host on your private network with a public-looking name shows up here.",
            "nbuddyn adivina qué hosts son internos por su nombre. Un host de tu red privada con nombre que parece público aparece acá.",
            "O nbuddyn adivinha quais hosts são internos pelo nome. Um host da sua rede privada com nome que parece público aparece aqui.",
        ),
        "env_access" | "command_execution" => lang.pick(
            "Found by searching the node's text. A mention inside a comment or a string counts too.",
            "Se detecta buscando en el texto del nodo. Una mención dentro de un comentario o de un texto también cuenta.",
            "Detectado buscando no texto do nó. Uma menção dentro de um comentário ou de um texto também conta.",
        ),
        "unused_credential" => lang.pick(
            "Credentials used only by n8n itself, or by workflows that are archived, are listed too.",
            "También aparecen las credenciales que usa solo el propio n8n, o workflows archivados.",
            "Também aparecem as credenciais usadas só pelo próprio n8n, ou por workflows arquivados.",
        ),
        "stale_workflow" => lang.pick(
            "A workflow that only runs when something happens outside can go quiet without being broken.",
            "Un workflow que solo corre cuando pasa algo afuera puede quedarse quieto sin estar roto.",
            "Um workflow que só roda quando algo acontece fora pode ficar parado sem estar quebrado.",
        ),
        _ => "",
    }
}

/// What nbuddyn does not look at, so a good score is not read as more than it is.
pub fn not_checked(lang: Lang) -> [&'static str; 5] {
    [
        lang.pick(
            "What a workflow does with its data: its logic, its expressions, what it sends where.",
            "Qué hace un workflow con sus datos: su lógica, sus expresiones, qué manda adónde.",
            "O que um workflow faz com os dados: a lógica, as expressões, o que envia para onde.",
        ),
        lang.pick(
            "Who may see or use each workflow and credential inside n8n.",
            "Quién puede ver o usar cada workflow y cada credencial dentro de n8n.",
            "Quem pode ver ou usar cada workflow e credencial dentro do n8n.",
        ),
        lang.pick(
            "The code of community nodes, and whether n8n itself is up to date.",
            "El código de los nodos de la comunidad, y si el propio n8n está actualizado.",
            "O código dos nós da comunidade, e se o próprio n8n está atualizado.",
        ),
        lang.pick(
            "How n8n is exposed: its proxy, its firewall, its own environment variables.",
            "Cómo está expuesto n8n: su proxy, su firewall, sus propias variables de entorno.",
            "Como o n8n está exposto: o proxy, o firewall, as próprias variáveis de ambiente.",
        ),
        lang.pick(
            "The data inside executions and the secrets inside credentials. It never reads either.",
            "Los datos de las ejecuciones y los secretos de las credenciales. Nunca lee ninguno de los dos.",
            "Os dados das execuções e os segredos das credenciais. Nunca lê nenhum dos dois.",
        ),
    ]
}

/// What a change to a workflow is called.
pub fn event_label(lang: Lang, kind: &str) -> &'static str {
    match kind {
        "workflow_created" => lang.pick("Workflow created", "Workflow creado", "Workflow criado"),
        "workflow_deleted" => lang.pick("Workflow deleted", "Workflow borrado", "Workflow apagado"),
        "workflow_changed" => lang.pick(
            "Workflow edited",
            "Workflow modificado",
            "Workflow modificado",
        ),
        "workflow_renamed" => lang.pick(
            "Workflow renamed",
            "Workflow renombrado",
            "Workflow renomeado",
        ),
        "workflow_activated" => lang.pick(
            "Workflow activated",
            "Workflow activado",
            "Workflow ativado",
        ),
        "workflow_deactivated" => lang.pick(
            "Workflow deactivated",
            "Workflow desactivado",
            "Workflow desativado",
        ),
        _ => "",
    }
}

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
        "no_main" => same(lang.pick(
            "The main n8n process is not running",
            "El proceso principal de n8n no está en marcha",
            "O processo principal do n8n não está em execução",
        )),
        "version_mismatch" => same(lang.pick(
            "The cluster is running mixed n8n versions",
            "El cluster corre versiones distintas de n8n",
            "O cluster está rodando versões diferentes do n8n",
        )),
        "n8n_outdated" => same(lang.pick(
            "A newer n8n version is out",
            "Hay una versión más nueva de n8n",
            "Há uma versão mais nova do n8n",
        )),
        "stale_workflow" => (
            lang.pick(
                "A workflow stopped running",
                "Un workflow dejó de ejecutarse",
                "Um workflow parou de executar",
            ),
            lang.pick(
                "{n} workflows stopped running",
                "{n} workflows dejaron de ejecutarse",
                "{n} workflows pararam de executar",
            ),
        ),
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
            "Delete the ones nothing else needs.",
            "Borrá las que nada más necesite.",
            "Exclua as que nada mais precisa.",
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
        "no_main" => lang.pick(
            "Nothing is scheduled or activated and the editor does not answer until it is back. Check the main n8n service and its log.",
            "Nada se programa ni se activa y el editor no responde hasta que vuelva. Revisá el servicio principal de n8n y su registro.",
            "Nada é agendado nem ativado e o editor não responde até ele voltar. Verifique o serviço principal do n8n e o log dele.",
        ),
        "version_mismatch" => lang.pick(
            "Main, workers and webhook processors must run the same version. Finish the update on the ones left behind.",
            "Main, workers y webhooks tienen que correr la misma versión. Terminá la actualización en los que quedaron atrás.",
            "Main, workers e webhooks precisam rodar a mesma versão. Conclua a atualização nos que ficaram para trás.",
        ),
        "stale_workflow" => lang.pick(
            "It used to run most days and has not run in three. Check its trigger, its schedule and whether it is still published.",
            "Corría casi todos los días y hace tres que no corre. Revisá su disparador, su horario y si sigue publicado.",
            "Rodava quase todos os dias e há três não roda. Verifique o gatilho, o horário e se continua publicado.",
        ),
        "n8n_outdated" => lang.pick(
            "Read n8n's release notes and update when it suits you. Fixes for security problems reach the newest versions first.",
            "Leé las notas de la versión de n8n y actualizá cuando te convenga. Los arreglos de seguridad llegan primero a las versiones más nuevas.",
            "Leia as notas da versão do n8n e atualize quando for conveniente. As correções de segurança chegam primeiro às versões mais novas.",
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
    pub drill_hint: &'static str,
    pub day_empty: &'static str,
    pub exec_title: &'static str,
    pub exec_pick: &'static str,
    pub exec_gone: &'static str,
    pub exec_more: &'static str,
    pub exec_note: &'static str,
    pub exec_failed_read: &'static str,
    pub col_time: &'static str,
    pub col_result: &'static str,
    pub col_took: &'static str,
    pub st_ok: &'static str,
    pub st_failed: &'static str,
    pub st_canceled: &'static str,
    pub st_running: &'static str,
    pub st_waiting: &'static str,
    pub exec_deleted: &'static str,
    pub exec_open: &'static str,
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
    pub nav_overview: &'static str,
    pub nav_findings: &'static str,
    pub nav_cluster: &'static str,
    pub scan_now: &'static str,
    pub scanning: &'static str,
    pub next_scan: &'static str,
    pub ago: &'static str,
    pub just_now: &'static str,
    pub loading: &'static str,
    pub do_first: &'static str,
    pub nothing_urgent: &'static str,
    pub see_findings: &'static str,
    pub see: &'static str,
    pub panel: &'static str,
    pub all: &'static str,
    pub search: &'static str,
    pub no_results: &'static str,
    pub clear_filter: &'static str,
    pub all_clear: &'static str,
    pub what_to_do: &'static str,
    pub where_label: &'static str,
    pub show_all: &'static str,
    pub show_less: &'static str,
    pub inventory: &'static str,
    pub inv_workflows: &'static str,
    pub inv_active: &'static str,
    pub inv_nodes: &'static str,
    pub inv_credentials: &'static str,
    pub inv_users: &'static str,
    pub last_7: &'static str,
    pub score_trend: &'static str,
    pub queue: &'static str,
    pub queue_delayed: &'static str,
    pub members: &'static str,
    pub col_kind: &'static str,
    pub col_host: &'static str,
    pub col_version: &'static str,
    pub col_status: &'static str,
    pub col_runner: &'static str,
    pub answering: &'static str,
    pub not_answering: &'static str,
    pub eviction: &'static str,
    pub cluster_off: &'static str,
    pub runners_off: &'static str,
    pub history_off: &'static str,
    pub go_settings: &'static str,
    pub saved: &'static str,
    pub accepted_toast: &'static str,
    pub restored_toast: &'static str,
    pub sec_n8n: &'static str,
    pub sec_scan: &'static str,
    pub sec_cluster: &'static str,
    pub sec_about: &'static str,
    pub not_set: &'static str,
    pub no_link_hint: &'static str,
    pub items: &'static str,
    pub print_report: &'static str,
    pub menu: &'static str,
    pub sec_policy: &'static str,
    pub policy_help: &'static str,
    pub level_default: &'static str,
    pub level_off: &'static str,
    pub set_accept_needs_note: &'static str,
    pub accept_needs_note_true: &'static str,
    pub accept_needs_note_false: &'static str,
    pub set_own_credentials: &'static str,
    pub own_credentials_false: &'static str,
    pub own_credentials_true: &'static str,
    pub help_own_credentials: &'static str,
    pub set_accept_days: &'static str,
    pub help_accept_days: &'static str,
    pub note_required: &'static str,
    pub sec_mcp: &'static str,
    pub mcp_help: &'static str,
    pub mcp_access: &'static str,
    pub mcp_url: &'static str,
    pub mcp_url_help: &'static str,
    pub copy: &'static str,
    pub copied: &'static str,
    pub mcp_connections: &'static str,
    pub mcp_none: &'static str,
    pub mcp_by: &'static str,
    pub mcp_used: &'static str,
    pub mcp_disconnect: &'static str,
    pub mcp_disconnect_confirm: &'static str,
    pub mcp_disconnected: &'static str,
    pub mcp_token_title: &'static str,
    pub mcp_token_help: &'static str,
    pub mcp_token_none: &'static str,
    pub mcp_token_set: &'static str,
    pub mcp_token_env: &'static str,
    pub mcp_token_new: &'static str,
    pub mcp_token_replace: &'static str,
    pub mcp_token_remove: &'static str,
    pub mcp_token_replace_confirm: &'static str,
    pub mcp_token_remove_confirm: &'static str,
    pub mcp_token_once: &'static str,
    pub connect_title: &'static str,
    pub connect_text: &'static str,
    pub connect_back: &'static str,
    pub connect_allow: &'static str,
    pub connect_deny: &'static str,
    pub connect_gone: &'static str,
    pub connect_admin: &'static str,
    pub act_mcp: &'static str,
    pub act_mcp_token: &'static str,
    pub act_mcp_connect: &'static str,
    pub act_mcp_revoke: &'static str,
    pub act_policy: &'static str,
    pub list_cut: &'static str,
    pub certain: &'static str,
    pub likely: &'static str,
    pub certain_help: &'static str,
    pub likely_help: &'static str,
    pub caveat_label: &'static str,
    pub not_checked_title: &'static str,
    pub not_checked_note: &'static str,
    pub not_checked: [&'static str; 5],
    pub set_check_updates: &'static str,
    pub check_updates_false: &'static str,
    pub check_updates_true: &'static str,
    pub help_check_updates: &'static str,
    pub env_n8n: &'static str,
    pub version_unknown: &'static str,
    pub env_tested: &'static str,
    pub sec_alerts: &'static str,
    pub alerts_help: &'static str,
    pub set_telegram_token: &'static str,
    pub help_telegram_token: &'static str,
    pub set_telegram_chat: &'static str,
    pub help_telegram_chat: &'static str,
    pub set_webhook_url: &'static str,
    pub help_webhook_url: &'static str,
    pub set_alert_level: &'static str,
    pub alert_level_high: &'static str,
    pub alert_level_medium: &'static str,
    pub set_alert_changes: &'static str,
    pub alert_changes_true: &'static str,
    pub alert_changes_false: &'static str,
    pub alerts_test: &'static str,
    pub alerts_test_ok: &'static str,
    pub alerts_test_first: &'static str,
    pub env_secrets: &'static str,
    pub secrets_environment: &'static str,
    pub secrets_data: &'static str,
    pub secrets_data_help: &'static str,
    pub nav_credentials: &'static str,
    pub cred_help: &'static str,
    pub col_credential: &'static str,
    pub col_used_by: &'static str,
    pub unused: &'static str,
    pub cred_search: &'static str,
    pub no_credentials: &'static str,
    pub col_avg: &'static str,
    pub col_slowest: &'static str,
    pub download_csv: &'static str,
    pub backup: &'static str,
    pub download_backup: &'static str,
    pub backup_help: &'static str,
    pub show_password: &'static str,
    pub hide_password: &'static str,
    pub first_scan_title: &'static str,
    pub first_scan_text: &'static str,
    pub scan_failed_title: &'static str,
    pub scan_failed_text: &'static str,
    pub logout: &'static str,
    pub users: &'static str,
    pub role_admin: &'static str,
    pub role_viewer: &'static str,
    pub set_user: &'static str,
    pub set_password: &'static str,
    pub help_users: &'static str,
    pub user_added: &'static str,
    pub user_removed: &'static str,
    pub user_remove_confirm: &'static str,
    pub users_env_note: &'static str,
    pub users_need_store: &'static str,
    pub audit: &'static str,
    pub audit_empty: &'static str,
    pub act_login: &'static str,
    pub act_login_failed: &'static str,
    pub act_logout: &'static str,
    pub act_accept: &'static str,
    pub act_unaccept: &'static str,
    pub act_settings: &'static str,
    pub act_instance_add: &'static str,
    pub act_instance_remove: &'static str,
    pub act_user_add: &'static str,
    pub act_user_remove: &'static str,
    pub nav_activity: &'static str,
    pub changes_title: &'static str,
    pub changes_new: &'static str,
    pub changes_resolved: &'static str,
    pub changes_workflows: &'static str,
    pub nothing_changed: &'static str,
    pub new_tag: &'static str,
    pub by: &'static str,
    pub was: &'static str,
    pub event_new: &'static str,
    pub event_resolved: &'static str,
    pub activity_note: &'static str,
    pub instances: &'static str,
    pub set_name: &'static str,
    pub set_database_url: &'static str,
    pub help_database_url: &'static str,
    pub add_instance: &'static str,
    pub add: &'static str,
    pub remove_instance: &'static str,
    pub remove_confirm: &'static str,
    pub instance_added: &'static str,
    pub instance_removed: &'static str,
    pub first_scan: &'static str,
    pub sec_instance: &'static str,
    pub sec_general: &'static str,
    pub urgent_short: &'static str,
    pub watching: &'static str,
    pub primary_note: &'static str,
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
        drill_hint: lang.pick(
            "Click a day or a workflow to see what is behind the numbers.",
            "Hacé clic en un día o en un workflow para ver qué hay detrás de los números.",
            "Clique em um dia ou em um workflow para ver o que há por trás dos números.",
        ),
        day_empty: lang.pick(
            "Nothing ran on this day, as far as nbuddyn remembers.",
            "Ese día no corrió nada, hasta donde nbuddyn recuerda.",
            "Nada rodou nesse dia, até onde o nbuddyn lembra.",
        ),
        exec_title: lang.pick(
            "Executions",
            "Ejecuciones",
            "Execuções",
        ),
        exec_pick: lang.pick(
            "Pick a day in the chart or the table to see its executions.",
            "Elegí un día en el gráfico o en la tabla para ver sus ejecuciones.",
            "Escolha um dia no gráfico ou na tabela para ver as execuções.",
        ),
        exec_gone: lang.pick(
            "n8n no longer keeps the executions of this day. nbuddyn still has the totals.",
            "n8n ya no conserva las ejecuciones de este día. nbuddyn sigue teniendo los totales.",
            "O n8n não guarda mais as execuções desse dia. O nbuddyn ainda tem os totais.",
        ),
        exec_more: lang.pick(
            "Showing the 200 most recent.",
            "Se muestran las 200 más recientes.",
            "Mostrando as 200 mais recentes.",
        ),
        exec_note: lang.pick(
            "Read from n8n just now. nbuddyn keeps no executions and never reads what went through them.",
            "Leídas de n8n recién. nbuddyn no guarda ejecuciones y nunca lee lo que pasó por ellas.",
            "Lidas do n8n agora. O nbuddyn não guarda execuções e nunca lê o que passou por elas.",
        ),
        exec_failed_read: lang.pick(
            "The executions could not be read",
            "No se pudieron leer las ejecuciones",
            "Não foi possível ler as execuções",
        ),
        col_time: lang.pick(
            "Time",
            "Hora",
            "Hora",
        ),
        col_result: lang.pick(
            "Result",
            "Resultado",
            "Resultado",
        ),
        col_took: lang.pick(
            "Took",
            "Duración",
            "Duração",
        ),
        st_ok: lang.pick(
            "succeeded",
            "terminó bien",
            "terminou bem",
        ),
        st_failed: lang.pick(
            "failed",
            "falló",
            "falhou",
        ),
        st_canceled: lang.pick(
            "canceled",
            "cancelada",
            "cancelada",
        ),
        st_running: lang.pick(
            "running",
            "en curso",
            "em andamento",
        ),
        st_waiting: lang.pick(
            "waiting",
            "en espera",
            "em espera",
        ),
        exec_deleted: lang.pick(
            "deleted in n8n",
            "borrada en n8n",
            "apagada no n8n",
        ),
        exec_open: lang.pick(
            "Open",
            "Abrir",
            "Abrir",
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
        nav_overview: lang.pick(
            "Overview",
            "Resumen",
            "Resumo",
        ),
        nav_findings: lang.pick(
            "Findings",
            "Hallazgos",
            "Achados",
        ),
        nav_cluster: lang.pick(
            "Cluster",
            "Cluster",
            "Cluster",
        ),
        scan_now: lang.pick(
            "Scan now",
            "Revisar ahora",
            "Verificar agora",
        ),
        scanning: lang.pick(
            "Scanning…",
            "Revisando…",
            "Verificando…",
        ),
        next_scan: lang.pick(
            "next scan in",
            "próximo barrido en",
            "próxima varredura em",
        ),
        ago: lang.pick(
            "ago",
            "hace",
            "há",
        ),
        just_now: lang.pick(
            "just now",
            "recién",
            "agora mesmo",
        ),
        loading: lang.pick(
            "Powering up the instruments…",
            "Encendiendo instrumentos…",
            "Ligando os instrumentos…",
        ),
        do_first: lang.pick(
            "What to do first",
            "Qué hacer primero",
            "O que fazer primeiro",
        ),
        nothing_urgent: lang.pick(
            "Nothing urgent on the radar. Enjoy the calm.",
            "Nada urgente en el radar. Disfrutá la calma.",
            "Nada urgente no radar. Aproveite a calma.",
        ),
        see_findings: lang.pick(
            "See all findings",
            "Ver todos los hallazgos",
            "Ver todos os achados",
        ),
        see: lang.pick(
            "See",
            "Ver",
            "Ver",
        ),
        panel: lang.pick(
            "Panel",
            "Tablero",
            "Painel",
        ),
        all: lang.pick(
            "All",
            "Todos",
            "Todos",
        ),
        search: lang.pick(
            "Search by workflow, node or problem",
            "Buscar por workflow, nodo o problema",
            "Buscar por workflow, nó ou problema",
        ),
        no_results: lang.pick(
            "Nothing on the radar with this filter.",
            "Nada en el radar con este filtro.",
            "Nada no radar com este filtro.",
        ),
        clear_filter: lang.pick(
            "Clear filter",
            "Quitar filtro",
            "Limpar filtro",
        ),
        all_clear: lang.pick(
            "Clear skies. nbuddyn found nothing to report.",
            "Cielo despejado. nbuddyn no encontró nada para reportar.",
            "Céu limpo. O nbuddyn não encontrou nada para relatar.",
        ),
        what_to_do: lang.pick(
            "What to do",
            "Qué hacer",
            "O que fazer",
        ),
        where_label: lang.pick(
            "Where",
            "Dónde",
            "Onde",
        ),
        show_all: lang.pick(
            "Show all",
            "Ver todos",
            "Ver todos",
        ),
        show_less: lang.pick(
            "Show less",
            "Ver menos",
            "Ver menos",
        ),
        inventory: lang.pick(
            "What was reviewed",
            "Qué se revisó",
            "O que foi revisado",
        ),
        inv_workflows: lang.pick(
            "workflows",
            "workflows",
            "workflows",
        ),
        inv_active: lang.pick(
            "active",
            "activos",
            "ativos",
        ),
        inv_nodes: lang.pick(
            "nodes",
            "nodos",
            "nós",
        ),
        inv_credentials: lang.pick(
            "credentials",
            "credenciales",
            "credenciais",
        ),
        inv_users: lang.pick(
            "users",
            "usuarios",
            "usuários",
        ),
        last_7: lang.pick(
            "Last 7 days",
            "Últimos 7 días",
            "Últimos 7 dias",
        ),
        score_trend: lang.pick(
            "Score",
            "Puntaje",
            "Pontuação",
        ),
        queue: lang.pick(
            "Queue",
            "Cola",
            "Fila",
        ),
        queue_delayed: lang.pick(
            "delayed",
            "demoradas",
            "atrasadas",
        ),
        members: lang.pick(
            "Processes",
            "Procesos",
            "Processos",
        ),
        col_kind: lang.pick(
            "Type",
            "Tipo",
            "Tipo",
        ),
        col_host: lang.pick(
            "Host",
            "Equipo",
            "Host",
        ),
        col_version: lang.pick(
            "Version",
            "Versión",
            "Versão",
        ),
        col_status: lang.pick(
            "Status",
            "Estado",
            "Estado",
        ),
        col_runner: lang.pick(
            "Runner",
            "Runner",
            "Runner",
        ),
        answering: lang.pick(
            "answering",
            "responde",
            "responde",
        ),
        not_answering: lang.pick(
            "not answering",
            "no responde",
            "não responde",
        ),
        eviction: lang.pick(
            "eviction policy",
            "política de memoria",
            "política de memória",
        ),
        cluster_off: lang.pick(
            "Add n8n's Redis in Settings to see the queue, the workers and the webhook processors.",
            "Agregá el Redis de n8n en Ajustes para ver la cola, los workers y los webhooks.",
            "Adicione o Redis do n8n em Configurações para ver a fila, os workers e os webhooks.",
        ),
        runners_off: lang.pick(
            "Add your task runners in Settings to know whether they are alive.",
            "Agregá tus runners en Ajustes para saber si están vivos.",
            "Adicione os seus runners em Configurações para saber se estão ativos.",
        ),
        history_off: lang.pick(
            "nbuddyn has no data directory, so it keeps no history. Mount a volume at /data.",
            "nbuddyn no tiene directorio de datos, así que no guarda historial. Montá un volumen en /data.",
            "O nbuddyn não tem diretório de dados, então não guarda histórico. Monte um volume em /data.",
        ),
        go_settings: lang.pick(
            "Open Settings",
            "Abrir Ajustes",
            "Abrir Configurações",
        ),
        saved: lang.pick(
            "Saved",
            "Guardado",
            "Salvo",
        ),
        accepted_toast: lang.pick(
            "Accepted. It no longer counts in the score.",
            "Aceptado. Ya no cuenta en el puntaje.",
            "Aceito. Não conta mais na pontuação.",
        ),
        restored_toast: lang.pick(
            "Back in the findings.",
            "Volvió a los hallazgos.",
            "Voltou aos achados.",
        ),
        sec_n8n: lang.pick(
            "Your n8n",
            "Tu n8n",
            "O seu n8n",
        ),
        sec_scan: lang.pick(
            "Scanning",
            "Revisión",
            "Verificação",
        ),
        sec_cluster: lang.pick(
            "Queue and runners",
            "Cola y runners",
            "Fila e runners",
        ),
        sec_about: lang.pick(
            "About",
            "Acerca de",
            "Sobre",
        ),
        not_set: lang.pick(
            "not set",
            "sin configurar",
            "não definido",
        ),
        no_link_hint: lang.pick(
            "Set n8n's address in Settings to open workflows from here.",
            "Cargá la dirección de n8n en Ajustes para abrir los workflows desde acá.",
            "Defina o endereço do n8n em Configurações para abrir os workflows daqui.",
        ),
        items: lang.pick(
            "items",
            "elementos",
            "itens",
        ),
        print_report: lang.pick(
            "Report",
            "Informe",
            "Relatório",
        ),
        menu: lang.pick(
            "Menu",
            "Menú",
            "Menu",
        ),
        sec_policy: lang.pick(
            "Your rules",
            "Tus reglas",
            "As suas regras",
        ),
        policy_help: lang.pick(
            "Decide what matters here. A check can be more or less severe than nbuddyn makes it, or be turned off. nbuddyn never changes n8n: it watches, scores and alerts by these rules.",
            "Decidí qué importa acá. Un chequeo puede ser más o menos grave de lo que dice nbuddyn, o apagarse. nbuddyn nunca cambia n8n: vigila, puntúa y avisa según estas reglas.",
            "Decida o que importa aqui. Uma verificação pode ser mais ou menos grave do que o nbuddyn diz, ou ser desligada. O nbuddyn nunca muda o n8n: vigia, pontua e avisa por estas regras.",
        ),
        level_default: lang.pick(
            "As nbuddyn says",
            "Como dice nbuddyn",
            "Como o nbuddyn diz",
        ),
        level_off: lang.pick(
            "Off",
            "Apagado",
            "Desligado",
        ),
        set_accept_needs_note: lang.pick(
            "Accepting a finding",
            "Aceptar un hallazgo",
            "Aceitar um achado",
        ),
        accept_needs_note_true: lang.pick(
            "Needs a reason",
            "Exige un motivo",
            "Exige um motivo",
        ),
        accept_needs_note_false: lang.pick(
            "A reason is optional",
            "El motivo es opcional",
            "O motivo é opcional",
        ),
        set_own_credentials: lang.pick(
            "Credentials n8n makes for itself",
            "Credenciales que n8n crea para sí mismo",
            "Credenciais que o n8n cria para si mesmo",
        ),
        own_credentials_false: lang.pick(
            "Leave them out of unused credentials",
            "No contarlas como credenciales sin uso",
            "Não contá-las como credenciais sem uso",
        ),
        own_credentials_true: lang.pick(
            "Report them like any other",
            "Informarlas como cualquier otra",
            "Informá-las como qualquer outra",
        ),
        help_own_credentials: lang.pick(
            "n8n 3 creates credentials for its assistant, named \"n8n Assistant ...\". No workflow uses them, and nobody chose to create them.",
            "n8n 3 crea credenciales para su asistente, llamadas \"n8n Assistant ...\". Ningún workflow las usa, y nadie eligió crearlas.",
            "O n8n 3 cria credenciais para o assistente, chamadas \"n8n Assistant ...\". Nenhum workflow as usa, e ninguém escolheu criá-las.",
        ),
        set_accept_days: lang.pick(
            "Days an acceptance lasts",
            "Días que dura una aceptación",
            "Dias que uma aceitação dura",
        ),
        help_accept_days: lang.pick(
            "After that the finding comes back for another look. 0 means it lasts as long as the finding.",
            "Después el hallazgo vuelve para que lo miren de nuevo. 0 significa que dura lo que dure el hallazgo.",
            "Depois o achado volta para ser olhado de novo. 0 significa que dura enquanto o achado durar.",
        ),
        note_required: lang.pick(
            "Your rules ask for a reason.",
            "Tus reglas piden un motivo.",
            "As suas regras pedem um motivo.",
        ),
        sec_mcp: lang.pick(
            "AI assistants (MCP)",
            "Asistentes de IA (MCP)",
            "Assistentes de IA (MCP)",
        ),
        mcp_help: lang.pick(
            "Lets an assistant such as Claude ask about your n8n in plain words. It can only read what this page shows; it cannot change anything.",
            "Permite que un asistente como Claude pregunte por tu n8n en lenguaje natural. Solo puede leer lo que muestra esta página; no puede cambiar nada.",
            "Permite que um assistente como o Claude pergunte sobre o seu n8n em linguagem natural. Ele só lê o que esta página mostra; não pode mudar nada.",
        ),
        mcp_access: lang.pick(
            "Access for assistants",
            "Acceso para asistentes",
            "Acesso para assistentes",
        ),
        mcp_url: lang.pick(
            "Address to give the assistant",
            "Dirección para darle al asistente",
            "Endereço para dar ao assistente",
        ),
        mcp_url_help: lang.pick(
            "In claude.ai: Settings → Connectors → Add custom connector, and paste this address. Claude brings you back here to say yes.",
            "En claude.ai: Settings → Connectors → Add custom connector, y pegá esta dirección. Claude te trae de vuelta acá para que digas que sí.",
            "No claude.ai: Settings → Connectors → Add custom connector, e cole este endereço. O Claude traz você de volta aqui para dizer sim.",
        ),
        copy: lang.pick(
            "Copy",
            "Copiar",
            "Copiar",
        ),
        copied: lang.pick(
            "Copied",
            "Copiado",
            "Copiado",
        ),
        mcp_connections: lang.pick(
            "Connected assistants",
            "Asistentes conectados",
            "Assistentes conectados",
        ),
        mcp_none: lang.pick(
            "No assistant has signed in yet.",
            "Todavía no se conectó ningún asistente.",
            "Nenhum assistente se conectou ainda.",
        ),
        mcp_by: lang.pick(
            "approved by",
            "lo aprobó",
            "aprovado por",
        ),
        mcp_used: lang.pick(
            "last used",
            "último uso",
            "último uso",
        ),
        mcp_disconnect: lang.pick(
            "Disconnect",
            "Desconectar",
            "Desconectar",
        ),
        mcp_disconnect_confirm: lang.pick(
            "Disconnect this assistant? It will have to sign in again.",
            "¿Desconectar este asistente? Va a tener que volver a conectarse.",
            "Desconectar este assistente? Ele terá que se conectar de novo.",
        ),
        mcp_disconnected: lang.pick(
            "Disconnected",
            "Desconectado",
            "Desconectado",
        ),
        mcp_token_title: lang.pick(
            "Token for clients that cannot sign in",
            "Token para clientes que no pueden iniciar sesión",
            "Token para clientes que não conseguem fazer login",
        ),
        mcp_token_help: lang.pick(
            "For Claude Code, scripts and other clients that take a fixed token. They send it as Authorization: Bearer.",
            "Para Claude Code, scripts y otros clientes que usan un token fijo. Lo mandan como Authorization: Bearer.",
            "Para o Claude Code, scripts e outros clientes que usam um token fixo. Eles o enviam como Authorization: Bearer.",
        ),
        mcp_token_none: lang.pick(
            "No token made here.",
            "No hay un token creado acá.",
            "Não há um token criado aqui.",
        ),
        mcp_token_set: lang.pick(
            "A token made here is in use.",
            "Hay un token creado acá en uso.",
            "Há um token criado aqui em uso.",
        ),
        mcp_token_env: lang.pick(
            "A token is also set in the environment (NBUDDYN_MCP_TOKEN). It keeps working and cannot be changed here.",
            "También hay un token en el entorno (NBUDDYN_MCP_TOKEN). Sigue funcionando y no se puede cambiar desde acá.",
            "Também há um token no ambiente (NBUDDYN_MCP_TOKEN). Ele continua funcionando e não pode ser alterado aqui.",
        ),
        mcp_token_new: lang.pick(
            "Create token",
            "Crear token",
            "Criar token",
        ),
        mcp_token_replace: lang.pick(
            "Replace token",
            "Reemplazar token",
            "Substituir token",
        ),
        mcp_token_remove: lang.pick(
            "Remove token",
            "Quitar token",
            "Remover token",
        ),
        mcp_token_replace_confirm: lang.pick(
            "Replace the token? Whatever uses the current one stops working.",
            "¿Reemplazar el token? Lo que use el actual deja de funcionar.",
            "Substituir o token? O que usa o atual para de funcionar.",
        ),
        mcp_token_remove_confirm: lang.pick(
            "Remove the token? Whatever uses it stops working.",
            "¿Quitar el token? Lo que lo use deja de funcionar.",
            "Remover o token? O que o usa para de funcionar.",
        ),
        mcp_token_once: lang.pick(
            "Copy it now. It will not be shown again.",
            "Copialo ahora. No se va a mostrar de nuevo.",
            "Copie agora. Ele não será mostrado de novo.",
        ),
        connect_title: lang.pick(
            "wants to read your nbuddyn",
            "quiere leer tu nbuddyn",
            "quer ler o seu nbuddyn",
        ),
        connect_text: lang.pick(
            "It will see what this page shows: the status, the findings, credentials by name, the activity and the history. It cannot change anything, here or in n8n, and it never sees a secret.",
            "Va a ver lo que muestra esta página: el estado, los hallazgos, las credenciales por nombre, la actividad y el historial. No puede cambiar nada, ni acá ni en n8n, y nunca ve un secreto.",
            "Ele verá o que esta página mostra: o estado, os achados, as credenciais por nome, a atividade e o histórico. Não pode mudar nada, nem aqui nem no n8n, e nunca vê um segredo.",
        ),
        connect_back: lang.pick(
            "After you answer, you go back to",
            "Después de responder, volvés a",
            "Depois de responder, você volta para",
        ),
        connect_allow: lang.pick(
            "Allow",
            "Permitir",
            "Permitir",
        ),
        connect_deny: lang.pick(
            "Deny",
            "Rechazar",
            "Recusar",
        ),
        connect_gone: lang.pick(
            "This request expired or was already answered. Start again from the assistant.",
            "Este pedido venció o ya fue respondido. Empezá de nuevo desde el asistente.",
            "Este pedido expirou ou já foi respondido. Comece de novo pelo assistente.",
        ),
        connect_admin: lang.pick(
            "Only an administrator can connect an assistant.",
            "Solo un administrador puede conectar un asistente.",
            "Só um administrador pode conectar um assistente.",
        ),
        act_mcp: lang.pick(
            "changed assistant access",
            "cambió el acceso de asistentes",
            "mudou o acesso de assistentes",
        ),
        act_mcp_token: lang.pick(
            "changed the assistant token",
            "cambió el token de asistentes",
            "mudou o token de assistentes",
        ),
        act_mcp_connect: lang.pick(
            "connected an assistant",
            "conectó un asistente",
            "conectou um assistente",
        ),
        act_mcp_revoke: lang.pick(
            "disconnected an assistant",
            "desconectó un asistente",
            "desconectou um assistente",
        ),
        act_policy: lang.pick(
            "changed the rules",
            "cambió las reglas",
            "mudou as regras",
        ),
        list_cut: lang.pick(
            "{n} more are not listed. Search to find a specific one, or use the API.",
            "Hay {n} más sin listar. Buscá para encontrar uno puntual, o usá la API.",
            "Há mais {n} não listados. Busque para achar um específico, ou use a API.",
        ),
        certain: lang.pick(
            "Verified",
            "Comprobado",
            "Verificado",
        ),
        likely: lang.pick(
            "To review",
            "A revisar",
            "A revisar",
        ),
        certain_help: lang.pick(
            "A fact nbuddyn counted or measured.",
            "Un hecho que nbuddyn contó o midió.",
            "Um fato que o nbuddyn contou ou mediu.",
        ),
        likely_help: lang.pick(
            "A sign worth a look. nbuddyn cannot be sure from where it stands.",
            "Una señal que merece una mirada. nbuddyn no puede estar seguro desde donde mira.",
            "Um sinal que merece uma olhada. O nbuddyn não pode ter certeza de onde olha.",
        ),
        caveat_label: lang.pick(
            "It may be fine",
            "Puede estar bien",
            "Pode estar tudo bem",
        ),
        not_checked_title: lang.pick(
            "What nbuddyn does not check",
            "Qué no revisa nbuddyn",
            "O que o nbuddyn não verifica",
        ),
        not_checked_note: lang.pick(
            "The score sums up what nbuddyn can see. It is a radar, not an audit.",
            "El puntaje resume lo que nbuddyn puede ver. Es un radar, no una auditoría.",
            "A pontuação resume o que o nbuddyn consegue ver. É um radar, não uma auditoria.",
        ),
        not_checked: not_checked(lang),
        set_check_updates: lang.pick(
            "Newer n8n versions",
            "Versiones nuevas de n8n",
            "Versões novas do n8n",
        ),
        check_updates_false: lang.pick(
            "Do not look",
            "No buscar",
            "Não procurar",
        ),
        check_updates_true: lang.pick(
            "Tell me when one is out",
            "Avisarme cuando salga una",
            "Avisar quando sair uma",
        ),
        help_check_updates: lang.pick(
            "Off by default, because it is the only thing nbuddyn asks outside your server. Once a day it reads two public lists (registry.npmjs.org and hub.docker.com) and sends nothing about your n8n.",
            "Apagado por defecto, porque es lo único que nbuddyn pregunta fuera de tu servidor. Una vez por día lee dos listas públicas (registry.npmjs.org y hub.docker.com) y no manda nada sobre tu n8n.",
            "Desligado por padrão, porque é a única coisa que o nbuddyn pergunta fora do seu servidor. Uma vez por dia lê duas listas públicas (registry.npmjs.org e hub.docker.com) e não envia nada sobre o seu n8n.",
        ),
        env_n8n: lang.pick(
            "n8n version",
            "Versión de n8n",
            "Versão do n8n",
        ),
        version_unknown: lang.pick(
            "not known",
            "no se sabe",
            "não se sabe",
        ),
        env_tested: lang.pick(
            "Tested with n8n",
            "Probado con n8n",
            "Testado com n8n",
        ),
        sec_alerts: lang.pick(
            "Alerts",
            "Alertas",
            "Alertas",
        ),
        alerts_help: lang.pick(
            "nbuddyn alerts when something changes: a new finding at or above the level you choose, one that goes away, or an n8n it can no longer read. Never about the whole report, and never twice in six hours for the same thing.",
            "nbuddyn avisa cuando algo cambia: un hallazgo nuevo del nivel que elijas o más grave, uno que se resuelve, o un n8n que ya no puede leer. Nunca sobre todo el informe, y nunca dos veces en seis horas por lo mismo.",
            "O nbuddyn avisa quando algo muda: um achado novo do nível que você escolher ou mais grave, um que se resolve, ou um n8n que ele não consegue mais ler. Nunca sobre o relatório inteiro, e nunca duas vezes em seis horas pela mesma coisa.",
        ),
        set_telegram_token: lang.pick(
            "Telegram bot token",
            "Token del bot de Telegram",
            "Token do bot do Telegram",
        ),
        help_telegram_token: lang.pick(
            "The token @BotFather gives when you create a bot. It is sealed when saved and never shown again.",
            "El token que da @BotFather al crear un bot. Se cifra al guardarlo y no se vuelve a mostrar.",
            "O token que o @BotFather dá ao criar um bot. É cifrado ao salvar e não é mostrado de novo.",
        ),
        set_telegram_chat: lang.pick(
            "Telegram chat",
            "Chat de Telegram",
            "Chat do Telegram",
        ),
        help_telegram_chat: lang.pick(
            "The chat's number, such as -1001234567890, or a public channel as @name. Add the bot to that chat first.",
            "El número del chat, como -1001234567890, o un canal público como @nombre. Primero agregá el bot a ese chat.",
            "O número do chat, como -1001234567890, ou um canal público como @nome. Primeiro adicione o bot a esse chat.",
        ),
        set_webhook_url: lang.pick(
            "Webhook",
            "Webhook",
            "Webhook",
        ),
        help_webhook_url: lang.pick(
            "Any address that takes a JSON POST: a Slack incoming webhook, an n8n webhook, a pager. Empty turns it off.",
            "Cualquier dirección que reciba un POST con JSON: un webhook entrante de Slack, un webhook de n8n, un pager. Vacío lo apaga.",
            "Qualquer endereço que receba um POST com JSON: um webhook de entrada do Slack, um webhook do n8n, um pager. Vazio desliga.",
        ),
        set_alert_level: lang.pick(
            "Alert from",
            "Avisar desde",
            "Avisar a partir de",
        ),
        alert_level_high: lang.pick(
            "Urgent only",
            "Solo urgentes",
            "Somente urgentes",
        ),
        alert_level_medium: lang.pick(
            "Urgent and important",
            "Urgentes e importantes",
            "Urgentes e importantes",
        ),
        set_alert_changes: lang.pick(
            "Workflow changes",
            "Cambios en workflows",
            "Mudanças em workflows",
        ),
        alert_changes_true: lang.pick(
            "Alert too",
            "Avisar también",
            "Avisar também",
        ),
        alert_changes_false: lang.pick(
            "Do not alert",
            "No avisar",
            "Não avisar",
        ),
        alerts_test: lang.pick(
            "Send a test",
            "Enviar una prueba",
            "Enviar um teste",
        ),
        alerts_test_ok: lang.pick(
            "Sent. Check the chat.",
            "Enviado. Fijate en el chat.",
            "Enviado. Confira o chat.",
        ),
        alerts_test_first: lang.pick(
            "Save a destination first.",
            "Primero guardá un destino.",
            "Primeiro salve um destino.",
        ),
        env_secrets: lang.pick(
            "Stored secrets",
            "Secretos guardados",
            "Segredos guardados",
        ),
        secrets_environment: lang.pick(
            "sealed with NBUDDYN_SECRET_KEY",
            "cifrados con NBUDDYN_SECRET_KEY",
            "cifrados com NBUDDYN_SECRET_KEY",
        ),
        secrets_data: lang.pick(
            "sealed with a key nbuddyn keeps in its data directory",
            "cifrados con una clave que nbuddyn guarda en su directorio de datos",
            "cifrados com uma chave que o nbuddyn guarda no diretório de dados",
        ),
        secrets_data_help: lang.pick(
            "Database and Redis passwords saved here are sealed before they are written. For stronger protection set NBUDDYN_SECRET_KEY, so the key does not live next to what it protects.",
            "Las claves de base y de Redis guardadas acá se cifran antes de escribirse. Para más protección definí NBUDDYN_SECRET_KEY, así la clave no vive al lado de lo que protege.",
            "As senhas de banco e de Redis guardadas aqui são cifradas antes de serem gravadas. Para mais proteção defina NBUDDYN_SECRET_KEY, assim a chave não fica ao lado do que protege.",
        ),
        nav_credentials: lang.pick(
            "Credentials",
            "Credenciales",
            "Credenciais",
        ),
        cred_help: lang.pick(
            "Which workflows use each credential: what would break if you rotated or deleted it. nbuddyn never reads the secrets themselves.",
            "Qué workflows usan cada credencial: lo que se rompería si la cambiás o la borrás. nbuddyn nunca lee los secretos.",
            "Quais workflows usam cada credencial: o que quebraria se você a trocasse ou apagasse. O nbuddyn nunca lê os segredos.",
        ),
        col_credential: lang.pick(
            "Credential",
            "Credencial",
            "Credencial",
        ),
        col_used_by: lang.pick(
            "Used by",
            "La usan",
            "Usada por",
        ),
        unused: lang.pick(
            "no workflow uses it",
            "ningún workflow la usa",
            "nenhum workflow usa",
        ),
        cred_search: lang.pick(
            "Search a credential, a type or a workflow",
            "Buscar una credencial, un tipo o un workflow",
            "Buscar uma credencial, um tipo ou um workflow",
        ),
        no_credentials: lang.pick(
            "This n8n has no credentials yet.",
            "Este n8n todavía no tiene credenciales.",
            "Este n8n ainda não tem credenciais.",
        ),
        col_avg: lang.pick(
            "Average",
            "Promedio",
            "Média",
        ),
        col_slowest: lang.pick(
            "Slowest",
            "Más lenta",
            "Mais lenta",
        ),
        download_csv: lang.pick(
            "Download CSV",
            "Descargar CSV",
            "Baixar CSV",
        ),
        backup: lang.pick(
            "Backup",
            "Respaldo",
            "Backup",
        ),
        download_backup: lang.pick(
            "Download this n8n's history",
            "Descargar el historial de este n8n",
            "Baixar o histórico deste n8n",
        ),
        backup_help: lang.pick(
            "It is the same file nbuddyn keeps in its data directory. To restore it, put it back there while nbuddyn is stopped.",
            "Es el mismo archivo que nbuddyn guarda en su directorio de datos. Para restaurarlo, volvé a ponerlo ahí con nbuddyn detenido.",
            "É o mesmo arquivo que o nbuddyn guarda no diretório de dados. Para restaurar, coloque-o de volta lá com o nbuddyn parado.",
        ),
        show_password: lang.pick(
            "Show password",
            "Mostrar la clave",
            "Mostrar a senha",
        ),
        hide_password: lang.pick(
            "Hide password",
            "Ocultar la clave",
            "Ocultar a senha",
        ),
        first_scan_title: lang.pick(
            "Powering up the instruments",
            "Encendiendo instrumentos",
            "Ligando os instrumentos",
        ),
        first_scan_text: lang.pick(
            "nbuddyn is doing its first sweep of this n8n. It usually takes a few seconds, and this page updates by itself.",
            "nbuddyn está haciendo el primer barrido de este n8n. Suele tardar unos segundos, y esta página se actualiza sola.",
            "O nbuddyn está fazendo a primeira varredura deste n8n. Costuma levar alguns segundos, e esta página se atualiza sozinha.",
        ),
        scan_failed_title: lang.pick(
            "nbuddyn cannot read this n8n",
            "nbuddyn no puede leer este n8n",
            "O nbuddyn não consegue ler este n8n",
        ),
        scan_failed_text: lang.pick(
            "It keeps trying on every sweep. The reason is above; the database address is in Settings.",
            "Sigue intentando en cada barrido. El motivo está arriba; la dirección de la base está en Ajustes.",
            "Ele continua tentando a cada varredura. O motivo está acima; o endereço do banco está em Configurações.",
        ),
        logout: lang.pick(
            "Sign out",
            "Cerrar sesión",
            "Sair",
        ),
        users: lang.pick(
            "Users",
            "Usuarios",
            "Usuários",
        ),
        role_admin: lang.pick(
            "Administrator",
            "Administrador",
            "Administrador",
        ),
        role_viewer: lang.pick(
            "Read only",
            "Solo lectura",
            "Somente leitura",
        ),
        set_user: lang.pick(
            "User name",
            "Usuario",
            "Usuário",
        ),
        set_password: lang.pick(
            "Password",
            "Clave",
            "Senha",
        ),
        help_users: lang.pick(
            "An administrator can accept findings, change settings and manage users. Read only can look at everything else. Passwords need at least 10 characters.",
            "Un administrador puede aceptar hallazgos, cambiar ajustes y manejar usuarios. Solo lectura puede ver todo lo demás. Las claves necesitan al menos 10 caracteres.",
            "Um administrador pode aceitar achados, mudar configurações e gerenciar usuários. Somente leitura pode ver todo o resto. As senhas precisam de pelo menos 10 caracteres.",
        ),
        user_added: lang.pick(
            "User saved.",
            "Usuario guardado.",
            "Usuário salvo.",
        ),
        user_removed: lang.pick(
            "User removed.",
            "Usuario quitado.",
            "Usuário removido.",
        ),
        user_remove_confirm: lang.pick(
            "Remove this user? Their sessions end now.",
            "¿Quitar este usuario? Sus sesiones se cierran ahora.",
            "Remover este usuário? As sessões dele terminam agora.",
        ),
        users_env_note: lang.pick(
            "from the environment",
            "del entorno",
            "do ambiente",
        ),
        users_need_store: lang.pick(
            "Users cannot be added: nbuddyn has no data directory.",
            "No se pueden agregar usuarios: nbuddyn no tiene directorio de datos.",
            "Não é possível adicionar usuários: o nbuddyn não tem diretório de dados.",
        ),
        audit: lang.pick(
            "Audit log",
            "Registro de auditoría",
            "Registro de auditoria",
        ),
        audit_empty: lang.pick(
            "Nothing recorded yet.",
            "Todavía no hay nada registrado.",
            "Ainda não há nada registrado.",
        ),
        act_login: lang.pick(
            "signed in",
            "entró",
            "entrou",
        ),
        act_login_failed: lang.pick(
            "failed to sign in",
            "falló al entrar",
            "falhou ao entrar",
        ),
        act_logout: lang.pick(
            "signed out",
            "salió",
            "saiu",
        ),
        act_accept: lang.pick(
            "accepted a finding",
            "aceptó un hallazgo",
            "aceitou um achado",
        ),
        act_unaccept: lang.pick(
            "restored a finding",
            "restauró un hallazgo",
            "restaurou um achado",
        ),
        act_settings: lang.pick(
            "changed settings",
            "cambió ajustes",
            "mudou configurações",
        ),
        act_instance_add: lang.pick(
            "added an n8n",
            "agregó un n8n",
            "adicionou um n8n",
        ),
        act_instance_remove: lang.pick(
            "removed an n8n",
            "quitó un n8n",
            "removeu um n8n",
        ),
        act_user_add: lang.pick(
            "saved a user",
            "guardó un usuario",
            "salvou um usuário",
        ),
        act_user_remove: lang.pick(
            "removed a user",
            "quitó un usuario",
            "removeu um usuário",
        ),
        nav_activity: lang.pick(
            "Activity",
            "Actividad",
            "Atividade",
        ),
        changes_title: lang.pick(
            "Last 24 hours",
            "Últimas 24 horas",
            "Últimas 24 horas",
        ),
        changes_new: lang.pick(
            "new findings",
            "hallazgos nuevos",
            "achados novos",
        ),
        changes_resolved: lang.pick(
            "resolved",
            "resueltos",
            "resolvidos",
        ),
        changes_workflows: lang.pick(
            "workflow changes",
            "cambios en workflows",
            "mudanças em workflows",
        ),
        nothing_changed: lang.pick(
            "A quiet flight: nothing changed in this period.",
            "Vuelo tranquilo: no cambió nada en este período.",
            "Voo tranquilo: nada mudou neste período.",
        ),
        new_tag: lang.pick(
            "new",
            "nuevo",
            "novo",
        ),
        by: lang.pick(
            "by",
            "por",
            "por",
        ),
        was: lang.pick(
            "was",
            "antes",
            "antes",
        ),
        event_new: lang.pick(
            "New",
            "Nuevo",
            "Novo",
        ),
        event_resolved: lang.pick(
            "Resolved",
            "Resuelto",
            "Resolvido",
        ),
        activity_note: lang.pick(
            "nbuddyn compares each scan with the one before. Changes show up within one scan interval.",
            "nbuddyn compara cada barrido con el anterior. Los cambios aparecen dentro de un intervalo de barrido.",
            "O nbuddyn compara cada varredura com a anterior. As mudanças aparecem dentro de um intervalo de varredura.",
        ),
        instances: lang.pick(
            "Your n8n instances",
            "Tus n8n",
            "Os seus n8n",
        ),
        set_name: lang.pick(
            "Name",
            "Nombre",
            "Nome",
        ),
        set_database_url: lang.pick(
            "Database",
            "Base de datos",
            "Banco de dados",
        ),
        help_database_url: lang.pick(
            "As postgres://user:password@host:5432/n8n or sqlite:/path/database.sqlite. Use a read-only user. The password is never shown here.",
            "Como postgres://usuario:clave@host:5432/n8n o sqlite:/ruta/database.sqlite. Usá un usuario de solo lectura. La clave nunca se muestra acá.",
            "Como postgres://usuario:senha@host:5432/n8n ou sqlite:/caminho/database.sqlite. Use um usuário somente leitura. A senha nunca é mostrada aqui.",
        ),
        add_instance: lang.pick(
            "Add an n8n",
            "Agregar un n8n",
            "Adicionar um n8n",
        ),
        add: lang.pick(
            "Add",
            "Agregar",
            "Adicionar",
        ),
        remove_instance: lang.pick(
            "Remove",
            "Quitar",
            "Remover",
        ),
        remove_confirm: lang.pick(
            "Stop watching this n8n? Its history file stays on disk.",
            "¿Dejar de vigilar este n8n? Su archivo de historial queda en el disco.",
            "Parar de vigiar este n8n? O arquivo de histórico dele fica no disco.",
        ),
        instance_added: lang.pick(
            "Added. Its first scan is running.",
            "Agregado. Ya está corriendo su primer barrido.",
            "Adicionado. A primeira varredura já está rodando.",
        ),
        instance_removed: lang.pick(
            "Removed.",
            "Quitado.",
            "Removido.",
        ),
        first_scan: lang.pick(
            "first scan under way",
            "primer barrido en curso",
            "primeira varredura em andamento",
        ),
        sec_instance: lang.pick(
            "This n8n",
            "Este n8n",
            "Este n8n",
        ),
        sec_general: lang.pick(
            "General",
            "General",
            "Geral",
        ),
        urgent_short: lang.pick(
            "urgent",
            "urgentes",
            "urgentes",
        ),
        watching: lang.pick(
            "Watching",
            "Viendo",
            "Vendo",
        ),
        primary_note: lang.pick(
            "Set in the environment",
            "Se configura en el entorno",
            "Definido no ambiente",
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
