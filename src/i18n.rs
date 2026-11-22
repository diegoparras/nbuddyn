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

/// Title and advice for one check.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct CheckText {
    pub title: &'static str,
    pub advice: &'static str,
}

pub fn check_text(lang: Lang, check: &str) -> CheckText {
    let (title, advice) = match check {
        "public_entry_no_auth" => (
            lang.pick(
                "Public entry point without authentication",
                "Entrada pública sin autenticación",
                "Entrada pública sem autenticação",
            ),
            lang.pick(
                "Anyone who learns the URL can call it. Add authentication on the trigger node, or validate the caller inside the workflow.",
                "Cualquiera que conozca la dirección puede llamarla. Agregá autenticación en el nodo disparador, o validá a quien llama dentro del workflow.",
                "Qualquer pessoa que conheça o endereço pode chamá-la. Adicione autenticação no nó de gatilho, ou valide quem chama dentro do workflow.",
            ),
        ),
        "hardcoded_secret" => (
            lang.pick(
                "Secret written inside a node",
                "Clave escrita dentro de un nodo",
                "Chave escrita dentro de um nó",
            ),
            lang.pick(
                "Move it to an n8n credential so it is stored encrypted and does not travel with the workflow.",
                "Pasala a una credencial de n8n para que se guarde cifrada y no viaje con el workflow.",
                "Mova-a para uma credencial do n8n para que fique criptografada e não viaje com o workflow.",
            ),
        ),
        "no_error_workflow" => (
            lang.pick(
                "Active workflow without an error workflow",
                "Workflow activo sin workflow de error",
                "Workflow ativo sem workflow de erro",
            ),
            lang.pick(
                "If it fails, nobody is told. Assign an error workflow in its settings.",
                "Si falla, nadie recibe aviso. Asignale un workflow de error en su configuración.",
                "Se falhar, ninguém é avisado. Atribua um workflow de erro nas configurações.",
            ),
        ),
        "repeated_failures" => (
            lang.pick(
                "Workflow failing repeatedly",
                "Workflow que falla repetidamente",
                "Workflow falhando repetidamente",
            ),
            lang.pick(
                "Open its latest failed execution to see which node breaks. Expired credentials are a common cause.",
                "Abrí su última ejecución fallida para ver qué nodo se rompe. Una credencial vencida es una causa frecuente.",
                "Abra a última execução com falha para ver qual nó quebra. Credenciais expiradas são uma causa comum.",
            ),
        ),
        "stuck_execution" => (
            lang.pick(
                "Execution stuck for over an hour",
                "Ejecución trabada hace más de una hora",
                "Execução travada há mais de uma hora",
            ),
            lang.pick(
                "Check that workers and task runners are alive, then stop the execution if it will not finish.",
                "Revisá que los workers y los runners estén vivos, y detené la ejecución si no va a terminar.",
                "Verifique se os workers e os runners estão ativos, e pare a execução se ela não for terminar.",
            ),
        ),
        "removed_node_v3" => (
            lang.pick(
                "Node removed in n8n 3",
                "Nodo eliminado en n8n 3",
                "Nó removido no n8n 3",
            ),
            lang.pick(
                "The workflow fails when it runs. Replace the node with its current equivalent.",
                "El workflow falla al ejecutarse. Reemplazá el nodo por su equivalente actual.",
                "O workflow falha ao executar. Substitua o nó pelo equivalente atual.",
            ),
        ),
        "plaintext_http" => (
            lang.pick(
                "Unencrypted call to an external host",
                "Llamada sin cifrar a un destino externo",
                "Chamada sem criptografia a um destino externo",
            ),
            lang.pick(
                "Data travels readable over the network. Use https:// if the destination supports it.",
                "Los datos viajan legibles por la red. Usá https:// si el destino lo admite.",
                "Os dados trafegam legíveis pela rede. Use https:// se o destino suportar.",
            ),
        ),
        "no_mfa" => (
            lang.pick(
                "Users without two-factor authentication",
                "Usuarios sin doble factor",
                "Usuários sem autenticação de dois fatores",
            ),
            lang.pick(
                "Enable it under Settings > Personal, especially for owner accounts.",
                "Activalo en Settings > Personal, sobre todo en las cuentas dueñas.",
                "Ative em Settings > Personal, principalmente nas contas proprietárias.",
            ),
        ),
        "env_access" => (
            lang.pick(
                "Node reads server environment variables",
                "Nodo que lee variables de entorno del servidor",
                "Nó que lê variáveis de ambiente do servidor",
            ),
            lang.pick(
                "It stops working when environment access is blocked, and it can expose server secrets when it is not.",
                "Deja de funcionar si el acceso al entorno está bloqueado, y puede exponer claves del servidor si no lo está.",
                "Deixa de funcionar se o acesso ao ambiente estiver bloqueado, e pode expor chaves do servidor se não estiver.",
            ),
        ),
        "unused_credential" => (
            lang.pick(
                "Credential not used by any workflow",
                "Credencial que ningún workflow usa",
                "Credencial não usada por nenhum workflow",
            ),
            lang.pick(
                "Delete it if nothing else needs it. Credentials used by n8n itself, such as the assistant's, also appear here.",
                "Borrala si nada más la necesita. Las que usa el propio n8n, como las del asistente, también aparecen acá.",
                "Exclua se nada mais precisar dela. As usadas pelo próprio n8n, como as do assistente, também aparecem aqui.",
            ),
        ),
        "command_execution" => (
            lang.pick(
                "Node runs system commands",
                "Nodo que ejecuta comandos del sistema",
                "Nó que executa comandos do sistema",
            ),
            lang.pick(
                "Expected for some workflows. Make sure only trusted people can edit it.",
                "Es esperable en algunos workflows. Asegurate de que solo gente de confianza pueda editarlo.",
                "É esperado em alguns workflows. Garanta que só pessoas de confiança possam editá-lo.",
            ),
        ),
        _ => ("", ""),
    };
    CheckText { title, advice }
}

/// Labels for the web page, sent with every report so the page holds no text of its own.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct UiText {
    pub tagline: &'static str,
    pub score: &'static str,
    pub generated: &'static str,
    pub findings: &'static str,
    pub nothing: &'static str,
    pub workflows: &'static str,
    pub active: &'static str,
    pub credentials: &'static str,
    pub users: &'static str,
    pub nodes: &'static str,
    pub waiting: &'static str,
    pub high: &'static str,
    pub medium: &'static str,
    pub low: &'static str,
    pub info: &'static str,
    pub inactive: &'static str,
    pub read_only: &'static str,
    pub unavailable: &'static str,
    pub language: &'static str,
}

pub fn ui_text(lang: Lang) -> UiText {
    UiText {
        tagline: lang.pick(
            "Read-only cockpit for n8n",
            "Cabina de solo lectura para n8n",
            "Cabine somente leitura para n8n",
        ),
        score: lang.pick("Score", "Puntaje", "Pontuação"),
        generated: lang.pick("Last check", "Último chequeo", "Última verificação"),
        findings: lang.pick("Findings", "Hallazgos", "Achados"),
        nothing: lang.pick(
            "Nothing to report.",
            "Nada para reportar.",
            "Nada a relatar.",
        ),
        workflows: lang.pick("Workflows", "Workflows", "Workflows"),
        active: lang.pick("Active", "Activos", "Ativos"),
        credentials: lang.pick("Credentials", "Credenciales", "Credenciais"),
        users: lang.pick("Users", "Usuarios", "Usuários"),
        nodes: lang.pick("Nodes", "Nodos", "Nós"),
        waiting: lang.pick(
            "Waiting executions",
            "Ejecuciones en espera",
            "Execuções em espera",
        ),
        high: lang.pick("High", "Alta", "Alta"),
        medium: lang.pick("Medium", "Media", "Média"),
        low: lang.pick("Low", "Baja", "Baixa"),
        info: lang.pick("Info", "Informativo", "Informativo"),
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHECKS: &[&str] = &[
        "public_entry_no_auth",
        "hardcoded_secret",
        "no_error_workflow",
        "repeated_failures",
        "stuck_execution",
        "removed_node_v3",
        "plaintext_http",
        "no_mfa",
        "env_access",
        "unused_credential",
        "command_execution",
    ];

    #[test]
    fn language_codes_are_parsed_leniently() {
        assert_eq!(Lang::parse("es-AR"), Lang::Es);
        assert_eq!(Lang::parse("PT_br"), Lang::Pt);
        assert_eq!(Lang::parse("fr"), Lang::En);
        assert_eq!(Lang::parse(""), Lang::En);
    }

    #[test]
    fn every_check_is_translated_in_every_language() {
        for check in CHECKS {
            let texts: Vec<CheckText> = [Lang::En, Lang::Es, Lang::Pt]
                .iter()
                .map(|l| check_text(*l, check))
                .collect();
            for text in &texts {
                assert!(!text.title.is_empty(), "{check} has no title");
                assert!(!text.advice.is_empty(), "{check} has no advice");
            }
            assert_ne!(
                texts[0].title, texts[1].title,
                "{check} title not translated to Spanish"
            );
            assert_ne!(
                texts[0].advice, texts[2].advice,
                "{check} advice not translated to Portuguese"
            );
        }
    }
}
