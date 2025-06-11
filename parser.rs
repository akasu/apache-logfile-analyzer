use lazy_static::lazy_static;
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LogType {
    Access,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LogEntry {
    pub log_type: LogType,
    pub timestamp: String, // Für Einfachheit als String, könnte chrono::DateTime sein

    // Access log fields
    pub ip_address: String,
    pub method: String,
    pub path: String,
    pub protocol: String,
    pub status_code: u16,
    pub user_agent: String,

    // Error log fields
    pub level: String,  // z.B. [error], [warn], [notice]
    pub module: String, // z.B. [core:error]
    pub message: String, // Die eigentliche Fehlermeldung
                        // Weitere Felder nach Bedarf (z.B. referrer, bytes_sent)
}

lazy_static! {
    // Regex für Apache Access-Logformat (Combined Log Format mit referer und user-agent).
    // Beispiel: 57.141.0.15 - - [11/Jun/2025:00:00:08 +0200] "GET /path HTTP/1.1" 200 74369 "-" "Mozilla..."
    static ref ACCESS_LOG_REGEX: Regex = Regex::new(
        r#"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" (?P<status>\d{3}) \S+ "(?:[^"]*)" "(?P<useragent>[^"]*)""#
    ).unwrap();

    // Regex für ein gängiges Apache Error-Logformat
    // Beispiel: [Wed Oct 11 14:32:52 2000] [error] [client 127.0.0.1] client denied by server configuration: /export/home/live/ap/htdocs/test
    static ref ERROR_LOG_REGEX: Regex = Regex::new(
        r#"\[(?P<time>[^\]]+)\] \[(?P<level>[^\]]+)\] (?:\[(?P<module>[^\]]+)\] )?(?:\[client (?P<ip>[^\]]+)\] )?(?P<message>.*)"#
    ).unwrap();

    // Regex für Apache Access Log Zeitformat: 11/Jun/2025:00:00:08 +0200
    static ref ACCESS_TIME_REGEX: Regex = Regex::new(
        r#"(\d{1,2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*[+-]\d{4}"#
    ).unwrap();

    // Regex für Apache Error Log Zeitformat: Wed Jun 11 00:00:26.842501 2025
    static ref ERROR_TIME_REGEX: Regex = Regex::new(
        r#"\w{3}\s+\w{3}\s+\d{1,2}\s+(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?\s+\d{4}"#
    ).unwrap();

    // Alte TIME_REGEX für Rückwärtskompatibilität (falls andere Teile sie verwenden)
    static ref TIME_REGEX: Regex = Regex::new(r#"(\d{2}):(\d{2}):(\d{2})"#).unwrap();

    // ========== ERWEITERTE ANGRIFFSERKENNUNG (2024-2025) ==========

    // SQL Injection Patterns
    static ref SQL_INJECTION_REGEX: Regex = Regex::new(
        r#"(?i)(?:^|\s|;|=|&|\?|"|\()(union\s+select|union\s+all\s+select|select\s+[^\/\.\s][^\/]*?\s+from\s+|insert\s+into\s+|update\s+[^\/\.\s][^\/]*?\s+set\s+|delete\s+from\s+|drop\s+table|drop\s+database|truncate\s+table|\s+or\s+1\s*=\s*1|\s+or\s+'1'\s*=\s*'1'|\s+or\s+"1"\s*=\s*"1"|\s+and\s+1\s*=\s*1|\s+and\s+'1'\s*=\s*'1'|exec\s*\(|execute\s*\(|sp_executesql|waitfor\s+delay|sleep\s*\(|benchmark\s*\(|load_file\s*\(|into\s+outfile|into\s+dumpfile|\/\*[\s\S]*?\*\/|--[\s\r\n]|#[\s\r\n]|(?:^|\s|=|&|\?|"|;|\()0x[0-9a-f]{2,}|char\s*\(|concat\s*\(|ascii\s*\(|information_schema|mysql\.user|pg_catalog|sysobjects|sys\.|@@version|@@user|user\s*\(\)|extractvalue\s*\(|updatexml\s*\(|exp\s*\(|\$\{.*?\}|\#\{.*?\}|procedure\s+analyse|group_concat\s*\()(?:\s|$|;|&|"|>|\))"#
    ).unwrap();

    // XSS Patterns
    static ref XSS_REGEX: Regex = Regex::new(
    r#"(?i)(<script[^>]*>|</script>|javascript\s*:|data\s*:|on\w+\s*=\s*["']|onerror\s*=\s*["']|onload\s*=\s*["']|onclick\s*=\s*["']|onmouseover\s*=\s*["']|alert\s*\(\s*["']|confirm\s*\(\s*["']|prompt\s*\(\s*["']|eval\s*\(\s*["']|setTimeout\s*\(\s*["']|document\.(?:cookie|write|location)|window\.(?:location|open|eval)|String\.fromCharCode\(|unescape\s*\(\s*["']|decodeURI\(|&lt;script|&#x[0-9a-f]+;|&#\d+;|<svg[^>]*onload|<img[^>]*onerror|<iframe[^>]*onload|expression\s*\(|behavior\s*:|vbscript\s*:|livescript\s*:)"#
).unwrap();

    // Path Traversal Patterns
    // Path Traversal Patterns
    static ref PATH_TRAVERSAL_REGEX: Regex = Regex::new(
        r#"(?:^|[?&;]|\s+|=)(?:\.\.\/|\.\.\%2f|\.\.\\|\.\.\%5c|%2e%2e%2f|%2e%2e%5c|%c0%ae%c0%ae\/|%c0%ae%c0%ae\\|%c1%9c|%e0%80%af|\.\.%c0%af|\.\.%e0%80%af|\.\.%c1%9c|\/etc\/passwd|\/etc\/shadow|\/etc\/hosts|c:\\windows\\system32\\|c:\/windows\/system32\/|\\boot\.ini|\\autoexec\.bat|\\config\.sys|file:\/\/\/|php:\/\/filter|php:\/\/input|expect:\/\/|zip:\/\/|phar:\/\/|data:\/\/|glob:\/\/|proc\/self\/|proc\/version|proc\/meminfo|\/\.\.\/|%00|\\x00|\x00)"#
    ).unwrap();

    // Command Injection Patterns
    static ref COMMAND_INJECTION_REGEX: Regex = Regex::new(
        r#"(?:^|[;&`|]|\s+|=)(?:(?:;|\&\&|\|\||\`|\$\(|\$\{)(?:\s*[a-zA-Z0-9_\-]+)?|(?:\/bin\/|\/usr\/bin\/|\/sbin\/|cmd\.exe|powershell\.exe)(?:\s+[a-zA-Z0-9_\-]+)?|(?:bash|sh|cmd|powershell|pwsh)(?:\s+\-c|\s+\/c)(?:\s+[\'\"\\])?|(?:nc|netcat)\s+(?:\-e|\-c|\-l|\-p|\-z)(?:\s+[0-9]+)?|(?:wget|curl)\s+(?:\-O|\-o|\-s|\-S|\-\-output)(?:\s+[\'\"\\])?|(?:python|perl|ruby|php)\s+(?:\-e|\-c|\-r|\-\-eval|\-\-command|\-\-exec)(?:\s+[\'\"\\])?|\$\{IFS\}|\$\{PATH\}|\$\{HOME\}|\$\{USER\}|\/dev\/(?:tcp|udp)\/[0-9\.]+\/[0-9]+)"#
    ).unwrap();

    // NoSQL Injection Patterns
    static ref NOSQL_INJECTION_REGEX: Regex = Regex::new(
        r#"(?i)(?:^|[?&;]|\s+|=)(?:\$(?:where|regex|ne|gt|lt|gte|lte|in|nin|and|or|nor|not|exists|type|expr|jsonSchema|text|search|geoWithin|geoIntersects|near|nearSphere|all|elemMatch|size|bitsAllSet|bitsAnySet|bitsAllClear|bitsAnyClear|comment|rand|natural|explain|max|min|orderby|query|currentDate|inc|mul|rename|set|setOnInsert|unset|eval|function|accumulator)(?:\s*:|\s*\(|\s*=)|\{\s*\$|\[\s*\{|\{\s*["']?\$|db\.(?:getCollection|getUser|getMongo|runCommand|auth|addUser|removeUser|createCollection|createUser|dropUser|dropDatabase|eval|shutdownServer)|rs\.(?:slaveOk|initiate|reconfig|status|stepDown|freeze|add|remove|syncFrom)|sh\.(?:addShard|removeShard|status|stopBalancer|setBalancerState)|sleep\s*\(\s*[0-9]+\s*\)|benchmark\s*\(\s*[0-9]+\s*,|\{\s*\}\s*;\s*(?:while|for)\s*\(|\{\s*\$\w+\s*:\s*(?:true|false|1|0|-1|null|undefined|NaN|Infinity|new|this|constructor|prototype|__proto__|__defineGetter__|__defineSetter__|__lookupGetter__|__lookupSetter__|toString|valueOf|hasOwnProperty|isPrototypeOf|propertyIsEnumerable))"#
    ).unwrap();

    // LDAP Injection Patterns
    static ref LDAP_INJECTION_REGEX: Regex = Regex::new(
        r#"(?:^|[?&;]|\s+|=)(?:(?:\*\)|\(\*|&\(|\|\(|\!\()(?:[^a-zA-Z0-9]|$)|(?:cn|sn|givenName|mail|uid|objectClass|memberOf|userPassword|shadowLastChange|shadowMax|shadowExpire|sambaNTPassword|sambaLMPassword|userAccountControl|pwdLastSet|memberUid|uniqueMember|member)=\*(?:[^a-zA-Z0-9]|$)|(?:\)\)|\(\(|&\(&|\|\(\|)(?:[^a-zA-Z0-9]|$)|(?:admin|root|user|guest|administrator|backup|bin|daemon|adm|lp|sync|shutdown|halt|mail|news|uucp|operator|games|man|postmaster|proxy|www-data|apache|nginx|mysql|postgres|oracle|ftp|ssh|sshd|nobody)\*(?:[^a-zA-Z0-9]|$)|\*(?:admin|root|user|guest|administrator|backup|bin|daemon|adm|lp|sync|shutdown|halt|mail|news|uucp|operator|games|man|postmaster|proxy|www-data|apache|nginx|mysql|postgres|oracle|ftp|ssh|sshd|nobody)(?:[^a-zA-Z0-9]|$)|[^a-zA-Z0-9]objectCategory=(?:person|computer|group|organizationalUnit|container|domainDNS|certificationAuthority)(?:[^a-zA-Z0-9]|$))"#
    ).unwrap();

    // XXE Injection Patterns
    static ref XXE_INJECTION_REGEX: Regex = Regex::new(
        r#"(?i)(?:<!(?:entity|doctype|element|attlist|notation)\s+(?:\w+\s+)*(?:system|public)\s+["'](?:file|https?|ftp|php|data|jar|netdoc|expect|gopher|zip|phar):\/\/|\[<!entity\s+(?:%\s*)?\w+\s+(?:system|public)\s+["']|\&\#(?:x[0-9a-f]{1,4}|[0-9]{1,5});|<!entity\s+(?:%\s*)?\w+\s+(?:system|public)|<!DOCTYPE[^>]+\[|<!DOCTYPE[^>]+SYSTEM\s+["']|<!DOCTYPE[^>]+PUBLIC\s+["']|<\?xml(?:\s+version=["'][^"']*["'])?\s+(?:encoding=["'][^"']*["'])?\s+(?:standalone=["'][^"']*["'])?\s*\?>)"#
    ).unwrap();

    // SSTI (Server-Side Template Injection) Patterns
    static ref SSTI_INJECTION_REGEX: Regex = Regex::new(
        r#"(?:\{\{\s*(?:config|self|request|session|url_for|g|get_flashed_messages|lipsum|cycler|joiner|namespace|dict|range|7\*7|7\+7|7-6|7\/1)|\{\{\s*[\d\+\-\*\/\(\)]+\s*\}\}|\{\{\s*__(?:class__|mro__|globals__|subclasses__|import__)|\{\{\s*open\s*\(|\{\%\s*(?:for|if|macro|set|with|block|extends|include|import|from|autoescape|filter|raw)\s+|\{\%\s*(?:end(?:for|if|macro|set|with|block|autoescape|filter|raw))|\{\#.*?\#\}|\$\{\s*(?:[a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*|[\d\+\-\*\/\(\)]+|__(?:class__|mro__|globals__|subclasses__|import__)|open\s*\())"#
    ).unwrap();

    // Log Poisoning Patterns
    static ref LOG_POISONING_REGEX: Regex = Regex::new(
        r#"(?:<\?(?:php|=).*?\?>|<\?.*?\?>|<%.*?%>|<script\s+(?:runat|language)=(?:["']?(?:php|vbscript|jscript)["']?).*?>|\$\{jndi:(?:ldap|rmi|dns|iiop|corba|nds|http|https):\/\/|(?:^|[;&`|]|\s+|=)(?:system|exec|passthru|shell_exec|popen|proc_open|pcntl_exec|eval|assert)\s*\(|(?:%0[ad]|\\r|\\n){2,}|User-Agent\s*:\s*(?:[\r\n]+|.*?(?:%0[ad]|\\r|\\n)))"#
    ).unwrap();

    // Header Injection Patterns
    static ref HEADER_INJECTION_REGEX: Regex = Regex::new(
        r#"(?:(?:%0[ad]|\\r|\\n){2,}|(?:%0[ad]|\\r|\\n)(?:(?:Set-Cookie|Location|Content-Type|Content-Disposition|Content-Length|X-XSS-Protection|X-Frame-Options|X-Content-Type-Options|Refresh|Window-target|Content-Security-Policy|Access-Control-Allow-Origin|Access-Control-Allow-Credentials|Access-Control-Expose-Headers|Access-Control-Max-Age|Access-Control-Allow-Methods|Access-Control-Allow-Headers)\s*:|HTTP/[0-9.]+\s+[0-9]+)|(?:^|[?&;]|\s+|=)(?:Set-Cookie|Location|Content-Type|Content-Disposition|Content-Length|X-XSS-Protection|X-Frame-Options|X-Content-Type-Options|Refresh|Window-target|Content-Security-Policy|Access-Control-Allow-Origin|Access-Control-Allow-Credentials|Access-Control-Expose-Headers|Access-Control-Max-Age|Access-Control-Allow-Methods|Access-Control-Allow-Headers)\s*:\s*(?:[^;\s]|$))"#
    ).unwrap();

    // SSRF Patterns
    static ref SSRF_REGEX: Regex = Regex::new(
        r#"(?:^|[?&;=]|\s+|"|')(?:https?|ftp|php|data|file|dict|gopher|ws|wss|jar|ldap|ldaps|tftp|ssh|telnet|smtp|imap|pop3|vnc|redis):\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1|%3A%3A1|169\.254\.|192\.168\.|10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.|%40|@|%2F%2Flocalhost|%2F%2F127\.0\.0\.1|%2F%2F0\.0\.0\.0|%2F%2F::1|%2F%2F%3A%3A1)"#
    ).unwrap();
}

pub fn parse_log_line(line: &str) -> Option<LogEntry> {
    // Versuche zuerst, die Zeile als Access-Log zu parsen
    if let Some(caps) = ACCESS_LOG_REGEX.captures(line) {
        return Some(LogEntry {
            log_type: LogType::Access,
            ip_address: caps
                .name("ip")
                .map_or_else(String::new, |m| m.as_str().to_string()),
            timestamp: caps
                .name("time")
                .map_or_else(String::new, |m| m.as_str().to_string()),
            method: caps
                .name("method")
                .map_or_else(String::new, |m| m.as_str().to_string()),
            path: caps
                .name("path")
                .map_or_else(String::new, |m| m.as_str().to_string()),
            protocol: caps
                .name("protocol")
                .map_or_else(String::new, |m| m.as_str().to_string()),
            status_code: caps
                .name("status")
                .map_or(0, |m| m.as_str().parse().unwrap_or(0)),
            user_agent: caps
                .name("useragent")
                .map_or_else(String::new, |m| m.as_str().to_string()),
            // Leere Werte für Error-Log-Felder
            level: String::new(),
            module: String::new(),
            message: String::new(),
        });
    }

    // Wenn es kein Access-Log ist, versuche es als Error-Log zu parsen
    if let Some(caps) = ERROR_LOG_REGEX.captures(line) {
        return Some(LogEntry {
            log_type: LogType::Error,
            timestamp: caps
                .name("time")
                .map_or_else(String::new, |m| m.as_str().to_string()),
            level: caps
                .name("level")
                .map_or_else(String::new, |m| m.as_str().to_string()),
            module: caps
                .name("module")
                .map_or_else(String::new, |m| m.as_str().to_string()),
            message: caps
                .name("message")
                .map_or_else(String::new, |m| m.as_str().to_string()),
            // IP-Adresse kann in Error-Logs vorhanden sein (als [client IP])
            ip_address: caps
                .name("ip")
                .map_or_else(String::new, |m| m.as_str().to_string()),
            // Leere Werte für Access-Log-Felder
            method: String::new(),
            path: String::new(),
            protocol: String::new(),
            status_code: 0,
            user_agent: String::new(),
        });
    }

    // Wenn die Zeile weder als Access-Log noch als Error-Log geparst werden kann, gib None zurück
    None
}

pub fn group_by_ip(entries: &[LogEntry]) -> HashMap<String, Vec<LogEntry>> {
    let mut grouped = HashMap::new();
    for entry in entries {
        grouped
            .entry(entry.ip_address.clone())
            .or_insert_with(Vec::new)
            .push(entry.clone());
    }
    grouped
}

pub fn group_by_user_agent(entries: &[LogEntry]) -> HashMap<String, Vec<LogEntry>> {
    let mut grouped = HashMap::new();
    for entry in entries {
        grouped
            .entry(entry.user_agent.clone())
            .or_insert_with(Vec::new)
            .push(entry.clone());
    }
    grouped
}

pub fn filter_errors(entries: &[LogEntry]) -> Vec<LogEntry> {
    entries
        .iter()
        .filter(|e| e.status_code >= 400)
        .cloned()
        .collect()
}

pub fn filter_by_http_status(entries: &[LogEntry], status_code: u16) -> Vec<LogEntry> {
    entries
        .iter()
        .filter(|e| e.status_code == status_code)
        .cloned()
        .collect()
}

pub fn filter_by_time_range(
    entries: &[LogEntry],
    start_time: &str,
    end_time: &str,
) -> Vec<LogEntry> {
    println!("DEBUG: Filtere von '{}' bis '{}'", start_time, end_time);

    let filtered: Vec<LogEntry> = entries
        .iter()
        .filter(|e| {
            // Versuche zuerst Access Log Format (11/Jun/2025:00:00:08 +0200)
            if let Some(caps) = ACCESS_TIME_REGEX.captures(&e.timestamp) {
                // Neue Gruppierung: Tag/Monat/Jahr:Stunde:Minute:Sekunde Timezone
                // Gruppen: 1=Tag, 2=Monat, 3=Jahr, 4=Stunde, 5=Minute, 6=Sekunde
                let hour = caps
                    .get(4)
                    .map_or(0, |m| m.as_str().parse::<u32>().unwrap_or(0));
                let minute = caps
                    .get(5)
                    .map_or(0, |m| m.as_str().parse::<u32>().unwrap_or(0));
                let second = caps
                    .get(6)
                    .map_or(0, |m| m.as_str().parse::<u32>().unwrap_or(0));

                let entry_time = format!("{:02}:{:02}:{:02}", hour, minute, second);
                let in_range = is_time_in_range(&entry_time, start_time, end_time);

                println!(
                    "DEBUG: Access Log - Zeit: {} | In Range: {}",
                    entry_time, in_range
                );
                return in_range;
            }

            // Versuche Error Log Format (Wed Jun 11 00:00:26.842501 2025)
            if let Some(caps) = ERROR_TIME_REGEX.captures(&e.timestamp) {
                let hour = caps
                    .get(1)
                    .map_or(0, |m| m.as_str().parse::<u32>().unwrap_or(0));
                let minute = caps
                    .get(2)
                    .map_or(0, |m| m.as_str().parse::<u32>().unwrap_or(0));
                let second = caps
                    .get(3)
                    .map_or(0, |m| m.as_str().parse::<u32>().unwrap_or(0));

                let entry_time = format!("{:02}:{:02}:{:02}", hour, minute, second);
                let in_range = is_time_in_range(&entry_time, start_time, end_time);

                println!(
                    "DEBUG: Error Log - Zeit: {} | In Range: {}",
                    entry_time, in_range
                );
                return in_range;
            }

            // Fallback: Versuche die alte TIME_REGEX für andere Formate
            if let Some(caps) = TIME_REGEX.captures(&e.timestamp) {
                let hour = caps
                    .get(1)
                    .map_or(0, |m| m.as_str().parse::<u32>().unwrap_or(0));
                let minute = caps
                    .get(2)
                    .map_or(0, |m| m.as_str().parse::<u32>().unwrap_or(0));
                let second = caps
                    .get(3)
                    .map_or(0, |m| m.as_str().parse::<u32>().unwrap_or(0));

                let entry_time = format!("{:02}:{:02}:{:02}", hour, minute, second);
                let in_range = is_time_in_range(&entry_time, start_time, end_time);

                println!(
                    "DEBUG: Fallback - Zeit: {} | In Range: {}",
                    entry_time, in_range
                );
                return in_range;
            }

            // Wenn keines der Formate matcht, Eintrag ausschließen
            println!("DEBUG: Kein Regex-Match für Timestamp: '{}'", e.timestamp);
            false
        })
        .cloned()
        .collect();

    println!(
        "DEBUG: {} von {} Einträgen gefiltert",
        filtered.len(),
        entries.len()
    );
    filtered
}

fn is_time_in_range(time: &str, start: &str, end: &str) -> bool {
    // Konvertiere Zeit-Strings zu vergleichbaren Werten
    let time_val = time_to_seconds(time);
    let start_val = time_to_seconds(start);
    let end_val = time_to_seconds(end);

    // Handle Zeitbereich über Mitternacht hinweg
    if start_val <= end_val {
        // Normaler Zeitbereich (z.B. 09:00 bis 17:00)
        time_val >= start_val && time_val <= end_val
    } else {
        // Zeitbereich über Mitternacht (z.B. 22:00 bis 06:00)
        time_val >= start_val || time_val <= end_val
    }
}

fn time_to_seconds(time_str: &str) -> u32 {
    let parts: Vec<&str> = time_str.split(':').collect();
    if parts.len() != 3 {
        return 0;
    }

    let hours = parts[0].parse::<u32>().unwrap_or(0);
    let minutes = parts[1].parse::<u32>().unwrap_or(0);
    let seconds = parts[2].parse::<u32>().unwrap_or(0);

    hours * 3600 + minutes * 60 + seconds
}

pub fn detect_injection_attempts(entries: &[LogEntry]) -> Vec<LogEntry> {
    entries
        .iter()
        .filter(|e| {
            // Kombiniere alle zu durchsuchenden Felder
            let search_text = format!("{} {} {} {}", e.path, e.user_agent, e.message, e.ip_address);

            // URL-Dekodierung für bessere Erkennung
            let decoded_text = url_decode(&search_text);
            let full_text = format!("{} {}", search_text, decoded_text);

            // Prüfe alle Angriffsarten
            is_sql_injection(&full_text)
                || is_xss_attack(&full_text)
                || is_path_traversal(&full_text)
                || is_command_injection(&full_text)
                || is_nosql_injection(&full_text)
                || is_ldap_injection(&full_text)
                || is_xxe_injection(&full_text)
                || is_ssti_injection(&full_text)
                || is_log_poisoning(&full_text)
                || is_header_injection(&full_text)
                || is_ssrf_attack(&full_text)
                || is_suspicious_user_agent(&e.user_agent)
        })
        .cloned()
        .collect()
}

// Spezielle Erkennungsfunktionen für verschiedene Angriffstypen
fn is_sql_injection(text: &str) -> bool {
    SQL_INJECTION_REGEX.is_match(text)
}

fn is_xss_attack(text: &str) -> bool {
    XSS_REGEX.is_match(text)
}

fn is_path_traversal(text: &str) -> bool {
    PATH_TRAVERSAL_REGEX.is_match(text)
}

fn is_command_injection(text: &str) -> bool {
    COMMAND_INJECTION_REGEX.is_match(text)
}

fn is_nosql_injection(text: &str) -> bool {
    NOSQL_INJECTION_REGEX.is_match(text)
}

fn is_ldap_injection(text: &str) -> bool {
    LDAP_INJECTION_REGEX.is_match(text)
}

fn is_xxe_injection(text: &str) -> bool {
    XXE_INJECTION_REGEX.is_match(text)
}

fn is_ssti_injection(text: &str) -> bool {
    SSTI_INJECTION_REGEX.is_match(text)
}

fn is_log_poisoning(text: &str) -> bool {
    LOG_POISONING_REGEX.is_match(text)
}

fn is_header_injection(text: &str) -> bool {
    HEADER_INJECTION_REGEX.is_match(text)
}

fn is_ssrf_attack(text: &str) -> bool {
    SSRF_REGEX.is_match(text)
}

fn is_suspicious_user_agent(user_agent: &str) -> bool {
    let ua_lower = user_agent.to_lowercase();

    // Specific security tools and vulnerability scanners
    let security_tools = [
        "sqlmap",
        "nikto",
        "dirb",
        "gobuster",
        "nessus",
        "nmap",
        "masscan",
        "owasp zap",
        "burpsuite",
        "burp proxy",
        "w3af",
        "acunetix",
        "nuclei",
        "metasploit",
        "hydra",
        "dirbuster",
        "wfuzz",
        "skipfish",
        "arachni",
        "wpscan",
        "joomscan",
        "droopescan",
    ];

    // Suspicious patterns that indicate potential malicious activity
    let suspicious_patterns = [
        "vulnerability",
        "pentest",
        "security scan",
        "exploit",
        "attack",
        "hack",
        "shell",
        "backdoor",
        "malware",
        "payload",
        "injection",
    ];

    // Check for security tools
    if security_tools.iter().any(|&tool| ua_lower.contains(tool)) {
        return true;
    }

    // Check for suspicious patterns
    if suspicious_patterns.iter().any(|&pattern| ua_lower.contains(pattern)) {
        return true;
    }

    // Check for empty or extremely short user agents (often used in attacks)
    if user_agent.len() < 5 {
        return true;
    }

    // Check for user agents that claim to be common tools but are suspiciously formatted
    // This helps avoid flagging legitimate wget/curl usage
    if (ua_lower.contains("wget") || ua_lower.contains("curl")) && 
       (ua_lower.len() < 20 || !ua_lower.contains("mozilla") && !ua_lower.contains("http")) {
        return true;
    }

    // Don't flag legitimate bots like Googlebot, Bingbot, etc.
    if (ua_lower.contains("bot") || ua_lower.contains("crawler") || ua_lower.contains("spider")) && 
       !(ua_lower.contains("googlebot") || 
         ua_lower.contains("bingbot") || 
         ua_lower.contains("yandexbot") || 
         ua_lower.contains("baiduspider") || 
         ua_lower.contains("facebookexternalhit") || 
         ua_lower.contains("twitterbot") || 
         ua_lower.contains("applebot") || 
         ua_lower.contains("msnbot") || 
         ua_lower.contains("slurp") ||
         ua_lower.contains("duckduckbot") ||
         ua_lower.contains("semrushbot") ||
         ua_lower.contains("blexbot") ||
         ua_lower.contains("ahrefsbot") ||
         ua_lower.contains("petalbot") ||
         ua_lower.contains("sistrix") ||
         ua_lower.contains("externalagent")) {
        return true;
    }

    false
}

// URL-Dekodierungsfunktion
fn url_decode(input: &str) -> String {
    let mut result = String::new();
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '%' {
            if let (Some(h1), Some(h2)) = (chars.next(), chars.next()) {
                if let (Some(d1), Some(d2)) = (h1.to_digit(16), h2.to_digit(16)) {
                    let byte = (d1 * 16 + d2) as u8;
                    if byte.is_ascii() {
                        result.push(byte as char);
                        continue;
                    }
                }
            }
        }
        result.push(ch);
    }

    result
}

// Spezifische Filter für verschiedene Angriffstypen
pub fn filter_sql_injection_attempts(entries: &[LogEntry]) -> Vec<LogEntry> {
    entries
        .iter()
        .filter(|e| {
            let search_text = format!("{} {} {}", e.path, e.user_agent, e.message);
            let decoded_text = url_decode(&search_text);
            let full_text = format!("{} {}", search_text, decoded_text);
            is_sql_injection(&full_text)
        })
        .cloned()
        .collect()
}

pub fn filter_xss_attempts(entries: &[LogEntry]) -> Vec<LogEntry> {
    entries
        .iter()
        .filter(|e| {
            let search_text = format!("{} {} {}", e.path, e.user_agent, e.message);
            let decoded_text = url_decode(&search_text);
            let full_text = format!("{} {}", search_text, decoded_text);
            is_xss_attack(&full_text)
        })
        .cloned()
        .collect()
}

pub fn filter_path_traversal_attempts(entries: &[LogEntry]) -> Vec<LogEntry> {
    entries
        .iter()
        .filter(|e| {
            let search_text = format!("{} {} {}", e.path, e.user_agent, e.message);
            let decoded_text = url_decode(&search_text);
            let full_text = format!("{} {}", search_text, decoded_text);
            is_path_traversal(&full_text)
        })
        .cloned()
        .collect()
}

pub fn filter_command_injection_attempts(entries: &[LogEntry]) -> Vec<LogEntry> {
    entries
        .iter()
        .filter(|e| {
            let search_text = format!("{} {} {}", e.path, e.user_agent, e.message);
            let decoded_text = url_decode(&search_text);
            let full_text = format!("{} {}", search_text, decoded_text);
            is_command_injection(&full_text)
        })
        .cloned()
        .collect()
}

pub fn filter_nosql_injection_attempts(entries: &[LogEntry]) -> Vec<LogEntry> {
    entries
        .iter()
        .filter(|e| {
            let search_text = format!("{} {} {}", e.path, e.user_agent, e.message);
            let decoded_text = url_decode(&search_text);
            let full_text = format!("{} {}", search_text, decoded_text);
            is_nosql_injection(&full_text)
        })
        .cloned()
        .collect()
}

pub fn filter_suspicious_user_agents(entries: &[LogEntry]) -> Vec<LogEntry> {
    entries
        .iter()
        .filter(|e| is_suspicious_user_agent(&e.user_agent))
        .cloned()
        .collect()
}

pub fn filter_ldap_injection_attempts(entries: &[LogEntry]) -> Vec<LogEntry> {
    entries
        .iter()
        .filter(|e| {
            let search_text = format!("{} {} {}", e.path, e.user_agent, e.message);
            let decoded_text = url_decode(&search_text);
            let full_text = format!("{} {}", search_text, decoded_text);
            is_ldap_injection(&full_text)
        })
        .cloned()
        .collect()
}

pub fn filter_xxe_injection_attempts(entries: &[LogEntry]) -> Vec<LogEntry> {
    entries
        .iter()
        .filter(|e| {
            let search_text = format!("{} {} {}", e.path, e.user_agent, e.message);
            let decoded_text = url_decode(&search_text);
            let full_text = format!("{} {}", search_text, decoded_text);
            is_xxe_injection(&full_text)
        })
        .cloned()
        .collect()
}

pub fn filter_ssti_injection_attempts(entries: &[LogEntry]) -> Vec<LogEntry> {
    entries
        .iter()
        .filter(|e| {
            let search_text = format!("{} {} {}", e.path, e.user_agent, e.message);
            let decoded_text = url_decode(&search_text);
            let full_text = format!("{} {}", search_text, decoded_text);
            is_ssti_injection(&full_text)
        })
        .cloned()
        .collect()
}

pub fn filter_log_poisoning_attempts(entries: &[LogEntry]) -> Vec<LogEntry> {
    entries
        .iter()
        .filter(|e| {
            let search_text = format!("{} {} {}", e.path, e.user_agent, e.message);
            let decoded_text = url_decode(&search_text);
            let full_text = format!("{} {}", search_text, decoded_text);
            is_log_poisoning(&full_text)
        })
        .cloned()
        .collect()
}

pub fn filter_header_injection_attempts(entries: &[LogEntry]) -> Vec<LogEntry> {
    entries
        .iter()
        .filter(|e| {
            let search_text = format!("{} {} {}", e.path, e.user_agent, e.message);
            let decoded_text = url_decode(&search_text);
            let full_text = format!("{} {}", search_text, decoded_text);
            is_header_injection(&full_text)
        })
        .cloned()
        .collect()
}

pub fn filter_ssrf_attack_attempts(entries: &[LogEntry]) -> Vec<LogEntry> {
    entries
        .iter()
        .filter(|e| {
            let search_text = format!("{} {} {}", e.path, e.user_agent, e.message);
            let decoded_text = url_decode(&search_text);
            let full_text = format!("{} {}", search_text, decoded_text);
            is_ssrf_attack(&full_text)
        })
        .cloned()
        .collect()
}

// Erweiterte Analysefunktion mit Details
pub fn analyze_attack_types(entries: &[LogEntry]) -> HashMap<String, usize> {
    let mut attack_stats = HashMap::new();

    for entry in entries {
        let search_text = format!(
            "{} {} {} {}",
            entry.path, entry.user_agent, entry.message, entry.ip_address
        );
        let decoded_text = url_decode(&search_text);
        let full_text = format!("{} {}", search_text, decoded_text);

        if is_sql_injection(&full_text) {
            *attack_stats.entry("SQL Injection".to_string()).or_insert(0) += 1;
        }
        if is_xss_attack(&full_text) {
            *attack_stats.entry("XSS Attack".to_string()).or_insert(0) += 1;
        }
        if is_path_traversal(&full_text) {
            *attack_stats
                .entry("Path Traversal".to_string())
                .or_insert(0) += 1;
        }
        if is_command_injection(&full_text) {
            *attack_stats
                .entry("Command Injection".to_string())
                .or_insert(0) += 1;
        }
        if is_nosql_injection(&full_text) {
            *attack_stats
                .entry("NoSQL Injection".to_string())
                .or_insert(0) += 1;
        }
        if is_ldap_injection(&full_text) {
            *attack_stats
                .entry("LDAP Injection".to_string())
                .or_insert(0) += 1;
        }
        if is_xxe_injection(&full_text) {
            *attack_stats.entry("XXE Injection".to_string()).or_insert(0) += 1;
        }
        if is_ssti_injection(&full_text) {
            *attack_stats
                .entry("SSTI Injection".to_string())
                .or_insert(0) += 1;
        }
        if is_log_poisoning(&full_text) {
            *attack_stats.entry("Log Poisoning".to_string()).or_insert(0) += 1;
        }
        if is_header_injection(&full_text) {
            *attack_stats
                .entry("Header Injection".to_string())
                .or_insert(0) += 1;
        }
        if is_ssrf_attack(&full_text) {
            *attack_stats.entry("SSRF Attack".to_string()).or_insert(0) += 1;
        }
        if is_suspicious_user_agent(&entry.user_agent) {
            *attack_stats
                .entry("Suspicious User-Agent".to_string())
                .or_insert(0) += 1;
        }
    }

    attack_stats
}

// Funktion zur Anzeige der Angriffsstatistiken
pub fn print_attack_statistics(entries: &[LogEntry]) {
    let stats = analyze_attack_types(entries);
    let total_attacks: usize = stats.values().sum();

    println!("=== ATTACK DETECTION STATISTICS ===");
    println!("Total entries analyzed: {}", entries.len());
    println!("Total attack attempts detected: {}", total_attacks);
    println!();

    if total_attacks > 0 {
        println!("Attack type breakdown:");
        for (attack_type, count) in &stats {
            let percentage = (*count as f32 / total_attacks as f32) * 100.0;
            println!("  {}: {} ({:.1}%)", attack_type, count, percentage);
        }
    } else {
        println!("No attacks detected in the analyzed logs.");
    }

    println!("=====================================");
}

// Debug-Hilfsfunktion um Timestamp-Formate zu testen
pub fn debug_timestamp_formats(entries: &[LogEntry]) {
    println!("=== DEBUG: Analysiere Timestamp-Formate ===");

    for (i, entry) in entries.iter().take(5).enumerate() {
        println!("Entry {}: timestamp = '{}'", i, entry.timestamp);

        // Teste Access Log Format
        if let Some(caps) = ACCESS_TIME_REGEX.captures(&entry.timestamp) {
            println!(
                "  ✓ Access Log Format matched: Tag={} Monat={} Jahr={} Zeit={}:{}:{}",
                caps.get(1).map_or("??", |m| m.as_str()),
                caps.get(2).map_or("??", |m| m.as_str()),
                caps.get(3).map_or("??", |m| m.as_str()),
                caps.get(4).map_or("??", |m| m.as_str()),
                caps.get(5).map_or("??", |m| m.as_str()),
                caps.get(6).map_or("??", |m| m.as_str())
            );
            continue;
        }

        // Teste Error Log Format
        if let Some(caps) = ERROR_TIME_REGEX.captures(&entry.timestamp) {
            println!(
                "  ✓ Error Log Format matched: {}:{}:{}",
                caps.get(1).map_or("??", |m| m.as_str()),
                caps.get(2).map_or("??", |m| m.as_str()),
                caps.get(3).map_or("??", |m| m.as_str())
            );
            continue;
        }

        // Teste Fallback Format
        if let Some(caps) = TIME_REGEX.captures(&entry.timestamp) {
            println!(
                "  ✓ Fallback Format matched: {}:{}:{}",
                caps.get(1).map_or("??", |m| m.as_str()),
                caps.get(2).map_or("??", |m| m.as_str()),
                caps.get(3).map_or("??", |m| m.as_str())
            );
            continue;
        }

        println!("  ✗ Kein Format matched!");
    }
    println!("=== Ende DEBUG ===");
}
