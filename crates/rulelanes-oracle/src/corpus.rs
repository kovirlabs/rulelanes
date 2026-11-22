//! The generated R1 log corpus.
//!
//! Every line is generated from a fixed seed, so the corpus is the same on
//! every machine. The lines exercise `testdata/ruleset/` (written for
//! rulelanes) and include near misses and lines no decoder takes. Nothing
//! here comes from a real network.

/// A small deterministic generator (xorshift64*).
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed.max(1))
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }

    pub fn pick<'a>(&mut self, v: &[&'a str]) -> &'a str {
        v[self.below(v.len())]
    }

    pub fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }
}

const MONTHS: &[&str] = &[
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];
const HOSTS: &[&str] = &["web01", "db-02", "gw.lab", "node_7", "edge-3.example.net"];
const USERS: &[&str] = &[
    "root",
    "admin",
    "alice",
    "bob",
    "svc-backup",
    "carol_1",
    "dave@corp",
];
const WORDS: &[&str] = &[
    "alpha",
    "beta",
    "gamma",
    "delta",
    "omega",
    "noisy",
    "healthcheck",
];

fn ip(r: &mut Rng) -> String {
    match r.below(4) {
        0 => format!("10.0.0.{}", r.below(254) + 1),
        1 => format!("10.{}.{}.{}", r.below(255), r.below(255), r.below(254) + 1),
        2 => format!("192.168.{}.{}", r.below(20), r.below(254) + 1),
        _ => format!("203.0.113.{}", r.below(254) + 1),
    }
}

fn port(r: &mut Rng) -> String {
    r.pick(&["22", "2222", "80", "443", "3389", "53", "8080", "51515"])
        .to_string()
}

fn bsd_header(r: &mut Rng, prog: &str, pid: bool) -> String {
    let day = r.below(28) + 1;
    let ts = format!(
        "{} {:>2} {:02}:{:02}:{:02}",
        r.pick(MONTHS),
        day,
        r.below(24),
        r.below(60),
        r.below(60)
    );
    let host = r.pick(HOSTS);
    if pid {
        format!("{ts} {host} {prog}[{}]: ", r.below(60000) + 1)
    } else {
        format!("{ts} {host} {prog}: ")
    }
}

/// One generated line for template `k`.
fn line(r: &mut Rng, k: usize) -> String {
    match k {
        0 => {
            let u = r.pick(USERS);
            let tail = if r.chance(10) { " failure" } else { "" };
            format!(
                "{}Failed password for {u} from {} port {} ssh2{tail}",
                bsd_header(r, "rlauth", true),
                ip(r),
                port(r)
            )
        }
        1 => format!(
            "{}Accepted {} for {} from {} port {} ssh2",
            bsd_header(r, "rlauth", true),
            r.pick(&["password", "publickey", "keyboard-interactive"]),
            r.pick(USERS),
            ip(r),
            port(r)
        ),
        2 => {
            let u = if r.chance(15) { "" } else { r.pick(USERS) };
            format!(
                "{}Invalid user {u} from {}",
                bsd_header(r, "rlauth", false),
                ip(r)
            )
        }
        3 => format!(
            "{}pam_unix(rlauth:session): session {} for user {}{}",
            bsd_header(r, "rlauth", true),
            r.pick(&["opened", "closed"]),
            r.pick(USERS),
            if r.chance(20) { " by (uid=0)" } else { "" }
        ),
        4 => format!(
            "{}{} {} from monitor",
            bsd_header(r, "rlauth", true),
            r.pick(&["healthcheck", "noisy", "plain"]),
            r.pick(WORDS)
        ),
        5 => {
            let m = r.pick(&["GET", "POST", "PUT", "DELETE", "HEAD"]);
            let path = r.pick(&[
                "/",
                "/index.html",
                "/admin/login",
                "/api/v1/items",
                "/static/app.js",
            ]);
            let st = r.pick(&["200", "201", "301", "404", "403", "500", "503"]);
            let bytes = if r.chance(20) {
                "0".to_string()
            } else {
                (r.below(90000) + 1).to_string()
            };
            let ipp = if r.chance(30) {
                format!("192.168.10.{}", r.below(254) + 1)
            } else {
                ip(r)
            };
            if r.chance(10) {
                // Missing the ip= part: the third sibling regex fails.
                format!(
                    "{}{m} {path} HTTP/1.1 {st} {bytes}",
                    bsd_header(r, "rlweb", false)
                )
            } else {
                format!(
                    "{}{m} {path} HTTP/1.{} {st} {bytes} ip={ipp}",
                    bsd_header(r, "rlweb", false),
                    r.below(2)
                )
            }
        }
        6 => format!(
            "{}{} {} {}:{} -> {}:{}",
            bsd_header(r, "rlfw", true),
            r.pick(&["DROP", "ACCEPT", "REJECT"]),
            r.pick(&["tcp", "udp", "icmp"]),
            ip(r),
            r.below(65000) + 1024,
            if r.chance(25) {
                "10.0.0.1".to_string()
            } else {
                ip(r)
            },
            port(r)
        ),
        7 => {
            let app = r.pick(&["billing", "billing-eu", "shop", "auth"]);
            let user = r.pick(&["admin", "ann", "ben"]);
            let ok = r.pick(&["true", "false"]);
            let amount = r.below(200000);
            let tags = if r.chance(30) {
                r#", "tags": ["a", "b"]"#
            } else {
                ""
            };
            format!(
                r#"{{"rlapp": "{app}", "user": {{"name": "{user}", "id": {}}}, "srcip": "{}", "ok": {ok}, "amount": "{amount}"{tags}}}"#,
                r.below(1000),
                ip(r)
            )
        }
        8 => {
            let sev = r.pick(&["low", "medium", "high"]);
            let cat = r.pick(&["Security Events", "security", "System", "UniFi Devices"]);
            let msg = r.pick(&[
                "Device went offline.",
                "Login ok",
                "Config changed by admin",
                "x",
            ]);
            match r.below(3) {
                0 => format!("RLKV severity={sev} category={cat} msg={msg}"),
                1 => format!("RLKV msg={msg} severity={sev}"),
                _ => format!("RLKV category={cat} other=1"),
            }
        }
        9 => {
            let prog = format!("rldb-{}", r.below(9));
            if r.chance(60) {
                format!(
                    "{}query {} on {} took {}ms",
                    bsd_header(r, &prog, true),
                    r.pick(&["SELECT", "INSERT", "DROP", "drop", "UPDATE"]),
                    r.pick(&["users", "orders", "audit"]),
                    r.below(20000)
                )
            } else {
                format!(
                    "{}error code={} msg={}",
                    bsd_header(r, &prog, true),
                    r.pick(&["1045", "1146", "2002"]),
                    r.pick(&["access denied for user", "table missing", "cannot connect"])
                )
            }
        }
        10 => format!(
            "{}queued from=<{}@{}> to=<{}@{}>",
            {
                let p = r.pick(&["rlmail", "rlmail2", "rlmailer"]);
                bsd_header(r, p, true)
            },
            r.pick(USERS),
            r.pick(&["example.com", "example.org"]),
            r.pick(USERS),
            r.pick(&["example.com", "example.org"])
        ),
        11 => format!(
            "{}vpn: {}tunnel tun{} {} peer {}",
            bsd_header(r, "rlvpn", true),
            if r.chance(10) { "x " } else { "" },
            r.below(9),
            r.pick(&["up", "down", "flapping"]),
            ip(r)
        ),
        12 => {
            if r.chance(70) {
                format!(
                    "{}CMD ({})",
                    bsd_header(r, "rlcron", true),
                    r.pick(&[
                        "run-parts /etc/cron.daily",
                        "rm -rf /tmp/cache",
                        "backup.sh --full"
                    ])
                )
            } else {
                format!("{}session started", bsd_header(r, "rlcron", true))
            }
        }
        13 => format!(
            "RLPLAIN: {}={}",
            r.pick(&["mode", "user", "level"]),
            r.pick(&["safe", "debug", "x1"])
        ),
        14 => format!(
            "{} {:>2} 10:00:{:02} rlsolo: job {} {}",
            r.pick(MONTHS),
            r.below(28) + 1,
            r.below(60),
            r.below(9999),
            r.pick(&["done", "failed", "queued"])
        ),
        15 => format!(
            "{}query: {} IN {} from {}",
            bsd_header(r, "rldns", true),
            r.pick(&["www.example.com", "mail.example.ru", "x.test"]),
            r.pick(&["A", "AAAA", "MX", "TXT", "SRV"]),
            ip(r)
        ),
        16 => format!(
            "{}{} {} {} {}",
            bsd_header(r, "rlproxy", true),
            r.below(100000),
            r.pick(&["DENIED", "ALLOWED", "BLOCKED"]),
            ip(r),
            r.pick(&[
                "http://a.test/setup.exe",
                "http://b.test/",
                "http://c.test/x.EXE"
            ])
        ),
        17 => format!(
            "{}[{}:{}] {} {{{}}} {} -> {}",
            bsd_header(r, "rlids", true),
            r.pick(&["2000419", "1000", "2001219"]),
            r.below(9) + 1,
            r.pick(&["ET SCAN probe", "Possible exploit attempt", "x"]),
            r.pick(&["TCP", "UDP", "ICMP"]),
            ip(r),
            ip(r)
        ),
        18 => format!(
            "{}{}{} : TTY=pts/{} ; PWD=/home/{} ; USER={} ; COMMAND=/usr/bin/{}",
            bsd_header(r, "rlsudo", false),
            if r.chance(30) { "   " } else { "" },
            r.pick(USERS),
            r.below(9),
            r.pick(USERS),
            r.pick(&["root", "postgres"]),
            r.pick(&[
                "passwd alice",
                "cat /etc/shadow",
                "ls -la",
                "systemctl restart web"
            ])
        ),
        19 => format!(
            "{}{}\t{}",
            bsd_header(r, "rltab", true),
            r.pick(WORDS),
            r.pick(WORDS)
        ),
        20 => format!(
            "{}{}{}",
            bsd_header(r, "rlpunct", true),
            r.pick(&["!!", "#", "[]", "<>", "{}", "::"]),
            r.pick(WORDS)
        ),
        21 => {
            let lvl = r.pick(&["info", "error", "fatal", "debug"]);
            match r.below(3) {
                0 => format!(
                    "2026-11-{:02}T10:{:02}:{:02}+00:00 {} rliso: level={lvl} msg=x",
                    r.below(28) + 1,
                    r.below(60),
                    r.below(60),
                    r.pick(HOSTS)
                ),
                1 => format!(
                    "2026-11-{:02}T10:{:02}:{:02}.{:03}+01:00 {} rliso[{}]: level={lvl}",
                    r.below(28) + 1,
                    r.below(60),
                    r.below(60),
                    r.below(1000),
                    r.pick(HOSTS),
                    r.below(999)
                ),
                _ => format!(
                    "2026 {} {:02} 10:{:02}:{:02} {} rliso: level={lvl}",
                    r.pick(MONTHS),
                    r.below(28) + 1,
                    r.below(60),
                    r.below(60),
                    r.pick(HOSTS)
                ),
            }
        }
        22 => format!(
            "{}{}/{}.{} start",
            bsd_header(r, "rldyn", true),
            r.pick(&["billing", "shop", "auth"]),
            r.below(5),
            r.below(20)
        ),
        23 => format!(
            "{}x={}",
            {
                let p = r.pick(&["rlcase", "RLCASE", "RlCase"]);
                bsd_header(r, p, true)
            },
            r.below(500)
        ),
        24 => format!(
            "{} {:>2} 09:00:{:02} {} rlspace[{}] {} {}",
            r.pick(MONTHS),
            r.below(28) + 1,
            r.below(60),
            r.pick(HOSTS),
            r.below(500) + 1,
            r.pick(&["msg", "other"]),
            r.pick(WORDS)
        ),
        25 => format!(
            "{} item {}",
            r.pick(&["RLALT1", "RLALT2", "RLALT3", "rlalt1"]),
            r.below(1000)
        ),
        26 => format!(
            "{}a{}b{}{}",
            bsd_header(r, "rlstar", true),
            if r.chance(50) {
                r.below(100).to_string()
            } else {
                String::new()
            },
            r.pick(&[" ", "::", "/", " - "]),
            if r.chance(70) { r.pick(WORDS) } else { "" }
        ),
        27 => format!("RLLOC check {}", r.pick(WORDS)),
        28 => format!(
            "{}{} {}",
            {
                let p = r.pick(&["unknownd", "kernel", "rlnothing"]);
                bsd_header(r, p, true)
            },
            r.pick(&["something happened", "fatal error in module", "all good"]),
            r.below(100)
        ),
        _ => format!(
            "{} free text {}",
            r.pick(&["random", "error:", "Failed password for x"]),
            r.below(100)
        ),
    }
}

/// Number of line templates.
pub const TEMPLATES: usize = 30;

/// The corpus: `n` lines from `seed`, cycling through the templates in a
/// shuffled order so every template appears.
pub fn generate(seed: u64, n: usize) -> Vec<String> {
    let mut r = Rng::new(seed);
    (0..n)
        .map(|i| {
            let k = if i < TEMPLATES { i } else { r.below(TEMPLATES) };
            line(&mut r, k)
        })
        .collect()
}

/// Seed and size of the committed corpus `testdata/corpus/corpus.log`.
pub const SEED: u64 = 0x5EED_2026_1122;
pub const SIZE: usize = 1200;
