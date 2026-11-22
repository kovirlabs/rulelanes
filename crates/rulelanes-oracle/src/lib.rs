//! Test support for R1: drive `wazuh-logtest` in the Wazuh container,
//! record its results as fixtures, and compare them with the reference
//! engine.
//!
//! The oracle runs with an isolated ruleset: for the length of a run the
//! manager's `<ruleset>` section is replaced so that a new logtest session
//! loads only the decoders and rules under test (from
//! `/var/ossec/etc/rulelanes/`), then the stock configuration is put back.
//! Logtest sessions read the ruleset when they start, so the running
//! manager is not restarted and its own analysis is not affected.
#![forbid(unsafe_code)]

pub mod corpus;

use serde_json::Value;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;

/// The logtest driver, run inside the container with its Python.
pub const LOGTEST_PY: &str = include_str!("../../../oracle/logtest.py");

const ETC: &str = "/var/ossec/etc";
const PYTHON: &str = "/var/ossec/framework/python/bin/python3";

static LOCAL_LOCK: Mutex<()> = Mutex::new(());

/// What R1 compares for one event.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Observed {
    pub decoder_name: Option<String>,
    pub decoder_parent: Option<String>,
    /// Extracted fields, flattened to dotted keys; non-string leaves are
    /// their compact JSON text.
    pub data: BTreeMap<String, String>,
    pub rule_id: Option<String>,
    pub rule_level: Option<u64>,
    pub rule_description: Option<String>,
    pub rule_groups: Vec<String>,
    pub alert: bool,
}

impl Observed {
    /// From one line of `oracle/logtest.py` output, or from
    /// [`rulelanes_engine::outcome_json`] (same shape).
    pub fn from_json(v: &Value) -> Observed {
        let out = &v["output"];
        let mut data = BTreeMap::new();
        if let Value::Object(m) = &out["data"] {
            flatten("", m, &mut data);
        }
        let rule = &out["rule"];
        Observed {
            decoder_name: out["decoder"]["name"].as_str().map(str::to_string),
            decoder_parent: out["decoder"]["parent"].as_str().map(str::to_string),
            data,
            rule_id: rule["id"].as_str().map(str::to_string),
            rule_level: rule["level"].as_u64(),
            rule_description: rule["description"].as_str().map(str::to_string),
            rule_groups: str_list(&rule["groups"]),
            alert: v["alert"].as_bool().unwrap_or(false),
        }
    }

    pub fn from_outcome(o: &rulelanes_model::Outcome) -> Observed {
        Observed::from_json(&rulelanes_engine::outcome_json(o))
    }

    pub fn to_json(&self) -> Value {
        serde_json::json!({
            "decoder_name": self.decoder_name,
            "decoder_parent": self.decoder_parent,
            "data": self.data,
            "rule_id": self.rule_id,
            "rule_level": self.rule_level,
            "rule_description": self.rule_description,
            "rule_groups": self.rule_groups,
            "alert": self.alert,
        })
    }

    pub fn from_fixture_json(v: &Value) -> Observed {
        Observed {
            decoder_name: v["decoder_name"].as_str().map(str::to_string),
            decoder_parent: v["decoder_parent"].as_str().map(str::to_string),
            data: v["data"]
                .as_object()
                .map(|m| {
                    m.iter()
                        .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string()))
                        .collect()
                })
                .unwrap_or_default(),
            rule_id: v["rule_id"].as_str().map(str::to_string),
            rule_level: v["rule_level"].as_u64(),
            rule_description: v["rule_description"].as_str().map(str::to_string),
            rule_groups: str_list(&v["rule_groups"]),
            alert: v["alert"].as_bool().unwrap_or(false),
        }
    }

    /// Differences as readable strings; `self` is the oracle.
    pub fn diff(&self, engine: &Observed) -> Vec<String> {
        let mut d = Vec::new();
        let mut cmp = |name: &str, a: String, b: String| {
            if a != b {
                d.push(format!("{name}: oracle {a} != engine {b}"));
            }
        };
        cmp(
            "decoder.name",
            format!("{:?}", self.decoder_name),
            format!("{:?}", engine.decoder_name),
        );
        cmp(
            "decoder.parent",
            format!("{:?}", self.decoder_parent),
            format!("{:?}", engine.decoder_parent),
        );
        cmp(
            "data",
            format!("{:?}", self.data),
            format!("{:?}", engine.data),
        );
        cmp(
            "rule.id",
            format!("{:?}", self.rule_id),
            format!("{:?}", engine.rule_id),
        );
        cmp(
            "rule.level",
            format!("{:?}", self.rule_level),
            format!("{:?}", engine.rule_level),
        );
        cmp(
            "rule.description",
            format!("{:?}", self.rule_description),
            format!("{:?}", engine.rule_description),
        );
        cmp(
            "rule.groups",
            format!("{:?}", self.rule_groups),
            format!("{:?}", engine.rule_groups),
        );
        cmp(
            "alert",
            format!("{:?}", self.alert),
            format!("{:?}", engine.alert),
        );
        d
    }
}

fn str_list(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|g| g.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn flatten(prefix: &str, m: &serde_json::Map<String, Value>, out: &mut BTreeMap<String, String>) {
    for (k, v) in m {
        let key = if prefix.is_empty() {
            k.clone()
        } else {
            format!("{prefix}.{k}")
        };
        match v {
            Value::Object(inner) => flatten(&key, inner, out),
            Value::String(s) => {
                out.insert(key, s.clone());
            }
            other => {
                out.insert(key, other.to_string());
            }
        }
    }
}

/// One recorded oracle result.
#[derive(Debug, Clone)]
pub struct FixtureRow {
    pub event: String,
    pub observed: Observed,
}

/// Read a fixture file: a header line, then one row per event.
pub fn read_fixture(path: &Path) -> std::io::Result<(Value, Vec<FixtureRow>)> {
    let text = std::fs::read_to_string(path)?;
    let mut header = Value::Null;
    let mut rows = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let v: Value = serde_json::from_str(line)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        if !v["header"].is_null() {
            header = v["header"].clone();
            continue;
        }
        rows.push(FixtureRow {
            event: v["event"].as_str().unwrap_or_default().to_string(),
            observed: Observed::from_fixture_json(&v["observed"]),
        });
    }
    Ok((header, rows))
}

pub fn write_fixture(path: &Path, header: &Value, rows: &[FixtureRow]) -> std::io::Result<()> {
    let mut f = std::io::BufWriter::new(std::fs::File::create(path)?);
    writeln!(f, "{}", serde_json::json!({ "header": header }))?;
    for r in rows {
        writeln!(
            f,
            "{}",
            serde_json::json!({ "event": r.event, "observed": r.observed.to_json() })
        )?;
    }
    f.flush()
}

/// The Wazuh manager container used as the oracle.
pub struct Oracle {
    pub container: String,
    api_password: Option<String>,
}

/// The oracle-only manager container (`oracle/compose.oracle.yml`).
pub const ORACLE_CONTAINER: &str = "rulelanes-oracle-manager";

/// Read `KEY=value` from the git-ignored `oracle/secrets.env`.
fn secret(key: &str) -> Option<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../oracle/secrets.env");
    let text = std::fs::read_to_string(path).ok()?;
    text.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .find_map(|l| l.strip_prefix(key)?.strip_prefix('=').map(str::to_string))
}

impl Default for Oracle {
    fn default() -> Self {
        Oracle::from_env()
    }
}

impl Oracle {
    /// The oracle container [`ORACLE_CONTAINER`], or the one named in
    /// `RULELANES_WAZUH_CONTAINER`. A run edits the target's `ossec.conf`
    /// for its duration, so any other target is refused by
    /// [`Oracle::available`] unless `RULELANES_ALLOW_NON_ORACLE_TARGET=1`.
    /// The API password comes from `WAZUH_API_PASSWORD` or
    /// `ORACLE_API_PASSWORD` in `oracle/secrets.env`.
    pub fn from_env() -> Oracle {
        Oracle {
            container: std::env::var("RULELANES_WAZUH_CONTAINER")
                .unwrap_or_else(|_| ORACLE_CONTAINER.to_string()),
            api_password: std::env::var("WAZUH_API_PASSWORD")
                .ok()
                .or_else(|| secret("ORACLE_API_PASSWORD")),
        }
    }

    /// `Ok` when the target is the oracle container (or explicitly
    /// allowed), it is running, it has `wazuh-logtest`, and an API password
    /// is known; otherwise the reason, for a SKIPPED message.
    pub fn available(&self) -> Result<(), String> {
        if self.container != ORACLE_CONTAINER
            && std::env::var("RULELANES_ALLOW_NON_ORACLE_TARGET").as_deref() != Ok("1")
        {
            return Err(format!(
                "refusing to use '{}' as the oracle: only {ORACLE_CONTAINER} \
                 (set RULELANES_ALLOW_NON_ORACLE_TARGET=1 to override)",
                self.container
            ));
        }
        if self.api_password.is_none() {
            return Err(
                "no API password: set WAZUH_API_PASSWORD or create oracle/secrets.env".into(),
            );
        }
        let out = Command::new("docker")
            .args([
                "exec",
                &self.container,
                "test",
                "-x",
                "/var/ossec/bin/wazuh-logtest",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| format!("cannot run docker: {e}"))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!(
                "container {} not running or has no wazuh-logtest: {}",
                self.container,
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    }

    fn sh(&self, script: &str, stdin: Option<&[u8]>) -> Result<String, String> {
        let mut child = Command::new("docker")
            .args(["exec", "-i", &self.container, "sh", "-c", script])
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("docker exec: {e}"))?;
        if let Some(data) = stdin {
            let mut s = child.stdin.take().ok_or("no stdin")?;
            s.write_all(data).map_err(|e| e.to_string())?;
        }
        let out = child.wait_with_output().map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err(format!(
                "`{script}` failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// The banner of `wazuh-logtest -V`, which names the Wazuh version.
    pub fn version(&self) -> Result<String, String> {
        let v = self.sh("/var/ossec/bin/wazuh-logtest -V 2>&1", None)?;
        Ok(v.lines()
            .find(|l| l.contains("Wazuh v") || l.contains("wazuh-logtest v"))
            .unwrap_or("")
            .trim()
            .to_string())
    }

    /// Run `lines` through `wazuh-logtest` with only the given decoder and
    /// rule files loaded. Returns one JSON object per line (the
    /// `oracle/logtest.py` output). The stock configuration is restored
    /// before this returns, also on error.
    pub fn run_isolated(
        &self,
        decoder_files: &[PathBuf],
        rule_files: &[PathBuf],
        lines: &[String],
        location: &str,
    ) -> Result<Vec<Value>, String> {
        self.available()?;
        let _local = LOCAL_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let mut tries = 0;
        while self
            .sh(&format!("mkdir {ETC}/rulelanes.lock"), None)
            .is_err()
        {
            tries += 1;
            if tries > 600 {
                return Err(format!(
                    "oracle busy: {ETC}/rulelanes.lock exists in the container (remove it if no run is active)"
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let result = self.run_locked(decoder_files, rule_files, lines, location);
        let restore = self.restore();
        let _ = self.sh(&format!("rmdir {ETC}/rulelanes.lock"), None);
        restore?;
        result
    }

    /// Put the stock `<ruleset>` configuration back if a run left it
    /// isolated.
    pub fn restore(&self) -> Result<(), String> {
        self.sh(
            &format!(
                "if [ -f {ETC}/ossec.conf.rulelanes-stock ]; then \
                 cat {ETC}/ossec.conf.rulelanes-stock > {ETC}/ossec.conf && \
                 rm {ETC}/ossec.conf.rulelanes-stock; fi; rm -rf {ETC}/rulelanes"
            ),
            None,
        )
        .map(|_| ())
    }

    fn run_locked(
        &self,
        decoder_files: &[PathBuf],
        rule_files: &[PathBuf],
        lines: &[String],
        location: &str,
    ) -> Result<Vec<Value>, String> {
        self.sh(
            &format!(
                "rm -rf {ETC}/rulelanes && mkdir -p {ETC}/rulelanes/decoders {ETC}/rulelanes/rules"
            ),
            None,
        )?;
        for (dir, files) in [("decoders", decoder_files), ("rules", rule_files)] {
            for f in files {
                let name = f
                    .file_name()
                    .and_then(|n| n.to_str())
                    .ok_or_else(|| format!("bad file name {}", f.display()))?;
                let data = std::fs::read(f).map_err(|e| format!("{}: {e}", f.display()))?;
                self.sh(&format!("cat > {ETC}/rulelanes/{dir}/{name}"), Some(&data))?;
            }
        }
        let isolate = format!(
            "chown -R wazuh:wazuh {ETC}/rulelanes && \
             ( [ -f {ETC}/ossec.conf.rulelanes-stock ] || cp -p {ETC}/ossec.conf {ETC}/ossec.conf.rulelanes-stock ) && \
             awk '/<ruleset>/{{print; print \"    <decoder_dir>etc/rulelanes/decoders</decoder_dir>\"; \
             print \"    <rule_dir>etc/rulelanes/rules</rule_dir>\"; skip=1; next}} \
             /<\\/ruleset>/{{skip=0}} !skip' {ETC}/ossec.conf.rulelanes-stock > /tmp/rulelanes-ossec.conf && \
             cat /tmp/rulelanes-ossec.conf > {ETC}/ossec.conf"
        );
        self.sh(&isolate, None)?;
        let mut input = String::new();
        for l in lines {
            input.push_str(l);
            input.push('\n');
        }
        let mut child = Command::new("docker")
            .args([
                "exec",
                "-i",
                "-e",
                &format!("LOGTEST_LOCATION={location}"),
                // Passed through from this process's environment, so the
                // password is not on a command line.
                "-e",
                "WAZUH_API_PASSWORD",
                &self.container,
                PYTHON,
                "-c",
                LOGTEST_PY,
            ])
            .env(
                "WAZUH_API_PASSWORD",
                self.api_password.as_deref().unwrap_or_default(),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("docker exec: {e}"))?;
        let mut stdin = child.stdin.take().ok_or("no stdin")?;
        let writer = std::thread::spawn(move || stdin.write_all(input.as_bytes()));
        let out = child.wait_with_output().map_err(|e| e.to_string())?;
        let _ = writer.join();
        if !out.status.success() {
            return Err(format!(
                "logtest driver failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        let mut results = Vec::new();
        for l in String::from_utf8_lossy(&out.stdout).lines() {
            let v: Value =
                serde_json::from_str(l).map_err(|e| format!("bad driver output: {e}"))?;
            if v["output"].is_null() {
                return Err(format!("logtest refused the ruleset: {}", v["messages"]));
            }
            results.push(v);
        }
        if results.len() != lines.len() {
            return Err(format!(
                "logtest returned {} results for {} lines",
                results.len(),
                lines.len()
            ));
        }
        Ok(results)
    }
}
