//! A stand-in for 1Password's Core, for the tests that run sesame's binary
//! (tests/e2e.rs): a vault in files, answering the Core methods opcore calls
//! as the Core v0.4.1 does where sesame depends on it, and logging each
//! method called, one per line of `calls.log`, ` refused` after it when it
//! answered an error (a call 1Password refuses spends none of its Budget). Only in a debug build, and
//! only when `DIR_VAR` names its directory; a release build has none.
use opcore::core::{Core, Failure};
use serde_json::{Value, json};
use std::path::PathBuf;

/// The stand-in's directory: `items.json` (active items, as the Core gives
/// them), `archived.json`, `calls.log`.
pub const DIR_VAR: &str = "SESAME_STAND_IN_DIR";
/// The one service account token it signs in.
pub const TOKEN_VAR: &str = "SESAME_STAND_IN_TOKEN";
/// `over-budget`: every write is refused by the rate limit. `put-refused`:
/// every `ItemsPut` is refused, as one of an item removed meanwhile.
pub const FAULT_VAR: &str = "SESAME_STAND_IN_FAULT";
/// Writes past this many (in `calls.log`) are refused by the rate limit.
pub const MAX_WRITES_VAR: &str = "SESAME_STAND_IN_MAX_WRITES";
/// The one vault it has, unless `Stand::on` names another.
const VAULT: &str = "scratch";
const WRITES: [&str; 3] = ["ItemsCreateAll", "ItemsPut", "ItemsArchive"];

/// The stand-in on the vault in `dir`: a Core opcore signs in on.
pub struct Stand {
    dir: PathBuf,
    vault: String,
    /// A fault of this one alone, as `FAULT_VAR` names them (the unit tests
    /// run at once in one process, which shares its environment).
    fault: Option<&'static str>,
}

impl Stand {
    /// The vault `scratch`, kept in `dir`.
    pub fn new(dir: PathBuf) -> Stand {
        Stand::on(dir, VAULT)
    }

    /// The vault titled `vault`, kept in `dir`.
    pub fn on(dir: PathBuf, vault: &str) -> Stand {
        Stand {
            dir,
            vault: vault.into(),
            fault: None,
        }
    }

    /// This one with `fault` (`over-budget`), or `sign-in-refused`: every
    /// sign-in is refused, as one with a revoked token.
    #[cfg(test)]
    pub fn with_fault(self, fault: &'static str) -> Stand {
        Stand {
            fault: Some(fault),
            ..self
        }
    }

    fn faulty(&self, fault: &str) -> bool {
        self.fault == Some(fault) || std::env::var(FAULT_VAR).is_ok_and(|f| f == fault)
    }
}

fn error(name: &str, message: &str) -> Failure {
    Failure::Error(json!({ "name": name, "message": message }).to_string())
}

impl Stand {
    fn read(&self, file: &str) -> Vec<Value> {
        std::fs::read(self.dir.join(file))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn write(&self, file: &str, items: &[Value]) {
        let text = serde_json::to_vec_pretty(items).expect("JSON");
        std::fs::write(self.dir.join(file), text).expect("the stand-in's dir is writable");
    }

    /// Runs `call` as `method` and logs it, ` refused` if it failed; `call`
    /// is given how many calls and writes came before it.
    fn log<T>(
        &self,
        method: &str,
        call: impl FnOnce(usize, usize) -> Result<T, Failure>,
    ) -> Result<T, Failure> {
        let path = self.dir.join("calls.log");
        let log = std::fs::read_to_string(&path).unwrap_or_default();
        let method_of = |l: &str| l.split(' ').next().unwrap_or_default().to_string();
        let writes = log
            .lines()
            .filter(|l| WRITES.contains(&method_of(l).as_str()))
            .count();
        let answer = call(log.lines().count(), writes);
        let refused = if answer.is_err() { " refused" } else { "" };
        std::fs::write(&path, format!("{log}{method}{refused}\n"))
            .expect("the stand-in's dir is writable");
        answer
    }

    fn answer(&self, method: &str, p: &Value, n: usize) -> Result<Value, Failure> {
        let mut items = self.read("items.json");
        let find = |items: &[Value], id: &Value| items.iter().position(|i| i["id"] == *id);
        let answer = match method {
            "VaultsList" => json!([{ "id": "v1", "title": self.vault }]),
            "ItemsList" => items
                .iter()
                .map(|i| {
                    json!({"id": i["id"], "title": i["title"], "category": i["category"],
                        "vaultId": "v1", "websites": [], "tags": i["tags"],
                        "createdAt": i["createdAt"], "updatedAt": i["updatedAt"],
                        "state": "active"})
                })
                .collect(),
            "ItemsGetAll" => {
                let each: Vec<Value> = p["item_ids"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|id| match find(&items, id) {
                        Some(at) => json!({ "content": items[at] }),
                        None => json!({ "error": { "type": "itemNotFound" } }),
                    })
                    .collect();
                json!({ "individualResponses": each })
            }
            "ItemsCreateAll" => {
                let mut each = Vec::new();
                for t in p["params"].as_array().into_iter().flatten() {
                    let mut i = t.clone();
                    let count = items.len() + self.read("archived.json").len() + 1;
                    i["id"] = format!("{count:0>26}").into();
                    i["version"] = 1.into();
                    i["createdAt"] = format!("t{n}").into();
                    i["updatedAt"] = format!("t{n}").into();
                    for k in ["fields", "sections", "tags", "websites", "files"] {
                        if i.get(k).is_none() {
                            i[k] = json!([]);
                        }
                    }
                    if i.get("notes").is_none() {
                        i["notes"] = "".into();
                    }
                    items.push(i.clone());
                    each.push(json!({ "content": i }));
                }
                json!({ "individualResponses": each })
            }
            "ItemsPut" => {
                if std::env::var(FAULT_VAR).is_ok_and(|f| f == "put-refused") {
                    return Err(error("Unknown", "the item to put is not in the vault"));
                }
                let mut i = p["item"].clone();
                let at = find(&items, &i["id"])
                    .ok_or_else(|| error("Unknown", "the item to put is not in the vault"))?;
                if items[at]["version"] != i["version"] {
                    return Err(error("Unknown", "the item changed since it was read"));
                }
                i["version"] = (i["version"].as_u64().unwrap_or(0) + 1).into();
                i["updatedAt"] = format!("t{n}").into();
                items[at] = i.clone();
                i
            }
            "ItemsArchive" => {
                let at = find(&items, &p["item_id"])
                    .ok_or_else(|| error("Unknown", "no such item to archive"))?;
                let mut archived = self.read("archived.json");
                archived.push(items.remove(at));
                self.write("archived.json", &archived);
                Value::Null
            }
            other => return Err(Failure::Trap(format!("the stand-in has no {other}"))),
        };
        self.write("items.json", &items);
        Ok(answer)
    }
}

impl Core for Stand {
    fn init_client(&mut self, config: &str) -> Result<String, Failure> {
        self.log("init_client", |_, _| {
            let config: Value = serde_json::from_str(config).unwrap_or_default();
            let accepted = std::env::var(TOKEN_VAR).unwrap_or_default();
            if config["serviceAccountToken"] != accepted.as_str() || self.faulty("sign-in-refused")
            {
                return Err(error(
                    "Unauthorized",
                    "authentication failed: the service account token is not valid",
                ));
            }
            Ok("1".into())
        })
    }

    fn invoke(&mut self, invocation: &str) -> Result<String, Failure> {
        let inv: Value = serde_json::from_str(invocation).unwrap_or_default();
        let call = &inv["invocation"]["parameters"];
        let method = call["name"].as_str().unwrap_or_default();
        self.log(method, |n, writes| {
            if WRITES.contains(&method) {
                let max = std::env::var(MAX_WRITES_VAR)
                    .ok()
                    .and_then(|m| m.parse().ok());
                let spent = self.faulty("over-budget");
                if spent || max.is_some_and(|m: usize| writes >= m) {
                    return Err(error("RateLimitExceeded", "Too many requests"));
                }
            }
            Ok(match self.answer(method, &call["parameters"], n)? {
                Value::Null => String::new(),
                a => a.to_string(),
            })
        })
    }

    fn release_client(&mut self, _id: &str) {}
}
