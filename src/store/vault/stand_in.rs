//! A stand-in for 1Password's Core, for the tests that run sesame's binary
//! (tests/e2e.rs): a vault in files, answering the Core methods opcore calls
//! as the Core v0.4.1 does where sesame depends on it, and logging each
//! method called, one per line of `calls.log`. Only in a debug build, and
//! only when `DIR_VAR` names its directory; a release build has none.
use opcore::Client;
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
/// The one vault it has.
const VAULT: &str = "scratch";
const WRITES: [&str; 3] = ["ItemsCreateAll", "ItemsPut", "ItemsArchive"];

type SignIn = Box<dyn Fn() -> Result<Client<Stand>, opcore::Error>>;

/// Signs in to the stand-in in `dir`, as opcore signs in to the Core.
pub fn sign_in(dir: PathBuf, token: &str, vault: &str) -> SignIn {
    let (t, v) = (token.to_string(), vault.to_string());
    Box::new(move || Client::with_core(Stand { dir: dir.clone() }, &t, &v))
}

pub struct Stand {
    dir: PathBuf,
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

    /// Logs `method`; how many calls and writes came before it.
    fn log(&self, method: &str) -> (usize, usize) {
        let path = self.dir.join("calls.log");
        let log = std::fs::read_to_string(&path).unwrap_or_default();
        let writes = log.lines().filter(|l| WRITES.contains(l)).count();
        let calls = log.lines().count();
        std::fs::write(&path, format!("{log}{method}\n")).expect("the stand-in's dir is writable");
        (calls, writes)
    }

    fn answer(&self, method: &str, p: &Value, n: usize) -> Result<Value, Failure> {
        let mut items = self.read("items.json");
        let find = |items: &[Value], id: &Value| items.iter().position(|i| i["id"] == *id);
        let answer = match method {
            "VaultsList" => json!([{ "id": "v1", "title": VAULT }]),
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
        self.log("init_client");
        let config: Value = serde_json::from_str(config).unwrap_or_default();
        let accepted = std::env::var(TOKEN_VAR).unwrap_or_default();
        if config["serviceAccountToken"] != accepted.as_str() {
            return Err(error(
                "Unauthorized",
                "authentication failed: the service account token is not valid",
            ));
        }
        Ok("1".into())
    }

    fn invoke(&mut self, invocation: &str) -> Result<String, Failure> {
        let inv: Value = serde_json::from_str(invocation).unwrap_or_default();
        let call = &inv["invocation"]["parameters"];
        let method = call["name"].as_str().unwrap_or_default();
        let (n, writes) = self.log(method);
        if WRITES.contains(&method) {
            let max = std::env::var(MAX_WRITES_VAR)
                .ok()
                .and_then(|m| m.parse().ok());
            let spent = std::env::var(FAULT_VAR).is_ok_and(|f| f == "over-budget");
            if spent || max.is_some_and(|m: usize| writes >= m) {
                return Err(error("RateLimitExceeded", "Too many requests"));
            }
        }
        let answer = self.answer(method, &call["parameters"], n)?;
        Ok(match answer {
            Value::Null => String::new(),
            a => a.to_string(),
        })
    }

    fn release_client(&mut self, _id: &str) {}
}
