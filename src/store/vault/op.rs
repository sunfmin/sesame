//! How the vault store talks to 1Password: the item requests it makes
//! (`Op`), and `OpCli`, the `op` CLI that answers them, the only code in
//! sesame that spawns it. The tests answer them in memory (`Memory`).
use super::{TOKEN_VAR, VAULT_VAR};
use serde_json::Value;
use std::io::Write;
use std::process::{Command, Stdio};

/// An item as `op item get --format json` prints it.
#[derive(Clone, Debug)]
pub struct Item {
    pub id: String,
    pub json: Value,
}

/// One item of a listing.
pub struct Listed {
    pub title: String,
    pub id: String,
    pub version: u64,
}

pub enum OpError {
    /// The item does not exist.
    NoItem,
    Failed(String),
}

/// The item requests the vault store makes, each one request to 1Password.
pub trait Op: Send + Sync {
    /// The items tagged `tag`.
    fn list(&self, tag: &str) -> Result<Vec<Listed>, OpError>;
    /// The item `query` (an id or a title) names.
    fn get(&self, query: &str) -> Result<Item, OpError>;
    /// Creates an item from `template`; the item, if 1Password printed it.
    fn create(&self, template: &Value) -> Result<Option<Item>, OpError>;
    /// Replaces item `id` with `template`; the item, if 1Password printed it.
    fn edit(&self, id: &str, template: &Value) -> Result<Option<Item>, OpError>;
    /// Archives item `id` (it can be restored in 1Password).
    fn archive(&self, id: &str) -> Result<(), OpError>;
}

/// The `op` CLI, as a service account, on vault `vault`: values reach it only
/// on its stdin, the token only in its environment.
pub struct OpCli {
    pub vault: String,
    pub token: String,
}

impl OpCli {
    /// Runs `op` with `args`, `input` on its stdin, the token in its
    /// environment; its stdout.
    fn run(&self, args: &[&str], input: Option<&[u8]>) -> Result<String, OpError> {
        let mut child = Command::new("op")
            .args(args)
            .env(TOKEN_VAR, &self.token)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| OpError::Failed(format!("running `op`: {e}")))?;
        if let (Some(input), Some(mut stdin)) = (input, child.stdin.take()) {
            // op takes an item template from stdin only when it is a pipe.
            stdin
                .write_all(input)
                .map_err(|e| OpError::Failed(format!("writing to `op`: {e}")))?;
        }
        let out = child
            .wait_with_output()
            .map_err(|e| OpError::Failed(format!("running `op`: {e}")))?;
        if out.status.success() {
            return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
        }
        let err = op_message(&String::from_utf8_lossy(&out.stderr));
        if err.contains("isn't an item") {
            return Err(OpError::NoItem);
        }
        if err.contains("isn't a vault") {
            return Err(OpError::Failed(format!(
                "the service account cannot read the 1Password vault `{}` ({VAULT_VAR}): \
                 check its name and that the service account has access to it ({err})",
                self.vault
            )));
        }
        Err(OpError::Failed(err))
    }

    /// A create or edit, the item's template on stdin.
    fn write(&self, args: &[&str], template: &Value) -> Result<Option<Item>, OpError> {
        let out = self.run(args, Some(template.to_string().as_bytes()))?;
        Ok(parse_item(&out).ok())
    }
}

impl Op for OpCli {
    fn list(&self, tag: &str) -> Result<Vec<Listed>, OpError> {
        let args = [
            "item",
            "list",
            "--vault",
            &self.vault,
            "--tags",
            tag,
            "--format",
            "json",
        ];
        let out = self.run(&args, None)?;
        let items: Vec<Value> =
            serde_json::from_str(&out).map_err(|e| OpError::Failed(e.to_string()))?;
        Ok(items
            .iter()
            .filter_map(|i| {
                Some(Listed {
                    title: i["title"].as_str()?.into(),
                    id: i["id"].as_str()?.into(),
                    version: i["version"].as_u64().unwrap_or(0),
                })
            })
            .collect())
    }

    fn get(&self, query: &str) -> Result<Item, OpError> {
        let args = [
            "item",
            "get",
            query,
            "--vault",
            &self.vault,
            "--format",
            "json",
        ];
        parse_item(&self.run(&args, None)?).map_err(OpError::Failed)
    }

    fn create(&self, template: &Value) -> Result<Option<Item>, OpError> {
        let args = ["item", "create", "--vault", &self.vault, "--format", "json"];
        self.write(&args, template)
    }

    fn edit(&self, id: &str, template: &Value) -> Result<Option<Item>, OpError> {
        // Without `tags` an edit wipes them; without a category it keeps its own.
        let args = [
            "item",
            "edit",
            id,
            "--vault",
            &self.vault,
            "--format",
            "json",
        ];
        self.write(&args, template)
    }

    fn archive(&self, id: &str) -> Result<(), OpError> {
        let args = ["item", "delete", id, "--vault", &self.vault, "--archive"];
        self.run(&args, None).map(drop)
    }
}

fn parse_item(out: &str) -> Result<Item, String> {
    let json: Value = serde_json::from_str(out).map_err(|e| format!("op printed no item: {e}"))?;
    let id = json["id"]
        .as_str()
        .ok_or("op printed an item without an id")?
        .to_string();
    Ok(Item { id, json })
}

/// op's error without its `[ERROR] <date> <time> ` prefix.
fn op_message(stderr: &str) -> String {
    let s = stderr.trim();
    match s.strip_prefix("[ERROR] ") {
        Some(rest) => rest.splitn(3, ' ').nth(2).unwrap_or(rest).to_string(),
        None => s.to_string(),
    }
}

/// A vault in memory, answering as `op` does where sesame depends on it (an
/// edit without `tags` wipes them), and recording each request as one line:
/// `list <tag>`, `get <query>`, `create <title>`, `edit <id>`, `archive <id>`.
#[cfg(test)]
#[derive(Clone, Default)]
pub struct Memory(std::sync::Arc<std::sync::Mutex<MemoryState>>);

#[cfg(test)]
#[derive(Default)]
pub struct MemoryState {
    pub items: Vec<Value>,
    pub calls: Vec<String>,
    /// Ids a listing leaves out, as 1Password may a new item.
    pub unlisted: Vec<String>,
    next_id: u64,
}

#[cfg(test)]
impl Memory {
    pub fn state(&self) -> std::sync::MutexGuard<'_, MemoryState> {
        self.0.lock().unwrap()
    }

    /// The requests made since the last `take_calls`.
    pub fn take_calls(&self) -> Vec<String> {
        std::mem::take(&mut self.state().calls)
    }

    /// The item titled `title`, as 1Password holds it.
    pub fn item(&self, title: &str) -> Option<Value> {
        self.state()
            .items
            .iter()
            .find(|i| i["title"] == title)
            .cloned()
    }

    /// Changes item `title` as another machine would: a new version.
    pub fn change(&self, title: &str, f: impl FnOnce(&mut Value)) {
        let mut s = self.state();
        let item = s.items.iter_mut().find(|i| i["title"] == title).unwrap();
        f(item);
        item["version"] = (item["version"].as_u64().unwrap() + 1).into();
    }

    /// Creates an item as another machine would; its id.
    pub fn add(&self, template: Value) -> String {
        let item = self.create(&template).ok().flatten().unwrap();
        self.state().calls.pop();
        item.id
    }

    fn find(s: &MemoryState, query: &str) -> Result<usize, OpError> {
        s.items
            .iter()
            .position(|i| i["id"] == query || i["title"] == query)
            .ok_or(OpError::NoItem)
    }
}

#[cfg(test)]
impl Op for Memory {
    fn list(&self, tag: &str) -> Result<Vec<Listed>, OpError> {
        let mut s = self.state();
        s.calls.push(format!("list {tag}"));
        Ok(s.items
            .iter()
            .filter(|i| i["tags"].as_array().unwrap().iter().any(|t| t == tag))
            .filter(|i| !s.unlisted.iter().any(|u| i["id"] == *u))
            .map(|i| Listed {
                title: i["title"].as_str().unwrap().into(),
                id: i["id"].as_str().unwrap().into(),
                version: i["version"].as_u64().unwrap(),
            })
            .collect())
    }

    fn get(&self, query: &str) -> Result<Item, OpError> {
        let mut s = self.state();
        s.calls.push(format!("get {query}"));
        let i = Memory::find(&s, query)?;
        let json = s.items[i].clone();
        Ok(Item {
            id: json["id"].as_str().unwrap().into(),
            json,
        })
    }

    fn create(&self, template: &Value) -> Result<Option<Item>, OpError> {
        let mut s = self.state();
        s.calls
            .push(format!("create {}", template["title"].as_str().unwrap()));
        s.next_id += 1;
        let id = format!("id{}", s.next_id);
        let mut json = template.clone();
        json["id"] = id.clone().into();
        json["version"] = 1.into();
        if json.get("tags").is_none() {
            json["tags"] = serde_json::json!([]);
        }
        s.items.push(json.clone());
        Ok(Some(Item { id, json }))
    }

    fn edit(&self, id: &str, template: &Value) -> Result<Option<Item>, OpError> {
        let mut s = self.state();
        s.calls.push(format!("edit {id}"));
        let i = Memory::find(&s, id)?;
        let item = &mut s.items[i];
        for k in ["title", "fields", "sections"] {
            if let Some(v) = template.get(k) {
                item[k] = v.clone();
            }
        }
        item["tags"] = template
            .get("tags")
            .cloned()
            .unwrap_or(serde_json::json!([]));
        item["version"] = (item["version"].as_u64().unwrap() + 1).into();
        let json = item.clone();
        Ok(Some(Item {
            id: id.into(),
            json,
        }))
    }

    fn archive(&self, id: &str) -> Result<(), OpError> {
        let mut s = self.state();
        s.calls.push(format!("archive {id}"));
        let i = Memory::find(&s, id)?;
        s.items.remove(i);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn op_message_drops_the_prefix() {
        assert_eq!(
            op_message(
                "[ERROR] 2026/11/20 10:00:00 \"sesame.x\" isn't an item in the \"v\" vault.\n"
            ),
            "\"sesame.x\" isn't an item in the \"v\" vault."
        );
        assert_eq!(op_message("plain\n"), "plain");
    }
}
