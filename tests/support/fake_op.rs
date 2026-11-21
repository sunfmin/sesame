//! A fake `op` (1Password CLI) for the tests: the item commands sesame uses,
//! against items kept in `$FAKE_OP_DIR/items.json`. Every call is appended to
//! `$FAKE_OP_DIR/calls.log` as one JSON line: its argv and whether its
//! environment carried the service account token. It answers as op 2.x does
//! where sesame depends on it, as op 2.42.0 answered the contract's cases:
//! errors on stderr with an `[ERROR] <date> <time>` prefix, "isn't an item",
//! "isn't a vault", a template only from a stdin pipe without `--template`,
//! tags kept sorted, an edit without `tags` keeping them (though its own
//! answer shows none), and an archived item still answering `item get <id>`
//! (`"state": "ARCHIVED"`) but not its title, a list or an edit. With
//! `FAKE_OP_MAX_WRITES=<n>`, a write after the first n logged is refused as
//! op refuses one over the service account's budget. An edit of an item not
//! there is refused ("could not find item to edit"); with
//! `FAKE_OP_FAULT=edit-gone` every edit is, as if another machine had removed
//! its item since it was read. Each of these is a case
//! of its truefit contract (truefit.toml, tests/contract/): `truefit contract`
//! runs them in the gate, `truefit contract --real op` against the real `op`.
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::FileTypeExt;
use std::path::PathBuf;

fn fail(msg: &str) -> ! {
    eprintln!("[ERROR] 2026/11/20 10:00:00 {msg}");
    std::process::exit(1)
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

/// The item template on stdin, if stdin is a pipe: op reads one from
/// nothing else.
fn template() -> Option<Value> {
    let stdin = std::io::stdin();
    let fd = stdin.as_fd().try_clone_to_owned().unwrap();
    if !std::fs::File::from(fd)
        .metadata()
        .is_ok_and(|m| m.file_type().is_fifo())
    {
        return None;
    }
    let mut s = String::new();
    stdin.lock().read_to_string(&mut s).unwrap();
    Some(serde_json::from_str(&s).unwrap_or_else(|e| fail(&format!("invalid template: {e}"))))
}

fn archived(item: &Value) -> bool {
    item["state"] == "ARCHIVED"
}

/// `tags` sorted, as op keeps them.
fn sort_tags(item: &mut Value) {
    if let Some(tags) = item["tags"].as_array_mut() {
        tags.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
    }
}

fn main() {
    let dir = PathBuf::from(std::env::var("FAKE_OP_DIR").expect("FAKE_OP_DIR"));
    let args: Vec<String> = std::env::args().skip(1).collect();
    let token = std::env::var("OP_SERVICE_ACCOUNT_TOKEN").ok();
    let expected = std::env::var("FAKE_OP_TOKEN").ok();
    let mut log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("calls.log"))
        .unwrap();
    let line = json!({"argv": args, "token": token.is_some() && token == expected});
    writeln!(log, "{line}").unwrap();
    if token.is_none() || token != expected {
        fail("authentication failed: invalid service account token");
    }
    let is_write = |argv: &[Value]| {
        argv.len() > 1
            && argv[0] == "item"
            && ["create", "edit", "delete"].iter().any(|w| argv[1] == *w)
    };
    if let Ok(max) = std::env::var("FAKE_OP_MAX_WRITES") {
        let writes = std::fs::read_to_string(dir.join("calls.log"))
            .unwrap()
            .lines()
            .filter(|l| {
                let v: Value = serde_json::from_str(l).unwrap();
                is_write(v["argv"].as_array().unwrap())
            })
            .count();
        if writes > max.parse().unwrap() && is_write(line["argv"].as_array().unwrap()) {
            // As op 2.42.0 refused them (sesame#31): no number of seconds;
            // an edit or create, from its stdin template, as a network error
            // on its line 1; an archive with exit 4.
            let m = "Too many requests. Your client has been rate-limited. Try again in  seconds";
            if args[1] == "delete" {
                eprintln!("[ERROR] 2026/11/20 10:00:00 {m}: {m}");
                std::process::exit(4)
            }
            fail(&format!("unable to process line 1: Network: ({m}), {m}"));
        }
    }
    if args.iter().any(|a| a == "--template") {
        fail(
            "unable to process line 1: cannot create an item from template and stdin at the same time",
        );
    }
    let vault = std::env::var("FAKE_OP_VAULT").unwrap();
    if let Some(v) = flag(&args, "--vault")
        && v != vault
    {
        fail(&format!(
            "\"{v}\" isn't a vault in this account. Specify the vault with its ID or name."
        ));
    }
    let path = dir.join("items.json");
    let mut items: Vec<Value> = std::fs::read(&path)
        .ok()
        .map(|b| serde_json::from_slice(&b).unwrap())
        .unwrap_or_default();
    // An archived item answers its id only.
    let find = |items: &[Value], q: &str| -> usize {
        let hits: Vec<usize> = (0..items.len())
            .filter(|&i| items[i]["id"] == q || (items[i]["title"] == q && !archived(&items[i])))
            .collect();
        match hits.as_slice() {
            [i] => *i,
            [] => fail(&format!(
                "\"{q}\" isn't an item in the \"{vault}\" vault. Specify the item with its UUID, name, or domain."
            )),
            _ => fail(&format!("More than one item matches \"{q}\".")),
        }
    };
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["item", "get", q, ..] => {
            let i = find(&items, q);
            println!("{}", items[i]);
        }
        ["item", "list", ..] => {
            let tag = flag(&args, "--tags");
            let listed: Vec<Value> = items
                .iter()
                .filter(|i| !archived(i))
                .filter(|i| {
                    tag.as_ref().is_none_or(|t| {
                        i["tags"]
                            .as_array()
                            .is_some_and(|ts| ts.iter().any(|x| x == t))
                    })
                })
                .map(|i| json!({"id": i["id"], "title": i["title"], "tags": i["tags"], "version": i["version"]}))
                .collect();
            println!("{}", Value::Array(listed));
        }
        ["item", "create", ..] => {
            let Some(mut t) = template() else {
                fail("provide the item category with '--category' flag")
            };
            let id = format!("item{}", std::process::id());
            t["id"] = id.into();
            t["version"] = 1.into();
            t["vault"] = json!({"name": vault});
            if t.get("tags").is_none() {
                t["tags"] = json!([]);
            }
            sort_tags(&mut t);
            println!("{t}");
            items.push(t);
        }
        ["item", "edit", q, ..] => {
            let gone = std::env::var("FAKE_OP_FAULT").is_ok_and(|f| f == "edit-gone");
            if gone
                || !items
                    .iter()
                    .any(|i| i["id"] == *q || (i["title"] == *q && !archived(i)))
            {
                fail("unable to process line 1: could not find item to edit");
            }
            let i = find(&items, q);
            let Some(t) = template() else {
                fail("fake op: an edit takes its template on a stdin pipe")
            };
            if archived(&items[i]) {
                fail("unable to process line 1: Couldn't update the item.");
            }
            let item = &mut items[i];
            for k in ["title", "fields", "sections", "tags"] {
                if let Some(v) = t.get(k) {
                    item[k] = v.clone();
                }
            }
            sort_tags(item);
            item["version"] = (item["version"].as_u64().unwrap() + 1).into();
            // As op does: an edit without `tags` keeps them, but its answer
            // shows none.
            let mut answer = item.clone();
            if t.get("tags").is_none() {
                answer["tags"] = json!([]);
            }
            println!("{answer}");
        }
        ["item", "delete", q, ..] => {
            let i = find(&items, q);
            if args.iter().any(|a| a == "--archive") {
                items[i]["state"] = "ARCHIVED".into();
                items[i]["version"] = (items[i]["version"].as_u64().unwrap() + 1).into();
            } else {
                items.remove(i);
            }
        }
        ["read", reference] => {
            let r = reference
                .strip_prefix("op://")
                .unwrap_or_else(|| fail("bad reference"));
            let parts: Vec<&str> = r.split('/').collect();
            let [v, title, field] = parts.as_slice() else {
                fail("bad reference")
            };
            if *v != vault {
                fail(&format!("\"{v}\" isn't a vault in this account."));
            }
            let i = find(&items, title);
            let f = items[i]["fields"]
                .as_array()
                .unwrap()
                .iter()
                .find(|f| f["id"] == *field || f["label"] == *field)
                .unwrap_or_else(|| fail(&format!("no field `{field}`")));
            println!("{}", f["value"].as_str().unwrap());
        }
        _ => fail(&format!("fake op does not know: {args:?}")),
    }
    std::fs::write(&path, serde_json::to_vec_pretty(&items).unwrap()).unwrap();
}
