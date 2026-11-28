//! What each command spends of the service account's Budget, on the
//! stand-in Core: each scenario asserts its Core calls and its reads and
//! writes, and `docs/budget.md` is the table of them all, with the
//! account's requests they spend (one per read and per write, opcore's
//! decision record 7), which this test fails on when it is stale. Each
//! method's cost is read from opcore's decision record 1, the one home of
//! the numbers, in the opcore source this build compiles (found by `cargo
//! metadata`).
#[path = "support/harness.rs"]
mod harness;

use harness::{Call, FakeProvider, FakeVault, Machine, Out};
use serde_json::Value;
use std::path::{Path, PathBuf};

const FILE: &str = "docs/budget.md";

/// Reads and writes. The account's daily requests count each of both
/// (opcore's decision record 7).
type Budget = [u32; 2];

/// opcore's decision record 1: each method's cost, and what a sign-in's
/// first vault call spends besides it.
struct Costs {
    each: Vec<(String, Budget)>,
    first_call: Budget,
}

/// opcore's decision record 1, in the source `Cargo.lock` pins.
fn adr() -> PathBuf {
    let out = std::process::Command::new(env!("CARGO"))
        .args(["metadata", "--format-version", "1", "--locked"])
        .args([
            "--manifest-path",
            concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let meta: Value = serde_json::from_slice(&out.stdout).unwrap();
    let packages = meta["packages"].as_array().unwrap();
    let opcore = packages.iter().find(|p| p["name"] == "opcore").unwrap();
    let manifest = PathBuf::from(opcore["manifest_path"].as_str().unwrap());
    let dir = manifest.parent().unwrap().join("docs/adr");
    std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("0001-")
        })
        .unwrap_or_else(|| panic!("no decision record 1 in {}", dir.display()))
}

/// The record's table (`| `Method` … | reads | writes | … |`, a parenthesis
/// saying how a row was measured) and its line `A sign-in's first vault
/// call: N read; …`.
fn costs() -> Costs {
    let adr = std::fs::read_to_string(adr()).unwrap();
    let mut each = Vec::new();
    for line in adr.lines().filter(|l| l.starts_with("| `")) {
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        let cost = [cells[2].parse().unwrap(), cells[3].parse().unwrap()];
        let methods = cells[1].split('(').next().unwrap().split('`');
        for m in methods.skip(1).step_by(2) {
            each.push((m.to_string(), cost));
        }
    }
    let lead = "A sign-in's first vault call:";
    let line = adr.lines().find_map(|l| l.strip_prefix(lead));
    let line = line.unwrap_or_else(|| panic!("opcore's decision record 1 lacks `{lead}`"));
    let reads = line.split_whitespace().next().unwrap().parse().unwrap();
    assert!(!each.is_empty(), "opcore's decision record 1 has no table");
    Costs {
        each,
        first_call: [reads, 0],
    }
}

/// What `log` spent: each call the Core did not refuse, its method's cost,
/// and each sign-in's first vault call `first_call` more.
fn spent(costs: &Costs, log: &[Call]) -> Budget {
    let mut spent = [0; 2];
    let mut add = |b: Budget| (0..2).for_each(|i| spent[i] += b[i]);
    let mut first = false;
    for call in log.iter().filter(|c| !c.refused) {
        let method = call.method.as_str();
        if method == "init_client" {
            first = true;
        } else if std::mem::take(&mut first) {
            add(costs.first_call);
        }
        let cost = costs.each.iter().find(|(m, _)| m == method);
        add(cost.unwrap_or_else(|| panic!("no cost of {method}")).1);
    }
    spent
}

struct Row {
    command: String,
    calls: Vec<Call>,
    spent: Budget,
}

/// A scenario: what the row says, the arguments, its stdin, the stand-in's
/// fault (`SESAME_STAND_IN_FAULT`, "" for none), the Core calls it makes
/// (` refused` after one the Core refuses) and what they spend.
type Step<'a> = (&'a str, &'a str, &'a str, &'a str, &'a str, Budget);

/// Runs each step on `m`, asserting it exits 0 with its calls and Budget,
/// and answers its rows.
fn steps(costs: &Costs, m: &Machine, steps: &[Step]) -> Vec<Row> {
    let mut rows = Vec::new();
    for &(command, args, stdin, fault, calls, budget) in steps {
        let args: Vec<&str> = args.split_whitespace().collect();
        let mut c = m.cmd(&args);
        if !fault.is_empty() {
            c.env("SESAME_STAND_IN_FAULT", fault);
        }
        let out: Out = m.output(c, stdin);
        assert!(out.ok, "{command}: {out}");
        let row = Row {
            command: command.into(),
            spent: spent(costs, &out.log),
            calls: out.log,
        };
        let said: Vec<String> = row.calls.iter().map(logged).collect();
        assert_eq!(
            said,
            calls.split_whitespace().collect::<Vec<_>>(),
            "{command}"
        );
        assert_eq!(row.spent, budget, "{command}");
        rows.push(row);
    }
    rows
}

/// A call as a step names it: its method, `!` after it if refused.
fn logged(c: &Call) -> String {
    format!("{}{}", c.method, if c.refused { "!" } else { "" })
}

/// `hub`, a fake provider with the device flow: a login's token lasts 30 s,
/// inside the minute a token must have left, so the first call refreshes
/// it; a refresh's lasts an hour.
fn provider() -> FakeProvider {
    let mut refreshes = 0;
    FakeProvider::serve(move |r| {
        match r.target.as_str() {
        "/device" => (
            "200 OK",
            r#"{"device_code":"dev","user_code":"WDJB-MJHT","verification_uri":"https://example.com/device","expires_in":60,"interval":0}"#.into(),
        ),
        "/token" if r.body.contains("grant_type=urn") => (
            "200 OK",
            r#"{"access_token":"login-token","refresh_token":"refresh-secret","expires_in":30}"#.into(),
        ),
        "/token" if r.is_refresh() => {
            refreshes += 1;
            let b = format!(
                r#"{{"access_token":"refreshed-{refreshes}","refresh_token":"refresh-secret","expires_in":3600}}"#
            );
            ("200 OK", b)
        }
        "/me" => ("200 OK", r#"{"me":"octo"}"#.into()),
        _ => ("404 Not Found", "{}".into()),
    }
    })
}

/// A new host's sign-in: it finds the vault. After it, the Copy knows the
/// vault, and a sign-in is `init_client` alone.
const FIRST_SIGN_IN: &str = "init_client VaultsList";

/// Every command's scenarios, in the order they run on two machines.
fn rows() -> Vec<Row> {
    let costs = costs();
    let fake = provider();
    let vault = FakeVault::new();
    let a = Machine::new("budget-a").with_vault(&vault);
    let b = Machine::new("budget-b").with_vault(&vault);
    let base = fake.base();
    let add = fake.add_args("hub", "", &["--device-url", &format!("{base}/device")]);
    let add = add.join(" ");
    // A sync that finds nothing moved.
    let listed = "init_client ItemsList".to_string();
    // A write, staged and pushed: the push's list, its read of the item as
    // 1Password holds it now, the write.
    let edit = format!("{listed} ItemsGetAll ItemsPut");
    // A refresh: the sync it decides on, then its write's push.
    let refresh = format!("{listed} ItemsList ItemsGetAll ItemsPut");
    // A create: a sync first (another host may have made the item), then
    // the push.
    let create = format!("{listed} ItemsList ItemsCreateAll");
    let mut rows = steps(
        &costs,
        &a,
        &[
            (
                "`provider add`, the first run on a new host",
                &add,
                "",
                "",
                &format!("{FIRST_SIGN_IN} ItemsList ItemsList ItemsCreateAll"),
                [2, 1],
            ),
            (
                "`client`",
                "client hub --client-id cid --secret-stdin",
                "client-secret\n",
                "",
                &create,
                [2, 1],
            ),
            ("`login`", "login hub --no-browser", "", "", &edit, [3, 1]),
            (
                "a refresh (`token`, the token expiring)",
                "token hub",
                "",
                "",
                &refresh,
                [3, 1],
            ),
            (
                "a valid token from the Copy (`api`)",
                "api hub /me",
                "",
                "",
                "",
                [0, 0],
            ),
            (
                "a valid token from the Copy (`token`)",
                "token hub",
                "",
                "",
                "",
                [0, 0],
            ),
            (
                "a forced refresh (`token --min-life 7200`)",
                "token hub --min-life 7200",
                "",
                "",
                &refresh,
                [3, 1],
            ),
            (
                "a refresh 1Password refuses to write (the rate limit), the token kept in the Copy",
                "token hub --min-life 7200",
                "",
                "over-budget",
                &format!("{listed} ItemsList ItemsGetAll ItemsPut!"),
                [1, 0],
            ),
        ],
    );
    // Past opcore's retry wait (1 s) for the write that waits.
    std::thread::sleep(std::time::Duration::from_millis(1500));
    rows.extend(steps(
        &costs,
        &a,
        &[
            (
                "`providers`, writing the kept token",
                "providers",
                "",
                "",
                &edit,
                [3, 1],
            ),
            ("`providers`", "providers", "", "", &listed, [1, 0]),
            (
                "`provider set`",
                "provider set hub --about second",
                "",
                "",
                &edit,
                [3, 1],
            ),
            ("`provider show`", "provider show hub", "", "", "", [0, 0]),
        ],
    ));
    rows.extend(steps(
        &costs,
        &b,
        &[(
            "`token`, the first run on a new host",
            "token hub",
            "",
            "",
            &format!("{FIRST_SIGN_IN} ItemsList ItemsGetAll"),
            [1, 0],
        )],
    ));
    rows.extend(steps(
        &costs,
        &a,
        &[
            ("`logout`", "logout hub", "", "", &edit, [3, 1]),
            (
                "`client --reset`, the item left empty archived",
                "client hub --reset",
                "",
                "",
                &format!("{listed} ItemsArchive"),
                [3, 1],
            ),
            (
                "`provider rm`, the last provider's fields: their item archived",
                "provider rm hub",
                "",
                "",
                &format!("{listed} ItemsArchive"),
                [3, 1],
            ),
        ],
    ));
    rows
}

/// The calls in order, a run of one method as one entry with its count, a
/// refused one marked.
fn calls(calls: &[Call]) -> String {
    let one = |c: &Call| {
        let refused = if c.refused { " (refused)" } else { "" };
        format!("`{}`{refused}", c.method)
    };
    let run = |run: &[Call]| match run.len() {
        1 => one(&run[0]),
        n => format!("{} ×{n}", one(&run[0])),
    };
    let runs: Vec<String> = calls.chunk_by(|a, b| a == b).map(run).collect();
    if runs.is_empty() {
        "none".into()
    } else {
        runs.join(", ")
    }
}

fn table(rows: &[Row]) -> String {
    let mut t = String::from(
        "# Budget per command\n\n\
         Generated by `tests/budget.rs`, which fails when this file differs from \
         what its scenarios spend on the stand-in Core; \
         `UPDATE_BUDGET=1 cargo test --test budget` rewrites it. Each method's cost \
         is opcore's decision record 1, in the opcore source `Cargo.lock` pins. \
         Each command is a new process: its first vault call after signing in \
         spends one read more. The account's daily requests count each read and \
         each write (opcore's decision record 7). A call 1Password refuses spends \
         nothing. `scripts/e2e.sh` measures the same commands on the vault \
         `sesame-scratch`.\n\n\
         | Command | Core calls | Reads | Writes | Account requests |\n\
         |---|---|---|---|---|\n",
    );
    for r in rows {
        let [reads, writes] = r.spent;
        let calls = calls(&r.calls);
        t.push_str(&format!(
            "| {} | {calls} | {reads} | {writes} | {} |\n",
            r.command,
            reads + writes
        ));
    }
    t
}

#[test]
fn docs_budget_md_is_what_each_command_spends() {
    let made = table(&rows());
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(FILE);
    if std::env::var_os("UPDATE_BUDGET").is_some() {
        std::fs::write(&path, &made).unwrap();
    }
    let kept = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        kept == made,
        "{FILE} is not what the commands spend: run `UPDATE_BUDGET=1 cargo test --test budget` \
         and commit it.\n--- {FILE}\n{kept}\n--- the scenarios\n{made}"
    );
}
