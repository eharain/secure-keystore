//! The command line for the secure-keystore format.
//!
//! ```sh
//! cargo install secure-keystore
//! ```
//!
//! Every line this crate prints is printed here. The library takes a logger and
//! is otherwise silent, which is what lets it drop into a server that has
//! opinions about its own logging.
//!
//! The verbs, the error codes and the `--json` output match every other
//! implementation, so a shell script should not be able to tell which one it is
//! calling.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use secure_keystore::{
    decrypt_value, encrypt_value, Error, Keystore, DEFAULT_ITERATIONS, STORE_FORMAT_VERSION, VERSION,
};
use serde_json::{json, Value};

const NAME: &str = "secure-keystore";

#[derive(Default)]
struct Flags {
    keystore: Option<PathBuf>,
    iterations: Option<u32>,
    json: bool,
    quiet: bool,
    help: bool,
    version: bool,
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let (flags, positional) = parse_args(&argv);

    if flags.version {
        println!("{VERSION}");
        return ExitCode::SUCCESS;
    }

    if flags.help || positional.is_empty() {
        print_help();
        return ExitCode::SUCCESS;
    }

    match run(&flags, &positional) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // The code first, because the code is the half that is stable, and
            // the same line every implementation prints for the same failure.
            if flags.json {
                eprintln!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "error": error.message,
                        "code": error.code.as_str(),
                    }))
                    .unwrap_or_default()
                );
            } else {
                eprintln!("{}: {}", error.code, error.message);
            }
            ExitCode::FAILURE
        }
    }
}

/// Pulls the flags out and leaves the positional arguments behind.
///
/// Written by hand rather than with a parser crate, because this binary accepts
/// fifteen fixed shapes and a dependency with a release cadence of its own is a
/// more expensive thing to own than thirty lines.
fn parse_args(argv: &[String]) -> (Flags, Vec<String>) {
    let mut flags = Flags::default();
    let mut positional = Vec::new();
    let mut index = 0;

    while index < argv.len() {
        let arg = argv[index].as_str();
        match arg {
            "--keystore" if index + 1 < argv.len() => {
                index += 1;
                flags.keystore = Some(PathBuf::from(&argv[index]));
            }
            "--iterations" if index + 1 < argv.len() => {
                index += 1;
                flags.iterations = argv[index].parse().ok();
            }
            "--json" => flags.json = true,
            "--quiet" => flags.quiet = true,
            "--help" | "-h" => flags.help = true,
            "--version" | "-v" => flags.version = true,
            _ => {
                if let Some(value) = arg.strip_prefix("--keystore=") {
                    flags.keystore = Some(PathBuf::from(value));
                } else if let Some(value) = arg.strip_prefix("--iterations=") {
                    flags.iterations = value.parse().ok();
                } else {
                    positional.push(arg.to_string());
                }
            }
        }
        index += 1;
    }

    (flags, positional)
}

fn run(flags: &Flags, positional: &[String]) -> Result<(), Error> {
    let mut builder = Keystore::builder().iterations(flags.iterations.unwrap_or(DEFAULT_ITERATIONS));

    if let Some(dir) = &flags.keystore {
        builder = builder.keystore_dir(dir);
    }
    if !flags.quiet && !flags.json {
        builder = builder.logger(|message| println!("{message}"));
    }

    let store = builder.build()?;
    let command = positional[0].as_str();
    let args: Vec<&str> = positional[1..].iter().map(String::as_str).collect();

    // Each command hands over both forms of its result at once: text for a
    // person, data for a script. Which one is printed is decided in one place.
    let emit = |text: String, data: Value| {
        if flags.json {
            println!("{}", serde_json::to_string_pretty(&data).unwrap_or_default());
        } else {
            println!("{text}");
        }
    };

    match command {
        "secure" => {
            let [input, user_key, rest @ ..] = args.as_slice() else {
                return Err(usage("secure <input-file> <user-key> [store-name]"));
            };
            let result = store.secure(Path::new(input), user_key, rest.first().copied())?;
            emit(
                result.keys.join("\n"),
                json!({
                    "storeName": result.store_name,
                    "storeDir": result.store_dir,
                    "totalKeys": result.total_keys,
                    "keys": result.keys,
                }),
            );
        }

        "get" => {
            let [key, user_key, rest @ ..] = args.as_slice() else {
                return Err(usage("get <key> <user-key> [store-name]"));
            };
            let value = store.get(key, user_key, rest.first().copied())?;
            // The bare value, so KEY=$(secure-keystore get x "$K" prod) works.
            emit(value.clone(), json!({ "key": key, "value": value }));
        }

        "all" => {
            let [store_name, user_key] = args.as_slice() else {
                return Err(usage("all <store-name> <user-key>"));
            };
            let values = store.get_all(user_key, store_name)?;
            let text = values
                .iter()
                .map(|(key, value)| format!("{key}={value}"))
                .collect::<Vec<_>>()
                .join("\n");
            emit(text, json!({ "store": store_name, "values": values }));
        }

        "set" => {
            let [key, value, user_key, store_name] = args.as_slice() else {
                return Err(usage("set <key> <value> <user-key> <store-name>"));
            };
            let result = store.set(key, value, user_key, store_name)?;
            let verb = if result.added { "added to" } else { "updated in" };
            emit(
                format!("Key {:?} {verb} {:?}", result.key, result.store_name),
                json!({
                    "key": result.key,
                    "storeName": result.store_name,
                    "added": result.added,
                    "format": result.format,
                }),
            );
        }

        "migrate" => {
            let [store_name, user_key] = args.as_slice() else {
                return Err(usage("migrate <store-name> <user-key>"));
            };
            let result = store.migrate(store_name, user_key)?;
            let text = if result.from == result.to {
                format!(
                    "Store {:?} re-encrypted in format {} at {} iterations",
                    result.store_name, result.to, result.iterations
                )
            } else {
                format!(
                    "Store {:?} migrated from format {} to {}",
                    result.store_name, result.from, result.to
                )
            };
            emit(
                text,
                json!({
                    "storeName": result.store_name,
                    "from": result.from,
                    "to": result.to,
                    "keys": result.keys,
                    "iterations": result.iterations,
                }),
            );
        }

        "list" => {
            let [store_name] = args.as_slice() else {
                return Err(usage("list <store-name>"));
            };
            let keys = store.list_keys(store_name)?;
            emit(keys.join("\n"), json!({ "store": store_name, "keys": keys }));
        }

        "stores" => {
            let mut infos = Vec::new();
            let mut lines = Vec::new();

            for name in store.list_stores()? {
                if let Ok(info) = store.store_info(&name) {
                    lines.push(format!("{}  ({} keys)", info.name, info.total_keys));
                    infos.push(json!({
                        "name": info.name,
                        "version": info.version,
                        "current": info.current,
                        "totalKeys": info.total_keys,
                    }));
                }
            }

            let text = if lines.is_empty() {
                "No stores found".to_string()
            } else {
                lines.join("\n")
            };
            emit(text, json!({ "stores": infos }));
        }

        "info" => {
            let [store_name] = args.as_slice() else {
                return Err(usage("info <store-name>"));
            };
            let info = store.store_info(store_name)?;
            let shown = if info.current {
                info.version.clone()
            } else {
                format!("{}  (run migrate to bring it to {STORE_FORMAT_VERSION})", info.version)
            };
            let text = [
                format!("Name:        {}", info.name),
                format!("Path:        {}", info.path.display()),
                format!("Format:      {shown}"),
                format!("Created:     {}", info.created),
                format!("Updated:     {}", info.updated),
                format!("Iterations:  {}", info.iterations),
                format!("Total keys:  {}", info.total_keys),
                format!("Keys:        {}", info.keys.join(", ")),
                format!("Source file: {}", info.source_file),
            ]
            .join("\n");
            emit(
                text,
                json!({
                    "name": info.name,
                    "path": info.path,
                    "version": info.version,
                    "current": info.current,
                    "created": info.created,
                    "updated": info.updated,
                    "iterations": info.iterations,
                    "totalKeys": info.total_keys,
                    "keys": info.keys,
                    "sourceFile": info.source_file,
                }),
            );
        }

        "delete" => {
            let [key, store_name] = args.as_slice() else {
                return Err(usage("delete <key> <store-name>"));
            };
            store.delete_key(key, store_name)?;
            emit(
                format!("Key {key:?} deleted from {store_name:?}"),
                json!({ "key": key, "store": store_name, "deleted": true }),
            );
        }

        "delete-store" => {
            let [store_name] = args.as_slice() else {
                return Err(usage("delete-store <store-name>"));
            };
            store.delete_store(store_name)?;
            emit(
                format!("Keystore {store_name:?} deleted"),
                json!({ "store": store_name, "deleted": true }),
            );
        }

        "export" => {
            let [store_name, rest @ ..] = args.as_slice() else {
                return Err(usage("export <store-name> [backup-path]"));
            };
            let written = store.export_store(store_name, rest.first().map(Path::new))?;
            emit(
                written.display().to_string(),
                json!({ "store": store_name, "path": written }),
            );
        }

        "import" => {
            let [backup, rest @ ..] = args.as_slice() else {
                return Err(usage("import <backup-path> [store-name]"));
            };
            let imported = store.import_store(Path::new(backup), rest.first().copied())?;
            emit(
                format!("Store imported as {imported:?}"),
                json!({ "store": imported }),
            );
        }

        "encrypt" => {
            let [value, user_key] = args.as_slice() else {
                return Err(usage("encrypt <value> <user-key>"));
            };
            let token = encrypt_value(value, user_key, flags.iterations)?;
            emit(token.clone(), json!({ "token": token }));
        }

        "decrypt" => {
            let [token, user_key] = args.as_slice() else {
                return Err(usage("decrypt <token> <user-key>"));
            };
            let value = decrypt_value(token, user_key)?;
            emit(value.clone(), json!({ "value": value }));
        }

        other => {
            eprintln!("Unknown command: {other}\n");
            print_help();
            return Err(Error {
                code: secure_keystore::Code::InvalidArgument,
                message: format!("unknown command: {other}"),
            });
        }
    }

    Ok(())
}

fn usage(line: &str) -> Error {
    eprintln!("Usage: {NAME} {line}");
    Error {
        code: secure_keystore::Code::InvalidArgument,
        message: format!("usage: {NAME} {line}"),
    }
}

fn print_help() {
    println!(
        "
{NAME} {VERSION} - encrypted secrets at rest, with no service to run

Usage:
  {NAME} secure <input-file> <user-key> [store-name]
  {NAME} get <key> <user-key> [store-name]
  {NAME} all <store-name> <user-key>
  {NAME} set <key> <value> <user-key> <store-name>
  {NAME} migrate <store-name> <user-key>
  {NAME} list <store-name>
  {NAME} stores
  {NAME} info <store-name>
  {NAME} delete <key> <store-name>
  {NAME} delete-store <store-name>
  {NAME} export <store-name> [backup-path]
  {NAME} import <backup-path> [store-name]
  {NAME} encrypt <value> <user-key>
  {NAME} decrypt <token> <user-key>
  {NAME} --help | --version

Options:
  --keystore <dir>     where stores live (default ./.keystore)
  --iterations <n>     PBKDF2 rounds for new or migrated stores (default {DEFAULT_ITERATIONS})
  --json               print machine-readable JSON instead of prose
  --quiet              print results only, no progress

Examples:
  {NAME} secure keys.env \"$USER_KEY\" production
  {NAME} get api_key \"$USER_KEY\" production
  {NAME} stores
  {NAME} migrate production \"$USER_KEY\"

A key name is not a secret: 'list', 'stores' and 'info' read metadata and need
no user key. 'get', 'all', 'set' and 'migrate' decrypt, and do."
    );
}
