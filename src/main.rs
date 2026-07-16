use anyhow::Result;
use clap::Parser;
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::{fs::File, io::Read, path::Path};

use lolbin_watcher::{
    collector::process::collect_process_snapshot,
    collector::process::is_elevated,
    detector::rules::RuleEngine,
    logger::jsonl::append_jsonl,
    models::ProcEvent,
};

#[derive(Parser, Debug)]
#[command(name = "lolbin-watcher", version)]
struct Args {
    #[arg(long)]
    once: bool,

    #[arg(long, default_value = "logs/lolbin-watcher.jsonl")]
    out: String,

    #[arg(long, default_value = "rules/allowlist.txt")]
    allowlist: String,
}

fn main() -> Result<()> {
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(parent) = exe_path.parent() {
            let _ = std::env::set_current_dir(parent);
        }
    }

    if !is_elevated() {
        eprintln!("[WARN] lolbin-watcher is not running as Administrator. \
                   System processes will have missing exe_path.");
    }
    let args = Args::parse();
    let engine = RuleEngine::from_allowlist_file(&args.allowlist);

    if args.once {
        run_once(&engine, &args.out)?;
        return Ok(());
    }

    loop {
        run_once(&engine, &args.out)?;
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
}

fn run_once(engine: &RuleEngine, out_path: &str) -> Result<()> {
    let snapshot = collect_process_snapshot()?;

    let mut pid_to_name = std::collections::HashMap::new();
    for p in &snapshot {
        pid_to_name.insert(p.pid, p.name.clone());
    }

    for p in snapshot {
    let exe_str = p.exe_path.as_ref().map(|x| x.to_string_lossy().to_string());
    let orig_fn = p.original_filename.as_deref();
    let parent_name = p.parent_pid.and_then(|pid| pid_to_name.get(&pid).map(|s| s.as_str()));

    let quick = engine.quick_flags(&p.name, exe_str.as_deref(), orig_fn, &p.cmd, parent_name);

    let should_hash = quick.iter().any(|f|
        f == "exec_from_temp" ||
        f == "exec_from_downloads" ||
        f == "exec_from_appdata" ||
        f == "lolbin_process" ||
        f == "renamed_binary" ||
        f == "suspicious_cmdline" ||
        f == "suspicious_parent" ||
        f == "lolbin_masquerade"
    );

    let sha_str = if should_hash {
        match p.exe_path.as_ref() {
            Some(path) => hash_file_sha256(path).ok(),
            None => None,
        }
    } else {
        None
    };

    let det = engine.detect(
        &p.name,
        exe_str.as_deref(),
        orig_fn,
        &p.cmd,
        parent_name,
        sha_str.as_deref(),
    );

    let evt = ProcEvent {
        ts_utc: Utc::now(),
        pid: p.pid,
        name: p.name,
        exe_path: exe_str,
        original_filename: p.original_filename,
        cmd: p.cmd,
        parent_pid: p.parent_pid,
        sha256: sha_str,
        flags: det.flags,
        severity: det.severity,
    };

    let line = serde_json::to_string(&evt)?;
    append_jsonl(out_path, &line)?;

    if matches!(evt.severity, lolbin_watcher::models::Severity::Medium | lolbin_watcher::models::Severity::High) {
        println!("{}", line);
    }
}

    Ok(())
}

fn hash_file_sha256<P: AsRef<Path>>(path: P) -> Result<String> {
    let mut f = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 1024 * 64];

    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}