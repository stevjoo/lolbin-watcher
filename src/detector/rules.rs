use crate::models::{DetectionResult, Severity};
use std::{collections::HashSet, fs, path::Path};

#[derive(Debug, Clone)]
pub struct RuleEngine {
    allowlisted_names: HashSet<String>,
}

impl RuleEngine {
    pub fn from_allowlist_file<P: AsRef<Path>>(path: P) -> Self {
        let mut set = HashSet::new();
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines() {
                let t = line.trim();
                if t.is_empty() || t.starts_with('#') {
                    continue;
                }
                set.insert(t.to_lowercase());
            }
        }
        Self {
            allowlisted_names: set,
        }
    }

    pub fn detect(&self, proc_name: &str, exe_path: Option<&str>, sha256: Option<&str>) -> DetectionResult {
        let mut flags: Vec<String> = Vec::new();

        let name_lc = proc_name.to_lowercase();
        let path_lc = exe_path.unwrap_or("").to_lowercase();

        let known_system = ["lsass.exe", "csrss.exe", "smss.exe", "wininit.exe"];
        if exe_path.is_none() && !known_system.contains(&name_lc.as_str()) {
            flags.push("no_exe_path".to_string());
        }

        if self.allowlisted_names.contains(&name_lc) {
            return DetectionResult {
                flags: vec!["allowlisted_name".to_string()],
                severity: Severity::Low,
            };
        }

        if exe_path.is_none() {
            flags.push("no_exe_path".to_string());
        }

        if sha256.is_none() {
            flags.push("no_hash".to_string());
        }

        if !path_lc.is_empty() {
            if path_lc.contains("\\appdata\\local\\temp\\") || path_lc.contains("\\windows\\temp\\") {
                flags.push("exec_from_temp".to_string());
            }
            if path_lc.contains("\\downloads\\") {
                flags.push("exec_from_downloads".to_string());
            }
            if path_lc.contains("\\appdata\\roaming\\") || path_lc.contains("\\appdata\\local\\") {
                flags.push("exec_from_appdata".to_string());
            }
        }

        let lolbins = [
            "powershell.exe",
            "pwsh.exe",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta.exe",
            "rundll32.exe",
            "regsvr32.exe",
            "certutil.exe",
            "bitsadmin.exe",
            "wmic.exe",
        ];
        if lolbins.iter().any(|x| *x == name_lc) {
            flags.push("lolbin_process".to_string());
        }

        let severity = if flags.contains(&"exec_from_temp".to_string()) && flags.contains(&"lolbin_process".to_string()) {
            Severity::High
        } else if flags.iter().any(|f| f.starts_with("exec_from_")) || flags.contains(&"lolbin_process".to_string()) {
            Severity::Medium
        } else if flags.is_empty() {
            Severity::Low
        } else {
            Severity::Low
        };

        DetectionResult { flags, severity }
    }

        pub fn quick_flags(&self, proc_name: &str, exe_path: Option<&str>) -> Vec<String> {
        let mut flags: Vec<String> = Vec::new();

        let name_lc = proc_name.to_lowercase();
        let path_lc = exe_path.unwrap_or("").to_lowercase();

        if !path_lc.is_empty() {
            if path_lc.contains("\\appdata\\local\\temp\\") || path_lc.contains("\\windows\\temp\\") {
                flags.push("exec_from_temp".to_string());
            }
            if path_lc.contains("\\downloads\\") {
                flags.push("exec_from_downloads".to_string());
            }
            if path_lc.contains("\\appdata\\roaming\\") || path_lc.contains("\\appdata\\local\\") {
                flags.push("exec_from_appdata".to_string());
            }
        } else {
            flags.push("no_exe_path".to_string());
        }

        let lolbins = [
            "powershell.exe",
            "pwsh.exe",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta.exe",
            "rundll32.exe",
            "regsvr32.exe",
            "certutil.exe",
            "bitsadmin.exe",
            "wmic.exe",
        ];
        if lolbins.iter().any(|x| *x == name_lc) {
            flags.push("lolbin_process".to_string());
        }

        if self.allowlisted_names.contains(&name_lc) {
            flags.push("allowlisted_name".to_string());
        }

        flags
    }
}
