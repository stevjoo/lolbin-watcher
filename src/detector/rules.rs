use crate::models::{DetectionResult, Severity};
use std::{collections::HashSet, fs, path::Path};

// Well-known Living-off-the-Land Binaries.
// Checked against BOTH the actual process name AND the PE OriginalFilename.
const LOLBINS: &[&str] = &[
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

    // Helper Function Call --> Intinya jadi helper function ko

    // Check if a name is in the LOLBin list.
    fn is_lolbin(name: &str) -> bool {
        LOLBINS.iter().any(|x| *x == name)
    }

    // Normalize a PE OriginalFilename for comparison.
    // Windows PE VersionInfo sering pakai suffix .MUI atau .dll untuk binary
    // yang sebenarnya exe, jadi kita harus normalize dulu sebelum compare.
    //   "PowerShell.EXE.MUI" → "powershell.exe"
    //   "CTFMON.EXE.MUI"     → "ctfmon.exe"
    //   "Copilot.dll"        → "copilot.dll" (tetap, bukan rename sebenarnya)
    //   "svchost.exe.mui"    → "svchost.exe"
    fn normalize_original_filename(orig: &str) -> String {
        let s = orig.trim().to_lowercase();
        // Strip trailing .mui (resource-only naming convention)
        if let Some(base) = s.strip_suffix(".mui") {
            base.to_string()
        } else {
            s
        }
    }

    // Determine whether a binary has been renamed by comparing its current
    // file-system name to the OriginalFilename from its PE VersionInfo.
    // Returns `true` when the two names are present AND different (case-insensitive).
    //
    // Handles common Windows PE conventions:
    //  - .MUI suffix (e.g. "PowerShell.EXE.MUI" is NOT a rename of powershell.exe)
    //  - .dll vs .exe mismatch in Electron/MSIX apps (e.g. "Copilot.dll" is NOT
    //    a rename of Copilot.exe — same stem = not suspicious)
    fn is_renamed(actual_name: &str, original_filename: Option<&str>) -> bool {
        match original_filename {
            Some(orig) => {
                let normalized = Self::normalize_original_filename(orig);
                if normalized.is_empty() {
                    return false;
                }
                let actual_lc = actual_name.to_lowercase();

                // Exact match after normalization artinya not renamed
                if normalized == actual_lc {
                    return false;
                }

                // Same stem, different extension (.exe vs .dll) -> not renamed
                // Ini sering terjadi di Electron/MSIX apps
                let stem_actual = actual_lc.rsplit_once('.').map(|(s, _)| s).unwrap_or(&actual_lc);
                let stem_orig = normalized.rsplit_once('.').map(|(s, _)| s).unwrap_or(&normalized);
                if stem_actual == stem_orig {
                    return false;
                }

                true
            }
            None => false,
        }
    }

    // Path-based flags

    fn path_flags(path_lc: &str) -> Vec<String> {
        let mut flags = Vec::new();
        if path_lc.is_empty() {
            return flags;
        }
        if path_lc.contains("\\appdata\\local\\temp\\") || path_lc.contains("\\windows\\temp\\") {
            flags.push("exec_from_temp".to_string());
        }
        if path_lc.contains("\\downloads\\") {
            flags.push("exec_from_downloads".to_string());
        }
        // AppData\Local\Programs\ itu standard install directory untuk user-level
        // apps (Discord, VS Code, Opera, dsb). Jangan flag ini sebagai suspicious.
        // Yang kita flag hanya direct execution dari AppData yang bukan Programs.
        let is_appdata = path_lc.contains("\\appdata\\roaming\\") || path_lc.contains("\\appdata\\local\\");
        let is_programs = path_lc.contains("\\appdata\\local\\programs\\");
        if is_appdata && !is_programs {
            flags.push("exec_from_appdata".to_string());
        }
        flags
    }

    // public API used by main.rs

    // Lightweight pre-scan: returns a list of flag strings so `main.rs` can
    // decide whether it is worth computing the SHA-256 hash for this process.
    pub fn quick_flags(
        &self,
        proc_name: &str,
        exe_path: Option<&str>,
        original_filename: Option<&str>,
    ) -> Vec<String> {
        let mut flags: Vec<String> = Vec::new();

        let name_lc = proc_name.to_lowercase();
        let path_lc = exe_path.unwrap_or("").to_lowercase();

        // Path-based flags
        if path_lc.is_empty() {
            flags.push("no_exe_path".to_string());
        } else {
            flags.extend(Self::path_flags(&path_lc));
        }

        // LOLBin detection: by actual name OR by OriginalFilename
        // Pakai normalize supaya .MUI suffix di-strip sebelum compare
        let orig_normalized = original_filename.map(|s| Self::normalize_original_filename(s));
        let is_lolbin_by_name = Self::is_lolbin(&name_lc);
        let is_lolbin_by_orig = orig_normalized.as_deref().map_or(false, Self::is_lolbin);

        if is_lolbin_by_name || is_lolbin_by_orig {
            flags.push("lolbin_process".to_string());
        }

        // Renamed binary detection
        if Self::is_renamed(&name_lc, orig_normalized.as_deref()) {
            flags.push("renamed_binary".to_string());
        }

        if self.allowlisted_names.contains(&name_lc) {
            flags.push("allowlisted_name".to_string());
        }

        flags
    }

    // Full detection with severity classification.
    pub fn detect(
        &self,
        proc_name: &str,
        exe_path: Option<&str>,
        original_filename: Option<&str>,
        sha256: Option<&str>,
    ) -> DetectionResult {
        let mut flags: Vec<String> = Vec::new();

        let name_lc = proc_name.to_lowercase();
        let path_lc = exe_path.unwrap_or("").to_lowercase();
        // Pakai normalize supaya .MUI suffix di-strip sebelum compare
        let orig_normalized = original_filename.map(|s| Self::normalize_original_filename(s));

        // Kalau ketemu missing exe_path
        let known_system = ["lsass.exe", "csrss.exe", "smss.exe", "wininit.exe"];
        if exe_path.is_none() && !known_system.contains(&name_lc.as_str()) {
            flags.push("no_exe_path".to_string());
        }

        // Allowlist short-circuit
        // Only trust the allowlist when the binary has NOT been renamed.
        // A renamed binary is suspicious regardless of its current name.
        let renamed = Self::is_renamed(&name_lc, orig_normalized.as_deref());
        if self.allowlisted_names.contains(&name_lc) && !renamed {
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

        // path-based flags
        flags.extend(Self::path_flags(&path_lc));

        // LOLBin detection: by actual name OR by OriginalFilename
        let is_lolbin_by_name = Self::is_lolbin(&name_lc);
        let is_lolbin_by_orig = orig_normalized.as_deref().map_or(false, Self::is_lolbin);

        if is_lolbin_by_name || is_lolbin_by_orig {
            flags.push("lolbin_process".to_string());
        }

        // renamed binary detection
        if renamed {
            flags.push("renamed_binary".to_string());
        }

        // If a LOLBin was detected only through the OriginalFilename
        // (meaning the file was renamed to evade name-based detection),
        // flag the masquerade explicitly.
        if !is_lolbin_by_name && is_lolbin_by_orig && renamed {
            flags.push("lolbin_masquerade".to_string());
        }

        // severity classification
        let has_exec_from = flags.iter().any(|f| f.starts_with("exec_from_"));
        let has_lolbin = flags.contains(&"lolbin_process".to_string());
        let has_masquerade = flags.contains(&"lolbin_masquerade".to_string());
        let has_renamed = flags.contains(&"renamed_binary".to_string());

        let severity = if has_masquerade {
            // Renamed LOLBin — always High regardless of path
            Severity::High
        } else if has_exec_from && has_lolbin {
            // LOLBin running from a suspicious path
            Severity::High
        } else if has_renamed && has_lolbin {
            // LOLBin copied but running from a non-suspicious path
            Severity::High
        } else if has_exec_from || has_lolbin {
            Severity::Medium
        } else if has_renamed {
            // Non-LOLBin renamed binary — worth investigating
            Severity::Medium
        } else if flags.is_empty() {
            Severity::Low
        } else {
            Severity::Low
        };

        DetectionResult { flags, severity }
    }
}
