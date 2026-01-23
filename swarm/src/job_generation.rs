use crate::LOGGER;
use serde_json::{Map, Value, from_reader};
use slog::{error, info, warn};
use std::collections::HashSet;
use std::ffi::OsString;
use std::fs::{File, copy};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct FuzzJob {
    pub fuzz_script: PathBuf,
    pub ta_harness_dir: PathBuf,
    pub ta_df_seed: Option<PathBuf>,
    pub ta_df_context: Option<String>,
    _ta_canonical_path: PathBuf,
    _ta_unique_name: String,
}

pub fn find_ta_files(
    top_directory: &Path,
    filter_pattern: &Vec<String>,
    fuzz_script: &Path,
    snapshot_based: &bool,
) -> HashSet<FuzzJob> {
    let mut ta_collection = Vec::new();
    let old_root = PathBuf::from("/root/TA_GP_emulator");
    let new_root = PathBuf::from("/srv");

    for entry in WalkDir::new(top_directory)
        .into_iter()
        .filter_map(|i| i.ok())
    {
        let path = entry.path();

        // BASIC FILTERS
        if !path.is_file() {
            continue;
        }

        if path.extension().and_then(|e| e.to_str()) != Some("ta") {
            continue;
        }

        // PATTERN FILTERS
        let path_str = path.to_string_lossy();

        if !path_str.contains("/harness/") {
            continue;
        }

        if !filter_pattern.iter().any(|p| path_str.contains(p)) {
            continue;
        }

        let Some(parent) = path.parent() else {
            error!(LOGGER, "Path {:?} has no parent; skip", path);
            continue;
        };

        let ta_unique_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap()
            .to_string();

        if *snapshot_based {
            // only check the fixed metadata json inside suspicious_inputs_replay
            let suspicious_dir = parent.join("in").join("suspicious_inputs_replay");
            let suspicious_dir = match suspicious_dir.canonicalize() {
                Ok(p) => p,
                Err(_) => {
                    warn!(
                        LOGGER,
                        "The dir {:?} is missing/unreadable. Check whether need to run the deduplication procedure first.",
                        suspicious_dir
                    );
                    continue;
                }
            };

            // df_fuzz need to container resource to launch, so we need to rebase the path here
            let ta_harness_dir = rebase_path(parent.to_path_buf(), &old_root, &new_root);

            let ta_canon_rebased = rebase_path(path.to_path_buf(), &old_root, &new_root);

            for suspicious_meta in suspicious_dir
                .read_dir()
                .into_iter()
                .flatten()
                .flatten()
                .map(|e| e.path())
            {
                let suspicious_meta_contexts: Vec<(PathBuf, String)> =
                    get_context_via_meta(&suspicious_dir, &suspicious_meta);

                for (seed_path, reg_hash) in suspicious_meta_contexts {
                    ta_collection.push(FuzzJob {
                        fuzz_script: fuzz_script.to_path_buf(),
                        ta_harness_dir: ta_harness_dir.clone(),
                        ta_df_context: Some(reg_hash),
                        ta_df_seed: Some(rebase_path(
                            seed_path.to_path_buf(),
                            &old_root,
                            &new_root,
                        )),
                        _ta_canonical_path: ta_canon_rebased.clone(),
                        _ta_unique_name: ta_unique_name.clone(),
                    });
                }
            }
        } else {
            if ta_collection
                .iter()
                .all(|j: &FuzzJob| j.ta_harness_dir != parent)
            {
                ta_collection.push(FuzzJob {
                    fuzz_script: fuzz_script.to_path_buf(),
                    ta_harness_dir: parent.to_path_buf(),
                    ta_df_context: None,
                    ta_df_seed: None,
                    _ta_canonical_path: path.canonicalize().unwrap().to_path_buf(),
                    _ta_unique_name: ta_unique_name,
                });
            }
        }
    }

    ta_collection.into_iter().collect()
}

pub fn get_context_via_meta(base_path: &Path, ta_suspicious_meta: &Path) -> Vec<(PathBuf, String)> {
    if ta_suspicious_meta.extension().and_then(|e| e.to_str()) != Some("meta") {
        return Vec::new();
    }

    let meta_data: Map<String, Value> = match from_reader(
        File::open(ta_suspicious_meta).expect("Failed to open suspicious meta file"),
    ) {
        Ok(data) => data,
        Err(e) => {
            error!(
                LOGGER,
                "Failed to parse suspicious meta file: {}. So pass it. Error: {}",
                ta_suspicious_meta.display(),
                e
            );
            return Vec::new();
        }
    };

    let mut context: Vec<(PathBuf, String, u64, u64, u64, u64)> = Vec::new();

    if let Some(seed_path) = meta_data.get("key") {
        let seed_path = base_path.join(seed_path.as_str().unwrap());

        if let Some(records) = meta_data.get("records").and_then(|v| v.as_array()) {
            for record in records.iter() {
                let regs = match record.get("regs") {
                    Some(r) => r,
                    None => continue,
                };
                
                let is_second_fetch = match record.get("is_second_fetch").and_then(|v| v.as_bool())
                {
                    Some(v) => v,
                    None => continue,
                };
                if !is_second_fetch {
                    continue;
                }

                let is_read = regs
                    .get("is_read")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if !is_read {
                    continue;
                }

                let size = record.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
                let addr = record.get("addr").and_then(|v| v.as_u64()).unwrap_or(0);
                let pc = regs.get("PC").and_then(|v| v.as_u64()).unwrap_or(0);
                let ret = regs.get("ret_addr").and_then(|v| v.as_u64()).unwrap_or(0);


                let Some(reg_hash) = regs.get("reg_hash").and_then(|v| v.as_str()) else {
                    continue;
                };
                
                // passing all checks, so push the context to the final result
                context.push((seed_path.clone(), reg_hash.to_string(), addr, size, pc, ret));
            }
        }
    }

    
    merge_contiguous_df_seet(context)
}

fn merge_contiguous_df_seet(mut context_vec: Vec<(PathBuf, String, u64, u64, u64, u64)>) -> Vec<(PathBuf, String)> {
    context_vec.sort_by_key(|(_, _, addr, _size, _pc, _ret)| *addr);
    let mut out: Vec<(PathBuf, String, u64, u64, u64, u64)> = Vec::with_capacity(context_vec.len());

    for (path, hash, addr, size, pc, ret) in context_vec {
        match out.last_mut() {
            Some((_, _, prev_addr, prev_size, prev_pc, prev_ret)) 
                if (*prev_addr + *prev_size == addr && *prev_pc == pc && *prev_ret == ret) => {
                    *prev_size += size;
                }
            _ => out.push((path, hash, addr, size, pc, ret)),
        }
    }

    out.into_iter().map(|(path, hash, _, _, _, _)| (path, hash)).collect()
}

pub fn rebase_path(path: PathBuf, old_root: &Path, new_root: &Path) -> PathBuf {
    // warn!(LOGGER, "Rebasing path: {:?} from {:?} to {:?}", path, old_root, new_root);

    let path = path.canonicalize().unwrap_or_else(|_| path.clone());

    let rel = path
        .strip_prefix(old_root)
        .expect("unexpected old_root for the path.");

    new_root.join(rel)
}

pub fn save_quick_exit_to_crash(
    ta_harness_dir: &PathBuf,
    ta_df_seed: Option<&PathBuf>,
    ta_df_context: Option<&String>,
    output: String,
) {
    if let Some(seed) = ta_df_seed {
        let seed_file_name = seed.file_name().unwrap();
        let mut df_fuzz_dir = OsString::from(seed_file_name);
        if let Some(context) = ta_df_context {
            df_fuzz_dir.push("_");
            df_fuzz_dir.push(context);
        }

        let crash_dir = ta_harness_dir
            .join("df_fuzz")
            .join(df_fuzz_dir)
            .join("out")
            .join("default")
            .join("crashes");

        if !crash_dir.exists() {
            match std::fs::create_dir_all(&crash_dir) {
                Ok(_) => (),
                Err(e) => {
                    error!(LOGGER, "Failed to create crash directory: {:?}", e);
                    return;
                }
            }
        }

        let crash_file = crash_dir.join(seed_file_name);

        if let Err(e) = copy(seed, &crash_file) {
            error!(LOGGER, "Failed to copy seed to crash directory: {:?}", e);
            return;
        }

        let mut output_file = crash_file.clone();
        output_file.set_extension("output");
        std::fs::write(output_file, output).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_save_quick_exit_to_crash() {
        let ta_harness_dir = PathBuf::from("/root/TA_GP_emulator/t6/harness/9459_df");
        let ta_df_seed = Some(PathBuf::from(
            "/root/TA_GP_emulator/t6/harness/9459_df/in/suspicious_inputs_replay/run:id:d3b07384d113edec49eaa6238ad5ff00",
        ));
        let ta_df_context = Some("174503571334591656523560700267902478073".to_string());
        let output = "testing_output".to_string();
        save_quick_exit_to_crash(
            &ta_harness_dir,
            ta_df_seed.as_ref(),
            ta_df_context.as_ref(),
            output,
        );
        let potential_crash_file = ta_harness_dir
            .join("df_fuzz")
            .join("run:id:d3b07384d113edec49eaa6238ad5ff00_174503571334591656523560700267902478073")
            .join("out")
            .join("default")
            .join("crashes")
            .join("run:id:d3b07384d113edec49eaa6238ad5ff00");
        assert!(potential_crash_file.exists());
        std::fs::remove_file(potential_crash_file).unwrap();
    }
}
