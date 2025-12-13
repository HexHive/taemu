use crate::LOGGER;
use serde_json::{Map, Value, from_reader};
use slog::{warn};
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
    filter_pattern: &str,
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
        if path.is_file()
            && path.extension().map(|s| s == "ta").unwrap_or(false)
            && path.to_string_lossy().contains(filter_pattern)
        {
            let ta_unique_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap()
                .to_string();

            if *snapshot_based {
                // only check the fixed metadata json inside suspicious_inputs_replay
                let suspicious_dir = path
                    .parent()
                    .unwrap()
                    .join("in")
                    .join("suspicious_inputs_replay");

                if suspicious_dir.exists() {
                    let suspicious_dir = suspicious_dir.canonicalize().unwrap();
                    for suspicious_meta in suspicious_dir.read_dir().unwrap() {
                        let suspicious_meta = suspicious_meta.unwrap().path();
                        let suspicious_meta_contexts =
                            get_context_via_meta(&suspicious_dir, &suspicious_meta);

                        for (seed_path, reg_hash) in suspicious_meta_contexts {
                            ta_collection.push(FuzzJob {
                                fuzz_script: fuzz_script.to_path_buf(),
                                ta_harness_dir: rebase_path(
                                    path.parent().unwrap().to_path_buf(),
                                    &old_root,
                                    &new_root,
                                ),
                                ta_df_context: Some(reg_hash),
                                ta_df_seed: Some(rebase_path(
                                    seed_path.to_path_buf(),
                                    &old_root,
                                    &new_root,
                                )),
                                _ta_canonical_path: rebase_path(
                                    path.to_path_buf(),
                                    &old_root,
                                    &new_root,
                                ),
                                _ta_unique_name: ta_unique_name.clone(),
                            });
                        }
                    }
                }
            } else {
                if ta_collection
                    .iter()
                    .all(|j: &FuzzJob| j.ta_harness_dir != path.parent().unwrap())
                {
                    ta_collection.push(FuzzJob {
                        fuzz_script: fuzz_script.to_path_buf(),
                        ta_harness_dir: path.parent().unwrap().to_path_buf(),
                        ta_df_context: None,
                        ta_df_seed: None,
                        _ta_canonical_path: path.canonicalize().unwrap().to_path_buf(),
                        _ta_unique_name: ta_unique_name,
                    });
                }
            }
        }
    }

    ta_collection.into_iter().collect()
}

pub fn get_context_via_meta(base_path: &Path, ta_suspicious_meta: &Path) -> Vec<(PathBuf, String)> {
    if ta_suspicious_meta.extension().unwrap_or_default() != "meta" {
        return Vec::new();
    }
    let meta_data: Map<String, Value> = match from_reader(
        File::open(ta_suspicious_meta).expect("Failed to open suspicious meta file"),
    ) {
        Ok(data) => data,
        Err(e) => {
            eprintln!(
                "Failed to parse suspicious meta file: {}. So pass it. Error: {}",
                ta_suspicious_meta.display(),
                e
            );
            return Vec::new();
        }
    };

    let mut context: Vec<(PathBuf, String)> = Vec::new();

    if let Some(seed_path) = meta_data.get("key") {
        let seed_path = base_path.join(seed_path.as_str().unwrap());
        if let Some(records) = meta_data.get("records").and_then(|v| v.as_array()) {
            for record in records.iter() {
                if record["regs"]["is_read"].as_bool() == Some(true) {
                    context.push((
                        PathBuf::from(seed_path.clone()),
                        record["regs"]["reg_hash"].as_str().unwrap().to_string(),
                    ));
                }
            }
        }
    }
    context
}

pub fn rebase_path(path: PathBuf, old_root: &Path, new_root: &Path) -> PathBuf {
    let path = path.canonicalize().unwrap_or_else(|_| {
        warn!(LOGGER, "path is {:?}", path);
        path.clone()
    });

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
            std::fs::create_dir_all(&crash_dir).unwrap();
        }
        let crash_file = crash_dir.join(seed_file_name);
        copy(seed, &crash_file).unwrap();
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
