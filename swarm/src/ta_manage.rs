use std::path::{Path, PathBuf};
use std::fs::File;
use walkdir::WalkDir;
use serde_json::{Value, Map, from_reader};
use std::collections::HashSet;

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct FuzzJob {
    pub fuzz_script: PathBuf,
    pub ta_harness_dir: PathBuf,
    pub ta_df_seed: Option<PathBuf>,
    pub ta_df_context: Option<String>,
    _ta_canonical_path: PathBuf,
    _ta_unique_name: String,
}

pub fn find_ta_files(top_directory: &Path, filter_pattern: &str, fuzz_script: &Path, snapshot_based: &bool) -> HashSet<FuzzJob> {
    let mut ta_collection = Vec::new();

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
                let suspicious_dir = path.parent().unwrap().join("in").join("suspicious_inputs");
                if suspicious_dir.exists() {
                    let suspicious_dir = suspicious_dir.canonicalize().unwrap();
                    for suspicious_meta in suspicious_dir.read_dir().unwrap() {
                        let suspicious_meta = suspicious_meta.unwrap().path();
                        let suspicious_meta_contexts = get_context_via_meta(&suspicious_dir, &suspicious_meta);

                        for (seed_path, reg_hash) in suspicious_meta_contexts {
                            ta_collection.push(FuzzJob {
                                fuzz_script: fuzz_script.to_path_buf(),
                                ta_harness_dir: path.parent().unwrap().to_path_buf(),
                                ta_df_context: Some(reg_hash),
                                ta_df_seed: Some(seed_path),
                                _ta_canonical_path: path.canonicalize().unwrap().to_path_buf(),
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
    let meta_data: Map<String, Value> = match from_reader(File::open(ta_suspicious_meta).expect("Failed to open suspicious meta file")) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to parse suspicious meta file: {}. So pass it. Error: {}", ta_suspicious_meta.display(), e);
            return Vec::new();
        }
    };

    let mut context: Vec<(PathBuf, String)> = Vec::new();

    if let Some(seed_path) = meta_data.get("key") {
        let seed_path = base_path.join(seed_path.as_str().unwrap());
        if let Some(records) = meta_data.get("records").and_then(|v| v.as_array()) {
            for record in records.iter() {
                context.push((PathBuf::from(seed_path.clone()), record["regs"]["reg_hash"].as_str().unwrap().to_string()));
            }
        }
    }
    context
}