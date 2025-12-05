use clap::Parser;
use slog::{Drain, Logger, o, info, warn, error};
use slog_async;
use slog_term;
use std::path::{Path, PathBuf};
use std::process;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time;
mod job_manage;


static SWARM_TAG: &str = "[Sw0rm]";

#[derive(Parser, Debug)]
#[command(version, about = "Swarm is a tool for fuzzing TAs in a batch mode")]
struct Args {
    #[arg(short, long)]
    top_directory: PathBuf,

    #[arg(short, long, default_value = "harness")]
    pattern: String,

    #[arg(short, long, default_value = "/srv/emulator/fuzz.sh")]
    fuzz_script: PathBuf,

    #[arg(short, long, default_value = "false")]
    snapshot_based: bool,

    #[arg(short, long, default_value = "60", help = "Duration of the fuzzing job in minutes")]
    duration: u64,

    #[arg(short, long, default_value_t = num_cpus::get())]
    max_parallel: usize,
}


fn basic_slogger() -> Logger {

    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::CompactFormat::new(decorator)
        .build()
        .ignore_res()   // 2. convert Err to Infallible by ignoring errors
        .fuse();
    let drain = slog_async::Async::new(drain).build().fuse();

    slog::Logger::root(drain, o!())
}

async fn run_fuzz_job(job: job_manage::FuzzJob, duration: u64, job_num: usize) {
    let log = basic_slogger();  

    let timeout_duration = Duration::from_secs(duration * 60);
    let start_time = Instant::now();

    info!(
        log,
        "{SWARM_TAG} Starting fuzz job {} for: {} (setting timeout to {} minute(s))",
        job_num,
        job.ta_harness_dir.display(),
        duration
    );

    let mut child = match tokio::process::Command::new("bash")
        .current_dir("/srv/emulator")
        .arg(&job.fuzz_script)
        .arg(&job.ta_harness_dir)
        .arg(&job.ta_df_seed.clone().unwrap_or_default())
        .arg(&job.ta_df_context.clone().unwrap_or_default())
        .stdout(process::Stdio::null())
        .stderr(process::Stdio::null())
        .kill_on_drop(true)
        .spawn(){
            Ok(child) => child,
            Err(e) => {
                error!(log, "[Job {}] Failed to spawn process: {}", job_num, e);
                return;
            }
        };
    info!(log, "[Job {}] Command: bash {:?} {:?} {:?} {:?}", 
        job_num, 
        job.fuzz_script,
        job.ta_harness_dir,
        job.ta_df_seed.as_ref().unwrap_or(&PathBuf::from("")),
        &job.ta_df_context,
    );

    match tokio::time::timeout(timeout_duration, child.wait()).await {
        Ok(Ok(status)) => {
            
            if status.success() {
                info!(log, "[Job {}] Fuzz job completed successfully", job_num);
            } else {
                info!(
                    log,
                    "[Job {}] Fuzz job for {} on {} {} completed with status: {:?} (runtime: {} minute(s))",
                    job_num,
                    job.ta_harness_dir.display(),
                    job.ta_df_seed.as_ref().unwrap().display(),
                    job.ta_df_context.unwrap_or_default(),
                    status,
                    Instant::now().duration_since(start_time).as_secs() / 60,
                );
            }
        }
        Ok(Err(e)) => {
            eprintln!(
                "[Job {}] Task join error for {}: {}",
                job_num,
                job.ta_harness_dir.display(),
                e
            );
        }
        Err(_) => {
            info!(
                log,
                "[Job {}] Timeout reached for {}. Stopping process...",
                job_num,
                job.ta_harness_dir.display(),
            );

            if let Err(e) = child.kill().await {
                error!(log, "[Job {}] Failed to kill process: {}", job_num, e);
            }

            info!(
                log,
                "[Job {}] Fuzz job for {} stopped after {} minute(s)",
                job_num,
                job.ta_harness_dir.display(),
                Instant::now().duration_since(start_time).as_secs() / 60
            );
        }
    }
}

#[tokio::main]
async fn main() {

    let args = Args::parse();

    let log = basic_slogger();

    info!(log, r#"
        {SWARM_TAG}
         _  _
        | )/ )
    \\  |//,' __
    (") (_)-"()))=-
        (\\    
    "#);

    if !args.top_directory.exists() {
        error!(log, "Top directory does not exist"; "path" => args.top_directory.display());
        process::exit(1);
    }

    if !args.top_directory.is_dir() {
        error!(log, "Top directory is not a directory"; "path" => args.top_directory.display());
        process::exit(1);
    }

    if !args.fuzz_script.exists() {
        error!(log, "Fuzz script does not exist"; "path" => args.fuzz_script.display());
        process::exit(1);
    }

    if !Path::new("/.dockerenv").exists() {
        error!(log, "Please run inside emulator Docker. Execute ./run-docker.sh first.");
        process::exit(1);
    }

    info!(log, "{SWARM_TAG} Scanning TAs in: {:?}", args.top_directory);


    let fuzz_script_path = if args.fuzz_script.is_absolute() {
        args.fuzz_script.to_path_buf()
    } else {
        let mut script_path = PathBuf::from(".");
        script_path.push(args.fuzz_script);
        script_path.canonicalize().unwrap().to_path_buf()
    };
    

    let ta_files = job_manage::find_ta_files(&args.top_directory, &args.pattern, &fuzz_script_path, &args.snapshot_based);
    if ta_files.is_empty() {
        warn!(log, "No TAs found in: {:?}", args.top_directory);
        process::exit(0);
    }

    info!(
        log,
        "{SWARM_TAG} Found {} TAs for fuzzing. Continue? (y/n)",
        ta_files.len()
    );
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();

    if input.trim().to_lowercase() != "y" {
        warn!(log, "User cancelled. Exiting...");
        process::exit(0);
    }

    info!(
        log,
        "{SWARM_TAG} Starting parallel fuzzing with max {} concurrent jobs on {} TAs...",
        args.max_parallel,
        ta_files.len()
    );

    // Create a semaphore to limit concurrent jobs
    let semaphore = Arc::new(Semaphore::new(args.max_parallel));
    let mut handles = Vec::new();
    let mut job_num = 0;

    for (idx, job) in ta_files.into_iter().enumerate() {
        let semaphore = Arc::clone(&semaphore);
        let permit: OwnedSemaphorePermit = semaphore.acquire_owned().await.unwrap();
        let duration = args.duration;
        
        job_num = idx + 1;
        println!("[******] Job for seed {:?}", job.ta_df_seed.as_ref().unwrap().to_string_lossy());

        let handle = tokio::spawn(async move {
            let _permit = permit; // Hold the permit for the duration of the job
            run_fuzz_job(job, duration, job_num).await;
        });

        handles.push(handle);
    }

    info!(log, "{SWARM_TAG} Waiting for all fuzz jobs to complete...");

    for handle in handles {
        let _ = handle.await;
    }
    
    // kill all python3 processes and their children
    let _ = Command::new("pkill").arg("-9").arg("-f").arg("python3").status();
    time::sleep(Duration::from_secs(3)).await;

    info!(log, "{SWARM_TAG} All fuzz jobs completed!");
}
