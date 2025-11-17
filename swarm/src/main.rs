use clap::Parser;
use slog::{Drain, Logger, o, info, warn, error};
use std::path::{Path, PathBuf};
use std::process;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time;
mod ta_manage;


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
    let drain = slog_term::CompactFormat::new(decorator).build();
    let drain = std::sync::Mutex::new(drain).fuse();

    let log = slog::Logger::root(drain, o!());
    log
}

async fn run_fuzz_job(job: ta_manage::FuzzJob, duration: u64, job_num: usize) {
    let log = basic_slogger();  

    let timeout_duration = Duration::from_secs(duration * 60);
    let start_time = Instant::now();

    info!(
        log,
        "{SWARM_TAG} Starting fuzz job {} for: {} (timeout: {} hour(s))",
        job_num,
        job.ta_harness_dir.display(),
        duration
    );

    let child = Command::new("bash")
        .current_dir("/srv/emulator")
        .arg(&job.fuzz_script)
        .arg(&job.ta_harness_dir)
        .arg(&job.ta_df_seed.unwrap_or(PathBuf::from("")))
        .arg(&job.ta_df_context.unwrap_or("".to_string()))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    

    let pid = child.id();

    let child_handle: tokio::task::JoinHandle<Result<process::ExitStatus, std::io::Error>> =
        tokio::task::spawn_blocking({
            move || {
                let mut child = child;
                child.wait()
            }
        });

    match tokio::time::timeout(timeout_duration, child_handle).await {
        Ok(Ok(Ok(status))) => {
            info!(
                log,
                "[Job {}] Fuzz job for {} completed with status: {:?} (runtime: {:?})",
                job_num,
                job.ta_harness_dir.display(),
                status,
                start_time.elapsed(),
            );
        }
        Ok(Ok(Err(e))) => {
            error!(
                log,
                "[Job {}] Error waiting for process {}: {}",
                job_num,
                job.ta_harness_dir.display(),
                e
            );
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
                "[Job {}] Timeout reached for {}. Stopping process (PID: {})...",
                job_num,
                job.ta_harness_dir.display(),
                pid
            );

            // Kill the process by PID
            let _ = Command::new("kill").arg("-9").arg(pid.to_string()).status();

            time::sleep(Duration::from_secs(2)).await;

            info!(
                log,
                "[Job {}] Fuzz job for {} stopped after {} hour(s)",
                job_num,
                job.ta_harness_dir.display(),
                duration
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
    

    let ta_files = ta_manage::find_ta_files(&args.top_directory, &args.pattern, &fuzz_script_path, &args.snapshot_based);
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

    for (idx, job) in ta_files.into_iter().enumerate() {
        let semaphore = Arc::clone(&semaphore);
        let permit: OwnedSemaphorePermit = semaphore.acquire_owned().await.unwrap();
        let duration = args.duration;
        let job_num = idx + 1;

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
