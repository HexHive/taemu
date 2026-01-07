use crate::container::Management;
use crate::resource_pool::ResourcePool;
use bollard::errors::Error as BollardError;
use clap::Parser;
use lazy_static::lazy_static;
use slog::{Drain, Level, Logger, debug, error, info, o, warn};
use std::env;
use std::path::{Path, PathBuf};
use std::process;
use std::process::Command;
use std::time::{Duration, Instant};
use tokio::task::JoinSet;
mod container;
mod job_generation;
use indicatif::{ProgressBar, ProgressState, ProgressStyle};
use std::{cmp::min, fmt::Write};
mod resource_pool;
use rayon::prelude::*;
use slog_scope;
use slog_stdlog;
use std::sync::Mutex;
use std::sync::atomic;

static SWARM_TAG: &str = "[Sw0rm]";

#[derive(Parser, Debug)]
#[command(version, about = "Swarm is a tool for fuzzing TAs in a batch mode")]
struct Args {
    #[arg(short, long)]
    top_directory: PathBuf,

    #[arg(
        short,
        long,
        value_delimiter = ',',
        default_value = "harness",
        help = "pattern required to be contained in the TA name"
    )]
    pattern: Vec<String>,

    #[arg(short, long, default_value = "/root/TA_GP_emulator/emulator/fuzz.sh")]
    fuzz_script: PathBuf,

    #[arg(
        long,
        help = "Filter by suspicious df seed name (e.g. run:id:xxxx)",
        default_value = ""
    )]
    filter_df_seed: String,

    #[arg(short, long, default_value = "false")]
    snapshot_based: bool,

    #[arg(
        short,
        long,
        default_value = "60",
        help = "Duration of the fuzzing job in minutes"
    )]
    duration: u64,

    #[arg(short, long, default_value_t = num_cpus::get())]
    max_parallel: usize,
}

fn get_log_level() -> Level {
    match env::var("LOG_LEVEL")
        .unwrap_or_else(|_| "debug".to_string())
        .to_lowercase()
        .as_ref()
    {
        "trace" => Level::Trace,
        "debug" => Level::Debug,
        "info" => Level::Info,
        "warning" => Level::Warning,
        "error" => Level::Error,
        "critical" => Level::Critical,
        _ => Level::Info,
    }
}

lazy_static! {
    pub static ref LOGGER: Logger = {
        let level = get_log_level();
        let decorator = slog_term::TermDecorator::new().stdout().build();
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        let drain = slog::LevelFilter::new(drain, level).fuse();
        let drain = slog_async::Async::new(drain)
            .chan_size(10240)
            .build()
            .fuse();
        Logger::root(drain, o!())
    };
    static ref LOGGER_GUARD: Mutex<Option<slog_scope::GlobalLoggerGuard>> = Mutex::new(None);
}

pub fn init_logging() {
    let guard: slog_scope::GlobalLoggerGuard = slog_scope::set_global_logger(LOGGER.clone());
    slog_stdlog::init().unwrap();
    let mut guard_store = LOGGER_GUARD.lock().unwrap();
    *guard_store = Some(guard);
}

async fn run_fuzz_job(
    job: job_generation::FuzzJob,
    duration: u64,
    job_num: usize,
    pool: ResourcePool<container::Emulator>,
) -> Result<bool, String> {
    let timeout_duration = Duration::from_secs(duration * 60);

    let container = match pool
        .get_without_timeout(Some(format!("Job {}", job_num)))
        .await
    {
        Ok(container) => {
            info!(
                LOGGER,
                "[Job {}] Acquired container {:?} from pool successfully.",
                job_num,
                container.container_name
            );
            container
        }
        Err(e) => {
            error!(
                LOGGER,
                "[Job {}] Failed to acquire container from pool ({:?}) and stop the job.",
                job_num,
                e
            );
            return Err(format!("Error: acquire container {:?}", e));
        }
    };

    info!(
        LOGGER,
        "{SWARM_TAG} Starting fuzz job {} for: {} (setting timeout to {} minute(s))",
        job_num,
        job.ta_harness_dir.display(),
        duration
    );

    let start_time = Instant::now();
    let mut output = String::new();
    match tokio::time::timeout(timeout_duration, async {
        let command = vec![
            "bash".to_string(),
            job.fuzz_script.to_string_lossy().to_string(),
            job.ta_harness_dir.to_string_lossy().to_string(),
            job.ta_df_seed
                .as_ref()
                .unwrap_or(&PathBuf::from(""))
                .to_string_lossy()
                .to_string(),
            job.ta_df_context.clone().unwrap_or_default(),
        ];
        debug!(LOGGER, "[Job {}] COMMAND => {:?}", job_num, &command);
        output = container.execute_command(command).await?;

        // for fuzzing, basically the following code will be unreachable.
        info!(
            LOGGER,
            "[Job {}] Emulator for command output => {:?}", job_num, output
        );
        Ok::<(), BollardError>(())
    })
    .await
    {
        Ok(Ok(())) => {
            let _ = container
                .execute_command(vec![
                    "pkill".to_string(),
                    "-2".to_string(),
                    "afl-fuzz".to_string(),
                ])
                .await;
            warn!(
                LOGGER,
                "[Job {}] Fuzz job for {:?} on {:?} {} completed (runtime: {} minute(s)) [Quick Exit!]",
                job_num,
                job.ta_harness_dir,
                job.ta_df_seed.as_ref().unwrap_or(&PathBuf::from("")),
                job.ta_df_context.as_ref().unwrap_or(&String::new()),
                Instant::now().duration_since(start_time).as_secs() / 60,
            );

            pool.put_back(container);
            let old_root = PathBuf::from("/srv");
            let new_root = PathBuf::from("/root/TA_GP_emulator");

            //TODO: check if the job is successful
            job_generation::save_quick_exit_to_crash(
                &job_generation::rebase_path(job.ta_harness_dir.clone(), &old_root, &new_root),
                Some(&job_generation::rebase_path(
                    job.ta_df_seed.as_ref().unwrap().clone(),
                    &old_root,
                    &new_root,
                )),
                job.ta_df_context.as_ref(),
                output,
            );

            return Ok(true);
        }
        Ok(Err(e)) => {
            let _ = container
                .execute_command(vec![
                    "pkill".to_string(),
                    "-2".to_string(),
                    "afl-fuzz".to_string(),
                ])
                .await;
            error!(
                LOGGER,
                "[Job {}] Task join error for {:?}: {}", job_num, job.ta_harness_dir, e
            );
            pool.put_back(container);
            return Err(e.to_string());
        }
        Err(_) => {
            let _ = container
                .execute_command(vec![
                    "pkill".to_string(),
                    "-2".to_string(),
                    "afl-fuzz".to_string(),
                ])
                .await;
            info!(
                LOGGER,
                "[Job {}] Timeout reached for {:?} with {} minutes running. Stopping process...",
                job_num,
                job.ta_harness_dir,
                Instant::now().duration_since(start_time).as_secs() / 60,
            );
            pool.put_back(container);
            return Ok(true);
        }
    }
}

fn generate_fuzz_jobs(args: &Args) -> Vec<job_generation::FuzzJob> {
    let old_root = PathBuf::from("/root/TA_GP_emulator/emulator");
    let new_root = PathBuf::from("/srv/emulator");
    let fuzz_script_path =
        job_generation::rebase_path(args.fuzz_script.clone(), &old_root, &new_root);

    let ta_files = job_generation::find_ta_files(
        &args.top_directory,
        &args.pattern,
        &fuzz_script_path,
        &args.snapshot_based,
    );

    if ta_files.is_empty() {
        warn!(LOGGER, "No TAs found in: {:?}", args.top_directory);
        process::exit(0);
    }
    ta_files.into_iter().collect()
}

fn run_fuzz_jobs(
    rt: &tokio::runtime::Runtime,
    args: &Args,
    fuzz_jobs: Vec<job_generation::FuzzJob>,
    pool: ResourcePool<container::Emulator>,
) -> (usize, usize, usize) {
    let job_num = atomic::AtomicUsize::new(0);
    let skipped_jobs = atomic::AtomicUsize::new(0);

    // let mut fuzz_jobs = fuzz_jobs;
    // fuzz_jobs.truncate(500);

    let filtered_fuzz_jobs: Vec<(job_generation::FuzzJob, usize)> = fuzz_jobs
        .into_par_iter()
        .filter(|job| -> bool {
            if args.filter_df_seed.is_empty()
                || job
                    .ta_df_seed
                    .as_ref()
                    .unwrap_or(&PathBuf::from(""))
                    .to_string_lossy()
                    .to_string()
                    .contains(args.filter_df_seed.as_str())
            {
                return true;
            }
            skipped_jobs.fetch_add(1, atomic::Ordering::Relaxed);
            return false;
        })
        .map(|job| -> (job_generation::FuzzJob, usize) {
            (job, job_num.fetch_add(1, atomic::Ordering::Relaxed))
        })
        .collect();

    let all_jobs = filtered_fuzz_jobs.len();
    info!(
        LOGGER,
        "{SWARM_TAG} After seed filtering, only {} TA Jobs left for fuzzing", all_jobs
    );

    let res = rt.block_on(async move {
        let mut handles = JoinSet::new();

        // add progress bar
        let pb = ProgressBar::new(all_jobs as u64);
        pb.set_style(ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})")
            .unwrap()
            .with_key("eta", |state: &ProgressState, w: &mut dyn Write| write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap())
            .progress_chars("#>-"));

        for (job, job_num) in filtered_fuzz_jobs {
            pb.inc(1);
            let duration = args.duration;
            let pool_clone: ResourcePool<container::Emulator> = pool.clone();

            handles.spawn(async move {
                match run_fuzz_job(job, duration, job_num, pool_clone).await {
                    Ok(res) => res, // success
                    Err(e) => {
                        error!(LOGGER, "{SWARM_TAG} Task join error: {:?}", e);
                        false
                    } // error
                }
            });
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        pb.finish();

        let mut out = Vec::new();
        while let Some(res) = handles.join_next().await {
            // res: Result<bool, JoinError>
            out.push(res.unwrap_or(false));
        }
        out
    });

    let error_jobs = res.iter().filter(|item| **item == false).count();

    info!(
        LOGGER,
        "{SWARM_TAG} Waiting for all fuzz jobs to complete..."
    );

    (
        all_jobs,
        skipped_jobs.load(atomic::Ordering::Relaxed),
        error_jobs,
    )
}

async fn create_container_pool(
    args: &Args,
    num_containers: usize,
) -> Result<ResourcePool<container::Emulator>, String> {
    let mut containers = Vec::new();
    for i in 0..std::cmp::min(args.max_parallel, num_containers) {
        let mut ct = container::Emulator::new("ta_emu".to_string(), format!("swarm_emu_{}", i));

        ct.create(None)
            .await
            .map_err(|e| format!("Failed to create container {}: {}", i, e))?;
        containers.push(ct);
    }

    ResourcePool::new(containers, None)
        .map_err(|e| format!("Failed to create resource pool: {}", e))
}

fn create_redis_container() {
    let status = Command::new("docker")
        .arg("compose")
        .arg("-f")
        .arg("/root/TA_GP_emulator/docker-compose.redis.yml")
        .arg("up")
        .arg("-d")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("failed to execute docker-compose[for redis]");

    if !status.success() {
        error!(LOGGER, "docker-compose up failed with: {:?}", status);
    } else {
        info!(LOGGER, "docker-compose up completed");
    }
}

fn destroy_redis_container() {
    let status = Command::new("docker")
        .arg("compose")
        .arg("-f")
        .arg("/root/TA_GP_emulator/docker-compose.redis.yml")
        .arg("down")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("failed to execute docker-compose[for redis stopping]");

    if !status.success() {
        error!(LOGGER, "docker-compose down failed with: {:?}", status);
    } else {
        info!(LOGGER, "docker-compose down completed");
    }
}

fn _main_with_logging() -> i32 {
    let args = Args::parse();

    slog::info!(
        LOGGER,
        r#"
        {SWARM_TAG}
        _  _
        | )/ )
    \\  |//,' __
    (") (_)-"()))=-
        (\\    

"#
    );
    warn!(LOGGER, "[!!WARNING!!] Before running swarm, please make sure the ta_emu docker image is the latest version.");

    if !args.top_directory.exists() {
        error!(LOGGER, "Top directory does not exist"; "path" => args.top_directory.display());
        return 1;
    }

    if !args.top_directory.is_dir() {
        error!(LOGGER, "Top directory is not a directory"; "path" => args.top_directory.display());
        return 1;
    }

    if !args.fuzz_script.exists() {
        error!(LOGGER, "Fuzz script does not exist"; "path" => args.fuzz_script.display());
        return 1;
    }

    if Path::new("/.dockerenv").exists() {
        error!(LOGGER, "Please run outside of the emulator Docker.");
        return 2;
    }

    info!(
        LOGGER,
        "{SWARM_TAG} Scanning TAs in: {:?}", args.top_directory
    );

    let ta_files = generate_fuzz_jobs(&args);

    info!(
        LOGGER,
        "{SWARM_TAG} Found {} TA Jobs for fuzzing. Continue? (y/n)",
        ta_files.len()
    );
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();

    if input.trim().to_lowercase() != "y" {
        warn!(LOGGER, "User cancelled. Exiting...");
        return 3;
    }

    if args
        .fuzz_script
        .to_string_lossy()
        .to_string()
        .contains("/fuzz.sh")
    {
        create_redis_container();
        info!(LOGGER, "Redis container created");
    }

    info!(
        LOGGER,
        "{SWARM_TAG} Starting parallel fuzzing with max {} concurrent jobs on {} TAs...",
        args.max_parallel,
        ta_files.len()
    );

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(args.max_parallel)
        .max_blocking_threads(64)
        .enable_all()
        .build()
        .unwrap();

    let pool = match rt.block_on(create_container_pool(&args, ta_files.len())) {
        Ok(pool) => {
            info!(
                LOGGER,
                "{SWARM_TAG} Created container pool with {} containers successfully",
                args.max_parallel
            );
            pool
        }
        Err(e) => {
            error!(LOGGER, "{SWARM_TAG} Failed to create container pool: {}", e);
            return 4;
        }
    };

    let (all_jobs, skipped_jobs, error_jobs) = run_fuzz_jobs(&rt, &args, ta_files, pool.clone());

    // Cleanup resources
    if let Err(e) = rt.block_on(resource_pool::drop_resources(&pool)) {
        error!(LOGGER, "{SWARM_TAG} Failed to drop resources: {}", e);
    }

    std::thread::sleep(Duration::from_secs(3));

    if args
        .fuzz_script
        .to_string_lossy()
        .to_string()
        .contains("/fuzz.sh")
    {
        destroy_redis_container();
        info!(LOGGER, "Redis container destroyed");
    }

    // kill all python3 processes and their children even inside containers
    let _ = Command::new("pkill")
        .arg("-9")
        .arg("-f")
        .arg("afl-fuzz")
        .status();

    info!(
        LOGGER,
        "{SWARM_TAG} All fuzz jobs completed! \n Result: \n\tAll {} jobs. \n\tSkipped {} jobs. \n\tFailed {} jobs.",
        all_jobs,
        skipped_jobs,
        error_jobs
    );

    return 0;
}

fn main() {
    init_logging();
    let result = _main_with_logging();
    // wait for the log to be flushed, https://docs.rs/slog-async/latest/slog_async/
    std::thread::sleep(std::time::Duration::from_millis(100));
    process::exit(result);
}
