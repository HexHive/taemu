use bollard::Docker;
use bollard::errors::Error as BollardError;
use bollard::exec::StartExecOptions;
use bollard::models::{ExecConfig, HostConfig};
use chrono::{DateTime, Utc};
use futures::StreamExt;
use std::error::Error as StdError;
use crate::LOGGER;
use slog::{debug};

pub trait Management: Send + Sync + 'static {
    fn new(image_name: String, container_name: String) -> Self;

    async fn create(&mut self) -> Result<(), Box<dyn StdError + 'static>>;
    async fn destroy(&self) -> Result<(), Box<dyn StdError + 'static>>;
    async fn execute_command(&self, command: Vec<String>) -> Result<String, BollardError>;

    fn _host_conf(&self) -> Option<HostConfig> {
        Some(HostConfig {
            binds: Some(vec![
                "/root/TA_GP_emulator:/srv".into(),
                "/dev/shm:/dev/shm".into(),
            ]),
            shm_size: Some(100 * 1024 * 1024 * 1024), // 100G
            ipc_mode: Some("host".into()),
            network_mode: Some("host".into()),
            ..Default::default()
        })
    }
}

#[derive(Debug)]
pub struct Emulator {
    docker: Docker,
    image_name: String,
    pub container_name: String,
    container_id: Option<String>,
    container_status: bool, // true if running, false if stopped
    container_created_at: Option<DateTime<Utc>>,
}

impl Management for Emulator {
    fn new(image_name: String, container_name: String) -> Self {
        let docker = connect_docker_client();

        Emulator {
            docker,
            image_name,
            container_name,
            container_id: None,
            container_status: false,
            container_created_at: None,
        }
    }

    async fn create(&mut self) -> Result<(), Box<dyn StdError + 'static>> {
        let config = bollard::models::ContainerCreateBody {
            image: Some(self.image_name.clone()),
            tty: Some(true),
            host_config: self._host_conf(),
            ..Default::default()
        };

        let id = self.docker
            .create_container(
                Some(
                    bollard::query_parameters::CreateContainerOptionsBuilder::default()
                        .name(&self.container_name)
                        .build(),
                ),
                config,
            )
            .await?
            .id;

        self.docker
            .start_container(
                &id,
                None::<bollard::query_parameters::StartContainerOptions>,
            )
            .await?;

        self.container_id = Some(id);
        self.container_status = true;
        self.container_created_at = Some(Utc::now());
        Ok(())
    }

    async fn destroy(&self) -> Result<(), Box<dyn StdError + 'static>> {
        self.docker
            .remove_container(
                &self.container_name.as_str(),
                Some(
                    bollard::query_parameters::RemoveContainerOptionsBuilder::default()
                        .force(true)
                        .build(),
                ),
            )
            .await?;

        Ok(())
    }

    async fn execute_command(&self, command: Vec<String>) -> Result<String, BollardError> {
        debug!(LOGGER, "Emulator executing command: {:?}", command);

        let exec = self.docker
            .create_exec(
                &self.container_name.as_str(),
                ExecConfig {
                    attach_stdout: Some(true),
                    attach_stderr: Some(true),
                    cmd: Some(command),
                    ..Default::default()
                },
            )
            .await?
            .id;

        let ready_result = self.docker
            .start_exec(&exec, None::<StartExecOptions>)
            .await
            .expect("Failed to execute command in container.");

        if let bollard::exec::StartExecResults::Attached { mut output, .. } = ready_result {
            let mut all_output = String::new();
            while let Some(line) = output.next().await {
                all_output.push_str(&line.unwrap().to_string());
            }
            return Ok(all_output);
        }

        Ok("no output".to_string())
    }
}

fn connect_docker_client() -> Docker {
    Docker::connect_with_socket_defaults().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    // cargo test -- --no-capture

    #[tokio::test]
    async fn test_execute_command() {
        let mut container = Emulator::new("ta_emu".to_string(), "test_container".to_string());
        container.create().await.unwrap();
        let output = container
            .execute_command(vec!["echo".to_string(), "hello".to_string()])
            .await
            .unwrap();
        println!("Emulator output: {:?}", output);
        container.destroy().await.unwrap();
        assert_eq!(output, "hello\n");
    }

    #[tokio::test]
    async fn test_create_and_destroy() {
        let mut container = Emulator::new("ta_emu".to_string(), "test_container2".to_string());
        container.create().await.unwrap();
        assert!(container.container_id.is_some());
        let output = container
            .execute_command(vec![
                "bash".to_string(),
                "/srv/emulator/df_fuzz.sh".to_string(),
                "/srv/t6/harness/9459_df".to_string(),
                "/srv/t6/harness/9459_df/in/suspicious_inputs/run:id:79046b0045fdd4777ebfe6dab289ec0c".to_string(),
                "220932049320814838492345582247961928475".to_string(),
            ])
            .await
            .unwrap();
        println!("Emulator output: {:?}", output);
        container.destroy().await.unwrap();
    }
}
