use crate::container::Management;
use parking_lot::{Condvar, Mutex, MutexGuard};
use std::error;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

#[derive(Debug)]
pub struct ResourcePoolError(Option<String>);

impl fmt::Display for ResourcePoolError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str("ResourcePoolError")?;
        if let Some(ref err) = self.0 {
            write!(fmt, ": {}", err)?;
        }

        Ok(())
    }
}

impl error::Error for ResourcePoolError {
    fn description(&self) -> &str {
        "ResourcePoolError"
    }
}

pub struct ResourcePool<T>(Arc<SharedPool<T>>)
where
    T: Management;

impl<T> Clone for ResourcePool<T>
where
    T: Management,
{
    fn clone(&self) -> ResourcePool<T> {
        ResourcePool(self.0.clone())
    }
}

struct SharedPool<T> {
    resources: Mutex<Vec<T>>,
    available: Condvar,
    timeout: Duration,
}

impl<T: Management> SharedPool<T> {
    pub fn new(resources: Vec<T>, timeout: Duration) -> Self {
        SharedPool {
            resources: Mutex::new(resources),
            available: Condvar::new(),
            timeout,
        }
    }
}

impl<T: Management + std::fmt::Debug> ResourcePool<T> {
    pub fn new(resources: Vec<T>, timeout: Option<Duration>) -> Result<Self, ResourcePoolError> {
        Ok(ResourcePool(Arc::new(SharedPool::new(
            resources,
            timeout.unwrap_or(Duration::from_secs(10)),
        ))))
    }

    pub fn get(&self) -> Result<T, ResourcePoolError> {
        self.get_timeout(self.0.timeout)
    }

    pub fn get_timeout(&self, timeout: Duration) -> Result<T, ResourcePoolError> {
        let start = Instant::now();
        let end = start + timeout;
        let mut resources = self.0.resources.lock();
        loop {
            match self.try_get_inner(resources) {
                Ok(resource) => {
                    return Ok(resource);
                }
                Err(guard) => resources = guard,
            }

            if self.0.available.wait_until(&mut resources, end).timed_out() {
                return Err(ResourcePoolError(Some(
                    "Failed to get resource since timeout happens. Timeout".to_string(),
                )));
            }
        }
    }

    fn try_get_inner<'a>(
        &self,
        mut resources: MutexGuard<'a, Vec<T>>,
    ) -> Result<T, MutexGuard<'a, Vec<T>>> {
        match resources.pop() {
            Some(resource) => Ok(resource),
            None => Err(resources),
        }
    }

    pub fn put_back(&self, resource: T) {
        let mut resources = self.0.resources.lock();
        resources.push(resource);
        self.0.available.notify_one();
    }
}

pub async fn drop_resources<M>(pool: &ResourcePool<M>) -> Result<(), ResourcePoolError>
where
    M: Management + std::fmt::Debug,
{
    let mut resources = pool.0.resources.lock();
    for resource in resources.iter() {
        if let Err(_e) = resource.destroy().await {
            return Err(ResourcePoolError(Some(format!(
                "Failed to destroy resource: {:?}",
                resource
            ))));
        }
    }
    resources.clear();
    Ok(())
}
