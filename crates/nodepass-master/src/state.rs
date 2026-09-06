use crate::types::Instance;
use dashmap::DashMap;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::PathBuf;
use tracing::{error, info};

pub struct StateManager {
    path: PathBuf,
    lock: Mutex<()>,
}

impl StateManager {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            lock: Mutex::new(()),
        }
    }

    pub fn load(&self, instances: &DashMap<String, Instance>) -> io::Result<()> {
        let _guard = self.lock.lock();
        if !self.path.exists() {
            return Ok(());
        }

        let content = fs::read_to_string(&self.path)?;
        if content.trim().is_empty() {
            return Ok(());
        }

        match serde_json::from_str::<HashMap<String, Instance>>(&content) {
            Ok(map) => {
                for (id, mut inst) in map {
                    inst.status = "stopped".to_string();
                    instances.insert(id, inst);
                }
                info!("Loaded {} instances from state file {:?}", instances.len(), self.path);
                Ok(())
            }
            Err(e) => {
                error!("Failed to parse state file {:?}: {}", self.path, e);
                Err(io::Error::new(io::ErrorKind::InvalidData, e))
            }
        }
    }

    pub fn save(&self, instances: &DashMap<String, Instance>) -> io::Result<()> {
        let _guard = self.lock.lock();
        let map: HashMap<String, Instance> = instances
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect();

        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }

        let serialized = serde_json::to_string_pretty(&map)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let temp_path = self.path.with_extension("tmp");
        fs::write(&temp_path, serialized.as_bytes())?;
        fs::rename(&temp_path, &self.path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_state_save_and_load() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();
        let mgr = StateManager::new(path.clone());

        let instances = DashMap::new();
        let inst = Instance::new(
            "test-1".to_string(),
            "alias-1".to_string(),
            "server".to_string(),
            "server://:secret@127.0.0.1:8080/127.0.0.1:80".to_string(),
        );
        instances.insert("test-1".to_string(), inst);

        mgr.save(&instances).unwrap();

        let loaded = DashMap::new();
        mgr.load(&loaded).unwrap();
        assert_eq!(loaded.len(), 1);
        let item = loaded.get("test-1").unwrap();
        assert_eq!(item.alias, "alias-1");
        assert_eq!(item.status, "stopped");
    }
}
