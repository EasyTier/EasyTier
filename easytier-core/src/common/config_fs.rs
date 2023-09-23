// use filesystem as a config store

use std::{
    ffi::OsStr,
    io::Write,
    path::{Path, PathBuf},
};

static DEFAULT_BASE_DIR: &str = "/var/lib/easytier";
static DIR_ROOT_CONFIG_FILE_NAME: &str = "__root__";

pub struct ConfigFs {
    _db_name: String,
    db_path: PathBuf,
}

impl ConfigFs {
    pub fn new(db_name: &str) -> Self {
        Self::new_with_dir(db_name, DEFAULT_BASE_DIR)
    }

    pub fn new_with_dir(db_name: &str, dir: &str) -> Self {
        let p = Path::new(OsStr::new(dir)).join(OsStr::new(db_name));
        std::fs::create_dir_all(&p).unwrap();
        ConfigFs {
            _db_name: db_name.to_string(),
            db_path: p,
        }
    }

    pub fn get(&self, key: &str) -> Result<String, std::io::Error> {
        let path = self.db_path.join(OsStr::new(key));
        // if path is dir, read the DIR_ROOT_CONFIG_FILE_NAME in it
        if path.is_dir() {
            let path = path.join(OsStr::new(DIR_ROOT_CONFIG_FILE_NAME));
            std::fs::read_to_string(path)
        } else if path.is_file() {
            return std::fs::read_to_string(path);
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "key not found",
            ));
        }
    }

    pub fn list_keys(&self, key: &str) -> Result<Vec<String>, std::io::Error> {
        let path = self.db_path.join(OsStr::new(key));
        let mut keys = Vec::new();
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            let key = path.file_name().unwrap().to_str().unwrap().to_string();
            if key != DIR_ROOT_CONFIG_FILE_NAME {
                keys.push(key);
            }
        }
        Ok(keys)
    }

    #[allow(dead_code)]
    pub fn remove(&self, key: &str) -> Result<(), std::io::Error> {
        let path = self.db_path.join(OsStr::new(key));
        // if path is dir, remove the DIR_ROOT_CONFIG_FILE_NAME in it
        if path.is_dir() {
            std::fs::remove_dir_all(path)
        } else if path.is_file() {
            return std::fs::remove_file(path);
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "key not found",
            ));
        }
    }

    pub fn add_dir(&self, key: &str) -> Result<std::fs::File, std::io::Error> {
        let path = self.db_path.join(OsStr::new(key));
        // if path is dir, write the DIR_ROOT_CONFIG_FILE_NAME in it
        if path.is_file() {
            Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "key already exists",
            ))
        } else {
            std::fs::create_dir_all(&path)?;
            return std::fs::File::create(path.join(OsStr::new(DIR_ROOT_CONFIG_FILE_NAME)));
        }
    }

    pub fn add_file(&self, key: &str) -> Result<std::fs::File, std::io::Error> {
        let path = self.db_path.join(OsStr::new(key));
        let base_dir = path.parent().unwrap();
        if !path.is_file() {
            std::fs::create_dir_all(base_dir)?;
        }
        std::fs::File::create(path)
    }

    pub fn get_or_add<F>(
        &self,
        key: &str,
        val_fn: F,
        add_dir: bool,
    ) -> Result<String, std::io::Error>
    where
        F: FnOnce() -> String,
    {
        let get_ret = self.get(key);
        match get_ret {
            Ok(v) => Ok(v),
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    let val = val_fn();
                    if add_dir {
                        let mut f = self.add_dir(key)?;
                        f.write_all(val.as_bytes())?;
                    } else {
                        let mut f = self.add_file(key)?;
                        f.write_all(val.as_bytes())?;
                    }
                    Ok(val)
                } else {
                    Err(e)
                }
            }
        }
    }

    #[allow(dead_code)]
    pub fn get_or_add_dir<F>(&self, key: &str, val_fn: F) -> Result<String, std::io::Error>
    where
        F: FnOnce() -> String,
    {
        self.get_or_add(key, val_fn, true)
    }

    pub fn get_or_add_file<F>(&self, key: &str, val_fn: F) -> Result<String, std::io::Error>
    where
        F: FnOnce() -> String,
    {
        self.get_or_add(key, val_fn, false)
    }

    pub fn get_or_default<F>(&self, key: &str, default: F) -> Result<String, std::io::Error>
    where
        F: FnOnce() -> String,
    {
        let get_ret = self.get(key);
        match get_ret {
            Ok(v) => Ok(v),
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    Ok(default())
                } else {
                    Err(e)
                }
            }
        }
    }
}
