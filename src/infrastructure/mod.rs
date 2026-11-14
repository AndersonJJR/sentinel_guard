//! Infrastructure adapters implementing domain port traits (env config, SQLite, OS integrations).

pub mod config_env;
pub mod fs_watcher;
pub mod magic_bytes;
pub mod sqlite_repo;
