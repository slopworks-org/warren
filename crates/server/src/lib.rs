//! Warren server: a WireGuard hub, a reverse proxy with ACME certificates,
//! a multi-user web admin and its API, in one binary.
//!
//! The binary (`warren-server`) is a thin CLI over [`server`]; the other
//! modules are the building blocks it wires together.

pub mod access;
pub mod acl;
pub mod acme;
pub mod agent_api;
pub mod api;
pub mod auth;
pub mod config;
pub mod db;
pub mod http;
pub mod ipam;
pub mod lan;
pub mod secrets;
pub mod server;
pub mod state;
pub mod tls;
pub mod update;
pub mod util;
pub mod wg;
