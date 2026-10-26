//! Stand-ins for systems without WireGuard netlink: every call is `Unsupported`.

use crate::{AllowedIp, DeviceInfo, DeviceSet};
use std::io;

fn no<T>() -> io::Result<T> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "WireGuard control needs Linux"))
}

pub fn link_index(_: &str) -> Option<u32> {
    None
}

pub fn create_wireguard_link(_: &str) -> io::Result<()> {
    no()
}

pub fn delete_link(_: &str) -> io::Result<()> {
    no()
}

pub fn set_link_up(_: &str, _: u32) -> io::Result<()> {
    no()
}

pub fn list_addresses(_: &str) -> io::Result<Vec<AllowedIp>> {
    no()
}

pub fn add_address(_: &str, _: AllowedIp) -> io::Result<()> {
    no()
}

pub fn del_address(_: &str, _: AllowedIp) -> io::Result<()> {
    no()
}

pub fn get_device(_: &str) -> io::Result<DeviceInfo> {
    no()
}

pub fn set_device(_: &str, _: &DeviceSet) -> io::Result<()> {
    no()
}

pub fn set_forwarding(_: &str, _: bool) -> io::Result<()> {
    no()
}
