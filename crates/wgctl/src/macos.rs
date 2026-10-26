//! macOS: WireGuard through wireguard-go, which the kernel lacks.
//!
//! macOS names tunnel interfaces `utunN` and picks N itself, so `name` is a
//! logical name, mapped to the real one the way `wg-quick` does it:
//! `/var/run/wireguard/<name>.name` holds `utunN`, and wireguard-go serves
//! its configuration socket at `/var/run/wireguard/utunN.sock`. Addresses and
//! routes go through `ifconfig` and `route`.

use crate::{AllowedIp, DeviceInfo, DeviceSet, uapi};
use std::ffi::{CStr, CString};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

const RUN_DIR: &str = "/var/run/wireguard";
/// launchd starts services with a minimal PATH, so Homebrew's prefixes are
/// searched too.
const EXTRA_PATH: [&str; 2] = ["/opt/homebrew/bin", "/usr/local/bin"];

fn name_file(name: &str) -> PathBuf {
    Path::new(RUN_DIR).join(format!("{name}.name"))
}

fn socket(real: &str) -> PathBuf {
    Path::new(RUN_DIR).join(format!("{real}.sock"))
}

fn if_index(real: &str) -> Option<u32> {
    let c = CString::new(real).ok()?;
    // SAFETY: `c` is a valid NUL-terminated string.
    let i = unsafe { libc::if_nametoindex(c.as_ptr()) };
    (i != 0).then_some(i)
}

/// The `utunN` behind `name`, if wireguard-go still serves it. utun numbers
/// are reused by other VPNs, so a stale name file alone proves nothing.
fn real_name(name: &str) -> Option<String> {
    let real = std::fs::read_to_string(name_file(name)).ok()?.trim().to_string();
    let valid = real.strip_prefix("utun").is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
    (valid && socket(&real).exists() && if_index(&real).is_some()).then_some(real)
}

fn real(name: &str) -> io::Result<String> {
    real_name(name).ok_or_else(|| io::Error::from_raw_os_error(libc::ENODEV))
}

fn run(prog: &str, args: &[&str]) -> io::Result<()> {
    let out = Command::new(prog).args(args).stdin(Stdio::null()).output()?;
    if out.status.success() {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&out.stderr);
    Err(io::Error::other(format!("{prog} {}: {}", args.join(" "), err.trim())))
}

fn wireguard_go() -> io::Result<PathBuf> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .chain(EXTRA_PATH.iter().map(PathBuf::from))
        .map(|d| d.join("wireguard-go"))
        .find(|p| p.is_file())
        .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "wireguard-go not found; brew install wireguard-go"))
}

pub fn link_index(name: &str) -> Option<u32> {
    if_index(&real_name(name)?)
}

pub fn create_wireguard_link(name: &str) -> io::Result<()> {
    if real_name(name).is_some() {
        return Err(io::Error::from_raw_os_error(libc::EEXIST));
    }
    let bin = wireguard_go()?;
    std::fs::create_dir_all(RUN_DIR)?;
    let _ = std::fs::remove_file(name_file(name));
    // wireguard-go forks a daemon and exits once the interface and its
    // socket exist. Without LOG_LEVEL the daemon writes to /dev/null, so
    // waiting for the output does not wait for the daemon.
    let out = Command::new(bin)
        .arg("utun")
        .env("WG_TUN_NAME_FILE", name_file(name))
        .env_remove("LOG_LEVEL")
        .stdin(Stdio::null())
        .output()?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(io::Error::other(format!("wireguard-go: {}", err.trim())));
    }
    real(name).map(drop)
}

pub fn delete_link(name: &str) -> io::Result<()> {
    let real = real(name)?;
    // wireguard-go watches its socket and shuts down when it disappears.
    std::fs::remove_file(socket(&real))?;
    let _ = std::fs::remove_file(name_file(name));
    for _ in 0..50 {
        if if_index(&real).is_none() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(io::Error::new(io::ErrorKind::TimedOut, format!("{real} is still present")))
}

pub fn set_link_up(name: &str, mtu: u32) -> io::Result<()> {
    run("/sbin/ifconfig", &[&real(name)?, "mtu", &mtu.to_string(), "up"])
}

fn prefix_len(mask: IpAddr) -> u8 {
    let ones = match mask {
        IpAddr::V4(m) => u32::from(m).count_ones(),
        IpAddr::V6(m) => u128::from(m).count_ones(),
    };
    u8::try_from(ones).unwrap_or_default()
}

/// Reads an address from a `sockaddr` that getifaddrs filled in.
///
/// # Safety
/// `sa` is null or points to a valid `sockaddr` of its `sa_family`.
unsafe fn sockaddr_ip(sa: *const libc::sockaddr) -> Option<IpAddr> {
    if sa.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees `sa` points to a sockaddr of this family.
    unsafe {
        match i32::from((*sa).sa_family) {
            libc::AF_INET => {
                let v4 = &*sa.cast::<libc::sockaddr_in>();
                Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(v4.sin_addr.s_addr))))
            }
            libc::AF_INET6 => {
                let v6 = &*sa.cast::<libc::sockaddr_in6>();
                Some(IpAddr::V6(Ipv6Addr::from(v6.sin6_addr.s6_addr)))
            }
            _ => None,
        }
    }
}

pub fn list_addresses(name: &str) -> io::Result<Vec<AllowedIp>> {
    let real = real(name)?;
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs writes a list head to `head`, freed below.
    if unsafe { libc::getifaddrs(&raw mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut out = Vec::new();
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` is a node of the list getifaddrs returned, which
        // stays valid until freeifaddrs; its name is NUL-terminated and its
        // sockaddrs are null or valid for their family.
        unsafe {
            let ifa = &*cur;
            cur = ifa.ifa_next;
            if CStr::from_ptr(ifa.ifa_name).to_bytes() != real.as_bytes() {
                continue;
            }
            let (Some(addr), Some(mask)) = (sockaddr_ip(ifa.ifa_addr), sockaddr_ip(ifa.ifa_netmask)) else {
                continue;
            };
            if matches!(addr, IpAddr::V6(v) if v.is_unicast_link_local()) {
                continue;
            }
            out.push(AllowedIp { addr, cidr: prefix_len(mask) });
        }
    }
    // SAFETY: `head` came from a successful getifaddrs and is freed once.
    unsafe { libc::freeifaddrs(head) };
    Ok(out)
}

/// The network of `a`: its address with the host bits cleared.
fn network(a: AllowedIp) -> AllowedIp {
    let addr = match a.addr {
        IpAddr::V4(v) => {
            IpAddr::V4(Ipv4Addr::from(u32::from(v) & u32::MAX.checked_shl(32 - u32::from(a.cidr)).unwrap_or(0)))
        }
        IpAddr::V6(v) => {
            IpAddr::V6(Ipv6Addr::from(u128::from(v) & u128::MAX.checked_shl(128 - u32::from(a.cidr)).unwrap_or(0)))
        }
    };
    AllowedIp { addr, cidr: a.cidr }
}

fn family(a: AllowedIp) -> &'static str {
    if a.addr.is_ipv4() { "inet" } else { "inet6" }
}

fn route(op: &str, a: AllowedIp, real: &str) -> io::Result<()> {
    let net = network(a).to_string();
    run("/sbin/route", &["-q", "-n", op, &format!("-{}", family(a)), &net, "-interface", real])
}

/// Adds `a` and, as Linux does on its own, a route to its network: a utun
/// is point-to-point, so macOS adds none.
pub fn add_address(name: &str, a: AllowedIp) -> io::Result<()> {
    let real = real(name)?;
    let ip = a.addr.to_string();
    let with_prefix = a.to_string();
    if a.addr.is_ipv4() {
        run("/sbin/ifconfig", &[&real, "inet", &with_prefix, &ip, "alias"])?;
    } else {
        run("/sbin/ifconfig", &[&real, "inet6", &with_prefix, "alias"])?;
    }
    if a.cidr < if a.addr.is_ipv4() { 32 } else { 128 } {
        let _ = route("delete", a, &real);
        route("add", a, &real)?;
    }
    Ok(())
}

pub fn del_address(name: &str, a: AllowedIp) -> io::Result<()> {
    let real = real(name)?;
    let _ = route("delete", a, &real);
    run("/sbin/ifconfig", &[&real, family(a), &a.addr.to_string(), "-alias"])
}

pub fn get_device(name: &str) -> io::Result<DeviceInfo> {
    uapi::get_device(&socket(&real(name)?))
}

pub fn set_device(name: &str, set: &DeviceSet) -> io::Result<()> {
    uapi::set_device(&socket(&real(name)?), set)
}

pub fn set_forwarding(_: &str, _: bool) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "per-interface forwarding needs Linux"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn networks_and_prefixes() {
        let n = |s: &str| network(s.parse().unwrap()).to_string();
        assert_eq!(n("10.77.0.5/16"), "10.77.0.0/16");
        assert_eq!(n("10.77.0.5/0"), "0.0.0.0/0");
        assert_eq!(n("10.77.0.5/32"), "10.77.0.5/32");
        assert_eq!(n("fd00::1:2/112"), "fd00::1:0/112");
        assert_eq!(n("fd00::1:2/64"), "fd00::/64");
        assert_eq!(prefix_len("255.255.0.0".parse().unwrap()), 16);
        assert_eq!(prefix_len("ffff:ffff::".parse().unwrap()), 32);
    }

    #[test]
    fn missing_interface_is_not_found() {
        assert_eq!(link_index("warren-test-none"), None);
        assert_eq!(real("warren-test-none").unwrap_err().raw_os_error(), Some(libc::ENODEV));
    }
}
