use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

use tokio::io::unix::AsyncFd;

#[derive(Clone, Copy)]
pub enum Side {
    Read,
    Write,
}

pub async fn retry<T>(
    fd: &AsyncFd<OwnedFd>,
    side: Side,
    tolerate: impl Fn(&io::Error) -> bool,
    mut call: impl FnMut(RawFd) -> io::Result<T>,
) -> io::Result<T> {
    loop {
        let mut ready = match side {
            Side::Read => fd.readable().await?,
            Side::Write => fd.writable().await?,
        };
        match ready.try_io(|inner| call(inner.get_ref().as_raw_fd())) {
            Ok(Ok(value)) => return Ok(value),
            Ok(Err(e)) if tolerate(&e) => continue,
            Ok(Err(e)) => return Err(e),
            Err(_would_block) => continue,
        }
    }
}

pub fn never_tolerate(_: &io::Error) -> bool {
    false
}

pub fn set_opt(
    fd: RawFd,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    let r = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &value as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn count(n: isize) -> io::Result<usize> {
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}
