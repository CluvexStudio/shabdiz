use std::os::fd::RawFd;

use super::BATCH;

const CTL: usize = 32;

const STEP_FLOOR_NS: u64 = 20_000;

pub(super) fn enable(fd: RawFd) -> bool {
    let want = libc::sock_txtime {
        clockid: libc::CLOCK_MONOTONIC,
        flags: 0,
    };
    let r = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TXTIME,
            &want as *const libc::sock_txtime as *const libc::c_void,
            std::mem::size_of::<libc::sock_txtime>() as libc::socklen_t,
        )
    };
    r == 0
}

pub(super) fn now_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) } != 0 {
        return 0;
    }
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

pub(super) fn schedule(lead_ns: Option<u64>, datagrams: usize) -> Option<(u64, u64)> {
    let lead = lead_ns?;
    let now = now_ns();
    if now == 0 {
        return None;
    }
    let share = lead / datagrams.max(1) as u64;
    let step = if share >= STEP_FLOOR_NS { share } else { 0 };
    Some((
        now.saturating_add(lead.saturating_sub(step * datagrams as u64)),
        step,
    ))
}

unsafe fn stamp(msg: &mut libc::msghdr, ctl: &mut [u8; CTL], when: u64) {
    msg.msg_control = ctl.as_mut_ptr().cast();
    msg.msg_controllen = CTL as _;
    let cmsg = libc::CMSG_FIRSTHDR(msg);
    if cmsg.is_null() {
        msg.msg_control = std::ptr::null_mut();
        msg.msg_controllen = 0;
        return;
    }
    (*cmsg).cmsg_level = libc::SOL_SOCKET;
    (*cmsg).cmsg_type = libc::SCM_TXTIME;
    (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<u64>() as u32) as _;
    std::ptr::copy_nonoverlapping(
        when.to_ne_bytes().as_ptr(),
        libc::CMSG_DATA(cmsg),
        std::mem::size_of::<u64>(),
    );
    msg.msg_controllen = (*cmsg).cmsg_len;
}

pub(super) unsafe fn send_group_at(
    fd: RawFd,
    scratch: &[u8],
    lens: &[usize],
    plan: Option<(u64, u64)>,
) -> isize {
    let mut iov: [libc::iovec; BATCH] = std::mem::zeroed();
    let mut msgs: [libc::mmsghdr; BATCH] = std::mem::zeroed();
    let mut ctl = [[0u8; CTL]; BATCH];
    let mut at = 0;
    for (i, &len) in lens.iter().enumerate().take(BATCH) {
        iov[i] = libc::iovec {
            iov_base: scratch[at..].as_ptr() as *mut libc::c_void,
            iov_len: len,
        };
        msgs[i].msg_hdr.msg_iov = &mut iov[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        if let Some((first, step)) = plan {
            stamp(
                &mut msgs[i].msg_hdr,
                &mut ctl[i],
                first.saturating_add(step * i as u64),
            );
        }
        at += len;
    }
    libc::sendmmsg(fd, msgs.as_mut_ptr(), lens.len().min(BATCH) as u32, 0) as isize
}
