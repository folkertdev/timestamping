mod hwtimestamp;
mod interface_name;

use std::{io::IoSliceMut, marker::PhantomData, net::SocketAddr, os::fd::AsRawFd};

pub(crate) enum MessageQueue {
    Normal,
    Error,
}

pub(crate) fn cerr(t: libc::c_int) -> std::io::Result<libc::c_int> {
    match t {
        -1 => Err(std::io::Error::last_os_error()),
        _ => Ok(t),
    }
}

pub(crate) fn receive_message<'a>(
    socket: &std::net::UdpSocket,
    packet_buf: &mut [u8],
    control_buf: &'a mut [u8],
    queue: MessageQueue,
) -> std::io::Result<(
    libc::c_int,
    impl Iterator<Item = ControlMessage> + 'a,
    Option<SocketAddr>,
)> {
    let mut buf_slice = IoSliceMut::new(packet_buf);
    let mut addr = zeroed_sockaddr_storage();

    let mut mhdr = libc::msghdr {
        msg_control: control_buf.as_mut_ptr().cast::<libc::c_void>(),
        msg_controllen: control_buf.len() as _,
        msg_iov: (&mut buf_slice as *mut IoSliceMut).cast::<libc::iovec>(),
        msg_iovlen: 1,
        msg_flags: 0,
        msg_name: (&mut addr as *mut libc::sockaddr_storage).cast::<libc::c_void>(),
        msg_namelen: std::mem::size_of::<libc::sockaddr_storage>() as u32,
    };

    let receive_flags = match queue {
        MessageQueue::Normal => 0,
        MessageQueue::Error => libc::MSG_ERRQUEUE,
    };

    // Safety:
    // We have a mutable reference to the control buffer for the duration of the
    // call, and controllen is also set to it's length.
    // IoSliceMut is ABI compatible with iovec, and we only have 1 which matches iovlen
    // msg_name is initialized to point to an owned sockaddr_storage and
    // msg_namelen is the size of sockaddr_storage
    // If one of the buffers is too small, recvmsg cuts off data at appropriate boundary
    let sent_bytes = loop {
        match cerr(unsafe { libc::recvmsg(socket.as_raw_fd(), &mut mhdr, receive_flags) } as _) {
            Err(e) if std::io::ErrorKind::Interrupted == e.kind() => {
                // retry when the recv was interrupted
                continue;
            }
            Err(e) => return Err(e),
            Ok(sent) => break sent,
        }
    };

    if mhdr.msg_flags & libc::MSG_TRUNC > 0 {
        eprintln!(
            "packet is larger than expected (has cmsgs maybe?): {}",
            packet_buf.len(),
        );
    }

    if mhdr.msg_flags & libc::MSG_CTRUNC > 0 {
        panic!("truncated control messages");
    }

    // Clear out the fields for which we are giving up the reference
    mhdr.msg_iov = std::ptr::null_mut();
    mhdr.msg_iovlen = 0;
    mhdr.msg_name = std::ptr::null_mut();
    mhdr.msg_namelen = 0;

    // Safety:
    // recvmsg ensures that the control buffer contains
    // a set of valid control messages and that controllen is
    // the length these take up in the buffer.
    Ok((
        sent_bytes,
        unsafe { ControlMessageIterator::new(mhdr) },
        sockaddr_storage_to_socket_addr(&addr),
    ))
}

/// Convert a libc::sockaddr to a rust std::net::SocketAddr
///
/// # Safety
///
/// According to the posix standard, `sockaddr` does not have a defined size: the size depends on
/// the value of the `ss_family` field. We assume this to be correct.
///
/// In practice, types in rust/c need a statically-known stack size, so they pick some value. In
/// practice it can be (and is) larger than the `sizeof<libc::sockaddr>` value.
pub unsafe fn sockaddr_to_socket_addr(sockaddr: *const libc::sockaddr) -> Option<SocketAddr> {
    // Most (but not all) of the fields in a socket addr are in network byte ordering.
    // As such, when doing conversions here, we should start from the NATIVE
    // byte representation, as this will actualy be the big-endian representation
    // of the underlying value regardless of platform.
    match unsafe { (*sockaddr).sa_family as libc::c_int } {
        libc::AF_INET => {
            let inaddr: libc::sockaddr_in = unsafe { *(sockaddr as *const libc::sockaddr_in) };

            let socketaddr = std::net::SocketAddrV4::new(
                std::net::Ipv4Addr::from(inaddr.sin_addr.s_addr.to_ne_bytes()),
                u16::from_be_bytes(inaddr.sin_port.to_ne_bytes()),
            );

            Some(std::net::SocketAddr::V4(socketaddr))
        }
        libc::AF_INET6 => {
            let inaddr: libc::sockaddr_in6 = unsafe { *(sockaddr as *const libc::sockaddr_in6) };

            let sin_addr = inaddr.sin6_addr.s6_addr;
            let segment_bytes: [u8; 16] =
                unsafe { std::ptr::read_unaligned(&sin_addr as *const _ as *const _) };

            let socketaddr = std::net::SocketAddrV6::new(
                std::net::Ipv6Addr::from(segment_bytes),
                u16::from_be_bytes(inaddr.sin6_port.to_ne_bytes()),
                inaddr.sin6_flowinfo, // NOTE: Despite network byte order, no conversion is needed (see https://github.com/rust-lang/rust/issues/101605)
                inaddr.sin6_scope_id,
            );

            Some(std::net::SocketAddr::V6(socketaddr))
        }
        _ => None,
    }
}

pub fn sockaddr_storage_to_socket_addr(
    sockaddr_storage: &libc::sockaddr_storage,
) -> Option<SocketAddr> {
    // Safety:
    //
    // sockaddr_storage always has enough space to store either a sockaddr_in or sockaddr_in6
    unsafe { sockaddr_to_socket_addr(sockaddr_storage as *const _ as *const libc::sockaddr) }
}

// Invariants:
// self.mhdr points to a valid libc::msghdr with a valid control
// message region.
// self.current_msg points to one of the control messages
// in the region described by self.mhdr or is NULL
//
// These invariants are guaranteed from the safety conditions on
// calling ControlMessageIterator::new, the fact that next preserves
// these invariants and that the fields of ControlMessageIterator
// are not modified outside these two functions.
struct ControlMessageIterator<'a> {
    mhdr: libc::msghdr,
    next_msg: *const libc::cmsghdr,
    phantom: PhantomData<&'a [u8]>,
}

impl<'a> ControlMessageIterator<'a> {
    // Safety assumptions:
    // mhdr has a control and controllen field
    // that together describe a memory region
    // with lifetime 'a containing valid control
    // messages
    unsafe fn new(mhdr: libc::msghdr) -> Self {
        // Safety:
        // mhdr's control and controllen fields are valid and point
        // to valid control messages.
        let current_msg = unsafe { libc::CMSG_FIRSTHDR(&mhdr) };

        // Invariant preservation:
        // The safety assumptions guaranteed by the caller ensure
        // that mhdr points to a valid region with valid control
        // messages. CMSG_FIRSTHDR is then guaranteed to either
        // return the pointer to the first valid control message
        // in that region, or NULL if the region is empty.
        Self {
            mhdr,
            next_msg: current_msg,
            phantom: PhantomData,
        }
    }
}

pub(crate) enum LibcTimestamp {
    Timespec(libc::timespec),
    Timeval(libc::timeval),
}

pub(crate) enum ControlMessage {
    Timestamping(crate::LibcTimestamp),
    ReceiveError(libc::sock_extended_err),
    Other(libc::cmsghdr),
}

impl<'a> Iterator for ControlMessageIterator<'a> {
    type Item = ControlMessage;

    fn next(&mut self) -> Option<Self::Item> {
        // Safety:
        // By the invariants, self.current_msg either points to a valid control message
        // or is NULL
        let current_msg = unsafe { self.next_msg.as_ref() }?;

        // Safety:
        // Invariants ensure that self.mhdr points to a valid libc::msghdr with a valid control
        // message region, and that self.next_msg either points to a valid control message
        // or is NULL.
        // The previous statement would have returned if self.next_msg were NULL, therefore both passed
        // pointers are valid for use with CMSG_NXTHDR
        // Invariant preservation:
        // CMSG_NXTHDR returns either a pointer to the next valid control message in the control
        // message region described by self.mhdr, or NULL
        self.next_msg = unsafe { libc::CMSG_NXTHDR(&self.mhdr, self.next_msg) };

        Some(match (current_msg.cmsg_level, current_msg.cmsg_type) {
            #[cfg(target_os = "linux")]
            (libc::SOL_SOCKET, libc::SCM_TIMESTAMPING) => {
                // Safety:
                // current_msg was constructed from a pointer that pointed to a valid control message.
                // SO_TIMESTAMPING and SO_TIMESTAMPNS always have a timespec in the data
                let cmsg_data =
                    unsafe { libc::CMSG_DATA(current_msg) } as *const [libc::timespec; 3];
                let [software, _, hardware] = unsafe { std::ptr::read_unaligned(cmsg_data) };

                dbg!(
                    software.tv_sec,
                    software.tv_nsec,
                    hardware.tv_sec,
                    hardware.tv_nsec,
                );

                let timespec = if hardware.tv_sec == 0 && hardware.tv_nsec == 0 {
                    println!("a disappointing software timestamp, boo!");
                    software
                } else {
                    println!("actual hardware timestamp, yay!");
                    hardware
                };

                ControlMessage::Timestamping(LibcTimestamp::Timespec(timespec))
            }

            (libc::SOL_SOCKET, libc::SCM_TIMESTAMP) => {
                // Safety:
                // current_msg was constructed from a pointer that pointed to a valid control message.
                // SO_TIMESTAMP always has a timeval in the data
                let cmsg_data = unsafe { libc::CMSG_DATA(current_msg) } as *const libc::timeval;
                let timeval = unsafe { std::ptr::read_unaligned(cmsg_data) };
                ControlMessage::Timestamping(LibcTimestamp::Timeval(timeval))
            }

            (libc::SOL_IP, libc::IP_RECVERR) | (libc::SOL_IPV6, libc::IPV6_RECVERR) => {
                // this is part of how timestamps are reported.
                // Safety:
                // current_msg was constructed from a pointer that pointed to a valid
                // control message.
                // IP*_RECVERR always has a sock_extended_err in the data
                let error = unsafe {
                    let ptr = libc::CMSG_DATA(current_msg) as *const libc::sock_extended_err;
                    std::ptr::read_unaligned(ptr)
                };

                ControlMessage::ReceiveError(error)
            }
            _ => ControlMessage::Other(*current_msg),
        })
    }
}

fn zeroed_sockaddr_storage() -> libc::sockaddr_storage {
    // a zeroed-out sockaddr storage is semantically valid, because a ss_family with value 0 is
    // libc::AF_UNSPEC. Hence the rest of the data does not come with any constraints
    // Safety:
    // the MaybeUninit is zeroed before assumed to be initialized
    unsafe { std::mem::MaybeUninit::zeroed().assume_init() }
}

fn configure_timestamping_socket(
    udp_socket: &std::net::UdpSocket,
    options: u32,
) -> std::io::Result<libc::c_int> {
    let method = libc::SO_TIMESTAMPING;

    // Documentation on the timestamping calls:
    //
    // - linux: https://www.kernel.org/doc/Documentation/networking/timestamping.txt
    // - freebsd: https://man.freebsd.org/cgi/man.cgi?setsockopt
    //
    // SAFETY:
    //
    // - the socket is provided by (safe) rust, and will outlive the call
    // - method is guaranteed to be a valid "name" argument
    // - the options pointer outlives the call
    // - the `option_len` corresponds with the options pointer
    //
    // Only some bits are valid to set in `options`, but setting invalid bits is perfectly safe
    //
    // > Setting other bit returns EINVAL and does not change the current state.
    unsafe {
        cerr(libc::setsockopt(
            udp_socket.as_raw_fd(),
            libc::SOL_SOCKET,
            method as i32 as libc::c_int,
            &options as *const _ as *const libc::c_void,
            std::mem::size_of_val(&options) as libc::socklen_t,
        ))
    }
}

pub(crate) const fn control_message_space<T>() -> usize {
    // Safety: CMSG_SPACE is safe to call
    (unsafe { libc::CMSG_SPACE((std::mem::size_of::<T>()) as _) }) as usize
}

fn read_control_messages(socket: &std::net::UdpSocket) -> std::io::Result<Option<LibcTimestamp>> {
    const CONTROL_SIZE: usize = control_message_space::<[libc::timespec; 3]>()
        + control_message_space::<(libc::sock_extended_err, libc::sockaddr_storage)>();

    let mut control_buf = [0; CONTROL_SIZE];

    let (_, control_messages, _) =
        receive_message(&socket, &mut [], &mut control_buf, MessageQueue::Error)?;

    let mut send_ts = None;
    for msg in control_messages {
        match msg {
            ControlMessage::Timestamping(timestamp) => {
                send_ts = Some(timestamp);
            }

            ControlMessage::ReceiveError(error) => {
                // the timestamping does not set a message; if there is a message, that means
                // something else is wrong, and we want to know about it.
                if error.ee_errno as libc::c_int != libc::ENOMSG {
                    panic!("error message on the MSG_ERRQUEUE");
                }
            }

            ControlMessage::Other(msg) => {
                panic!(
                    "unexpected message on the MSG_ERRQUEUE: level={}, type={}",
                    msg.cmsg_level, msg.cmsg_type,
                );
            }
        }
    }

    Ok(send_ts)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::hwtimestamp::driver_enable_hardware_timestamping;

    use super::*;

    #[test]
    fn send_standard() -> std::io::Result<()> {
        // sofware timestamps can use localhost
        let listen_addr = SocketAddr::from((Ipv4Addr::new(0, 0, 0, 0), 8000));
        let peer_addr = SocketAddr::from((Ipv4Addr::new(0, 0, 0, 0), 8001));
        let socket = std::net::UdpSocket::bind(listen_addr)?;
        socket.connect(peer_addr)?;

        let mut options = 0;

        // enable software timestamping
        options |= libc::SOF_TIMESTAMPING_SOFTWARE;

        // we want receive timestamps
        options |= libc::SOF_TIMESTAMPING_RX_SOFTWARE;

        // we want send timestamps
        options |= libc::SOF_TIMESTAMPING_TX_SOFTWARE;

        configure_timestamping_socket(&socket, options)?;

        socket.send(&[1; 48])?;

        let send_ts = read_control_messages(&socket)?;
        assert!(send_ts.is_some());

        Ok(())
    }

    #[test]
    fn send_extra_fd() -> std::io::Result<()> {
        // sofware timestamps can use localhost
        let listen_addr = SocketAddr::from((Ipv4Addr::new(0, 0, 0, 0), 8002));
        let peer_addr = SocketAddr::from((Ipv4Addr::new(0, 0, 0, 0), 8003));
        let socket = std::net::UdpSocket::bind(listen_addr)?;
        socket.connect(peer_addr)?;

        let mut options = 0;

        // enable software timestamping
        options |= libc::SOF_TIMESTAMPING_SOFTWARE;

        // we want receive timestamps
        options |= libc::SOF_TIMESTAMPING_RX_SOFTWARE;

        // we want send timestamps
        options |= libc::SOF_TIMESTAMPING_TX_SOFTWARE
            | libc::SOF_TIMESTAMPING_OPT_TSONLY
            | libc::SOF_TIMESTAMPING_OPT_ID;

        configure_timestamping_socket(&socket, options)?;

        socket.send(&[1; 48])?;

        let send_ts = read_control_messages(&socket)?;
        assert!(send_ts.is_some());

        Ok(())
    }

    #[test]
    fn send_hardware_standard() -> std::io::Result<()> {
        let listen_addr = SocketAddr::from((Ipv4Addr::new(0, 0, 0, 0), 8004));
        let peer_addr = SocketAddr::from((Ipv4Addr::new(10, 0, 0, 16), 8005));
        let socket = std::net::UdpSocket::bind(listen_addr)?;
        socket.connect(peer_addr)?;

        driver_enable_hardware_timestamping(&socket)?;

        let mut options = 0;

        // enable software timestamping
        options |= libc::SOF_TIMESTAMPING_RAW_HARDWARE;

        // we want receive timestamps
        options |= libc::SOF_TIMESTAMPING_RX_HARDWARE;

        // we want send timestamps
        options |= libc::SOF_TIMESTAMPING_TX_HARDWARE;

        configure_timestamping_socket(&socket, options)?;

        socket.send(&[1; 48])?;

        // give some time for the timestamp to make it into the error queue
        std::thread::sleep(std::time::Duration::from_millis(300));

        let send_ts = read_control_messages(&socket)?;
        assert!(send_ts.is_some());

        match send_ts.unwrap() {
            LibcTimestamp::Timespec(timespec) => dbg!(timespec.tv_sec, timespec.tv_nsec),
            LibcTimestamp::Timeval(_) => unreachable!(),
        };

        Ok(())
    }

    #[test]
    fn send_hardware_extra_fd() -> std::io::Result<()> {
        let listen_addr = SocketAddr::from((Ipv4Addr::new(0, 0, 0, 0), 8006));
        let peer_addr = SocketAddr::from((Ipv4Addr::new(10, 0, 0, 17), 8007));
        let socket = std::net::UdpSocket::bind(listen_addr)?;
        socket.connect(peer_addr)?;

        driver_enable_hardware_timestamping(&socket)?;

        let mut options = 0;

        // enable software timestamping
        options |= libc::SOF_TIMESTAMPING_RAW_HARDWARE;

        // we want receive timestamps
        options |= libc::SOF_TIMESTAMPING_RX_HARDWARE;

        // we want send timestamps
        options |= libc::SOF_TIMESTAMPING_TX_HARDWARE
            | libc::SOF_TIMESTAMPING_OPT_TSONLY
            | libc::SOF_TIMESTAMPING_OPT_ID;

        configure_timestamping_socket(&socket, options)?;

        socket.send(&[1; 48])?;

        // give some time for the timestamp to make it into the error queue
        std::thread::sleep(std::time::Duration::from_millis(300));

        let send_ts = read_control_messages(&socket)?;
        assert!(send_ts.is_some());

        match send_ts.unwrap() {
            LibcTimestamp::Timespec(timespec) => dbg!(timespec.tv_sec, timespec.tv_nsec),
            LibcTimestamp::Timeval(_) => unreachable!(),
        };

        Ok(())
    }
}
