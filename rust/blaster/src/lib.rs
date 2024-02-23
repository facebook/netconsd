/*
 * Utility functions to send fake netconsole messages, can be used to test
 * netconsd and its modules.
 *
 * Copyright (C) 2022, Meta, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the license found in the LICENSE file in
 * the root directory of this source tree.
 */
use std::io::Cursor;
use std::mem::size_of;
use std::thread::sleep;
use std::time::Duration;

use byteorder::BigEndian;
use byteorder::ReadBytesExt;
use libc::c_int;
use libc::c_void;
use libc::in6_addr;
use libc::sendto;
use libc::sockaddr;
use libc::sockaddr_in6;
use libc::socket;
use libc::AF_INET6;
use libc::IPPROTO_RAW;
use libc::IPPROTO_UDP;
use libc::SOCK_RAW;

#[derive(Debug)]
pub struct WorkerConfig {
    pub id: u8,
    pub packets_count: u64,
    pub dst_port: u16,
    pub sleep_duration: Option<Duration>,
    pub extended_msg: bool,
    pub sender_addr_rnd_bytes: usize,
}

#[repr(C, packed)]
#[derive(Default)]
struct UdpHdr {
    src_port: u16,
    dst_port: u16,
    len: u16,
    check: u16,
}

#[repr(C, packed)]
#[derive(Default)]
struct Ip6Hdr {
    ctl: u32,
    plen: u16,
    next: u8,
    hlim: u8,
    src: [u8; 16],
    dst: [u8; 16],
}

#[repr(C, packed)]
struct NetconsPacket {
    l3: Ip6Hdr,
    l4: UdpHdr,
    payload: [u8; 64],
}

impl NetconsPacket {
    fn new(dst_ip: [u8; 16], dst_port: u16) -> NetconsPacket {
        let len: u16 = 64 /* payload fixed length */ + 8 /* size of UdpHdr */;
        NetconsPacket {
            l3: Ip6Hdr {
                ctl: 6 << 4,
                plen: len.to_be(),
                next: IPPROTO_UDP as u8,
                hlim: 64,
                src: [0u8; 16],
                dst: dst_ip,
            },
            l4: UdpHdr {
                src_port: 6666u16.to_be(),
                dst_port: dst_port.to_be(),
                len: len.to_be(),
                check: 0,
            },
            payload: [0u8; 64],
        }
    }

    fn update_checksum(&mut self) {
        self.l4.check = compute_checksum(self);
    }

    fn set_payload(&mut self, msg: &str) {
        self.payload[0..msg.len()].copy_from_slice(msg.as_bytes());
        for i in msg.len()..64 {
            self.payload[i] = 0;
        }
    }
}

fn get_raw_socket() -> c_int {
    unsafe { socket(AF_INET6, SOCK_RAW, IPPROTO_RAW) }
}

fn sum_bytes_for_checksum(sum: &mut u32, b: &[u8]) {
    let mut i = 0;
    while i < b.len() {
        let mut v: u32 = b[i].into();
        i += 1;
        *sum += v << 8;
        v = b[i].into();
        *sum += v;
        i += 1;
    }
    if *sum > 0xffff {
        *sum -= 0xffff;
    }
}

fn sum_u16_for_checksum(sum: &mut u32, b: u16) {
    *sum += b as u32;
    if *sum > 0xffff {
        *sum -= 0xffff;
    }
}

fn compute_checksum(packet: &NetconsPacket) -> u16 {
    let mut sum = 0u32;
    sum_bytes_for_checksum(&mut sum, &packet.l3.src);
    sum_bytes_for_checksum(&mut sum, &packet.l3.dst);

    sum_u16_for_checksum(&mut sum, (packet.payload.len() + 8) as u16);
    sum_u16_for_checksum(&mut sum, IPPROTO_UDP as u16);

    sum_u16_for_checksum(&mut sum, packet.l4.src_port.to_be());
    sum_u16_for_checksum(&mut sum, packet.l4.dst_port.to_be());
    sum_u16_for_checksum(&mut sum, packet.l4.len.to_be());

    let mut payload_buf = Cursor::new(packet.payload);
    while let Ok(value) = payload_buf.read_u16::<BigEndian>() {
        sum_u16_for_checksum(&mut sum, value);
    }

    if sum == 0 {
        sum = 65535;
    }

    !(sum as u16).to_be()
}

fn send_packet(fd: c_int, packet: &NetconsPacket, sockaddr: &sockaddr_in6) {
    unsafe {
        let pkt_ptr = (packet as *const NetconsPacket) as *const c_void;
        let pkt_size = size_of::<NetconsPacket>();

        // libc::sendto requires a sockaddr pointer, but here we must use a sockaddr_in6,
        // this might be a bad implementation of rust libc.
        let sockaddr_ptr = &*((sockaddr as *const sockaddr_in6) as *const sockaddr);
        let sockaddr_size: u32 = size_of::<sockaddr_in6>()
            .try_into()
            .expect("Could not convert size of sockaddr_in6 to u32.");

        let _ = sendto(fd, pkt_ptr, pkt_size, 0, sockaddr_ptr, sockaddr_size);
    };
}

fn make_sockaddr_in6(dst_ip: [u8; 16]) -> sockaddr_in6 {
    sockaddr_in6 {
        sin6_family: AF_INET6 as u16,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: in6_addr { s6_addr: dst_ip },
        sin6_scope_id: 0,
    }
}

pub fn blast_worker(config: WorkerConfig) {
    let fd = get_raw_socket();

    let mut dst_ip = [0u8; 16];
    dst_ip[15] = 1;
    let addr = make_sockaddr_in6(dst_ip);

    let mut packet = NetconsPacket::new(dst_ip, config.dst_port);
    packet.l3.src[15] = config.id;

    for i in 0u64..config.packets_count {
        let msg = if config.extended_msg {
            format!("{},{},{},-;hello packet {} {}\n", 4, i, i, config.id, i)
        } else {
            format!("[{}] hello packet {} {}\n", i, config.id, i)
        };
        packet.set_payload(&msg);
        for j in 0..config.sender_addr_rnd_bytes {
            packet.l3.src[j] = rand::random();
        }
        packet.update_checksum();

        send_packet(fd, &packet, &addr);
        if let Some(t) = config.sleep_duration {
            sleep(t);
        }
    }
}
