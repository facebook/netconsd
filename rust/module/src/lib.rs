/*
 * These structs have been generated with bindgen (except for the bitfields getters),
 * and are passed to netconsd_output_handler function defined in a netconsd module.
 *
 * Copyright (C) 2022, Meta, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the license found in the LICENSE file in
 * the root directory of this source tree.
 */

use std::ffi::CStr;
use std::fmt;
use std::os::raw::c_char;
pub use std::os::raw::c_int;
use std::os::raw::c_void;

pub use libc::in6_addr;
use libc::iovec;
pub use libc::sockaddr_in6;

#[repr(C)]
#[derive(Debug)]
pub struct MsgBuf {
    pub next: *const MsgBuf,
    pub iovec: iovec,
    pub src: sockaddr_in6,
    pub hole: [u8; 4],
    pub rcv_time: u64,
    pub rcv_flags: c_int,
    pub rcv_bytes: c_int,
}

#[derive(Debug)]
#[repr(C)]
pub struct NcrxList {
    pub next: *mut NcrxList,
    pub prev: *mut NcrxList,
}

#[derive(Debug)]
#[repr(C)]
pub struct NcrxMsg {
    pub seq: u64,
    pub ts_usec: u64,
    pub text: *const c_char,
    pub dict: *const c_char,
    pub text_len: c_int,
    pub dict_len: c_int,
    pub facility: u8,
    pub level: u8,
    pub flags: u8,
    pub node: NcrxList,
    pub rx_at_mono: u64,
    pub rx_at_real: u64,
    pub ncfrag_off: c_int,
    pub ncfrag_len: c_int,
    pub ncfrag_left: c_int,
    pub _bitfield_align_2: [u8; 0],
    pub _bitfield_2: [u8; 1usize],
}

impl NcrxMsg {
    pub fn get_cont_start(&self) -> bool {
        self.flags & 0b1 > 0
    }
    pub fn get_cont(&self) -> bool {
        self.flags & 0b10 > 0
    }

    pub fn get_oos(&self) -> bool {
        self.flags & 0b100 > 0
    }
    pub fn get_seq_reset(&self) -> bool {
        self.flags & 0b1000 > 0
    }
}

pub fn format_in6_addr_ptr(ptr: *const in6_addr) -> String {
    match unsafe { ptr.as_ref() } {
        None => "NULL".to_owned(),
        Some(x) => format!("{:x?}", x.s6_addr),
    }
}

impl fmt::Display for NcrxMsg {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let cont_start = if self.get_cont_start() {
            "[CONT_START]"
        } else {
            ""
        };
        let cont = if self.get_cont() { "[CONT]" } else { "" };
        let oos = if self.get_oos() { "[OOS]" } else { "" };
        let seq_reset = if self.get_seq_reset() {
            "[SEQ_RESET]"
        } else {
            ""
        };
        let text = str_from_c_void(self.text as *const c_void);
        write!(
            formatter,
            "S{} T{} F{}/L{}{}{}{}{}: {}",
            self.seq,
            self.ts_usec,
            self.facility,
            self.level,
            cont_start,
            cont,
            oos,
            seq_reset,
            text
        )
    }
}

fn str_from_c_void(ptr: *const c_void) -> &'static str {
    unsafe { CStr::from_ptr(ptr as *const c_char).to_str().unwrap() }
}

impl fmt::Display for MsgBuf {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", str_from_c_void(self.iovec.iov_base))
    }
}
