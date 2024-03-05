/*
 * A minimal example of a Rust netconsd module.
 *
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use netconsd_module::c_int;
use netconsd_module::format_in6_addr_ptr;
use netconsd_module::in6_addr;
use netconsd_module::MsgBuf;
use netconsd_module::NcrxMsg;

fn fmt_ptr<T: std::fmt::Display>(ptr: *const T) -> String {
    match unsafe { ptr.as_ref() } {
        None => "NULL".to_owned(),
        Some(x) => format!("{}", x),
    }
}

#[no_mangle]
pub extern "C" fn netconsd_output_init(nr_workers: c_int) -> c_int {
    println!(
        "Rust example module init! netconsd will use {} workers",
        nr_workers
    );
    0
}

#[no_mangle]
pub extern "C" fn netconsd_output_handler(
    t: c_int,
    in6_addr: *const in6_addr,
    buf: *const MsgBuf,
    msg: *const NcrxMsg,
) -> i32 {
    println!(
        "Received message from {} on thread {}",
        format_in6_addr_ptr(in6_addr),
        t
    );

    println!("Buf: {}", fmt_ptr(buf));
    println!("Msg: {}", fmt_ptr(msg));
    0
}

#[no_mangle]
pub extern "C" fn netconsd_output_exit() {
    println!("Rust example module bye bye");
}
