/*
 * A netconsd module that sends messages to loopback and verifies that it
 * receives all the messages.
 * E.g. ./netconsd -w 2 -l 2 -u 6666 self_test_module.so
 *
 * Copyright (C) 2022, Meta, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the license found in the LICENSE file in
 * the root directory of this source tree.
 */
use std::ffi::CStr;
use std::os::raw::c_char;
use std::os::raw::c_int;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::thread;
use std::time::Duration;

use libblaster::blast_worker;
use libblaster::WorkerConfig;
use libc::in6_addr;
use netconsd_module::MsgBuf;
use netconsd_module::NcrxMsg;
use nix::sys::signal;
use nix::unistd::Pid;
use once_cell::sync::Lazy;

const MESSAGES_TO_SEND_PER_THREAD: usize = 100;
const SENDER_THREADS_COUNT: usize = 10;
const TOT_MESSAGES_TO_SEND: usize = SENDER_THREADS_COUNT * MESSAGES_TO_SEND_PER_THREAD;
static TERMINATED: AtomicBool = AtomicBool::new(false);
static INVOCATIONS_COUNT: AtomicUsize = AtomicUsize::new(0);
const TIMEOUT_DURATION: Duration = Duration::from_secs(5);
const BLASTER_SLEEP_DURATION: Duration = Duration::from_nanos(10);
const SENDR_ADDR_RND_BYTES: usize = 0;

#[derive(Clone, Debug)]
struct ReceivedMessage {
    src: [u8; 16],
    msg: String,
}

static RECEIVED_MESSAGES: Lazy<Mutex<Vec<ReceivedMessage>>> = Lazy::new(|| Mutex::new(Vec::new()));

fn result_str(result: bool) -> &'static str {
    if result { "-> OK" } else { "-> FAILURE" }
}

fn get_received_messages() -> MutexGuard<'static, Vec<ReceivedMessage>> {
    RECEIVED_MESSAGES
        .lock()
        .expect("Could not lock RECEIVED_MESSAGES")
}

fn verify_invocations_count() -> bool {
    let invocations_count = INVOCATIONS_COUNT.load(Ordering::SeqCst);
    let passed = invocations_count == TOT_MESSAGES_TO_SEND;
    print!("{} invocations ", invocations_count);
    if !passed {
        print!("but should have been {}", TOT_MESSAGES_TO_SEND);
    }
    println!("{}", result_str(passed));
    passed
}

fn verify_received_messages_texts() -> bool {
    let mut passed = true;
    for message in get_received_messages().iter() {
        if !message.msg.starts_with("hello packet") {
            println!("unexpected message: {}", message.msg);
            passed = false;
        }
    }
    println!("messages texts {}", result_str(passed));
    passed
}

fn verify_received_messages_count() -> bool {
    let messages_count = get_received_messages().len();
    print!("received {} ncrx messages ", messages_count);

    let passed = messages_count == TOT_MESSAGES_TO_SEND;
    if !passed {
        print!("but should have been {} ", TOT_MESSAGES_TO_SEND);
    }
    println!("{}", result_str(passed));
    passed
}

fn check_src_address(addr: &[u8; 16]) -> Option<usize> {
    if addr[0..15].iter().any(|x| *x != 0) {
        return None;
    }
    Some(addr[15].into())
}

fn verify_received_messages_addresses() -> bool {
    let mut passed = true;
    let mut seen_ids = vec![0; SENDER_THREADS_COUNT];

    for msg in get_received_messages().iter() {
        match check_src_address(&msg.src) {
            Some(id) => seen_ids[id] += 1,
            None => {
                println!("Bad src address: {:x?}", msg.src);
                passed = false;
            }
        }
    }
    for (i, seen_id) in seen_ids.into_iter().enumerate() {
        if seen_id != MESSAGES_TO_SEND_PER_THREAD {
            println!(
                "got {} messages from thread {}, should have been {}",
                seen_id, i, MESSAGES_TO_SEND_PER_THREAD
            );
            passed = false;
        }
    }
    println!("src addresses {}", result_str(passed));
    passed
}

fn end_self_test() {
    if !TERMINATED.fetch_or(true, Ordering::SeqCst) {
        signal::kill(Pid::this(), signal::SIGTERM).expect("Could not send SIGTERM");
    }
}

fn process_received_message(addr_ptr: *const in6_addr, msg_ptr: *const NcrxMsg) {
    if let Some(addr) = unsafe { addr_ptr.as_ref() } {
        if let Some(msg) = unsafe { msg_ptr.as_ref() } {
            let text = match unsafe { CStr::from_ptr(msg.text as *const c_char) }.to_str() {
                Ok(x) => x,
                Err(_) => {
                    println!("Could not convert NcrxMsg msg to string");
                    ""
                }
            };
            let received_message = ReceivedMessage {
                src: addr.s6_addr.clone(),
                msg: text.to_owned(),
            };
            get_received_messages().push(received_message);
        }
    }
}

fn spawn_blast_workers() {
    for i in 0..SENDER_THREADS_COUNT {
        thread::spawn(move || {
            let config = WorkerConfig {
                id: i as u8,
                packets_count: MESSAGES_TO_SEND_PER_THREAD as u64,
                dst_port: 6666,
                sleep_duration: Some(BLASTER_SLEEP_DURATION),
                extended_msg: true,
                sender_addr_rnd_bytes: SENDR_ADDR_RND_BYTES,
            };
            thread::sleep(Duration::from_millis(100));
            blast_worker(config);
        });
    }
}

fn start_test_timeout() {
    thread::spawn(|| {
        thread::sleep(TIMEOUT_DURATION);
        end_self_test();
    });
}

#[no_mangle]
pub extern "C" fn netconsd_output_init(nr_workers: c_int) -> c_int {
    println!("Selftest module init! {} workers", nr_workers);
    spawn_blast_workers();
    start_test_timeout();
    0
}

#[no_mangle]
pub extern "C" fn netconsd_output_handler(
    _t: c_int,
    in6_addr: *const in6_addr,
    _buf: *const MsgBuf,
    msg: *const NcrxMsg,
) -> i32 {
    process_received_message(in6_addr, msg);
    if INVOCATIONS_COUNT.fetch_add(1, Ordering::SeqCst) >= TOT_MESSAGES_TO_SEND - 1 {
        end_self_test();
    }
    0
}

#[no_mangle]
pub extern "C" fn netconsd_output_exit() {
    println!("\nSELF TEST RESULT");
    let mut passed = verify_invocations_count();
    passed &= verify_received_messages_count();
    passed &= verify_received_messages_texts();
    passed &= verify_received_messages_addresses();
    println!();
    if !passed {
        std::process::exit(1);
    }
}
