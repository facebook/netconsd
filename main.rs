/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the license found in the LICENSE file in
 * the root directory of this source tree.
 */

use anyhow::bail;
use anyhow::Error;
use clap::Parser;
use libc::in6_addr;
use libc::sigaction;
use libc::sigaddset;
use libc::sigemptyset;
use libc::sigprocmask;
use libc::sigset_t;
use libc::sigwait;
use libc::sockaddr_in6;
use libc::strsignal;
use libc::AF_INET6;
use libc::SA_NODEFER;
use libc::SIGHUP;
use libc::SIGINT;
use libc::SIGPIPE;
use libc::SIGTERM;
use libc::SIGUSR1;
use libc::SIG_BLOCK;
use libc::SIG_IGN;

extern "C" {
    fn register_output_module(path: *const c_char, nr_workers: c_int);
    fn create_threads(params: &netconsd_params) -> *const c_void;
    fn destroy_threads(ctl: *const c_void);
    fn destroy_output_modules();
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct netconsd_params {
    pub nr_workers: c_int,
    pub nr_listeners: c_int,
    pub mmsg_batch: c_int,
    pub gc_int_ms: c_uint,
    pub gc_age_ms: c_uint,
    pub listen_addr: sockaddr_in6,
}

#[derive(Debug)]
struct GcParams {
    age: u32,
    interval: u32,
}

impl FromStr for GcParams {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let split: Vec<&str> = s.split("/").collect();
        if split.len() != 2 {
            bail!("Wrong GC format, it should be <age>/<interval>");
        }
        let age = match split[0].parse::<u32>() {
            Ok(x) => x,
            Err(_) => bail!("Could not parse age, it should be an unsigned 32bits integer."),
        };

        let interval = match split[1].parse::<u32>() {
            Ok(x) => x,
            Err(_) => bail!("Could not parse interval, it should be an unsigned 32bits integer."),
        };

        if age < interval {
            bail!("GC age should >= GC interval");
        }
        Ok(GcParams { age, interval })
    }
}

#[derive(Parser, Debug)]
struct CliArgs {
    /// Number of worker threads
    #[clap(short, long)]
    workers: Option<u16>,

    /// Number of listener threads
    #[clap(short, long)]
    listeners: Option<u16>,

    /// Message batch size
    #[clap(short, long)]
    batch: Option<u16>,

    /// UDP listen IPV6 address
    #[clap(short, long)]
    address: Option<Ipv6Addr>,

    /// UDP listen port
    #[clap(short = 'u', long)]
    port: Option<u16>,

    /// Garbage collector interval/age in ms
    #[clap(short, long)]
    gc: Option<GcParams>,

    /// Dynamic modules to load
    #[clap()]
    modules: Vec<String>,
}

/*
 * This exists to kick the blocking recvmmsg() call in the listener threads, so
 * they get -EINTR, notice the stop flag, and terminate.
 *
 * See also: stop_and_wait_for_listeners() in threads.c
 */
fn interrupter_handler(_sig: c_int) {
    return;
}

unsafe fn init_sighandlers() {
    let ignorer: sigaction = sigaction {
        sa_sigaction: SIG_IGN,
        sa_mask: MaybeUninit::zeroed().assume_init(),
        sa_flags: 0,
        sa_restorer: None,
    };
    let interrupter = sigaction {
        sa_sigaction: interrupter_handler as usize,
        sa_mask: MaybeUninit::zeroed().assume_init(),
        sa_flags: SA_NODEFER,
        sa_restorer: None,
    };

    sigaction(SIGUSR1, &interrupter, std::ptr::null_mut::<sigaction>());
    sigaction(SIGPIPE, &ignorer, std::ptr::null_mut::<sigaction>());
}

/*
 * Initialize the set of signals for which we try to terminate gracefully.
 */
unsafe fn init_sigset(set: &mut sigset_t) {
    sigemptyset(set);
    sigaddset(set, SIGTERM);
    sigaddset(set, SIGINT);
    sigaddset(set, SIGHUP);
}

fn get_netconsd_params(cli_args: &CliArgs) -> netconsd_params {
    netconsd_params {
        nr_workers: cli_args.workers.unwrap_or(2).into(),
        nr_listeners: cli_args.listeners.unwrap_or(1).into(),
        mmsg_batch: cli_args.batch.unwrap_or(512).into(),
        gc_int_ms: cli_args.gc.as_ref().map(|gc| gc.interval).unwrap_or(0),
        gc_age_ms: cli_args.gc.as_ref().map(|gc| gc.age).unwrap_or(0),
        listen_addr: sockaddr_in6 {
            sin6_family: AF_INET6 as u16,
            sin6_port: cli_args.port.unwrap_or(1514).to_be(),
            sin6_flowinfo: 0,
            sin6_addr: in6_addr {
                s6_addr: cli_args
                    .address
                    .map(|x| x.octets().clone())
                    .unwrap_or_else(|| [0u8; 16]),
            },
            sin6_scope_id: 0,
        },
    }
}

fn main() {
    let cli_args = CliArgs::parse();
    let params = get_netconsd_params(&cli_args);

    unsafe {
        for module in cli_args.modules.iter() {
            let path = CString::new(module.as_str()).unwrap();
            register_output_module(path.as_ptr(), params.nr_workers);
        }

        init_sighandlers();
        let mut set: sigset_t = MaybeUninit::zeroed().assume_init();
        init_sigset(&mut set);
        sigprocmask(SIG_BLOCK, &set, std::ptr::null_mut::<sigset_t>());

        let mut num: c_int = 0;
        let ctl = create_threads(&params);
        sigwait(&set, &mut num);

        println!(
            "Signal: '{:?}', terminating",
            CStr::from_ptr(strsignal(num))
        );

        destroy_threads(ctl);
        destroy_output_modules();
    };
}
