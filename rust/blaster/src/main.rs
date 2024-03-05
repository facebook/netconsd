/*
 * Simple utility that sends netconsole messages to localhost.
 *
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
use std::thread;
use std::time::Duration;
use std::time::Instant;

use clap::Parser;
use libblaster::blast_worker;
use libblaster::WorkerConfig;

#[derive(Parser)]
struct CliArgs {
    #[clap(short, long, default_value_t = 1)]
    threads: u16,

    #[clap(short, long, default_value_t = std::u64::MAX)]
    packets: u64,

    #[clap(short = 'u', long, default_value_t = 6666u16)]
    port: u16,

    #[clap(short, long)]
    sleep_time_nano: Option<u64>,

    #[clap(short = 'r', long, default_value_t = 0)]
    sender_ip_rnd_bytes: usize,
}

fn format_duration(duration: &Duration) -> String {
    let mins = duration.as_secs() / 60;
    let secs = duration.as_secs() % 60;
    let ms = duration.as_millis() % 1000;
    format!("{:02}:{:02}.{:03}", mins, secs, ms)
}

fn main() {
    let args = CliArgs::parse();

    let mut workers: Vec<thread::JoinHandle<()>> = Vec::new();
    let sleep_duration = args.sleep_time_nano.map(Duration::from_nanos);
    let start_time = Instant::now();
    for i in 0..args.threads {
        let config = WorkerConfig {
            id: i as u8,
            packets_count: args.packets,
            dst_port: args.port,
            sleep_duration,
            extended_msg: true,
            sender_addr_rnd_bytes: args.sender_ip_rnd_bytes,
        };
        workers.push(thread::spawn(move || {
            blast_worker(config);
        }))
    }

    for w in workers {
        let _ = w.join();
    }
    let packets_sent = args.packets * args.threads as u64;
    println!(
        "Sent {} packets with {} threads in {}",
        packets_sent,
        args.threads,
        format_duration(&start_time.elapsed())
    );
}
