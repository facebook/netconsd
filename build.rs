/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::process::Command;

fn main() {
    Command::new("make")
        .arg("clean")
        .arg("rlib")
        .status()
        .expect("make build failed");

    println!("cargo:rustc-link-search=native=./");
    println!("cargo:rustc-link-lib=static=netconsd");
}
