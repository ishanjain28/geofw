#!/bin/bash

set -e
set -o pipefail

RUST_LOG=info cargo run --release

# RUST_LOG=info cargo run --config 'target."cfg(all())".runner="sudo -E"'
