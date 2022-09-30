# disasem

`disasem` is a simple CLI application for disassembling raw x86 machine code from an input file to stdout for a small subset of popular x86 instructions.

## Building/Installation

The recommended way of building `disasem` is to use the `cargo` tool provided 
by Rust.

To build the binary, `cd` into the root directory of the repo and then run

```
cargo build --release
```

at which point the binary can be found in `repo\target\release\disasem.exe`

---

Alternatively, you can use `cargo` to install `disasem` into your set
of `cargo`-managed binaries

```
cargo install --git https://github.com/galadiriancoding/disasem
```

or after cloning the repo

```
cargo install --path \path\to\repo
```


## Usage

```
disasem [OPTIONS] -i <INPUT>

Options:
  -i <INPUT>      Path to binary file to be disassembled
  -l, --linear    Use Linear Sweep (Recursive Descent is default)
  -h, --help      Print help information
  -V, --version   Print version information
```

## Algorithms

`disasem` supports two algorithms for parsing the binary file
- Simplified Recursive Descent (Default)
- Linear Sweep

SRD will follow the code path as best as can be determined at compile time.
As such, potentially unreachable code will be displayed as a set of `db`s. Linear Sweep will parse the file from begining to end and may attempt to parse
non-instructions (such as defined text) as potential instructions. If the
output using one algorithm does not make sense, try switching to the other one. 