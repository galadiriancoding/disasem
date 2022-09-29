# disasem

`disasem` is a simple CLI application for disassembling raw machine code from 
an input file to stdout.


## Usage

```
disasem.exe [OPTIONS] -i <INPUT>

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
outout using one algorithm does not make sense, try switching to the other one. 