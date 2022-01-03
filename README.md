# rdelf

A CLI application for parsing ELF headers written in Go.

## Install

```bash
go install github.com/kinpoko/rdelf@latest
```

## Usage

```bash
rdelf -h
A CLI application for parsing ELF headers.

Usage:
  rdelf [file name] [flags]

Flags:
      --hed     display elf header
  -h, --help    help for rdelf
  -l, --progh   display program headers
  -S, --segh    display section headers
```
