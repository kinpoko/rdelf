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

```bash
rdelf sample/a.out --hed
Magic: 7f 45 4c 46 2 1 1 0 0 0 0 0 0 0 0 0
Class: ELF64
Data: little endian
Version: 1
Type: A shared object
Machine: AMD x86-64
EntryPoint: 0x1060
Start of Program headers: 64 (bytes)
Start of Section headers: 14712 (bytes)
Number of Program headers: 13
Number of Section headers: 31
Section header string table index: 30

```
