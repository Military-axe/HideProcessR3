# Hide Process R3

A simple tool to hide processes in R3

## Usage

```sh
❯ .\hide_process_r3.exe -h
A simple tool to hide processes in R3

Usage: hide_process_r3.exe [COMMAND]

Commands:
  copy-str
  inject-dll
  windows-hook
  help          Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### copy-str

copy object process's command line and image name to other process PEB which you want to hide

```sh
❯ .\hide_process_r3.exe copy-str -h
Usage: hide_process_r3.exe copy-str --obj <OBJ> --fake <FAKE>

Options:
  -o, --obj <OBJ>
  -f, --fake <FAKE>
  -h, --help         Print help
```

### inject-dll

Inject dll into the specified process

```sh
❯ .\hide_process_r3.exe inject-dll -h
Usage: hide_process_r3.exe inject-dll [OPTIONS] --dll-path <DLL_PATH>

Options:
  -d, --dll-path <DLL_PATH>
  -p, --pid <PID>
  -n, --name <NAME>
  -h, --help                 Print help
```

**example**

```sh
❯ .\hide_process_r3.exe inject-dll -d ./hook.dll -n Taskmgr.exe
```

### windows hook

Use SetWindowsHookExA to globa hook. This feature is not stable

```sh
❯ .\hide_process_r3.exe windows-hook -h
Usage: hide_process_r3.exe windows-hook --dll-path <DLL_PATH>

Options:
  -d, --dll-path <DLL_PATH>
  -h, --help                 Print help
```

## Build

cargo version my self

```sh
❯ cargo --version
cargo 1.80.0-nightly (0de7f2ec6 2024-05-17)
```

build hide_process_r3.exe

```sh
cargo build
```

build hook.dll

- change the process id you want to hide in `hook/src/lib.rs` file.

```rust
// 需要隐藏的进程id
const HIDE_PID: i32 = 32652;
```

- build hook.dll

```sh
cargo build -p hook
```