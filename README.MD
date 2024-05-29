# Hide Process R3

A simple tool to hide processes in R3.

- Inject Dll to process
- Install Service
- Hook software use ZwQueryInformation(TaskMgr/ProcessHack/Systeminfo/...) to hide process
- Call [HideProcessR0](https://github.com/Military-axe/HideProcessR0) to hide process by break chains in Ring0

## Usage

```sh
❯ .\hide_process_r3.exe -h
A simple tool to hide processes in R3

Usage: hide_process_r3.exe [OPTIONS] [COMMAND]

Commands:
  copy-str      copy some strings of process `obj` to process `fake`
  inject-dll    Inject dll to the process
  windows-hook  Use SetWindowsHookEx to global hook
  services      Install Services
  chain-break   Break the chain in Ring0 to hide process
  help          Print this message or the help of the given subcommand(s)

Options:
  -d, --debug
  -h, --help     Print help
  -V, --version  Print version
```

### copy-str

copy object process's command line and image name to other process PEB which you want to hide

```sh
❯ .\hide_process_r3.exe copy-str -h
copy some strings of process `obj` to process `fake`

Usage: hide_process_r3.exe copy-str --obj <PID> --fake <PID>

Options:
  -o, --obj <PID>
  -f, --fake <PID>
  -h, --help        Print help
```

### inject-dll

Inject dll into the specified process

```sh
❯ .\hide_process_r3.exe inject-dll -h
Inject dll to the process

Usage: hide_process_r3.exe inject-dll [OPTIONS] --dll-path <DLL PATH>

Options:
  -d, --dll-path <DLL PATH>  dll file path
  -p, --pid <PROCESS PID>    process id which you want to inject it. pid or name just need one
  -n, --name <PROCESS NAME>  process name which you want to inject it. pid or name just need one
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
Use SetWindowsHookEx to global hook

Usage: hide_process_r3.exe windows-hook --dll-path <DLL PATH>

Options:
  -d, --dll-path <DLL PATH>  dll file path
  -h, --help                 Print help
```

### install services

```sh
❯ .\hide_process_r3.exe services -h
Install Services

Usage: hide_process_r3.exe services --sys <SYS PATH> --name <SERVICE NAME>

Options:
  -s, --sys <SYS PATH>       sys file path
  -n, --name <SERVICE NAME>  service name
  -h, --help                 Print help
```

### chain break
```sh
❯ .\hide_process_r3.exe chain-break -h
Break the chain in Ring0 to hide process

Usage: hide_process_r3.exe chain-break --pid <PID>

Options:
  -p, --pid <PID>  The process pid you want tio hide
  -h, --help       Print help
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

build HideProcessR0.sys

HideProcessR0 project in [here](https://github.com/Military-axe/HideProcessR0)

- Build it by msvc then get the `HideProcessR0.sys`
- Install HideProcessR0.sys as Service

```sh
  ./hide_process_r3.exe services -s ./HideProcessR0.sys -n HideProcess
```

- Start Services

```sh
net start HideProcessR0
```

Then you could use `hide_process.exe chain-break <PID>`

# TODO

- [ ] copy-str 完善
- [ ] setwindowshook 无效问题解决
- [ ] hook explorer