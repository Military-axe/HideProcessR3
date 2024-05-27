mod inject;
mod installsrv;
mod process;

use crate::inject::{Inject, WindowsHook};
use crate::installsrv::svc_install;
use crate::process::{FakeProcess, ObjProcess, Process};
use anyhow::Result;
use clap::{command, Parser, Subcommand};
use log::{debug, info, warn};
use std::env::set_var;

#[derive(Parser)]
#[command(author = "mi1itray.axe", version = "0.1", about = "A simple tool to hide processes in R3", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    #[arg(short, long)]
    debug: bool,
}

#[derive(Subcommand)]
enum Command {
    /// copy some strings of process `obj` to process `fake`.
    CopyStr {
        #[arg(short, long, value_name = "PID")]
        obj: u32,

        #[arg(short, long, value_name = "PID")]
        fake: u32,
    },

    /// Inject dll to the process
    InjectDll {
        /// dll file path
        #[arg(short, long, value_name = "DLL PATH")]
        dll_path: String,

        /// process id which you want to inject it. pid or name just need one
        #[arg(short, long, value_name = "PROCESS PID")]
        pid: Option<u32>,

        /// process name which you want to inject it. pid or name just need one
        #[arg(short, long, value_name = "PROCESS NAME")]
        name: Option<String>,
    },

    /// Use SetWindowsHookEx to global hook
    WindowsHook {
        /// dll file path
        #[arg(short, long, value_name = "DLL PATH")]
        dll_path: String,
    },

    /// Install Services
    Services {
        /// sys file path
        #[arg(short, long, value_name = "SYS PATH")]
        sys: String,

        /// service name
        #[arg(short, long, value_name = "SERVICE NAME")]
        name: String,
    },
}

fn copy_str_2_process(obj: u32, fake: u32) {
    let obj_process = ObjProcess::from(obj);
    let mut fake_process = FakeProcess::from(fake);
    let command_line = obj_process
        .get_command_line_2_vec()
        .expect("[! Hide Process R3] Get Command Line failed.");
    let image_name = obj_process
        .get_image_name_2_vec()
        .expect("[! Hide Process R3] Get Image Name failed.");
    debug!("{:#?}", Process::pwstr_to_string(&command_line));
    debug!("{:#?}", Process::pwstr_to_string(&image_name));

    fake_process
        .set_command_line(command_line)
        .expect("[! Hide Process R3] Set Command Line failed.");
    fake_process
        .set_image_name(image_name)
        .expect("[! Hide Process R3] Set Image Name failed.")
}

fn inject_dll_2_process(dll_path: &String, pid: &Option<u32>, name: Option<&String>) -> Result<()> {
    if pid.is_none() && name.is_none() {
        warn!("[! Hide Process R3] pid and name must have at least one parameter.");
        return Ok(());
    }

    if pid.is_some() {
        Inject::inject_dll_by_pid(dll_path, pid.unwrap())
    } else {
        Inject::inject_dll_by_name(dll_path, name.unwrap().as_str())
    }

    info!("Inject dll success");

    Ok(())
}

fn set_windows_hook(dll_path: *const u8) {
    WindowsHook::hook(dll_path).expect("[! Hide Process R3] SetWindowsHookEx failed.");
}

fn install_srv(sys: &str, name: &str) {
    svc_install(sys, name).expect("Services install failed.");
}

fn main() {
    let args: Cli = Cli::parse();

    // Set Debug logger;
    if args.debug {
        set_var("RUST_LOG", "debug")
    } else {
        set_var("RUST_LOG", "info")
    }

    env_logger::init();

    match &args.command {
        Some(Command::CopyStr { obj, fake }) => copy_str_2_process(*obj, *fake),
        Some(Command::InjectDll {
            dll_path,
            pid,
            name,
        }) => inject_dll_2_process(dll_path, pid, name.as_ref()).unwrap(),
        Some(Command::WindowsHook { dll_path }) => set_windows_hook(dll_path.as_ptr()),
        Some(Command::Services { sys, name }) => install_srv(sys, name),
        _ => {}
    }
}
