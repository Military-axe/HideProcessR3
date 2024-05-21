mod process;


use crate::process::{FakeProcess, ObjProcess, Process};
use clap::{command, Parser, Subcommand};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    copy_str: Option<Command>
}

#[derive(Subcommand)]
enum Command {
    // copy some strings of process `obj` to process `fake`.
    CopyStr{
        #[arg(short, long)]
        obj: u32,

        #[arg(short, long)]
        fake: u32,
    }
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
    println!("{:#?}", Process::pwstr_to_string(&command_line));
    println!("{:#?}", Process::pwstr_to_string(&image_name));

    fake_process.set_command_line(command_line)
        .expect("[! Hide Process R3] Set Command Line failed.");
    fake_process.set_image_name(image_name)
        .expect("[! Hide Process R3] Set Image Name failed.")
}

fn main() {
    let args: Cli = Cli::parse();
    match &args.copy_str {
        Some(Command::CopyStr { obj, fake }) => {
            copy_str_2_process(*obj, *fake)
        },
        _ => {}
    }
}
