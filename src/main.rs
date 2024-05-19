mod process;

use crate::process::{FakeProcess, ObjProcess, Process};
use clap::{command, Parser};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(short, long)]
    obj: u32,

    #[arg(short, long)]
    fake: u32,
}

fn main() {
    let args: Cli = Cli::parse();
    let obj = ObjProcess::from(args.obj);
    let mut fake = FakeProcess::from(args.fake);
    println!("[+] obj process: {:?}", obj);
    println!("[+] fake process: {:?}", fake);

    let command_line = obj
        .get_command_line_2_vec()
        .expect("[! Hide Process R3] Get Command Line failed.");
    let image_name = obj
        .get_image_name_2_vec()
        .expect("[! Hide Process R3] Get Image Name failed.");
    println!("{:#?}", Process::pwstr_to_string(&command_line));
    println!("{:#?}", Process::pwstr_to_string(&image_name));

    fake.set_command_line(command_line)
        .expect("[! Hide Process R3] Set Command Line failed.");
    fake.set_image_name(image_name)
        .expect("[! Hide Process R3] Set Image Name failed.");
}
