mod process_base;

pub use process_base::Process;
use std::os::raw::c_void;

use anyhow::Result;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct ObjProcess {
    pub process: Process,
}

impl From<u32> for ObjProcess {
    fn from(value: u32) -> Self {
        ObjProcess {
            process: Process::from(value),
        }
    }
}

impl ObjProcess {
    pub fn get_command_line_2_vec(&self) -> Result<Vec<c_void>> {
        let p = self.process.process_parameters;
        self.process
            .get_pwstr(p.CommandLine.Buffer.as_ptr(), p.CommandLine.Length as usize)
    }

    pub fn get_image_name_2_vec(&self) -> Result<Vec<c_void>> {
        let p = self.process.process_parameters;
        self.process.get_pwstr(
            p.ImagePathName.Buffer.as_ptr(),
            p.ImagePathName.Length as usize,
        )
    }
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FakeProcess {
    pub process: Process,
}

impl From<u32> for FakeProcess {
    fn from(value: u32) -> Self {
        FakeProcess {
            process: Process::from(value),
        }
    }
}

impl FakeProcess {
    pub fn set_image_name(&mut self, data: Vec<c_void>) -> Result<()> {
        self.process.set_pwstr(
            self.process
                .process_parameters
                .ImagePathName
                .Buffer
                .as_ptr(),
            data,
        )
    }

    pub fn set_command_line(&mut self, data: Vec<c_void>) -> Result<()> {
        self.process.set_pwstr(
            self.process
                .process_parameters
                .CommandLine
                .Buffer
                .as_ptr(),
            data,
        )
    }
}
