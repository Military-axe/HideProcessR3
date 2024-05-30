mod process_base;

use crate::utils::ctl_code;
use log::{debug, warn};
pub use process_base::Process;
use std::{mem::size_of, os::raw::c_void};
use windows::{
    core::s,
    Win32::{
        Foundation::{GetLastError, GENERIC_READ, GENERIC_WRITE},
        Storage::FileSystem::{CreateFileA, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE, OPEN_EXISTING},
        System::{
            Ioctl::{FILE_ANY_ACCESS, FILE_DEVICE_UNKNOWN, METHOD_BUFFERED},
            IO::DeviceIoControl,
        },
    },
};

use anyhow::{Error, Result};

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
            self.process.process_parameters.CommandLine.Buffer.as_ptr(),
            data,
        )
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct SetImageName {
    pub name: [u8; 250],
    pub pid: u64,
}

impl SetImageName {
    pub fn new(image_name: String, pid: u64) -> Self {
        let mut name_array = [0; 250];
        let byte_slice = image_name.as_bytes();

        // 截断字符串，如果它太长
        let len = byte_slice.len().min(250);
        name_array[..len].copy_from_slice(&byte_slice[..len]);

        SetImageName {
            name: name_array,
            pid,
        }
    }

    pub fn set(data: SetImageName) -> Result<()> {
        let hdevice = unsafe {
            CreateFileA(
                s!("\\\\.\\HideProcessR0"),
                (GENERIC_READ | GENERIC_WRITE).0,
                FILE_SHARE_NONE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )?
        };
        debug!("Open Device success");

        if hdevice.is_invalid() {
            warn!("Open Device failed {:?}.", unsafe { GetLastError() });
            return Err(Error::msg("Open Device failed."));
        }

        let input_buffer = &data as *const _ as *const c_void;
        unsafe {
            DeviceIoControl(
                hdevice,
                ctl_code(
                    FILE_DEVICE_UNKNOWN,
                    0x6667,
                    METHOD_BUFFERED,
                    FILE_ANY_ACCESS,
                ),
                Some(input_buffer),
                size_of::<SetImageName>() as u32,
                None,
                0,
                None,
                None,
            )?
        };
        debug!("Send iamge data to driver success");

        Ok(())
    }
}
