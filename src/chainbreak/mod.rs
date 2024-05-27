use std::{ffi::c_void, mem::size_of};

use anyhow::{Error, Result};
use log::{debug, warn};
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

#[derive(Debug)]
pub struct BreakChain {}

impl BreakChain {
    pub fn hide_by_pid(pid: u32) -> Result<()> {
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

        let input_buffer = &pid as *const u32 as *const c_void;
        unsafe {
            DeviceIoControl(
                hdevice,
                ctl_code(
                    FILE_DEVICE_UNKNOWN,
                    0x6666,
                    METHOD_BUFFERED,
                    FILE_ANY_ACCESS,
                ),
                Some(input_buffer),
                size_of::<u32>() as u32,
                None,
                0,
                None,
                None,
            )?
        };
        debug!("Send pid to driver success");

        Ok(())
    }
}

fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    ((device_type) << 16) | ((access) << 14) | ((function) << 2) | (method)
}
