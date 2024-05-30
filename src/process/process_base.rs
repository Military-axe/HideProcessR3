use std::{ffi::c_void, mem::size_of};

use anyhow::Result;

use log::{debug, warn};
use windows::{
    core::PWSTR,
    Wdk::System::Threading::{NtQueryInformationProcess, ProcessBasicInformation},
    Win32::{
        Foundation::{CloseHandle, HANDLE},
        System::{
            Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory},
            Threading::{
                OpenProcess, PEB, PROCESS_BASIC_INFORMATION, PROCESS_QUERY_INFORMATION,
                PROCESS_VM_READ, RTL_USER_PROCESS_PARAMETERS,
            },
        },
    },
};

#[repr(C)]
#[derive(Debug, Clone)]
pub struct Process {
    pub pid: u32,
    pub handle: HANDLE,
    pub pbi: PROCESS_BASIC_INFORMATION,
    pub peb: PEB,
    pub process_parameters: RTL_USER_PROCESS_PARAMETERS,
}

impl Process {
    fn get_pbi_by_pid(pid: u32) -> Result<PROCESS_BASIC_INFORMATION> {
        // 使用OpenProcess函数获取指定进程的句柄。
        // 此句柄用于后续的信息查询和读取操作。
        let handle = unsafe {
            OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)?
            // 如果打开进程失败，则提前返回错误。
        };

        // 初始化PROCESS_BASIC_INFORMATION结构体，用于接收进程基本信息。
        let mut pbi = PROCESS_BASIC_INFORMATION {
            ..Default::default()
        };

        // 获取PROCESS_BASIC_INFORMATION的指针，用于传递给NtQueryInformationProcess。
        let ppbi: *mut PROCESS_BASIC_INFORMATION = &mut pbi as *mut _;

        // 初始化返回长度变量，用于接收实际读取的数据长度。
        let mut return_length = 0u32;

        // 调用NtQueryInformationProcess获取指定进程的基本信息。
        // 使用unsafe块是因为这个函数直接与操作系统交互，并且需要处理裸指针。
        unsafe {
            let _ = NtQueryInformationProcess(
                handle,
                ProcessBasicInformation,
                ppbi as *mut c_void,
                size_of::<PROCESS_BASIC_INFORMATION>() as u32,
                &mut return_length,
            );
        };

        unsafe { CloseHandle(handle)? };

        // 如果成功获取了进程基本信息，则返回PEB的地址。
        Ok(pbi)
    }

    fn get_peb(&self) -> Result<PEB> {
        let mut peb = PEB::default();
        unsafe {
            ReadProcessMemory(
                *&self.handle,
                self.pbi.PebBaseAddress as *const c_void,
                &mut peb as *mut _ as *mut c_void,
                size_of::<PEB>(),
                None,
            )?;
        }
        Ok(peb)
    }

    fn get_process_parameters(&self) -> Result<RTL_USER_PROCESS_PARAMETERS> {
        let mut parm: RTL_USER_PROCESS_PARAMETERS = RTL_USER_PROCESS_PARAMETERS::default();
        unsafe {
            ReadProcessMemory(
                *&self.handle,
                self.peb.ProcessParameters as *const c_void,
                &mut parm as *mut _ as *mut c_void,
                size_of::<RTL_USER_PROCESS_PARAMETERS>(),
                None,
            )?;
        }
        Ok(parm)
    }

    /// 获取进程中指定地址的pwstr内容, 获取成功返回Ok(Vec<c_void>)，失败返回Err
    /// 
    /// # 参数
    /// 
    /// * `self` - 实例句柄
    /// * `address` - 需要获取内容的进程内地址
    /// * `length` - 需要读取内存的长度
    /// 
    /// # 返回
    /// 
    /// 如果成功，返回Ok(Vec<c_void>)，Vec中就是读取的内容
    /// 如果失败, 返回Err()
    pub fn get_pwstr(&self, address: *mut u16, length: usize) -> Result<Vec<c_void>> {
        let mut wstr = Vec::with_capacity(length);
        unsafe {
            ReadProcessMemory(
                *&self.handle,
                address as *const c_void,
                wstr.as_mut_ptr(),
                size_of::<RTL_USER_PROCESS_PARAMETERS>(),
                None,
            ).map_or_else(
                |x| warn!("Read data to process {} failed: {:?}", self.pid, x),
                |_| debug!("Read data to process {} success", self.pid),
            );
        }

        Ok(wstr)
    }

    /// 将指定的pwstr内容写入到进程中，写入成功返回Ok(())，写入失败返回报错
    /// 
    /// # 参数
    /// 
    /// * `self` - 实例句柄
    /// * `address` - 需要写入的进程内地址
    /// * `data` - 需要写入的内容
    /// 
    /// # 返回值
    /// 
    /// 写入成功返回Ok(())，写入失败返回Err()
    pub fn set_pwstr(&mut self, address: *mut u16, data: Vec<c_void>) -> Result<()> {
        Ok(unsafe {
            WriteProcessMemory(
                self.handle,
                address as *const c_void,
                data.as_ptr(),
                data.len(),
                None,
            )
            .map_or_else(
                |x| warn!("Write data to process {} failed: {:?}", self.pid, x),
                |_| debug!("Write data to process {} success", self.pid),
            );
        })
    }

    /// 将pwstr字符串转换成String类型, 传入指向pwstr的指针,返回String
    /// 
    /// # 参数
    /// 
    /// * `data` - 指向pwstr类型的指针
    /// 
    /// # 返回值
    /// 
    /// 如果成功返回有内容的String, 失败则返回空字符串
    pub fn pwstr_to_string(data: &Vec<c_void>) -> String {
        unsafe {
            match PWSTR::from_raw(data.as_ptr() as *mut u16).to_string() {
                Ok(v) => v,
                Err(e) => {
                    warn!("Convert pwstr to string failed: {:?}.", e);
                    return "".to_string();
                }
            }
        }
    }
}

impl From<u32> for Process {
    fn from(value: u32) -> Self {
        let ppbi = Process::get_pbi_by_pid(value).expect(&format!(
            "[! Hide Process R3] get process: {} failed.",
            value
        ));
        let handle: windows::Win32::Foundation::HANDLE = unsafe {
            OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, value)
                .expect("[! Hide Process R3] OpenProcess failed")
        };
        let mut p = Process {
            pid: value,
            pbi: ppbi,
            handle,
            peb: PEB::default(),
            process_parameters: RTL_USER_PROCESS_PARAMETERS::default(),
        };
        p.peb = p.get_peb().expect("[! Hide Process R3] Get Peb failed.");
        p.process_parameters = p
            .get_process_parameters()
            .expect("[! Hide Process R3] Get Process Paramemters failed.");
        p
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle).expect("[! Hide Process R3] CloseHandle error.");
        }
    }
}
