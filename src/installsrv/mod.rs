use anyhow::{Error, Result};
use windows::core::PCSTR;
use windows::Win32::System::Services::{
    CloseServiceHandle, SERVICE_ALL_ACCESS, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, SERVICE_WIN32_OWN_PROCESS
};
use windows::Win32::{
    Foundation::GetLastError,
    Security::SC_HANDLE,
    System::
        Services::{CreateServiceA, OpenSCManagerA, SC_MANAGER_ALL_ACCESS}
    ,
};
use log::{warn, info};

/// 安装一个Windows服务。
///
/// 这个函数尝试在Windows服务控制管理器(SCM)中创建一个新的服务项，该服务项将运行指定的驱动程序。
///
/// # 参数
///
/// * `sys_path` - 一个字符串，表示驱动程序的路径。
/// * `drive_name` - 一个字符串，表示服务的显示名称和内部名称。
///
/// # 返回值
///
/// 如果服务安装成功，则返回`Ok(())`；如果安装过程中发生错误，则返回`Err(Error)`。
///
/// # 错误处理
///
/// 函数中会检查`OpenSCManagerA`和`CreateServiceA`的返回值。如果这些函数返回`NULL`或无效句柄，函数将打印一条错误消息并返回`Err(Error)`。
///
/// # 安全性
///
/// 这个函数使用了`unsafe`块，因为它调用了Windows API中的不安全函数。调用者需要确保传递给函数的参数是有效的，以避免潜在的安全漏洞。
pub fn svc_install(sys_path: &str, drive_name: &str) -> Result<()> {
    let sc_manager: SC_HANDLE;
    let sc_service: SC_HANDLE;

    sc_manager = unsafe { OpenSCManagerA(None, None, SC_MANAGER_ALL_ACCESS)? };
    if sc_manager.is_invalid() {
        warn!("[! Hide Process] Open SC Mamager failed.");
        return Err(Error::msg("Open SC Mamager failed."));
    }

    sc_service = unsafe {
        CreateServiceA(
            sc_manager,
            PCSTR::from_raw(drive_name.as_ptr()),
            PCSTR::from_raw(drive_name.as_ptr()),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            PCSTR::from_raw(sys_path.as_ptr()),
            None,
            None,
            None,
            None,
            None,
        )?
    };

    if sc_service.is_invalid() {
        warn!("[! Hide Process] Create Service failed {:?}.", unsafe {
            GetLastError()
        });
        unsafe { CloseServiceHandle(sc_manager)? };
        return Err(Error::msg("Create Service failed."));
    }

    unsafe { 
        CloseServiceHandle(sc_service)?;
        CloseServiceHandle(sc_manager)?;
    }
    info!("[+ Hide Process]Service installed successfully");

    Ok(())
}
