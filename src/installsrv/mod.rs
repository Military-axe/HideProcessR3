use anyhow::{Error, Result};
use log::{debug, info, warn};
use std::fs::canonicalize;
use windows::core::PCSTR;
use windows::Win32::System::Services::{
    CloseServiceHandle, DeleteService, OpenServiceA, SERVICE_ALL_ACCESS, SERVICE_DEMAND_START,
    SERVICE_ERROR_NORMAL, SERVICE_KERNEL_DRIVER,
};
use windows::Win32::{
    Foundation::GetLastError,
    Security::SC_HANDLE,
    System::Services::{CreateServiceA, OpenSCManagerA, SC_MANAGER_ALL_ACCESS},
};

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
pub fn svc_install(path: &str, drive_name: &str) -> Result<()> {
    let sc_manager: SC_HANDLE;
    let sc_service: SC_HANDLE;

    let binding = canonicalize(path)?;
    let sys_path = binding.as_os_str().to_str().unwrap();
    debug!("Convert to absolute path: {:?}", sys_path);

    sc_manager = unsafe { OpenSCManagerA(None, None, SC_MANAGER_ALL_ACCESS)? };
    if sc_manager.is_invalid() {
        warn!(" DOpen SC Mamager failed.");
        return Err(Error::msg("Open SC Mamager failed."));
    }

    sc_service = unsafe {
        CreateServiceA(
            sc_manager,
            PCSTR::from_raw(drive_name.as_ptr()),
            PCSTR::from_raw(drive_name.as_ptr()),
            SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER,
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
        warn!("Create Service failed {:?}.", unsafe { GetLastError() });
        unsafe { CloseServiceHandle(sc_manager)? };
        return Err(Error::msg("Create Service failed."));
    }

    unsafe {
        CloseServiceHandle(sc_service)?;
        CloseServiceHandle(sc_manager)?;
    }
    info!("Service installed successfully");

    Ok(())
}

/// 使用Windows API删除指定的服务。
///
/// # 参数
///
/// * `sc_name` - 要删除的服务的名称。
///
/// # 返回值
///
/// 如果服务删除成功，返回`Ok(())`；如果发生错误，返回`Err`包含错误信息。
///
/// # 注意
///
/// 此函数需要以管理员权限运行，否则可能无法打开或删除服务。
pub fn svc_delete(sc_name: &str) -> Result<()> {
    let sc_manager: SC_HANDLE;
    let sc_service: SC_HANDLE;

    sc_manager = unsafe { OpenSCManagerA(None, None, SC_MANAGER_ALL_ACCESS)? };
    if sc_manager.is_invalid() {
        warn!("Open SC Mamager failed.");
        return Err(Error::msg("Open SC Mamager failed."));
    }

    // Get Service handle and delete access
    sc_service = unsafe { OpenServiceA(sc_manager, PCSTR::from_raw(sc_name.as_ptr()), 0x10000)? };
    if sc_service.is_invalid() {
        warn!("Open Services failed.");
        unsafe { CloseServiceHandle(sc_service) }?;
        return Err(Error::msg("Open Services failed."));
    }

    // Delete the service.
    match unsafe { DeleteService(sc_service) } {
        Ok(_) => info!("Delete service success."),
        Err(x) => warn!("Delete Service failed. {:?}", x),
    }

    unsafe {
        CloseServiceHandle(sc_service)?;
        CloseServiceHandle(sc_manager)?;
    }

    Ok(())
}
