use anyhow::Result;
use dll_syringe::{process::OwnedProcess, Syringe};
use log::warn;
use windows::core::PCSTR;
use windows::Win32::{
    Foundation::{LPARAM, LRESULT, WPARAM},
    System::LibraryLoader::LoadLibraryA,
    UI::WindowsAndMessaging::{CallNextHookEx, SetWindowsHookExA, WH_GETMESSAGE},
};

pub struct Inject {}

impl Inject {
    pub fn inject_dll_by_name(dll_path: &str, process_name: &str) {
        let target_process = OwnedProcess::find_first_by_name(process_name).unwrap();
        let syringe = Syringe::for_process(target_process);
        let _injected_payload = syringe.inject(dll_path).unwrap();
        // eject the payload from the target (optional)
        // syringe.eject(injected_payload).unwrap();
    }

    pub fn inject_dll_by_pid(dll_path: &str, pid: u32) {
        let target_process = OwnedProcess::from_pid(pid).unwrap();
        let syringe = Syringe::for_process(target_process);
        let _injected_payload = syringe.inject(dll_path).unwrap();
    }
}

pub struct WindowsHook {}

impl WindowsHook {
    #[no_mangle]
    unsafe extern "system" fn GetMsgProc(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
        CallNextHookEx(None, code, wparam, lparam)
    }

    pub fn hook(dll_path: *const u8) -> Result<()> {
        // 设置SetWindowsHookExA像消息进程注入的dll
        let hmod = unsafe { LoadLibraryA(PCSTR::from_raw(dll_path)) }?;
        let hhook =
            unsafe { SetWindowsHookExA(WH_GETMESSAGE, Some(WindowsHook::GetMsgProc), hmod, 0) }?;
        if hhook.is_invalid() {
            warn!("[! Hide Process R3] SetWindowsHookExA is invalid");
        }
        Ok(())
    }
}
