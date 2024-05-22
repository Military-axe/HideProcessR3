use dll_syringe::{process::OwnedProcess, Syringe};

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
