#![no_std]
#![no_main]

mod vmlinux;
use vmlinux::file;

use aya_ebpf::{
    macros::{lsm, map},
    maps::RingBuf,
    programs::LsmContext,
    helpers::{bpf_get_current_pid_tgid, bpf_d_path, bpf_get_current_comm},
};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileEvent {
    pub pid: u32,
    pub filename: [u8; 256],
    pub comm: [u8; 16],
}

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// flag to check whether the file is actually new
const FMODE_CREATED: u32 = 0x100000;

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    match try_file_open(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}


fn try_file_open(ctx: LsmContext) -> Result<i32, i32> {
    let file_ptr = ctx.arg::<*const file>(0);

    let mode = unsafe { (*file_ptr).f_mode } as u32;

    if (mode & FMODE_CREATED) == 0 {
        return Ok(0); 
    }

    if let Some(mut event_buf) = EVENTS.reserve::<FileEvent>(0) {
        let event = event_buf.as_mut_ptr();
        
        unsafe { (*event).pid = (bpf_get_current_pid_tgid() >> 32) as u32 };

        unsafe {
            let path_ptr = &(*file_ptr).__bindgen_anon_1 as *const _;
            bpf_d_path(
                path_ptr as *mut _, 
                (*event).filename.as_mut_ptr() as *mut _, 
                256
            );
        }

        // gets the command name for fallbacks
        unsafe {
            let comm = bpf_get_current_comm().unwrap_or([0; 16]);
            (*event).comm.copy_from_slice(&comm);
        }

        event_buf.submit(0);
    }

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
