use aya::maps::RingBuf;
use aya::programs::Lsm;
use aya::Btf;
use aya::Ebpf;
use std::ptr;
use tokio::io::unix::AsyncFd;
use tokio::signal;
   
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileEvent {
    pub pid: u32,
    pub filename: [u8; 256],
    pub comm: [u8; 16], // Changed from creator_path to comm
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        println!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/prov"
    )))?;
    let btf = Btf::from_sys_fs()?;
    let program: &mut Lsm = ebpf.program_mut("file_open").unwrap().try_into()?;
    program.load("file_open", &btf)?;
    program.attach()?;

    let ring_buf = RingBuf::try_from(ebpf.map_mut("EVENTS").unwrap())?;
    
    let mut poll = AsyncFd::new(ring_buf)?;

    println!("Listening for file creations... (Press Ctrl+C to exit)");


    loop {
        let mut guard = poll.readable_mut().await?;
        let ring_buf = guard.get_inner_mut();

        // read all available events from the ring buffer
        while let Some(item) = ring_buf.next() {
            let event = unsafe { ptr::read_unaligned(item.as_ptr() as *const FileEvent) };

            let path_str = match event.filename.split(|&c| c == 0).next() {
                Some(bytes) => std::str::from_utf8(bytes).unwrap_or("<invalid>"),
                None => continue,
            };

            let comm_str = match event.comm.split(|&c| c == 0).next() {
                Some(bytes) => std::str::from_utf8(bytes).unwrap_or("unknown"),
                None => "unknown",
            };

            // check for ghost files
            let path = std::path::Path::new(path_str);
            if !path.exists() { continue; }

            let creator_display = std::fs::read_link(format!("/proc/{}/exe", event.pid))
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|_| format!("{} (dead pid {})", comm_str, event.pid));

            println!("TAGGED: {} -> {} (Created by {})", event.pid, path_str, creator_display);

            match xattr::set(path, "user.creator_exe", creator_display.as_bytes()) {
                Ok(_) => {
                    // Only print this if it ACTUALLY worked
                    println!("SUCCESS: Tagged {} -> {} (Created by {})", event.pid, path_str, creator_display);
                },
                Err(e) => {
                    // Print why it failed
                    eprintln!("FAILED to tag {}: {}", path_str, e);
                }
            }
        }

        // 8. Tell Tokio we are done reading, go back to sleep
        guard.clear_ready();
    }
}
