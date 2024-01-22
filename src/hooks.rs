use std::{ffi::{c_void}, mem, ptr, println};
use winapi::um::consoleapi;
use windows::{Win32::{System::LibraryLoader}, w};

pub mod scanner;
pub mod interfaces;

#[allow(dead_code)]
struct QAngle {
    x: f32,
    y: f32,
    z: f32,
}

#[allow(dead_code)]
struct CUserCmd {
    vtable: usize,
    command_number: i32,
    tick_count: i32,
    viewangles: QAngle,
    forwardmove: f32,
    sidemove: f32,
    upmove: f32,
    pub buttons: i32,
}

static mut O_CREATEMOVE: *mut c_void = ptr::null_mut();

pub unsafe fn demo_init() {
    unsafe { consoleapi::AllocConsole() };
    println!("Hello, world!");
    //sig finding
    let mut addr: usize = 0;
    if addr == 0 {
        let client_mod = LibraryLoader::GetModuleHandleW(w!("client.dll")).unwrap();
        addr = scanner::find_sig(client_mod, "48 89 5C 24 ? 57 48 81 EC ? ? ? ? 0F 29 7C 24").unwrap() as usize;
        println!("Address of the function: {:x}", addr);
    }


    //interfaces?
    let client_mod = LibraryLoader::GetModuleHandleW(w!("client.dll")).unwrap();
    println!("client.dll @ {:X}", client_mod.0);

    let client_factory = interfaces::get_factory(client_mod).unwrap();
    let client = interfaces::get_interface(client_factory, "Source2Client002").unwrap();

    //hooks
    if minhook_sys::MH_Initialize() == minhook_sys::MH_OK {
        println!("Minhook initialized");
    } else { eprintln!("Minhook error"); }

    let offset = client as *mut c_void;

    O_CREATEMOVE = create_hook(offset, 21, hk_create_move as *mut c_void);
    println!("Created CreateMove hook");

    println!("Enabling hooks...\n");
    if minhook_sys::MH_EnableHook(ptr::null_mut()) == minhook_sys::MH_OK {
        println!("Hooks enabled");
    } else {
        eprintln!("Hooks NOT enabled!");
    }
}

unsafe fn create_hook(iface: *mut c_void, index: usize, hk_func: *mut c_void) -> *mut c_void {
    let vtable = *(iface as *const usize);
    let func_addr = *((vtable + (mem::size_of::<usize>() * index)) as *const usize);
    
    let mut original = ptr::null_mut();
    minhook_sys::MH_CreateHook(func_addr as *mut c_void, hk_func, &mut original);
    
    original
}

//our hooks

unsafe extern "stdcall" fn hk_create_move(sample_time: f32, cmd: *mut CUserCmd) -> bool {
    let original: extern "stdcall" fn(f32, *mut CUserCmd) = mem::transmute(O_CREATEMOVE);
    original(sample_time, cmd);

    println!("OUR CM CALLED :D");
    //println!("cuser cmd: {}", (*cmd).viewangles.x);

    false
}