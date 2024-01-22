use std::{ffi::{c_void, c_char, CString}, mem, ptr, println};
use windows::{Win32::{Foundation::HINSTANCE, System::LibraryLoader}, s};

type CreateInterfaceFn = extern "C" fn(name: *const c_char, rc: *mut i32) -> *mut c_void;
pub unsafe fn get_factory(module: HINSTANCE) -> Option<CreateInterfaceFn> {
    match LibraryLoader::GetProcAddress(module, s!("CreateInterface")) {
        Some(f) => Some(mem::transmute::<_, CreateInterfaceFn>(f)),
        None => None
    }
}

pub fn get_interface(factory: CreateInterfaceFn, version: &str) -> Option<*mut c_void> {
    let c_version = CString::new(version).unwrap();
    let i = factory(c_version.as_ptr(), ptr::null_mut());
    if i.is_null() {
        eprintln!("Couldn't get interface {version:?}");
        None
    } else {
        println!("Found interface {version} at {i:?}");
        Some(i)
    }
}