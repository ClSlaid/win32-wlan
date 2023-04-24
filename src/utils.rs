use windows::{
    core::{wcslen, PCWSTR},
    Win32::NetworkManagement::WiFi::L2_NOTIFICATION_DATA,
};

/// convert a vary length array to a Vec
/// # Note
/// all conversion should clone the origin data to your rust struct
/// or you will finally get a dangling pointer
pub unsafe fn vary_array_to_vec<Origin, To>(length: usize, vary_arr: &[Origin]) -> Vec<To>
where
    for<'a> To: From<&'a Origin>,
{
    let reference = &vary_arr[0] as *const Origin;

    let slc = std::slice::from_raw_parts(reference, length);
    let v = slc.iter().map(|x| x.into()).collect::<Vec<To>>();

    v
}

/// convert a vary length '\0' ended utf16 array to String
pub fn vary_utf16_to_string(utf16_str: &[u16]) -> String {
    let ptr = utf16_str.as_ptr();
    let slice = unsafe {
        let wptr: PCWSTR = std::mem::transmute(ptr);
        let len = wcslen(wptr);
        std::slice::from_raw_parts(ptr, len)
    };
    String::from_utf16_lossy(slice)
}

/// callback executor function
pub unsafe extern "system" fn callback_executor(
    data: *mut L2_NOTIFICATION_DATA,
    callback: *mut std::ffi::c_void,
) {
    let callback = callback as *mut Box<dyn FnOnce(*mut L2_NOTIFICATION_DATA)>;
    // free callback
    let callback = Box::from_raw(callback);
    callback(data);
}
