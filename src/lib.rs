/// WLAN structs
mod wlan_interface;

pub use wlan_interface::WlanHander;

pub(crate) use utils::*;
mod utils {
    use windows::core::{wcslen, PCWSTR};
    pub fn vary_array_to_vec<Origin, To>(length: usize, vary_arr: [Origin; 1]) -> Vec<To>
    where
        for<'a> To: From<&'a Origin>,
    {
        let reference = &vary_arr[0] as *const Origin;

        let slc = unsafe { std::slice::from_raw_parts(reference, length) };
        let v = slc.iter().map(|x| x.into()).collect::<Vec<To>>();

        v
    }

    pub fn vary_utf16_to_string(utf16_str: &[u16]) -> String {
        let ptr = utf16_str.as_ptr();
        let slice = unsafe {
            let wptr: PCWSTR = std::mem::transmute(ptr);
            let len = wcslen(wptr);
            std::slice::from_raw_parts(ptr, len as usize)
        };
        String::from_utf16(slice).unwrap()
    }
}
