use windows::Win32::Graphics::Gdi::{EnumDisplayMonitors, HDC, HMONITOR, MONITORINFOEXW};
use windows::Win32::Foundation::{BOOL, LPARAM, RECT};

struct EnumData {
    list: Vec<String>,
}

unsafe extern "system" fn enum_callback(
    hmonitor: HMONITOR,
    _: HDC,
    rect: *mut RECT,
    lparam: LPARAM,
) -> BOOL {
    let data = &mut *(lparam.0 as *mut EnumData);
    let mut mi = MONITORINFOEXW::default();
    mi.monitorInfo.cbSize = std::mem::size_of::<MONITORINFOEXW>() as u32;
    if windows::Win32::Graphics::Gdi::GetMonitorInfoW(hmonitor, &mut mi.monitorInfo).as_bool() {
        let name = String::from_utf16_lossy(&mi.szDevice)
            .trim_matches('\0')
            .to_string();
        data.list.push(name);
    }
    BOOL(1)
}

fn main() {
    let mut data = EnumData { list: Vec::new() };
    unsafe {
        EnumDisplayMonitors(
            HDC(0),
            None,
            Some(enum_callback),
            LPARAM(&mut data as *mut _ as isize),
        );
    }
    println!("EnumDisplayMonitors found {} monitors:", data.list.len());
    for name in &data.list {
        println!(" - {}", name);
    }

    // Try windows-capture as well if available (mocking it here or just using GDI)
}
