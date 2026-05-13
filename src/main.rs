use eframe::egui;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::UdpSocket;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use windows::Win32::Foundation::{BOOL, LPARAM, RECT};
use windows::Win32::Graphics::Gdi::{
    EnumDisplayMonitors, HMONITOR, MONITORINFOEXW, HDC,
    DEVMODEW, ChangeDisplaySettingsExW,
    DM_PELSWIDTH, DM_PELSHEIGHT,
    CreateCompatibleDC, CreateDIBSection, DeleteDC,
    SelectObject, BitBlt, SRCCOPY, BITMAPINFO,
    BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS, CreateDCW,
};
// windows-capture 제거됨 (GPU 방식 배제)
use windows::Win32::UI::Input::KeyboardAndMouse::{
    INPUT, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT, MOUSEINPUT, SendInput,
};
use windows::Win32::UI::WindowsAndMessaging::{
    GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN,
    SM_YVIRTUALSCREEN,
};
use windows::Win32::System::Memory::{
    CreateFileMappingW, MapViewOfFile, OpenFileMappingW,
    FILE_MAP_ALL_ACCESS, PAGE_READWRITE,
};
// GDI 커서 캡처 기능이 WGC 내장 기능으로 대체되었습니다.
use windows::Win32::System::Threading::{
    CreateEventW, OpenEventW,
    EVENT_MODIFY_STATE
};
use windows::Win32::Security::{
    InitializeSecurityDescriptor, SetSecurityDescriptorDacl,
    SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR,
};
use windows::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;

// --- 네트워크 통신 프로토콜 ---
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct InputPacket {
    event_type: u8, // 0: Mouse, 1: Key, 2: Text, 3: FocusMonitor, 4: Wheel
    msg: u32,
    msg2: i32,
    wparam: u64,
    lparam: i64,
    wheel_delta: i32,
    x_delta: i32,
    y_delta: i32,
    x: u16,
    y: u16,
    target_monitor_name: [u16; 32],
    is_admin: u8,
}

const WM_KEYDOWN: u32 = 0x0100;
const WM_KEYUP: u32 = 0x0101;
const WM_MOUSEMOVE: u32 = 0x0200;
const WM_LBUTTONDOWN: u32 = 0x0201;
const WM_LBUTTONUP: u32 = 0x0202;
const WM_RBUTTONDOWN: u32 = 0x0204;
const WM_RBUTTONUP: u32 = 0x0205;
const WM_MOUSEWHEEL: u32 = 0x020A;

// Lazy 임포트 삭제됨
// CACHED_MONITORS는 더 이상 사용되지 않아 삭제되었습니다.

// ===== 공유 메모리 (SHM) 상수 및 헬퍼 =====
// 슬롯 구조: [64바이트 헤더][최대 33MB RAW BGRA 데이터]
// 헤더: [0..4) seq [4..8) data_size [8..12) is_admin [12..14) width [14..16) height [16..64) reserved
const SHM_RAW_MAX: usize = 3840 * 2160 * 4; // 4K 32bpp = 33,177,600
const SHM_HDR_SIZE: usize = 64;
const SHM_SLOT_SIZE: usize = SHM_HDR_SIZE + SHM_RAW_MAX;

// 포인터/핸들을 스레드 간 이동 가능하게 래핑
struct ShmPtr(usize);
unsafe impl Send for ShmPtr {}
struct WinEvt(isize);
unsafe impl Send for WinEvt {}

struct RemoteSession {
    texture: Option<egui::TextureHandle>,
    last_update: std::time::Instant,
    is_admin: bool,
}

fn shm_name_for(username: &str, m_idx: usize) -> String {
    // NT 객체 이름은 대소문자를 구분할 수 있어, worker_ports.txt 의 USERNAME 과
    // 세션 환경변수 USERNAME 의 대소문자 차이로 SHM 이 열리지 않는 경우를 막는다.
    let s: String = username
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect::<String>()
        .to_lowercase();
    format!("Global\\AsterShm_{}_{}", s, m_idx)
}
fn evt_name_for(username: &str, m_idx: usize) -> String {
    let s: String = username
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect::<String>()
        .to_lowercase();
    format!("Global\\AsterEvt_{}_{}", s, m_idx)
}

// NULL DACL 보안 속성 생성 (모든 세션 접근 허용)
unsafe fn make_null_dacl() -> (SECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES) {
    use windows::Win32::Security::PSECURITY_DESCRIPTOR;
    unsafe {
        let mut sd: SECURITY_DESCRIPTOR = std::mem::zeroed();
        let psd = PSECURITY_DESCRIPTOR(&mut sd as *mut _ as *mut _);
        let _ = InitializeSecurityDescriptor(psd, SECURITY_DESCRIPTOR_REVISION);
        let psd2 = PSECURITY_DESCRIPTOR(&mut sd as *mut _ as *mut _);
        let _ = SetSecurityDescriptorDacl(
            psd2,
            windows::Win32::Foundation::BOOL(1), // bDaclPresent = TRUE
            None,
            windows::Win32::Foundation::BOOL(0), // bDaclDefaulted = FALSE
        );
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: &mut sd as *mut _ as *mut _,
            bInheritHandle: windows::Win32::Foundation::BOOL(0),
        };
        (sd, sa)
    }
}

// Worker: SHM 슬롯 생성
fn create_shm_slot(name: &str) -> Option<(ShmPtr, windows::Win32::Foundation::HANDLE)> {
    unsafe {
        let (mut sd, mut sa) = make_null_dacl();
        sa.lpSecurityDescriptor = &mut sd as *mut _ as *mut _;
        let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        let h = CreateFileMappingW(
            windows::Win32::Foundation::INVALID_HANDLE_VALUE,
            Some(&sa as *const _),
            PAGE_READWRITE, 0, SHM_SLOT_SIZE as u32,
            windows::core::PCWSTR(wide.as_ptr()),
        ).ok()?;
        let view = MapViewOfFile(h, FILE_MAP_ALL_ACCESS, 0, 0, SHM_SLOT_SIZE);
        if view.Value.is_null() { let _ = windows::Win32::Foundation::CloseHandle(h); return None; }
        Some((ShmPtr(view.Value as usize), h))
    }
}

// Controller: 기존 SHM 슬롯 열기
fn open_shm_slot(name: &str) -> Option<ShmPtr> {
    unsafe {
        let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        let h = OpenFileMappingW(
            FILE_MAP_ALL_ACCESS.0,
            windows::Win32::Foundation::BOOL(0),
            windows::core::PCWSTR(wide.as_ptr()),
        ).ok()?;
        let view = MapViewOfFile(h, FILE_MAP_ALL_ACCESS, 0, 0, SHM_SLOT_SIZE);
        if view.Value.is_null() { let _ = windows::Win32::Foundation::CloseHandle(h); return None; }
        Some(ShmPtr(view.Value as usize))
    }
}

// Worker: Named Event 생성
fn create_global_event(name: &str) -> Option<WinEvt> {
    unsafe {
        let (mut sd, mut sa) = make_null_dacl();
        sa.lpSecurityDescriptor = &mut sd as *mut _ as *mut _;
        let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        CreateEventW(
            Some(&sa as *const _),
            windows::Win32::Foundation::BOOL(0), // auto-reset
            windows::Win32::Foundation::BOOL(0), // initially nonsignaled
            windows::core::PCWSTR(wide.as_ptr()),
        ).ok().map(|h| WinEvt(h.0))
    }
}

// Controller: Named Event 열기
fn open_global_event(name: &str) -> Option<WinEvt> {
    unsafe {
        let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        // EVENT_MODIFY_STATE(0x0002) | SYNCHRONIZE(0x00100000)
        OpenEventW(
            EVENT_MODIFY_STATE | windows::Win32::System::Threading::SYNCHRONIZATION_SYNCHRONIZE,
            windows::Win32::Foundation::BOOL(0),
            windows::core::PCWSTR(wide.as_ptr()),
        ).ok().map(|h| WinEvt(h.0))
    }
}

unsafe fn write_shm_frame(base: *mut u8, pixels: &[u8], width: u32, height: u32, is_admin: bool) {
    unsafe {
        let hdr = base as *mut u32;
        let cur = hdr.read_volatile();
        hdr.write_volatile(cur | 1); // 홀수 = 쓰는 중
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
        
        let len = pixels.len().min(SHM_RAW_MAX);
        hdr.add(1).write_volatile(len as u32);
        hdr.add(2).write_volatile(if is_admin { 1 } else { 0 });
        
        // 12..14: width, 14..16: height
        let hdr_u16 = base.add(12) as *mut u16;
        hdr_u16.write_volatile(width as u16);
        hdr_u16.add(1).write_volatile(height as u16);

        // GDI BGR -> RGBA 스왑 및 복사
        let dst = base.add(SHM_HDR_SIZE);
        let src = pixels.as_ptr();
        let pixel_count = (width * height) as usize;
        
        for i in 0..pixel_count {
            let offset = i * 4;
            if offset + 3 >= len { break; }
            // BGR(src) -> RGB(dst)
            *dst.add(offset)     = *src.add(offset + 2); // Red
            *dst.add(offset + 1) = *src.add(offset + 1); // Green
            *dst.add(offset + 2) = *src.add(offset);     // Blue
            *dst.add(offset + 3) = 255;                  // Alpha
        }
        
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
        hdr.write_volatile((cur | 1) + 1); // 짝수 = 완료
    }
}

// Controller: seqlock 방식으로 SHM에서 RAW 프레임 읽기 (메모리 재사용)
unsafe fn read_shm_frame_into(base: *const u8, buf: &mut Vec<u8>) -> Option<(u32, u32, bool)> {
    unsafe {
        let hdr = base as *const u32;
        let seq1 = hdr.read_volatile();
        if seq1 == 0 || seq1 % 2 == 1 { return None; }
        
        let data_size = hdr.add(1).read_volatile() as usize;
        if data_size == 0 || data_size > SHM_RAW_MAX { return None; }
        let is_admin = hdr.add(2).read_volatile() != 0;
        
        let hdr_u16 = base.add(12) as *const u16;
        let width = hdr_u16.read_volatile() as u32;
        let height = hdr_u16.add(1).read_volatile() as u32;

        if buf.len() != data_size {
            buf.resize(data_size, 0);
        }
        std::ptr::copy_nonoverlapping(base.add(SHM_HDR_SIZE), buf.as_mut_ptr(), data_size);
        
        let seq2 = hdr.read_volatile();
        if seq1 != seq2 { return None; }
        Some((width, height, is_admin))
    }
}

fn main() -> eframe::Result<()> {
    // --- DPI 인식 설정 (화면 잘림 방지) ---
    unsafe {
        use windows::Win32::UI::HiDpi::{SetProcessDpiAwarenessContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2};
        let _ = SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    }

    let args: Vec<String> = std::env::args().collect();
    let is_worker = args.iter().any(|s| s == "--worker");
    let no_elevate = args.iter().any(|s| s == "--no-elevate");

    // --- 자동 승격 (Self-Elevation) ---
    if is_worker && !no_elevate && !is_elevated() {
        println!("🚀 워커 모드: 관리자 권한이 필요합니다. 승격을 시도합니다...");
        if run_as_admin(&args) {
            return Ok(());
        }
    }
    // ---------------------------------

    let username = std::env::var("USERNAME").unwrap_or_else(|_| "unknown".to_string());

    // --- 스마트 중복 실행 방지 (Single Instance Lock) ---
    unsafe {
        use windows::Win32::System::Threading::CreateMutexW;
        use windows::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError};
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;

        // 모드에 따라 뮤텍스 이름 분리 (컨트롤러는 PC당 1개, 워커는 유저당 1개)
        let mutex_name = if is_worker {
            format!("Global\\AsterDualWorkerMutex_{}", username)
        } else {
            "Global\\AsterDualControllerMutex".to_string()
        };
        
        let mut name_wide: Vec<u16> = OsStr::new(&mutex_name).encode_wide().collect();
        name_wide.push(0);
        
        let _handle = CreateMutexW(None, true, windows::core::PCWSTR(name_wide.as_ptr()));
        if GetLastError() == ERROR_ALREADY_EXISTS {
            return Ok(());
        }
    }
    // ------------------------------------------
    let port = args
        .iter()
        .position(|s| s == "--port")
        .and_then(|i| args.get(i + 1))
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(9090);

    let target_ip = args
        .iter()
        .position(|s| s == "--target")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| "127.0.0.1".to_string());

    let username = std::env::var("USERNAME").unwrap_or_default();

    let final_port = if args.iter().any(|s| s == "--worker") {
        get_auto_port(&username, port)
    } else {
        port
    };

    if args.iter().any(|s| s == "--worker") {
        println!(
            "🚀 멀티 모니터 워커 모드 시작 (유저: {}, 포트: {})",
            username, final_port
        );
        run_worker(final_port);
        return Ok(());
    }

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 720.0])
            .with_title("ASTER Dual Controller"),
        ..Default::default()
    };

    eframe::run_native(
        "dual_window",
        native_options,
        Box::new(move |cc| Box::new(MultiMonitorApp::new(cc, final_port, target_ip))),
    )
}

fn get_auto_port(username: &str, default_port: u16) -> u16 {
    let path = "C:\\Users\\Public\\worker_ports.txt";
    let mut mappings = HashMap::new();
    if let Ok(content) = std::fs::read_to_string(path) {
        for line in content.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() == 2 {
                if let Ok(p) = parts[1].parse::<u16>() {
                    mappings.insert(parts[0].to_string(), p);
                }
            }
        }
    }
    if let Some(&p) = mappings.get(username) {
        return p;
    }
    let max_port = mappings.values().cloned().max().unwrap_or(default_port - 2);
    let new_port = max_port + 2;
    mappings.insert(username.to_string(), new_port);
    let mut new_content = String::new();
    for (name, p) in &mappings {
        new_content.push_str(&format!("{}:{}\n", name, p));
    }
    let _ = std::fs::write(path, new_content);
    new_port
}

#[derive(Serialize, Deserialize, Clone)]
struct LoginRequest {
    user_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct LoginResponse {
    success: bool,
    message: String,
    expiry_date: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
struct StatusRequest {
    user_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct StatusResponse {
    success: bool,
}

#[derive(Clone, PartialEq)]
enum LoginState {
    LoggedOut,
    LoggingIn,
    LoggedIn { user_id: String, expiry: String },
}

struct MultiMonitorApp {
    connections: Arc<Mutex<HashMap<u32, RemoteSession>>>,
    udp_socket: Arc<UdpSocket>,
    virtual_cursor_pos: Option<egui::Pos2>,
    input_active: bool,
    last_modifiers: egui::Modifiers,
    grid_view: bool,
    grid_size: f32,
    bottom_size: f32,
    login_id_input: String,
    login_error: Option<String>,
    target_ip: String,
    login_state: LoginState,
}

impl MultiMonitorApp {
    fn new(cc: &eframe::CreationContext<'_>, _port: u16, target_ip: String) -> Self {
        setup_custom_style(&cc.egui_ctx);
        let udp_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").expect("UDP bind failed"));
        let connections = Arc::new(Mutex::new(HashMap::new()));
        let ctx = cc.egui_ctx.clone();

        let connections_clone = connections.clone();
        let ctx_discovery = ctx.clone();

        thread::spawn(move || {
            let mut active_users: Vec<String> = Vec::new();
            loop {
                let is_login = ctx_discovery.data(|d| {
                    d.get_temp::<bool>(egui::Id::from("is_login")).unwrap_or(false)
                });

                if is_login {
                    let path = "C:\\Users\\Public\\worker_ports.txt";
                    if let Ok(content) = std::fs::read_to_string(path) {
                        for line in content.lines() {
                            let parts: Vec<&str> = line.split(':').collect();
                            if parts.len() == 2 {
                                let username = parts[0].to_string();
                                if let Ok(p) = parts[1].parse::<u16>() {
                                    if !active_users.contains(&username) {
                                        active_users.push(username.clone());
                                        let ctx_inner = ctx_discovery.clone();
                                        let conn_inner = connections_clone.clone();
                                        let port_inner = p;
                                        let uname = username.clone();
                                        
                                        // --- user1 ~ user100 패턴만 허용 ---
                                        let uname_lower = uname.to_lowercase();
                                        let is_user_n = uname_lower.starts_with("user") && 
                                                        uname_lower[4..].parse::<u32>().map_or(false, |n| n >= 1 && n <= 100);
                                        
                                        if !is_user_n {
                                            continue;
                                        }

                                        // 본인(현재 컨트롤러 실행 유저)의 화면은 목록에서 제외
                                        let my_name = std::env::var("USERNAME").unwrap_or_default();
                                        if uname.to_lowercase() == my_name.to_lowercase() {
                                            println!("🚫 [SHM] 본인 세션 제외: {}", uname);
                                            continue;
                                        }
                                        
                                        println!("📡 [SHM] 워커 발견: {} (포트: {})", uname, p);

                                        thread::spawn(move || {
                                            let mut mon_threads: Vec<usize> = Vec::new();
                                            loop {
                                                for m_idx in 0..8usize {
                                                    if mon_threads.contains(&m_idx) { continue; }
                                                    let shm_name = shm_name_for(&uname, m_idx);
                                                    let evt_name = evt_name_for(&uname, m_idx);
                                                    if let (Some(shm), Some(evt)) = (
                                                        open_shm_slot(&shm_name),
                                                        open_global_event(&evt_name),
                                                    ) {
                                                        mon_threads.push(m_idx);
                                                        let ctx_thread = ctx_inner.clone();
                                                        let connections_inner = conn_inner.clone();
                                                        let unique_id = (port_inner as u32 * 100) + m_idx as u32;
                                                        let evt_h = windows::Win32::Foundation::HANDLE(evt.0);
                                                        let shm_ptr_wrapped = ShmPtr(shm.0 as usize);

                                                        thread::spawn(move || {
                                                            let shm_ptr = shm_ptr_wrapped.0 as *const u8;
                                                            use windows::Win32::System::Threading::WaitForSingleObject;
                                                            use windows::Win32::Foundation::WAIT_OBJECT_0;
                                                            
                                                            let mut pixel_buffer = Vec::new();
                                                            loop {
                                                                let res = unsafe { WaitForSingleObject(evt_h, 100) };
                                                                if res == WAIT_OBJECT_0 {
                                                                    unsafe {
                                                                        if let Some((w, h, is_admin)) = read_shm_frame_into(shm_ptr, &mut pixel_buffer) {
                                                                            let color_image = egui::ColorImage::from_rgba_unmultiplied(
                                                                                [w as usize, h as usize],
                                                                                &pixel_buffer
                                                                            );

                                                                            let mut conns = connections_inner.lock().unwrap();
                                                                            let entry = conns.entry(unique_id).or_insert_with(|| {
                                                                                let tex = ctx_thread.load_texture(
                                                                                    format!("remote_{}", unique_id),
                                                                                    egui::ColorImage::new([1,1], egui::Color32::BLACK),
                                                                                    Default::default()
                                                                                );
                                                                                RemoteSession {
                                                                                    texture: Some(tex),
                                                                                    last_update: std::time::Instant::now(),
                                                                                    is_admin: false,
                                                                                }
                                                                            });
                                                                            
                                                                            if let Some(tex) = &mut entry.texture {
                                                                                tex.set(color_image, egui::TextureOptions::LINEAR);
                                                                            }
                                                                            entry.last_update = std::time::Instant::now();
                                                                            entry.is_admin = is_admin;
                                                                            ctx_thread.request_repaint();
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        });
                                                    }
                                                }
                                                thread::sleep(Duration::from_secs(3));
                                            }
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
                thread::sleep(Duration::from_secs(5));
            }
        });

        Self {
            connections,
            udp_socket,
            virtual_cursor_pos: None,
            input_active: false,
            last_modifiers: egui::Modifiers::default(),
            grid_view: false,
            grid_size: 300.0,
            bottom_size: 160.0,
            login_id_input: String::new(),
            login_error: None,
            target_ip,
            login_state: LoginState::LoggedOut,
        }
    }

    fn show_login_screen(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(ctx.screen_rect().height() / 4.0);
                ui.heading(
                    egui::RichText::new("🔐 ASTER Dual Controller 로그인")
                        .size(32.0)
                        .strong(),
                );
                ui.add_space(20.0);

                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.set_width(300.0);
                    ui.add_space(10.0);

                    ui.label("아이디");
                    let resp = ui.text_edit_singleline(&mut self.login_id_input);
                    if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        self.attempt_login(ctx);
                    }

                    ui.add_space(10.0);

                    if let Some(err) = &self.login_error {
                        ui.label(egui::RichText::new(err).color(egui::Color32::RED));
                    }

                    ui.add_space(10.0);

                    ui.scope(|ui| {
                        if self.login_state == LoginState::LoggingIn {
                            ui.set_enabled(false);
                            ui.horizontal(|ui| {
                                ui.spinner();
                                ui.label("로그인 중...");
                            });
                        } else {
                            if ui
                                .button(egui::RichText::new("로그인").size(18.0).strong())
                                .clicked()
                            {
                                self.attempt_login(ctx);
                            }
                        }
                    });
                    ui.add_space(10.0);
                });
            });
        });
    }

    fn attempt_login(&mut self, ctx: &egui::Context) {
        let user_id = self.login_id_input.trim().to_string();
        if user_id.is_empty() {
            self.login_error = Some("아이디를 입력하세요.".to_string());
            return;
        }

        self.login_state = LoginState::LoggingIn;
        self.login_error = None; // 새로운 시도 시 이전 에러 제거
        let ctx_clone = ctx.clone();
        let api_server_ip = "93.127.129.57".to_string();

        thread::spawn(move || {
            let client = reqwest::blocking::Client::builder()
                .danger_accept_invalid_certs(true)
                .timeout(Duration::from_secs(5))
                .build();

            let client = match client {
                Ok(c) => c,
                Err(e) => {
                    println!("🚨 [CLIENT] 클라이언트 생성 실패: {}", e);
                    ctx_clone.data_mut(|d| {
                        d.insert_temp(
                            egui::Id::from("login_error"),
                            Some(format!("클라이언트 생성 실패: {}", e)),
                        );
                    });
                    ctx_clone.request_repaint();
                    return;
                }
            };

            let res = client
                .post(format!("https://{}:8095/api/login", api_server_ip))
                .json(&LoginRequest {
                    user_id: user_id.clone(),
                })
                .send();

            match res {
                Ok(response) => {
                    let status = response.status();
                    let body_text = response.text().unwrap_or_default();

                    if let Ok(login_res) = serde_json::from_str::<LoginResponse>(&body_text) {
                        if login_res.success {
                            let expiry = login_res.expiry_date.unwrap_or_default();
                            ctx_clone.data_mut(|d| {
                                d.insert_temp(egui::Id::from("login_event"), (user_id, expiry));
                            });
                        } else {
                            ctx_clone.data_mut(|d| {
                                d.insert_temp(egui::Id::from("login_error"), login_res.message);
                            });
                        }
                    } else {
                        ctx_clone.data_mut(|d| {
                            d.insert_temp(
                                egui::Id::from("login_error"),
                                format!("서버 응답 파싱 실패 (상태: {})", status),
                            );
                        });
                    }
                }
                Err(e) => {
                    ctx_clone.data_mut(|d| {
                        d.insert_temp(
                            egui::Id::from("login_error"),
                            format!("서버 연결 실패: {}", e),
                        );
                    });
                }
            }
            ctx_clone.request_repaint();
        });
    }

    fn start_heartbeat(&self, ctx: egui::Context, user_id: String) {
        let api_server_ip = "93.127.129.57".to_string();
        thread::spawn(move || {
            let client = reqwest::blocking::Client::builder()
                .danger_accept_invalid_certs(true)
                .build()
                .unwrap();

            loop {
                thread::sleep(Duration::from_secs(30));
                let res = client
                    .post(format!("https://{}:8095/api/check_status", api_server_ip))
                    .json(&StatusRequest {
                        user_id: user_id.clone(),
                    })
                    .send();

                match res {
                    Ok(response) => {
                        if let Ok(status_res) = response.json::<StatusResponse>() {
                            if !status_res.success {
                                ctx.data_mut(|d| {
                                    d.insert_temp(egui::Id::from("session_expired"), true)
                                });
                                break;
                            }
                        }
                    }
                    Err(_) => {}
                }
            }
            ctx.request_repaint();
        });
    }

    fn handle_input_static(
        unique_id: u32,
        rect: egui::Rect,
        ctx: &egui::Context,
        udp_socket: &UdpSocket,
        last_modifiers: &mut egui::Modifiers,
        target_ip: &str,
    ) {
        let port = (unique_id / 100) as u16;
        let m_idx = unique_id % 100;
        let udp_target = format!("{}:{}", target_ip, port);

        let pos_opt = ctx.input(|i| i.pointer.interact_pos().or(i.pointer.hover_pos()));
        if let Some(pos) = pos_opt {
            let is_in = rect.contains(pos);
            let is_down = ctx.input(|i| i.pointer.primary_down() || i.pointer.secondary_down());

            if is_in || is_down {
                let norm_x = ((pos.x - rect.min.x) / rect.width().max(1.0)).clamp(0.0, 1.0);
                let norm_y = ((pos.y - rect.min.y) / rect.height().max(1.0)).clamp(0.0, 1.0);

                let mon_name = format!("{}", m_idx);
                let mut name_u16 = [0u16; 32];
                for (i, c) in mon_name.encode_utf16().enumerate().take(31) {
                    name_u16[i] = c;
                }

                let send = |msg: u32, wheel: i32| {
                    let packet = InputPacket {
                        event_type: 0,
                        msg,
                        msg2: 0,
                        wparam: 0,
                        lparam: 0,
                        wheel_delta: wheel,
                        x_delta: 0,
                        y_delta: 0,
                        x: (norm_x * 65535.0) as u16,
                        y: (norm_y * 65535.0) as u16,
                        target_monitor_name: name_u16,
                        is_admin: 0,
                    };
                    let _ = udp_socket.send_to(
                        unsafe {
                            std::slice::from_raw_parts(
                                &packet as *const _ as *const u8,
                                std::mem::size_of::<InputPacket>(),
                            )
                        },
                        &udp_target,
                    );
                };

                let current_norm_pos = (norm_x, norm_y);
                let last_norm_pos: Option<(f32, f32)> =
                    ctx.data(|d| d.get_temp(egui::Id::from("last_norm_pos")));
                if last_norm_pos != Some(current_norm_pos) {
                    send(WM_MOUSEMOVE, 0);
                    ctx.data_mut(|d| {
                        d.insert_temp(egui::Id::from("last_norm_pos"), current_norm_pos)
                    });
                }
                ctx.input(|i| {
                    if is_in && i.pointer.button_pressed(egui::PointerButton::Primary) {
                        send(WM_LBUTTONDOWN, 0);
                    }
                    if i.pointer.button_released(egui::PointerButton::Primary) {
                        send(WM_LBUTTONUP, 0);
                    }
                    if is_in && i.pointer.button_pressed(egui::PointerButton::Secondary) {
                        send(WM_RBUTTONDOWN, 0);
                    }
                    if i.pointer.button_released(egui::PointerButton::Secondary) {
                        send(WM_RBUTTONUP, 0);
                    }
                    if is_in {
                        for event in &i.events {
                            if let egui::Event::Scroll(delta) = event {
                                if delta.y.abs() > 0.1 {
                                    send(WM_MOUSEWHEEL, (delta.y * 40.0) as i32);
                                }
                            }
                        }
                    }
                });
            }
        }

        // 키보드 처리
        {
            let current_modifiers = ctx.input(|i| i.modifiers);
            let mod_mask = (current_modifiers.ctrl as u64)
                | ((current_modifiers.shift as u64) << 1)
                | ((current_modifiers.alt as u64) << 2)
                | ((current_modifiers.command as u64) << 3);

            let send_key = |vk: u16, pressed: bool| {
                let mon_name = format!("{}", m_idx);
                let mut name_u16 = [0u16; 32];
                for (i, c) in mon_name.encode_utf16().enumerate().take(31) {
                    name_u16[i] = c;
                }
                let packet = InputPacket {
                    event_type: 1,
                    msg: if pressed { WM_KEYDOWN } else { WM_KEYUP },
                    msg2: 0,
                    wparam: vk as u64,
                    lparam: mod_mask as i64,
                    wheel_delta: 0,
                    x_delta: 0,
                    y_delta: 0,
                    x: 0,
                    y: 0,
                    target_monitor_name: name_u16,
                    is_admin: 0,
                };
                let _ = udp_socket.send_to(
                    unsafe {
                        std::slice::from_raw_parts(
                            &packet as *const _ as *const u8,
                            std::mem::size_of::<InputPacket>(),
                        )
                    },
                    &udp_target,
                );
            };

            // 특수 키(L/R 구분) 및 모디파이어 처리
            if current_modifiers.ctrl != last_modifiers.ctrl {
                let vk = unsafe {
                    if (windows::Win32::UI::Input::KeyboardAndMouse::GetKeyState(0xA3) as u16 & 0x8000) != 0 { 0xA3 } // RCtrl
                    else { 0xA2 } // LCtrl
                };
                send_key(vk, current_modifiers.ctrl);
            }
            if current_modifiers.shift != last_modifiers.shift {
                let vk = unsafe {
                    if (windows::Win32::UI::Input::KeyboardAndMouse::GetKeyState(0xA1) as u16 & 0x8000) != 0 { 0xA1 } // RShift
                    else { 0xA0 } // LShift
                };
                send_key(vk, current_modifiers.shift);
            }
            if current_modifiers.alt != last_modifiers.alt {
                let vk = unsafe {
                    if (windows::Win32::UI::Input::KeyboardAndMouse::GetKeyState(0xA5) as u16 & 0x8000) != 0 { 0xA5 } // RAlt
                    else { 0xA4 } // LAlt
                };
                send_key(vk, current_modifiers.alt);
            }
            *last_modifiers = current_modifiers;

            let events = ctx.input(|i| i.events.clone());
            for event in events {
                match event {
                    egui::Event::Key { key, pressed, .. } => {
                        let vk = egui_key_to_vk(key);
                        if vk != 0 {
                            send_key(vk, pressed);
                        }
                    }
                    egui::Event::Text(text) => {
                        let mut filtered_text = String::new();
                        for c in text.chars() {
                            // 영문, 숫자, 공백을 제외한 모든 문자(특수기호, 한글 등)를 허용
                            // @#$% 등은 여기서 처리되어 Unicode 패킷으로 전송됨
                            if !c.is_ascii_alphanumeric() && c != ' ' {
                                filtered_text.push(c);
                            }
                        }
                        if filtered_text.is_empty() {
                            continue;
                        }
                        let mut text_u16 = [0u16; 32];
                        for (i, c) in filtered_text.encode_utf16().enumerate().take(31) {
                            text_u16[i] = c;
                        }
                        let packet = InputPacket {
                            event_type: 2,
                            msg: 0,
                            msg2: 0,
                            wparam: 0,
                            lparam: 0,
                            wheel_delta: 0,
                            x_delta: 0,
                            y_delta: 0,
                            x: 0,
                            y: 0,
                            target_monitor_name: text_u16,
                            is_admin: 0,
                        };
                        let _ = udp_socket.send_to(
                            unsafe {
                                std::slice::from_raw_parts(
                                    &packet as *const _ as *const u8,
                                    std::mem::size_of::<InputPacket>(),
                                )
                            },
                            &udp_target,
                        );
                    }
                    _ => {}
                }
            }
        }
    }
}

impl eframe::App for MultiMonitorApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // 로그인/상태 이벤트 처리
        if let Some((user_id, expiry)) =
            ctx.data_mut(|d| d.remove_temp::<(String, String)>(egui::Id::from("login_event")))
        {
            self.login_state = LoginState::LoggedIn {
                user_id: user_id.clone(),
                expiry,
            };
            ctx.data_mut(|d| d.insert_temp(egui::Id::from("is_login"), true));
            self.start_heartbeat(ctx.clone(), user_id);
        }
        if let Some(error) =
            ctx.data_mut(|d| d.remove_temp::<String>(egui::Id::from("login_error")))
        {
            self.login_state = LoginState::LoggedOut;
            self.login_error = Some(error);
        }
        if ctx.data_mut(|d| {
            d.remove_temp::<bool>(egui::Id::from("session_expired"))
                .unwrap_or(false)
        }) {
            self.login_state = LoginState::LoggedOut;
            ctx.data_mut(|d| d.insert_temp(egui::Id::from("is_login"), false));
            self.login_error = Some("세션이 만료되었습니다.".to_string());
        }

        match &self.login_state {
            LoginState::LoggedOut | LoginState::LoggingIn => {
                self.show_login_screen(ctx);
            }
            LoginState::LoggedIn {
                user_id: _,
                expiry: _,
            } => {
                ctx.request_repaint(); // 60+ FPS UI loop for smooth input polling

                let prev_selected_idx: Option<u32> = ctx
                    .data_mut(|d| *d.get_temp_mut_or_default(egui::Id::from("selected_monitor")));
                let mut selected_idx = prev_selected_idx;
                
                let conns = self.connections.lock().unwrap();
                let mut keys: Vec<_> = conns.keys().cloned().collect();
                keys.sort();
                let is_connected = conns.values().any(|c| c.texture.is_some());
                // conns 락은 나중에 필요할 때 다시 걸거나 필요한 데이터를 복사해둡니다.
                // 여기서는 일단 드롭하고 아래에서 다시 걸어서 사용합니다.
                drop(conns);

                if ctx.input(|i| i.key_pressed(egui::Key::F12)) {
                    self.input_active = !self.input_active;
                }

                egui::TopBottomPanel::top("top_bar").show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.separator();
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let (btn_label, btn_color) = if self.input_active {
                                ("🖱 원격 제어 [F12]", egui::Color32::from_rgb(255, 80, 80))
                            } else {
                                ("👁 보기 전용 [F12]", egui::Color32::from_rgb(80, 180, 80))
                            };
                            if ui
                                .button(egui::RichText::new(btn_label).color(btn_color).strong())
                                .clicked()
                            {
                                self.input_active = !self.input_active;
                            }
                            ui.separator();
                            if is_connected {
                                ui.label(
                                    egui::RichText::new("✅ 온라인")
                                        .color(egui::Color32::GREEN)
                                        .strong(),
                                );
                            } else {
                                ui.label(
                                    egui::RichText::new("⏳ 오프라인")
                                        .color(egui::Color32::RED)
                                        .strong(),
                                );
                            }
                        });
                    });
                });

                egui::TopBottomPanel::bottom("bottom_thumbnails")
                    .exact_height(160.0)
                    .show(ctx, |ui| {
                        ui.add_space(5.0);
                        ui.heading(format!("🖥 모니터 ({})", keys.len()));
                        ui.separator();
                        if keys.is_empty() {
                            ui.label("⏳ 워커 대기 중...");
                        }

                        let mut user_names = HashMap::new();
                        let path = "C:\\Users\\Public\\worker_ports.txt";
                        if let Ok(content) = std::fs::read_to_string(path) {
                            for line in content.lines() {
                                let parts: Vec<&str> = line.split(':').collect();
                                if parts.len() == 2 {
                                    if let Ok(p) = parts[1].parse::<u16>() {
                                        user_names.insert(p, parts[0].to_string());
                                    }
                                }
                            }
                        }

                        egui::ScrollArea::horizontal().show(ui, |ui| {
                            ui.horizontal(|ui| {
                                for &unique_id in &keys {
                                    let port = (unique_id / 100) as u16;
                                    let m_idx = unique_id % 100;
                                    let user_name = user_names
                                        .get(&port)
                                        .cloned()
                                        .unwrap_or_else(|| format!("P:{}", port));
                                    let is_selected = selected_idx == Some(unique_id);

                                    ui.vertical(|ui| {
                                        let label_text =
                                            format!("Monitor #{} ({})", m_idx + 1, user_name);
                                        if is_selected {
                                            ui.label(
                                                egui::RichText::new(label_text)
                                                    .color(egui::Color32::YELLOW)
                                                    .strong(),
                                            );
                                        } else {
                                            ui.label(label_text);
                                        }

                                        let conns = self.connections.lock().unwrap();
                                        if let Some(session) = conns.get(&unique_id) {
                                            if let Some(texture) = &session.texture {
                                                let aspect_ratio =
                                                    texture.size()[0] as f32 / texture.size()[1] as f32;
                                                let width = self.bottom_size;
                                                let height = width / aspect_ratio;
                                                let size = egui::vec2(width, height);
                                                let response = ui.add(
                                                    egui::Image::new((texture.id(), size))
                                                        .sense(egui::Sense::click()),
                                                );
                                                if response.clicked() {
                                                    selected_idx = Some(unique_id);
                                                    self.grid_view = false;
                                                    ctx.data_mut(|d| {
                                                        d.insert_temp(
                                                            egui::Id::from("selected_monitor"),
                                                            Some(unique_id),
                                                        )
                                                    });
                                                }
                                                // 우클릭 컨텍스트 메뉴 추가
                                                response.context_menu(|ui| {
                                                    if ui.button("🖥 이 디스플레이 선택").clicked() {
                                                        selected_idx = Some(unique_id);
                                                        self.grid_view = false;
                                                        ui.close_menu();
                                                    }
                                                    ui.separator();
                                                    ui.label(format!("Monitor ID: {}", unique_id));
                                                });
                                            }
                                        }
                                    });
                                    ui.add_space(15.0);
                                }
                            });
                        });
                    });

                egui::SidePanel::right("right_panel")
                    .resizable(true)
                    .default_width(250.0)
                    .show(ctx, |ui| {
                        ui.heading("제어판");
                        ui.separator();
                        if let Some(idx) = selected_idx {
                            let port = (idx / 100) as u16;
                            ui.label(format!(
                                "선택됨: 모니터 #{} (포트: {})",
                                (idx % 100) + 1,
                                port
                            ));
                        } else {
                            ui.label("하단에서 모니터를 선택하세요.");
                        }
                        ui.label(format!(
                            "🖥 발견된 모든 사용자의 총 모니터 수: {}",
                            keys.len()
                        ));

                        ui.add_space(20.0);
                        ui.heading("모니터");
                        ui.separator();

                        egui::ScrollArea::vertical().show(ui, |ui| {
                            for &unique_id in &keys {
                                let m_idx = unique_id % 100;
                                let port = (unique_id / 100) as u16;
                                let btn_text = format!("🖥 모니터 #{} (Port: {})", m_idx + 1, port);
                                let is_selected =
                                    selected_idx == Some(unique_id) && !self.grid_view;

                                let response = ui.selectable_label(is_selected, btn_text);
                                if response.clicked() {
                                    selected_idx = Some(unique_id);
                                    self.grid_view = false;
                                    ctx.data_mut(|d| {
                                        d.insert_temp(
                                            egui::Id::from("selected_monitor"),
                                            Some(unique_id),
                                        )
                                    });
                                }
                                // 우클릭 메뉴 추가
                                response.context_menu(|ui| {
                                    if ui.button("🖥 이 디스플레이 선택").clicked() {
                                        selected_idx = Some(unique_id);
                                        self.grid_view = false;
                                        ui.close_menu();
                                    }
                                });
                            }
                        });

                        ui.add_space(20.0);
                        ui.heading("보기 설정");
                        ui.separator();
                        if ui
                            .selectable_label(self.grid_view, "🖼 전체 모니터 그리드 보기")
                            .clicked()
                        {
                            self.grid_view = true;
                        }

                        ui.add_space(10.0);
                        ui.label("그리드 크기 조절:");
                        ui.add(egui::Slider::new(&mut self.grid_size, 100.0..=1000.0).text("px"));

                        ui.add_space(10.0);
                        ui.label("하단 목록 크기 조절:");
                        ui.add(egui::Slider::new(&mut self.bottom_size, 80.0..=500.0).text("px"));
                    });

                egui::CentralPanel::default().show(ctx, |ui| {
                    if self.grid_view {
                        let connections = self.connections.lock().unwrap();
                        let num_monitors = connections.len();
                        if num_monitors == 0 {
                            ui.centered_and_justified(|ui| {
                                ui.label("📡 연결된 모니터가 없습니다. 워커를 검색 중...");
                            });
                        } else {
                            let gap = 15.0;
                            let final_w = self.grid_size;
                            let final_h = final_w / (1920.0 / 1080.0);
                            
                            let avail_w = ui.available_width();
                            let cols = (avail_w / (final_w + gap)).floor().max(1.0) as usize;
                            let rows = (num_monitors as f32 / cols as f32).ceil() as usize;

                            let mut sorted_keys: Vec<_> = connections.keys().cloned().collect();
                            sorted_keys.sort();

                            egui::ScrollArea::vertical().show(ui, |ui| {
                                for row in 0..rows {
                                    ui.horizontal(|ui| {
                                        for col in 0..cols {
                                            let idx_in_list = row * cols + col;
                                            if let Some(&idx) = sorted_keys.get(idx_in_list) {
                                                if let Some(session) = connections.get(&idx) {
                                                    if let Some(texture) = &session.texture {
                                                    ui.vertical(|ui| {
                                                        ui.set_max_width(final_w);
                                                        ui.label(
                                                            egui::RichText::new(format!(
                                                                "🖥 모니터 #{} (Port: {})",
                                                                (idx % 100) + 1,
                                                                idx / 100
                                                            ))
                                                            .small(),
                                                        );

                                                        let img_resp = ui.add(
                                                            egui::Image::new((
                                                                texture.id(),
                                                                egui::vec2(final_w, final_h),
                                                            ))
                                                            .sense(egui::Sense::click()),
                                                        );

                                                        if img_resp.clicked() {
                                                            selected_idx = Some(idx);
                                                            self.grid_view = false;
                                                            ctx.data_mut(|d| {
                                                                d.insert_temp(egui::Id::from("selected_monitor"), Some(idx))
                                                            });
                                                        }
                                                        
                                                        if img_resp.hovered() {
                                                            ui.painter().rect_stroke(
                                                                img_resp.rect,
                                                                0.0,
                                                                egui::Stroke::new(2.0, egui::Color32::from_rgb(100, 180, 255)),
                                                            );
                                                        }
                                                    });
                                                }
                                            }
                                        }
                                    }
                                });
                                ui.add_space(gap);
                            }
                        });
                    }
                    } else if let Some(idx) = selected_idx {
                        let connections = self.connections.lock().unwrap();
                        if let Some(session) = connections.get(&idx) {
                            if let Some(texture) = &session.texture {
                            let available_size = ui.available_size();
                            let aspect_ratio = 1920.0 / 1080.0;
                            let target_size = if available_size.x / available_size.y > aspect_ratio {
                                egui::vec2(available_size.y * aspect_ratio, available_size.y)
                            } else {
                                egui::vec2(available_size.x, available_size.x / aspect_ratio)
                            };
                            let (rect, response) = ui.allocate_exact_size(
                                target_size,
                                egui::Sense::click_and_drag(),
                            );
                            let painter = ui.painter_at(rect);
                            painter.image(
                                texture.id(),
                                rect,
                                egui::Rect::from_min_max(
                                    egui::pos2(0.0, 0.0),
                                    egui::pos2(1.0, 1.0),
                                ),
                                egui::Color32::WHITE,
                            );

                            let mouse_delta = ui.input(|i| i.pointer.delta());
                            if self.input_active && (mouse_delta.x.abs() > 0.0 || mouse_delta.y.abs() > 0.0) {
                                let packet = InputPacket {
                                    event_type: 0,
                                    msg: windows::Win32::UI::Input::KeyboardAndMouse::MOUSEEVENTF_MOVE.0,
                                    msg2: 0,
                                    wparam: 0,
                                    lparam: 0,
                                    wheel_delta: 0,
                                    x_delta: mouse_delta.x as i32,
                                    y_delta: mouse_delta.y as i32,
                                    x: 0, y: 0,
                                    target_monitor_name: [0; 32],
                                    is_admin: 0,
                                };
                                let _ = self.udp_socket.send_to(unsafe {
                                    std::slice::from_raw_parts(&packet as *const _ as *const u8, std::mem::size_of::<InputPacket>())
                                }, format!("{}:{}", self.target_ip, (idx / 100) as u16));
                            }

                            let scroll_delta = ui.input(|i| i.smooth_scroll_delta);
                            if scroll_delta.y.abs() > 0.1 {
                                let packet = InputPacket {
                                    event_type: 4,
                                    msg: 0,
                                    msg2: 0,
                                    wparam: 0,
                                    lparam: 0,
                                    wheel_delta: (scroll_delta.y * 15.0) as i32,
                                    x_delta: 0,
                                    y_delta: 0,
                                    x: 0,
                                    y: 0,
                                    target_monitor_name: [0; 32],
                                    is_admin: 0,
                                };
                                let _ = self.udp_socket.send_to(unsafe {
                                    std::slice::from_raw_parts(&packet as *const _ as *const u8, std::mem::size_of::<InputPacket>())
                                }, format!("{}:{}", self.target_ip, (idx / 100) as u16));
                            }
                            
                            if let Some(pos) = response.hover_pos() {
                                if rect.contains(pos) {
                                    self.virtual_cursor_pos = Some(pos);
                                    if self.input_active {
                                        // 마우스 포인터가 항상 보이도록 설정 (사용자 요청)
                                        ctx.set_cursor_icon(egui::CursorIcon::Default);
                                    }
                                } else {
                                    self.virtual_cursor_pos = None;
                                }
                            } else {
                                self.virtual_cursor_pos = None;
                            }

                            if self.input_active {
                                Self::handle_input_static(
                                    idx,
                                    rect,
                                    ctx,
                                    &self.udp_socket,
                                    &mut self.last_modifiers,
                                    &self.target_ip,
                                );
                                ctx.input_mut(|i| {
                                    i.events.retain(|e| matches!(e, egui::Event::Scroll(_)));
                                });
                            }

                            if !self.input_active {
                                painter.rect_filled(
                                    rect,
                                    0.0,
                                    egui::Color32::from_rgba_unmultiplied(0, 0, 0, 160),
                                );
                                let center = rect.center();
                                painter.text(
                                    center - egui::vec2(0.0, 22.0),
                                    egui::Align2::CENTER_CENTER,
                                    "👁 보기 전용 모드",
                                    egui::FontId::proportional(28.0),
                                    egui::Color32::WHITE,
                                );
                            } else {
                                painter.rect_stroke(
                                    rect.shrink(2.0),
                                    0.0,
                                    egui::Stroke::new(3.0, egui::Color32::from_rgb(255, 60, 60)),
                                );
                            }
                        }
                    }
                } else {
                        ui.centered_and_justified(|ui| {
                            ui.label(
                                egui::RichText::new("모니터를 선택하거나 전체 보기를 클릭하세요")
                                    .size(20.0),
                            );
                        });
                    }
                });

                // 선택된 모니터가 바뀌었으면 워커에게 포커스 패킷 전송
                if selected_idx != prev_selected_idx {
                    ctx.data_mut(|d| {
                        d.insert_temp(egui::Id::from("selected_monitor"), selected_idx)
                    });
                    // 포커스 신호를 연결된 모든 워커 포트로 전송
                    if let Some(sidx) = selected_idx {
                        let focused_m_idx = sidx % 100; // 모니터 인덱스만 추출
                        let path = "C:\\Users\\Public\\worker_ports.txt";
                        if let Ok(content) = std::fs::read_to_string(path) {
                            for line in content.lines() {
                                let parts: Vec<&str> = line.split(':').collect();
                                if parts.len() == 2 {
                                    if let Ok(p) = parts[1].parse::<u16>() {
                                        let udp_target = format!("{}:{}", self.target_ip, p);
                                        let name_u16 = [0u16; 32];
                                        let packet = InputPacket {
                                            event_type: 3, // FocusMonitor
                                            msg: focused_m_idx,
                                            msg2: 0,
                                            wparam: 0,
                                            lparam: 0,
                                            wheel_delta: 0,
                                            x_delta: 0,
                                            y_delta: 0,
                                            x: 0,
                                            y: 0,
                                            target_monitor_name: name_u16,
                                            is_admin: 0,
                                        };
                                        let _ = self.udp_socket.send_to(
                                            unsafe {
                                                std::slice::from_raw_parts(
                                                    &packet as *const _ as *const u8,
                                                    std::mem::size_of::<InputPacket>(),
                                                )
                                            },
                                            &udp_target,
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        if let LoginState::LoggedIn { user_id, .. } = &self.login_state {
            let uid = user_id.clone();
            let api_server_ip = "93.127.129.57".to_string();
            // 동기식 요청으로 프로그램 종료 전 로그아웃 처리
            let _ = reqwest::blocking::Client::builder()
                .danger_accept_invalid_certs(true)
                .build()
                .unwrap()
                .post(format!("https://{}:8095/api/logout", api_server_ip))
                .json(&StatusRequest {
                    user_id: uid.clone(),
                })
                .send();
        }
    }
}

// 모니터 정보를 캐싱하여 성능 저하 방지
static MONITOR_CACHE: once_cell::sync::Lazy<Mutex<(Vec<MonitorInfo>, std::time::Instant)>> =
    once_cell::sync::Lazy::new(|| Mutex::new((Vec::new(), std::time::Instant::now() - Duration::from_secs(10))));

fn get_cached_monitors() -> Vec<MonitorInfo> {
    let mut cache = MONITOR_CACHE.lock().unwrap();
    if cache.1.elapsed() > Duration::from_secs(5) || cache.0.is_empty() {
        cache.0 = get_detailed_monitors_quiet();
        cache.1 = std::time::Instant::now();
    }
    cache.0.clone()
}

fn handle_remote_input(packet: InputPacket) {
    let mut target_rect = RECT::default();
    let monitors = get_cached_monitors();
    if let Some(m) = monitors.get(packet.msg2 as usize) {
        target_rect = m.rect;
    } else if let Some(m) = monitors.first() {
        target_rect = m.rect;
    }

    match packet.event_type {
        0 => { // Mouse Move / Click
            unsafe {
                let mut input = INPUT::default();
                input.r#type = INPUT_MOUSE;
                let mut mi = MOUSEINPUT::default();

                if packet.x_delta != 0 || packet.y_delta != 0 {
                    // 원시 상대 좌표(Raw Delta) 이동
                    mi.dx = packet.x_delta;
                    mi.dy = packet.y_delta;
                    mi.dwFlags = windows::Win32::UI::Input::KeyboardAndMouse::MOUSEEVENTF_MOVE;
                } else {
                    // 절대 좌표 이동
                    let sm_cx = GetSystemMetrics(SM_CXVIRTUALSCREEN);
                    let sm_cy = GetSystemMetrics(SM_CYVIRTUALSCREEN);
                    let sm_x = GetSystemMetrics(SM_XVIRTUALSCREEN);
                    let sm_y = GetSystemMetrics(SM_YVIRTUALSCREEN);
                    let abs_x = target_rect.left + (packet.x as f64 / 65535.0 * (target_rect.right - target_rect.left) as f64) as i32;
                    let abs_y = target_rect.top + (packet.y as f64 / 65535.0 * (target_rect.bottom - target_rect.top) as f64) as i32;
                    
                    // MOUSEEVENTF_ABSOLUTE 0..65535 (사실상 0..65536 범위 매핑)
                    mi.dx = ((abs_x - sm_x) as f64 * 65536.0 / sm_cx as f64) as i32;
                    mi.dy = ((abs_y - sm_y) as f64 * 65536.0 / sm_cy as f64) as i32;
                    mi.dwFlags = windows::Win32::UI::Input::KeyboardAndMouse::MOUSEEVENTF_ABSOLUTE | windows::Win32::UI::Input::KeyboardAndMouse::MOUSEEVENTF_VIRTUALDESK | windows::Win32::UI::Input::KeyboardAndMouse::MOUSEEVENTF_MOVE;
                }

                match packet.msg {
                    WM_LBUTTONDOWN => mi.dwFlags |= windows::Win32::UI::Input::KeyboardAndMouse::MOUSEEVENTF_LEFTDOWN,
                    WM_LBUTTONUP => mi.dwFlags |= windows::Win32::UI::Input::KeyboardAndMouse::MOUSEEVENTF_LEFTUP,
                    WM_RBUTTONDOWN => mi.dwFlags |= windows::Win32::UI::Input::KeyboardAndMouse::MOUSEEVENTF_RIGHTDOWN,
                    WM_RBUTTONUP => mi.dwFlags |= windows::Win32::UI::Input::KeyboardAndMouse::MOUSEEVENTF_RIGHTUP,
                    _ => {}
                }
                input.Anonymous.mi = mi;
                let _ = SendInput(&[input], std::mem::size_of::<INPUT>() as i32);
            }
        }
        1 => { // Keyboard (Scan Code)
            unsafe {
                let vk = packet.wparam as u16;
                let scancode = windows::Win32::UI::Input::KeyboardAndMouse::MapVirtualKeyW(
                    vk as u32,
                    windows::Win32::UI::Input::KeyboardAndMouse::MAPVK_VK_TO_VSC,
                ) as u16;

                let mut input = INPUT::default();
                input.r#type = INPUT_KEYBOARD;
                let mut ki = KEYBDINPUT::default();
                
                if scancode > 0 {
                    ki.wScan = scancode;
                    ki.dwFlags = windows::Win32::UI::Input::KeyboardAndMouse::KEYEVENTF_SCANCODE;
                } else {
                    ki.wVk = windows::Win32::UI::Input::KeyboardAndMouse::VIRTUAL_KEY(vk);
                    ki.dwFlags = windows::Win32::UI::Input::KeyboardAndMouse::KEYBD_EVENT_FLAGS(0);
                }

                if packet.msg == WM_KEYUP {
                    ki.dwFlags |= windows::Win32::UI::Input::KeyboardAndMouse::KEYEVENTF_KEYUP;
                }
                
                // 확장 키 및 특수 키 처리
                // RAlt(0xA5), RCtrl(0xA3), 방향키, 한/영(0x15), 한자(0x19) 등
                if matches!(vk, 0x21..=0x28 | 0x2D | 0x2E | 0x6F | 0x90 | 0xA3 | 0xA5 | 0x5B | 0x5C | 0x5D | 0x15 | 0x19) {
                    ki.dwFlags |= windows::Win32::UI::Input::KeyboardAndMouse::KEYEVENTF_EXTENDEDKEY;
                }

                input.Anonymous.ki = ki;
                let _ = SendInput(&[input], std::mem::size_of::<INPUT>() as i32);
            }
        }
        2 => { // Text (Unicode)
            unsafe {
                let text_u16 = packet.target_monitor_name;
                for &c in text_u16.iter() {
                    if c == 0 { break; }
                    let mut inputs = [INPUT::default(); 2];
                    
                    inputs[0].r#type = INPUT_KEYBOARD;
                    inputs[0].Anonymous.ki = KEYBDINPUT {
                        wScan: c,
                        dwFlags: windows::Win32::UI::Input::KeyboardAndMouse::KEYEVENTF_UNICODE,
                        ..Default::default()
                    };
                    
                    inputs[1] = inputs[0];
                    inputs[1].Anonymous.ki.dwFlags |= windows::Win32::UI::Input::KeyboardAndMouse::KEYEVENTF_KEYUP;
                    
                    let _ = SendInput(&inputs, std::mem::size_of::<INPUT>() as i32);
                }
            }
        }
        4 => { // Wheel
            unsafe {
                let mut input = INPUT::default();
                input.r#type = INPUT_MOUSE;
                input.Anonymous.mi = MOUSEINPUT {
                    mouseData: packet.wheel_delta as u32,
                    dwFlags: windows::Win32::UI::Input::KeyboardAndMouse::MOUSEEVENTF_WHEEL,
                    ..Default::default()
                };
                let _ = SendInput(&[input], std::mem::size_of::<INPUT>() as i32);
            }
        }
        _ => {}
    }
}

// REMOTE_MODIFIER_STATE 및 sync_remote_modifiers는 더 이상 사용되지 않아 삭제되었습니다.

fn set_monitor_resolution(device_name: &str, width: u32, height: u32) {
    unsafe {
        let mut dev_mode = DEVMODEW::default();
        dev_mode.dmSize = std::mem::size_of::<DEVMODEW>() as u16;
        dev_mode.dmPelsWidth = width;
        dev_mode.dmPelsHeight = height;
        dev_mode.dmFields = DM_PELSWIDTH | DM_PELSHEIGHT;
        
        let device_name_wide: Vec<u16> = device_name.encode_utf16().chain(Some(0)).collect();
        let result = ChangeDisplaySettingsExW(
            windows::core::PCWSTR(device_name_wide.as_ptr()),
            Some(&dev_mode),
            None,
            windows::Win32::Graphics::Gdi::CDS_TYPE(0), // Temporary for current session
            None,
        );
        println!("📺 [Worker] 해상도 변경 시도: {} -> {}x{} (Result: {:?})", device_name, width, height, result);
    }
}

fn run_worker(port: u16) {
    let username = std::env::var("USERNAME").unwrap_or_else(|_| "unknown".to_string());
    
    // --- 로그인 직후 즉시 해상도 변경 시도 ---
    let initial_monitors = get_detailed_monitors();
    for info in initial_monitors {
        set_monitor_resolution(&info._name, 1920, 1080);
    }

    let udp_port = port;
    let active_monitor: Arc<std::sync::atomic::AtomicU32> =
        Arc::new(std::sync::atomic::AtomicU32::new(u32::MAX));

    let active_monitor_udp = active_monitor.clone();
    thread::spawn(move || {
        let udp_socket = UdpSocket::bind(format!("0.0.0.0:{}", udp_port)).expect("UDP bind failed");
        let mut buf = [0u8; std::mem::size_of::<InputPacket>()];
        loop {
            if let Ok((size, _)) = udp_socket.recv_from(&mut buf) {
                if size == std::mem::size_of::<InputPacket>() {
                    let packet: InputPacket = unsafe { std::ptr::read(buf.as_ptr() as *const _) };
                    if packet.event_type == 3 {
                        active_monitor_udp.store(packet.msg, Ordering::SeqCst);
                    } else {
                        handle_remote_input(packet);
                    }
                }
            }
        }
    });

    let monitors = loop {
        let m = get_detailed_monitors();
        if !m.is_empty() { break m; }
        thread::sleep(Duration::from_secs(2));
    };

    for (m_idx, info) in monitors.into_iter().enumerate() {
        let active_mon = active_monitor.clone();
        let shm_name = shm_name_for(&username, m_idx);
        let evt_name = evt_name_for(&username, m_idx);
        
        thread::spawn(move || {
            let Some((shm, _handle)) = create_shm_slot(&shm_name) else { return; };
            let Some(evt) = create_global_event(&evt_name) else { return; };
            let shm_ptr = shm.0 as *mut u8;
            let evt_h = windows::Win32::Foundation::HANDLE(evt.0);

            unsafe {
                let width = (info.rect.right - info.rect.left) as u32;
                let height = (info.rect.bottom - info.rect.top) as u32;

                // 1. 모니터 전용 DC 생성
                let device_name_wide: Vec<u16> = info._name.encode_utf16().chain(Some(0)).collect();
                let h_dc_screen = CreateDCW(
                    windows::core::w!("DISPLAY"),
                    windows::core::PCWSTR(device_name_wide.as_ptr()),
                    None,
                    None,
                );
                
                if h_dc_screen.is_invalid() {
                    eprintln!("❌ [Worker] DC 생성 실패: {}", info._name);
                    return;
                }

                // 2. 메모리 DC 및 DIB Section 생성 (더블 버퍼링 및 직접 포인터 접근)
                let h_dc_mem = CreateCompatibleDC(h_dc_screen);
                
                let bmi = BITMAPINFO {
                    bmiHeader: BITMAPINFOHEADER {
                        biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                        biWidth: width as i32,
                        biHeight: -(height as i32), // Top-down
                        biPlanes: 1,
                        biBitCount: 32,
                        biCompression: BI_RGB.0,
                        ..Default::default()
                    },
                    ..Default::default()
                };

                let mut bits_ptr: *mut std::ffi::c_void = std::ptr::null_mut();
                let h_bmp = CreateDIBSection(
                    h_dc_mem,
                    &bmi,
                    DIB_RGB_COLORS,
                    &mut bits_ptr,
                    None,
                    0,
                ).unwrap();

                if h_bmp.is_invalid() || bits_ptr.is_null() {
                    eprintln!("❌ [Worker] DIB Section 생성 실패");
                    let _ = DeleteDC(h_dc_screen);
                    let _ = DeleteDC(h_dc_mem);
                    return;
                }

                SelectObject(h_dc_mem, h_bmp);
                let pixel_data = std::slice::from_raw_parts(bits_ptr as *const u8, (width * height * 4) as usize);

                println!("🚀 [Worker] GDI BitBlt 캡처 시작: {} ({}x{})", info._name, width, height);

                let elevated = is_elevated();
                loop {
                    let focused = active_mon.load(Ordering::SeqCst);
                    let is_focused = focused == u32::MAX || focused == m_idx as u32;

                    // CPU 기반 초고속 BitBlt 전송
                    if BitBlt(h_dc_mem, 0, 0, width as i32, height as i32, h_dc_screen, 0, 0, SRCCOPY).is_ok() {
                        // SHM에 직접 쓰기
                        write_shm_frame(shm_ptr, pixel_data, width, height, elevated);
                        let _ = windows::Win32::System::Threading::SetEvent(evt_h);
                    }

                    if is_focused {
                        // 초고속 모드: 대기 시간을 최소화하여 GPU 수준의 속도 구현
                        thread::sleep(Duration::from_millis(1)); 
                    } else {
                        // 비활성 모니터는 자원 절약
                        thread::sleep(Duration::from_millis(30));
                    }
                }
            }
        });
    }
    loop { thread::sleep(Duration::from_secs(60)); }
}

#[derive(Clone)]
struct MonitorInfo {
    _name: String,
    rect: RECT,
    _is_primary: bool,
    _hmonitor: HMONITOR,
}

fn get_detailed_monitors() -> Vec<MonitorInfo> {
    get_detailed_monitors_internal(true)
}
fn get_detailed_monitors_quiet() -> Vec<MonitorInfo> {
    get_detailed_monitors_internal(false)
}

fn get_detailed_monitors_internal(_verbose: bool) -> Vec<MonitorInfo> {
    let mut results = Vec::new();
    let mut data = EnumData { list: Vec::new() };
    unsafe {
        let _ = EnumDisplayMonitors(
            HDC(0),
            None,
            Some(enum_callback),
            LPARAM(&mut data as *mut _ as isize),
        );
    }
    
    // 1. EnumDisplayMonitors로 찾은 물리/가상 모니터들
    for (name, rect, is_primary, hmonitor) in data.list {
        results.push(MonitorInfo {
            _name: name,
            rect,
            _is_primary: is_primary,
            _hmonitor: hmonitor,
        });
    }

    // 3. 메인 모니터 및 특정 모니터 필터링
    let _my_name = std::env::var("USERNAME").unwrap_or_default();
    results.retain(|m| {
        // 메인 모니터(사용자가 지정한 이름) 제외
        if m._name.contains("JtnCw8iKfGVx$") {
            return false;
        }
        // 기본 모니터 필터링 예시
        true
    });
    results
}

struct EnumData {
    list: Vec<(String, RECT, bool, HMONITOR)>,
}
unsafe extern "system" fn enum_callback(
    hmonitor: HMONITOR,
    _: HDC,
    _rect: *mut RECT,
    lparam: LPARAM,
) -> BOOL {
    let data = unsafe { &mut *(lparam.0 as *mut EnumData) };
    let mut mi = MONITORINFOEXW::default();
    mi.monitorInfo.cbSize = std::mem::size_of::<MONITORINFOEXW>() as u32;
    if unsafe {
        windows::Win32::Graphics::Gdi::GetMonitorInfoW(hmonitor, &mut mi.monitorInfo).as_bool()
    } {
        let name = String::from_utf16_lossy(&mi.szDevice)
            .trim_matches('\0')
            .to_string();
        let is_primary = (mi.monitorInfo.dwFlags & 1) != 0;
        data.list
            .push((name, mi.monitorInfo.rcMonitor, is_primary, hmonitor));
    }
    BOOL(1)
}

fn egui_key_to_vk(key: egui::Key) -> u16 {
    match key {
        egui::Key::A => 0x41,
        egui::Key::B => 0x42,
        egui::Key::C => 0x43,
        egui::Key::D => 0x44,
        egui::Key::E => 0x45,
        egui::Key::F => 0x46,
        egui::Key::G => 0x47,
        egui::Key::H => 0x48,
        egui::Key::I => 0x49,
        egui::Key::J => 0x4A,
        egui::Key::K => 0x4B,
        egui::Key::L => 0x4C,
        egui::Key::M => 0x4D,
        egui::Key::N => 0x4E,
        egui::Key::O => 0x4F,
        egui::Key::P => 0x50,
        egui::Key::Q => 0x51,
        egui::Key::R => 0x52,
        egui::Key::S => 0x53,
        egui::Key::T => 0x54,
        egui::Key::U => 0x55,
        egui::Key::V => 0x56,
        egui::Key::W => 0x57,
        egui::Key::X => 0x58,
        egui::Key::Y => 0x59,
        egui::Key::Z => 0x5A,
        egui::Key::Num0 => 0x30,
        egui::Key::Num1 => 0x31,
        egui::Key::Num2 => 0x32,
        egui::Key::Num3 => 0x33,
        egui::Key::Num4 => 0x34,
        egui::Key::Num5 => 0x35,
        egui::Key::Num6 => 0x36,
        egui::Key::Num7 => 0x37,
        egui::Key::Num8 => 0x38,
        egui::Key::Num9 => 0x39,
        egui::Key::Enter => 0x0D,
        egui::Key::Space => 0x20,
        egui::Key::Backspace => 0x08,
        egui::Key::Tab => 0x09,
        egui::Key::Delete => 0x2E,
        egui::Key::Escape => 0x1B,
        egui::Key::ArrowLeft => 0x25,
        egui::Key::ArrowRight => 0x27,
        egui::Key::ArrowUp => 0x26,
        egui::Key::ArrowDown => 0x28,
        egui::Key::PageUp => 0x21,
        egui::Key::PageDown => 0x22,
        egui::Key::Home => 0x24,
        egui::Key::End => 0x23,
        egui::Key::Insert => 0x2D,
        egui::Key::F1 => 0x70,
        egui::Key::F2 => 0x71,
        egui::Key::F3 => 0x72,
        egui::Key::F4 => 0x73,
        egui::Key::F5 => 0x74,
        egui::Key::F6 => 0x75,
        egui::Key::F7 => 0x76,
        egui::Key::F8 => 0x77,
        egui::Key::F9 => 0x78,
        egui::Key::F10 => 0x79,
        egui::Key::F11 => 0x7A,
        egui::Key::F12 => 0x7B,
        
        // --- 추가된 기호 및 특수 키 ---
        egui::Key::Comma => 0xBC,      // , <
        egui::Key::Period => 0xBE,     // . >
        egui::Key::Slash => 0xBF,      // / ?
        egui::Key::Semicolon => 0xBA,  // ; :
        egui::Key::OpenBracket => 0xDB, // [ {
        egui::Key::CloseBracket => 0xDD, // ] }
        egui::Key::Backslash => 0xDC,  // \ |
        egui::Key::Minus => 0xBD,      // - _
        egui::Key::Equals => 0xBB,     // = +
        _ => 0,
    }
}

fn setup_custom_style(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    let font_path = "C:\\Windows\\Fonts\\malgun.ttf";
    if let Ok(font_data) = std::fs::read(font_path) {
        fonts
            .font_data
            .insert("malgun".to_owned(), egui::FontData::from_owned(font_data));
        fonts
            .families
            .get_mut(&egui::FontFamily::Proportional)
            .unwrap()
            .insert(0, "malgun".to_owned());
        fonts
            .families
            .get_mut(&egui::FontFamily::Monospace)
            .unwrap()
            .push("malgun".to_owned());
        ctx.set_fonts(fonts);
    }
    ctx.set_visuals(egui::Visuals::dark());
}

fn is_elevated() -> bool {
    use windows::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    unsafe {
        let mut token = windows::Win32::Foundation::HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_ok() {
            let mut elevation = TOKEN_ELEVATION::default();
            let mut size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
            if GetTokenInformation(
                token,
                TokenElevation,
                Some(&mut elevation as *mut _ as *mut _),
                size,
                &mut size,
            )
            .is_ok()
            {
                return elevation.TokenIsElevated != 0;
            }
        }
    }
    false
}

fn run_as_admin(args: &[String]) -> bool {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOW;
    use windows::Win32::Foundation::HWND;
    use std::process::Command;

    // 1. 먼저 작업 스케줄러에 등록된 작업이 있는지 확인하고 있다면 그것을 실행 (UAC 창 없음)
    let global_task = "DualWindowWorker_Global".to_string();
    let user_task = format!("DualWindowWorker_{}", std::env::var("USERNAME").unwrap_or_default());
    
    for task_name in &[global_task, user_task] {
        let output = Command::new("schtasks")
            .args(&["/run", "/tn", task_name])
            .output();

        if let Ok(out) = output {
            if out.status.success() {
                println!("✅ 작업 스케줄러({})를 통해 자동으로 승격 실행되었습니다.", task_name);
                return true;
            }
        }
    }

    // 2. 작업 스케줄러 실패 시 기존처럼 runas 사용 (UAC 창 나타남)
    if let Ok(exe_path) = std::env::current_exe() {
        let mut params = args.iter().skip(1).cloned().collect::<Vec<_>>().join(" ");
        if !params.contains("--no-elevate") {
            if !params.is_empty() {
                params.push(' ');
            }
            params.push_str("--no-elevate");
        }

        let exe_path_wide: Vec<u16> = exe_path.as_os_str().encode_wide().chain(Some(0)).collect();
        let params_wide: Vec<u16> = OsStr::new(&params).encode_wide().chain(Some(0)).collect();
        let verb_wide: Vec<u16> = OsStr::new("runas").encode_wide().chain(Some(0)).collect();

        unsafe {
            let result = ShellExecuteW(
                HWND::default(),
                windows::core::PCWSTR(verb_wide.as_ptr()),
                windows::core::PCWSTR(exe_path_wide.as_ptr()),
                windows::core::PCWSTR(params_wide.as_ptr()),
                None,
                SW_SHOW,
            );
            return result.0 as usize > 32;
        }
    }
    false
}
