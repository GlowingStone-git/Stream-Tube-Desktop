//! System tray.
//!
//! The icon is created on the UI thread. Clicks and menu choices are delivered
//! on a channel and applied on GPUI's foreground executor, so the window
//! procedure (Windows) or the StatusNotifier thread (Linux) never re-enters
//! the UI while it is handling a message.
//!
//! Both settings start off. Until one is turned on there is no icon, and
//! minimize and close behave as they always have. If the desktop has no tray
//! (a Linux session without a StatusNotifier host, for example) the icon is
//! not created and those buttons keep their old behavior.
//!
//! A window hidden here counts as minimized: with Background play off, playback
//! pauses and resumes with the window; with it on, playback continues.

use gpui_kit::{App, Window};
use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Once, OnceLock};

const ID_SHOW: &str = "tray-show";
const ID_PLAY: &str = "tray-play";
const ID_PREV: &str = "tray-prev";
const ID_NEXT: &str = "tray-next";
const ID_QUIT: &str = "tray-quit";

static HIDDEN: AtomicBool = AtomicBool::new(false);
static PAUSED_FOR_TRAY: AtomicBool = AtomicBool::new(false);
static FORCE_QUIT: AtomicBool = AtomicBool::new(false);
static LISTENING: AtomicBool = AtomicBool::new(false);
static WARNED: AtomicBool = AtomicBool::new(false);

thread_local! {
    static ICON: RefCell<Option<tray_icon::TrayIcon>> = const { RefCell::new(None) };
    static MENU_SIG: RefCell<String> = const { RefCell::new(String::new()) };
}

/// The window is currently hidden in the tray (not merely minimized to the taskbar).
pub fn is_hidden() -> bool {
    HIDDEN.load(Ordering::SeqCst)
}

/// Taskbar-iconic or hidden in the tray. The background-play check uses this.
pub fn counts_as_minimized(iconic: bool, hidden_to_tray: bool) -> bool {
    iconic || hidden_to_tray
}

pub fn wants_minimize_to_tray(setting: bool, tray_ready: bool) -> bool {
    setting && tray_ready
}

pub fn wants_close_to_tray(setting: bool, tray_ready: bool, force_quit: bool) -> bool {
    setting && tray_ready && !force_quit
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrayMenu {
    pub tooltip: String,
    pub show_label: &'static str,
    pub play_label: &'static str,
    pub play_enabled: bool,
    pub prev_enabled: bool,
    pub next_enabled: bool,
    pub title: Option<String>,
}

/// Labels for the tray menu. `&` is escaped because the menu treats it as a mnemonic.
pub fn menu_for(
    hidden: bool,
    title: Option<&str>,
    paused: bool,
    has_video: bool,
    has_prev: bool,
    has_next: bool,
) -> TrayMenu {
    let raw = title.and_then(clip_title);
    let tooltip = match &raw {
        Some(t) => format!("Stream Tube — {t}"),
        None => "Stream Tube".into(),
    };
    TrayMenu {
        tooltip,
        show_label: if hidden { "Show" } else { "Hide" },
        play_label: if paused || !has_video { "Play" } else { "Pause" },
        play_enabled: has_video,
        prev_enabled: has_prev,
        next_enabled: has_next,
        // `&` starts a mnemonic in the menu. The tooltip shows the title as-is.
        title: raw.map(|t| t.replace('&', "&&")),
    }
}

fn clip_title(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let mut out: String = s.chars().take(80).collect();
    if s.chars().count() > 80 {
        out.push('…');
    }
    Some(out)
}

enum Cmd {
    Show,
    Toggle,
    PlayPause,
    Next,
    Prev,
    Quit,
}

/// Start listening for tray clicks, then show the icon if a setting asks for it.
pub fn install(cx: &mut App) {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let (tx, mut rx) = futures::channel::mpsc::unbounded::<Cmd>();
        let click = tx.clone();
        tray_icon::TrayIconEvent::set_event_handler(Some(move |event| {
            let cmd = match event {
                tray_icon::TrayIconEvent::Click {
                    button: tray_icon::MouseButton::Left,
                    button_state: tray_icon::MouseButtonState::Up,
                    ..
                }
                | tray_icon::TrayIconEvent::DoubleClick {
                    button: tray_icon::MouseButton::Left, ..
                } => Some(Cmd::Show),
                _ => None,
            };
            if let Some(cmd) = cmd {
                let _ = click.unbounded_send(cmd);
            }
        }));
        let menu = tx;
        tray_icon::menu::MenuEvent::set_event_handler(Some(move |event: tray_icon::menu::MenuEvent| {
            let cmd = match event.id.as_ref() {
                ID_SHOW => Cmd::Toggle,
                ID_PLAY => Cmd::PlayPause,
                ID_NEXT => Cmd::Next,
                ID_PREV => Cmd::Prev,
                ID_QUIT => Cmd::Quit,
                _ => return,
            };
            let _ = menu.unbounded_send(cmd);
        }));
        LISTENING.store(true, Ordering::SeqCst);
        use futures::StreamExt;
        App::spawn(cx, async move |cx| {
            while let Some(cmd) = rx.next().await {
                let _ = cx.update(|cx| apply(cmd, cx));
            }
        })
        .detach();
    });
    sync(cx);
}

/// Create, refresh, or remove the icon to match the settings.
pub fn sync(cx: &mut App) {
    if !LISTENING.load(Ordering::SeqCst) {
        return;
    }
    let s = crate::store::settings_snapshot();
    let want = s.minimize_to_tray || s.close_to_tray;
    let have = ICON.with(|icon| icon.borrow().is_some());
    if want && !have {
        match build_icon() {
            Ok(icon) => ICON.with(|slot| *slot.borrow_mut() = Some(icon)),
            Err(err) => {
                if !WARNED.swap(true, Ordering::SeqCst) {
                    eprintln!("streamtube: tray icon unavailable: {err}");
                    crate::ui::toast(cx, "Couldn't add a tray icon. Minimize and close stay as they are.");
                }
                return;
            }
        }
    }
    if !want && have {
        if is_hidden() {
            show(cx);
        }
        ICON.with(|slot| *slot.borrow_mut() = None);
        MENU_SIG.with(|sig| sig.borrow_mut().clear());
        return;
    }
    refresh_menu(cx);
}

/// Player state changed. Cheap when the menu would look the same.
pub fn note_player(cx: &mut App) {
    if ICON.with(|icon| icon.borrow().is_some()) {
        refresh_menu(cx);
    }
}

/// Minimize button. True when the window was hidden in the tray.
pub fn hide_for_minimize(window: &mut Window, cx: &mut App) -> bool {
    let s = crate::store::settings_snapshot();
    if !wants_minimize_to_tray(s.minimize_to_tray, tray_ready()) {
        return false;
    }
    crate::save_window_bounds(window);
    hide(window, cx);
    true
}

/// Close button / Alt+F4. True when the window was hidden instead of closed.
pub fn intercept_close(window: &mut Window, cx: &mut App) -> bool {
    let s = crate::store::settings_snapshot();
    if !wants_close_to_tray(s.close_to_tray, tray_ready(), FORCE_QUIT.load(Ordering::SeqCst)) {
        return false;
    }
    hide(window, cx);
    true
}

fn tray_ready() -> bool {
    ICON.with(|icon| icon.borrow().is_some())
}

fn hide(window: &mut Window, cx: &mut App) {
    HIDDEN.store(true, Ordering::SeqCst);
    // Pause before the platform hides us, so a visibility callback sees playback
    // already stopped and doesn't also try to resume it later.
    if should_pause_for_hide(cx) {
        crate::player::controller::player(cx).update(cx, |p, cx| {
            p.set_paused(true);
            cx.notify();
        });
        PAUSED_FOR_TRAY.store(true, Ordering::SeqCst);
    }
    hide_os(window);
    refresh_menu(cx);
}

fn show(cx: &mut App) {
    let Some(handle) = main_window(cx) else { return };
    let _ = handle.update(cx, |_, window, cx| {
        show_os(window);
        window.activate_window();
        HIDDEN.store(false, Ordering::SeqCst);
        if PAUSED_FOR_TRAY.swap(false, Ordering::SeqCst) {
            crate::player::controller::player(cx).update(cx, |p, cx| {
                p.set_paused(false);
                cx.notify();
            });
        }
        refresh_menu(cx);
    });
}

fn should_pause_for_hide(cx: &App) -> bool {
    if crate::store::settings_snapshot().background_play || crate::ui::pip::handle(cx).is_some() {
        return false;
    }
    let pl = crate::player::controller::player(cx).read(cx);
    pl.video.is_some() && !pl.paused
}

fn apply(cmd: Cmd, cx: &mut App) {
    match cmd {
        Cmd::Show => show(cx),
        Cmd::Toggle => {
            if is_hidden() {
                show(cx);
            } else if let Some(handle) = main_window(cx) {
                let _ = handle.update(cx, |_, window, cx| hide(window, cx));
            }
        }
        Cmd::PlayPause => {
            crate::player::controller::player(cx).update(cx, |p, cx| {
                if p.video.is_some() {
                    p.toggle_pause();
                    cx.notify();
                }
            });
            refresh_menu(cx);
        }
        Cmd::Next => {
            if let Some(handle) = main_window(cx) {
                let _ = handle.update(cx, |_, window, cx| crate::ui::app::play_next(window, cx));
            }
            refresh_menu(cx);
        }
        Cmd::Prev => {
            crate::ui::app::play_previous(cx);
            refresh_menu(cx);
        }
        Cmd::Quit => {
            FORCE_QUIT.store(true, Ordering::SeqCst);
            let handles: Vec<_> = cx.windows().into_iter().collect();
            for handle in handles {
                let _ = handle.update(cx, |_, window, _| window.remove_window());
            }
        }
    }
}

fn main_window(cx: &App) -> Option<gpui_kit::AnyWindowHandle> {
    let pip = crate::ui::pip::handle(cx);
    cx.windows().into_iter().find(|w| Some(*w) != pip)
}

fn refresh_menu(cx: &App) {
    let model = current_menu(cx);
    let sig = format!(
        "{}|{}|{}|{}|{}|{}|{:?}",
        is_hidden(),
        model.show_label,
        model.play_label,
        model.play_enabled,
        model.prev_enabled,
        model.next_enabled,
        model.title
    );
    let same = MENU_SIG.with(|cur| cur.borrow().as_str() == sig);
    if same {
        return;
    }
    MENU_SIG.with(|cur| *cur.borrow_mut() = sig);
    ICON.with(|slot| {
        let slot = slot.borrow();
        let Some(icon) = slot.as_ref() else { return };
        let _ = icon.set_tooltip(Some(model.tooltip.clone()));
        icon.set_menu(Some(Box::new(build_menu(&model))));
    });
}

fn current_menu(cx: &App) -> TrayMenu {
    let pl = crate::player::controller::player(cx).read(cx);
    let has_video = pl.video.is_some();
    let title = pl.video.as_ref().map(|v| v.title.clone());
    let has_prev = pl.queue_pos.is_some_and(|i| i > 0);
    let has_queue_next = pl.queue_pos.is_some_and(|i| i + 1 < pl.queue.len());
    let has_next = has_queue_next || crate::ui::app::has_autoplay_next(cx);
    menu_for(is_hidden(), title.as_deref(), pl.paused, has_video, has_prev, has_next)
}

fn build_menu(model: &TrayMenu) -> tray_icon::menu::Menu {
    use tray_icon::menu::{Menu, MenuItem, PredefinedMenuItem};
    let menu = Menu::new();
    let mut items: Vec<Box<dyn tray_icon::menu::IsMenuItem>> = Vec::new();
    if let Some(title) = &model.title {
        items.push(Box::new(MenuItem::with_id("tray-title", title, false, None)));
        items.push(Box::new(PredefinedMenuItem::separator()));
    }
    items.push(Box::new(MenuItem::with_id(ID_SHOW, model.show_label, true, None)));
    items.push(Box::new(PredefinedMenuItem::separator()));
    items.push(Box::new(MenuItem::with_id(ID_PLAY, model.play_label, model.play_enabled, None)));
    items.push(Box::new(MenuItem::with_id(ID_PREV, "Previous", model.prev_enabled, None)));
    items.push(Box::new(MenuItem::with_id(ID_NEXT, "Next", model.next_enabled, None)));
    items.push(Box::new(PredefinedMenuItem::separator()));
    items.push(Box::new(MenuItem::with_id(ID_QUIT, "Quit", true, None)));
    let refs: Vec<&dyn tray_icon::menu::IsMenuItem> = items.iter().map(|i| i.as_ref()).collect();
    let _ = menu.append_items(&refs);
    menu
}

fn build_icon() -> Result<tray_icon::TrayIcon, String> {
    let icon = app_icon().ok_or_else(|| "couldn't read the app icon".to_string())?;
    let menu = build_menu(&menu_for(false, None, true, false, false, false));
    tray_icon::TrayIconBuilder::new()
        .with_tooltip("Stream Tube")
        .with_icon(icon)
        .with_menu(Box::new(menu))
        .with_menu_on_left_click(false)
        .with_menu_on_right_click(true)
        .build()
        .map_err(|e| e.to_string())
}

fn app_icon() -> Option<tray_icon::Icon> {
    static CACHED: OnceLock<Option<tray_icon::Icon>> = OnceLock::new();
    CACHED.get_or_init(decode_icon).clone()
}

fn decode_icon() -> Option<tray_icon::Icon> {
    let img = image::load_from_memory(include_bytes!("../assets/logo.png")).ok()?;
    let img = image::imageops::resize(&img.to_rgba8(), 64, 64, image::imageops::FilterType::Triangle);
    let (w, h) = img.dimensions();
    tray_icon::Icon::from_rgba(img.into_raw(), w, h).ok()
}

#[cfg(windows)]
fn hide_os(window: &Window) {
    #[link(name = "user32")]
    unsafe extern "system" {
        fn ShowWindow(hwnd: isize, cmd: i32) -> i32;
    }
    if let Some(hwnd) = hwnd(window) {
        unsafe { ShowWindow(hwnd, 0) };
    }
}

#[cfg(windows)]
fn show_os(window: &Window) {
    #[link(name = "user32")]
    unsafe extern "system" {
        fn ShowWindow(hwnd: isize, cmd: i32) -> i32;
        fn SetForegroundWindow(hwnd: isize) -> i32;
    }
    if let Some(hwnd) = hwnd(window) {
        // SW_RESTORE shows a hidden window and un-minimizes an iconic one.
        unsafe {
            ShowWindow(hwnd, 9);
            SetForegroundWindow(hwnd);
        }
    }
}

#[cfg(windows)]
fn hwnd(window: &Window) -> Option<isize> {
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    let handle = HasWindowHandle::window_handle(window).ok()?;
    match handle.as_raw() {
        RawWindowHandle::Win32(w) => Some(w.hwnd.get()),
        _ => None,
    }
}

#[cfg(not(windows))]
fn hide_os(window: &Window) {
    // No portable "remove from the taskbar" on X11 and Wayland from outside
    // the window. Minimizing still leaves the tray icon as the way back.
    window.minimize_window();
}

#[cfg(not(windows))]
fn show_os(window: &Window) {
    window.activate_window();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[::core::prelude::v1::test]
    fn defaults_leave_minimize_and_close_alone() {
        let s = crate::store::Settings::default();
        assert!(!s.minimize_to_tray);
        assert!(!s.close_to_tray);
        assert!(!wants_minimize_to_tray(false, true));
        assert!(!wants_close_to_tray(false, true, false));
        assert!(!wants_minimize_to_tray(true, false));
        assert!(!wants_close_to_tray(true, false, false));
    }

    #[::core::prelude::v1::test]
    fn settings_hide_only_when_the_icon_exists_and_quit_still_closes() {
        assert!(wants_minimize_to_tray(true, true));
        assert!(wants_close_to_tray(true, true, false));
        assert!(!wants_close_to_tray(true, true, true));
    }

    #[::core::prelude::v1::test]
    fn a_window_in_the_tray_counts_as_minimized() {
        assert!(!counts_as_minimized(false, false));
        assert!(counts_as_minimized(true, false));
        assert!(counts_as_minimized(false, true));
    }

    #[::core::prelude::v1::test]
    fn menu_follows_playback_and_escapes_mnemonics() {
        let idle = menu_for(false, None, true, false, false, false);
        assert_eq!(idle.show_label, "Hide");
        assert_eq!(idle.play_label, "Play");
        assert!(!idle.play_enabled);
        assert!(!idle.prev_enabled);
        assert_eq!(idle.tooltip, "Stream Tube");

        let playing = menu_for(true, Some("A & B"), false, true, true, true);
        assert_eq!(playing.show_label, "Show");
        assert_eq!(playing.play_label, "Pause");
        assert!(playing.play_enabled);
        assert!(playing.prev_enabled);
        assert!(playing.next_enabled);
        assert_eq!(playing.title.as_deref(), Some("A && B"));
        assert!(playing.tooltip.contains("A & B"));
    }
}
