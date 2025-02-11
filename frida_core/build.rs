#[cfg(target_os = "macos")]
use cc;

fn main() {
    #[cfg(target_os = "macos")]
    cc::Build::new().file("src/c/utun.c").compile("utun");
}