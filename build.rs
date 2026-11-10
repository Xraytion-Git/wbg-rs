// build.rs — PE icon injected via rcedit (external tool), no resource compilation needed.
// Kept minimal: no windres/gcc dependency.
fn main() {
    // Nothing to compile.  Icon is injected post-build via rcedit:
    //   rcedit target/release/WootingTool.exe --set-icon wooting.ico
}
