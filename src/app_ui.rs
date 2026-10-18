use ledger_device_sdk::include_gif;
use ledger_device_sdk::nbgl::NbglGlyph;

pub mod address;
pub mod menu;
pub mod own_account;
pub mod sign;

// Distinct testnet glyphs; `include_gif!` needs a literal path, hence a macro.
macro_rules! variant_glyph {
    ($mainnet:tt, $testnet:tt) => {{
        #[cfg(not(feature = "variant_testnet"))]
        const GLYPH: NbglGlyph = NbglGlyph::from_include(include_gif!($mainnet, NBGL));
        #[cfg(feature = "variant_testnet")]
        const GLYPH: NbglGlyph = NbglGlyph::from_include(include_gif!($testnet, NBGL));
        &GLYPH
    }};
}

fn load_glyph() -> &'static NbglGlyph<'static> {
    #[cfg(target_os = "apex_p")]
    let glyph = variant_glyph!("glyphs/zcash_48px.png", "glyphs/zcash_48px_test.png");
    #[cfg(any(target_os = "stax", target_os = "flex"))]
    let glyph = variant_glyph!("glyphs/zcash_64px.png", "glyphs/zcash_64px_test.png");
    #[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
    let glyph = variant_glyph!(
        "icons/nanox_app_zcash.gif",
        "icons/nanox_app_zcash_test.gif"
    );
    glyph
}

fn load_ui_menu_glyph() -> &'static NbglGlyph<'static> {
    #[cfg(target_os = "apex_p")]
    let glyph = variant_glyph!("glyphs/zcash_48px.png", "glyphs/zcash_48px_test.png");
    #[cfg(any(target_os = "stax", target_os = "flex"))]
    let glyph = variant_glyph!("glyphs/zcash_64px.png", "glyphs/zcash_64px_test.png");
    #[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
    let glyph = variant_glyph!(
        "glyphs/home_nano_nbgl.png",
        "glyphs/home_nano_nbgl_test.png"
    );
    glyph
}
