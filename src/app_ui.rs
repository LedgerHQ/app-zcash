use ledger_device_sdk::include_gif;
use ledger_device_sdk::nbgl::NbglGlyph;

pub mod address;
pub mod menu;
pub mod sign;

fn load_glyph() -> &'static NbglGlyph<'static> {
    // Load glyph from file with include_gif macro. Creates an NBGL compatible glyph.
    #[cfg(target_os = "apex_p")]
    const APP_GLYPH: NbglGlyph =
        NbglGlyph::from_include(include_gif!("glyphs/zcash_48px.png", NBGL));
    #[cfg(any(target_os = "stax", target_os = "flex"))]
    const APP_GLYPH: NbglGlyph =
        NbglGlyph::from_include(include_gif!("glyphs/zcash_64px.png", NBGL));
    #[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
    const APP_GLYPH: NbglGlyph =
        NbglGlyph::from_include(include_gif!("icons/nanox_app_zcash.gif", NBGL));

    &APP_GLYPH
}

fn load_ui_menu_glyph() -> &'static NbglGlyph<'static> {
    // Load glyph from 64x64 4bpp gif file with include_gif macro. Creates an NBGL compatible glyph.
    #[cfg(target_os = "apex_p")]
    const APP_GLYPH: NbglGlyph =
        NbglGlyph::from_include(include_gif!("glyphs/zcash_48px.png", NBGL));
    #[cfg(any(target_os = "stax", target_os = "flex"))]
    const APP_GLYPH: NbglGlyph =
        NbglGlyph::from_include(include_gif!("glyphs/zcash_64px.png", NBGL));
    #[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
    const APP_GLYPH: NbglGlyph =
        NbglGlyph::from_include(include_gif!("glyphs/home_nano_nbgl.png", NBGL));

    &APP_GLYPH
}
