use ledger_device_sdk::include_gif;
use ledger_device_sdk::nbgl::NbglGlyph;

pub mod address;
pub mod menu;
pub mod sign;

// The testnet build carries its own glyphs, so that it cannot be mistaken for the mainnet app.
fn load_glyph() -> &'static NbglGlyph<'static> {
    // Load glyph from file with include_gif macro. Creates an NBGL compatible glyph.
    #[cfg(all(target_os = "apex_p", not(feature = "variant_testnet")))]
    const APP_GLYPH: NbglGlyph =
        NbglGlyph::from_include(include_gif!("glyphs/zcash_48px.png", NBGL));
    #[cfg(all(target_os = "apex_p", feature = "variant_testnet"))]
    const APP_GLYPH: NbglGlyph =
        NbglGlyph::from_include(include_gif!("glyphs/zcash_48px_test.png", NBGL));
    #[cfg(all(
        any(target_os = "stax", target_os = "flex"),
        not(feature = "variant_testnet")
    ))]
    const APP_GLYPH: NbglGlyph =
        NbglGlyph::from_include(include_gif!("glyphs/zcash_64px.png", NBGL));
    #[cfg(all(
        any(target_os = "stax", target_os = "flex"),
        feature = "variant_testnet"
    ))]
    const APP_GLYPH: NbglGlyph =
        NbglGlyph::from_include(include_gif!("glyphs/zcash_64px_test.png", NBGL));
    #[cfg(all(
        any(target_os = "nanosplus", target_os = "nanox"),
        not(feature = "variant_testnet")
    ))]
    const APP_GLYPH: NbglGlyph =
        NbglGlyph::from_include(include_gif!("icons/nanox_app_zcash.gif", NBGL));
    #[cfg(all(
        any(target_os = "nanosplus", target_os = "nanox"),
        feature = "variant_testnet"
    ))]
    const APP_GLYPH: NbglGlyph =
        NbglGlyph::from_include(include_gif!("icons/nanox_app_zcash_test.gif", NBGL));

    &APP_GLYPH
}

fn load_ui_menu_glyph() -> &'static NbglGlyph<'static> {
    // Load glyph from 64x64 4bpp gif file with include_gif macro. Creates an NBGL compatible glyph.
    #[cfg(all(target_os = "apex_p", not(feature = "variant_testnet")))]
    const APP_GLYPH: NbglGlyph =
        NbglGlyph::from_include(include_gif!("glyphs/zcash_48px.png", NBGL));
    #[cfg(all(target_os = "apex_p", feature = "variant_testnet"))]
    const APP_GLYPH: NbglGlyph =
        NbglGlyph::from_include(include_gif!("glyphs/zcash_48px_test.png", NBGL));
    #[cfg(all(
        any(target_os = "stax", target_os = "flex"),
        not(feature = "variant_testnet")
    ))]
    const APP_GLYPH: NbglGlyph =
        NbglGlyph::from_include(include_gif!("glyphs/zcash_64px.png", NBGL));
    #[cfg(all(
        any(target_os = "stax", target_os = "flex"),
        feature = "variant_testnet"
    ))]
    const APP_GLYPH: NbglGlyph =
        NbglGlyph::from_include(include_gif!("glyphs/zcash_64px_test.png", NBGL));
    #[cfg(all(
        any(target_os = "nanosplus", target_os = "nanox"),
        not(feature = "variant_testnet")
    ))]
    const APP_GLYPH: NbglGlyph =
        NbglGlyph::from_include(include_gif!("glyphs/home_nano_nbgl.png", NBGL));
    #[cfg(all(
        any(target_os = "nanosplus", target_os = "nanox"),
        feature = "variant_testnet"
    ))]
    const APP_GLYPH: NbglGlyph =
        NbglGlyph::from_include(include_gif!("glyphs/home_nano_nbgl_test.png", NBGL));

    &APP_GLYPH
}
