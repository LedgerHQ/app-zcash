use image::{ImageFormat, ImageReader, Pixel};

// Masks the icon to the small devices' rounded home-screen outline, then inverts it inside.
fn derive_home_glyph(source: &str, target: &str) {
    println!("cargo:rerun-if-changed=icons/{source}");

    let path = std::path::PathBuf::from("icons");
    let reader = ImageReader::open(path.join(source)).unwrap();
    let img = reader.decode().unwrap();
    let mut gray = img.into_luma8();

    // Apply mask
    let mask = ImageReader::open(path.join("mask_14x14.gif"))
        .unwrap()
        .decode()
        .unwrap()
        .into_luma8();

    for (x, y, mask_pixel) in mask.enumerate_pixels() {
        let mask_value = mask_pixel[0];
        let mut gray_pixel = *gray.get_pixel(x, y);
        if mask_value == 0 {
            gray_pixel = image::Luma([0]);
        } else {
            gray_pixel.invert();
        }
        gray.put_pixel(x, y, gray_pixel);
    }

    let glyph_path = std::path::PathBuf::from("glyphs");
    gray.save_with_format(glyph_path.join(target), ImageFormat::Png)
        .unwrap();
}

fn main() {
    println!("cargo:rerun-if-changed=script.ld");
    println!("cargo:rerun-if-changed=icons/mask_14x14.gif");

    // Both glyphs in every build, so each stays reproducible.
    derive_home_glyph("nanox_app_zcash.gif", "home_nano_nbgl.png");
    derive_home_glyph("nanox_app_zcash_test.gif", "home_nano_nbgl_test.png");
}
