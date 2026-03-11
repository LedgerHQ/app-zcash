use ledger_device_sdk::NVMData;
use ledger_device_sdk::nvm::*;
use zeroize::{Zeroize, Zeroizing};

// This is necessary to store the object in NVM and not in RAM
const SETTINGS_SIZE: usize = 10;
#[unsafe(link_section = ".nvm_data")]
static mut DATA: NVMData<AtomicStorage<[u8; SETTINGS_SIZE]>> =
    NVMData::new(AtomicStorage::new(&[0u8; SETTINGS_SIZE]));

#[derive(Clone, Copy)]
#[repr(C, packed)]
struct TrustedKeySettings {
    is_initialized: bool,
    key: [u8; 32],
}

impl TrustedKeySettings {
    const fn default() -> Self {
        TrustedKeySettings {
            is_initialized: false,
            key: [0u8; 32],
        }
    }
}

impl Zeroize for TrustedKeySettings {
    fn zeroize(&mut self) {
        self.is_initialized = false;
        self.key.zeroize();
    }
}

pub type TrustedInputKey = Zeroizing<[u8; 32]>;

#[unsafe(link_section = ".nvm_data")]
static mut TRUSTED_INPUT_KEY: NVMData<AtomicStorage<TrustedKeySettings>> =
    NVMData::new(AtomicStorage::new(&TrustedKeySettings::default()));

#[derive(Clone, Copy)]
pub struct Settings;

impl Default for Settings {
    fn default() -> Self {
        Settings
    }
}

impl Settings {
    #[inline(never)]
    pub fn get_mut(&mut self) -> &mut AtomicStorage<[u8; SETTINGS_SIZE]> {
        let data = &raw mut DATA;
        unsafe { (*data).get_mut() }
    }

    pub fn trusted_input_key(&mut self) -> Option<TrustedInputKey> {
        let data = &raw const TRUSTED_INPUT_KEY;
        let storage = unsafe { (*data).get_ref() };
        let s = storage.get_ref();

        if !s.is_initialized {
            return None;
        }

        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&s.key);
        Some(key)
    }

    pub fn set_trusted_input_key(&mut self, trusted_input_key: &TrustedInputKey) {
        let data = &raw mut TRUSTED_INPUT_KEY;
        let storage = unsafe { (*data).get_mut() };
        let trusted_key_settings = Zeroizing::new(TrustedKeySettings {
            is_initialized: true,
            key: **trusted_input_key,
        });

        storage.update(&trusted_key_settings);
    }
}
