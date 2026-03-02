use ledger_device_sdk::NVMData;
use ledger_device_sdk::nvm::*;

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
    #[allow(unused)]
    pub fn get_mut(&mut self) -> &mut AtomicStorage<[u8; SETTINGS_SIZE]> {
        let data = &raw mut DATA;
        unsafe { (*data).get_mut() }
    }

    #[inline(never)]
    #[allow(unused)]
    pub fn get_ref(&mut self) -> &AtomicStorage<[u8; SETTINGS_SIZE]> {
        let data = &raw const DATA;
        unsafe { (*data).get_ref() }
    }

    #[allow(unused)]
    pub fn get_element(&self, index: usize) -> u8 {
        let data = &raw const DATA;
        let storage = unsafe { (*data).get_ref() };
        let settings = storage.get_ref();
        settings[index]
    }

    #[allow(unused)]
    // Not used in this boilerplate, but can be used to set a value in the settings
    pub fn set_element(&self, index: usize, value: u8) {
        let data = &raw mut DATA;
        let storage = unsafe { (*data).get_mut() };
        let mut updated_data = *storage.get_ref();
        updated_data[index] = value;
        unsafe {
            storage.update(&updated_data);
        }
    }

    pub fn trusted_input_key(&mut self) -> Option<[u8; 32]> {
        let data = &raw const TRUSTED_INPUT_KEY;
        let storage = unsafe { (*data).get_ref() };
        let s = *storage.get_ref();

        if s.is_initialized { Some(s.key) } else { None }
    }

    pub fn set_trusted_input_key(&mut self, trusted_input_key: [u8; 32]) {
        let data = &raw mut TRUSTED_INPUT_KEY;
        let storage = unsafe { (*data).get_mut() };

        storage.update(&TrustedKeySettings {
            is_initialized: true,
            key: trusted_input_key,
        });
    }
}
