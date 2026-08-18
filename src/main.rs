/*****************************************************************************
 *   Ledger App Boilerplate Rust.
 *   (c) 2023 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#![no_std]
#![no_main]

mod app_ui;

mod handlers {
    pub mod get_public_key;
    pub mod get_shielded_addr;
    pub mod get_trusted_input;
    pub mod get_version;
    pub mod get_vk;
    pub mod pczt;
    pub mod sign_tx;
}

mod consts;
mod parser;
mod settings;
mod swap;
mod tx;
mod utils;
mod zip32;

use alloc::boxed::Box;
use core::mem::{self, MaybeUninit};

use app_ui::menu::ui_menu_main;
use handlers::{
    get_public_key::handler_get_public_key, get_shielded_addr::handler_get_shielded_addr,
    get_version::handler_get_version, get_vk::handler_get_vk,
};
use ledger_device_sdk::log::{debug, error};
use ledger_device_sdk::nbgl::StatusType;
use ledger_device_sdk::{io::StatusWords, libcall::swap::CreateTxParams};
use ledger_device_sdk::{
    io::{ApduHeader, Comm, Reply},
    nbgl::init_comm,
    random::rand_bytes,
};
use tx::TxContext;
use zeroize::Zeroizing;

use crate::consts::{
    INS_GET_SHIELD_ADDR, MAX_PCZT_ORCHARD_ACTIONS_NUMBER, MAX_PCZT_TRANSPARENT_INPUTS_NUMBER,
    P1_FINALIZE_FULL_CHANGEINFO, P1_FINALIZE_FULL_LAST, P1_FINALIZE_FULL_MORE, P1_FIRST,
    P1_GET_PUBLIC_KEY_DISPLAY, P1_GET_PUBLIC_KEY_NO_DISPLAY, P1_GET_VK_CONTINUE, P1_GET_VK_FIRST,
    P1_HASH_INPUT_START_FIRST, P1_HASH_INPUT_START_NEXT, P1_LAST, P1_NEXT,
    P2_FINALIZE_FULL_DEFAULT, P2_HASH_INPUT_START_CONTINUE, P2_HASH_INPUT_START_SAPLING,
    P2_PCZT_CONTINUE, P2_PCZT_FINISHED, P2ShieldedAddrMode, P2VkMode,
};
use crate::consts::{
    INS_PCZT_IRONWOOD_ACTION, INS_PCZT_SIGN_IRONWOOD, MAX_PCZT_IRONWOOD_ACTIONS_NUMBER,
};
use crate::handlers::pczt::{handler_pczt_ironwood_action, handler_pczt_sign_ironwood};
use crate::swap::panic_handler::get_swap_panic_handler;
use crate::{
    consts::{
        INS_GET_FIRMWARE_VERSION, INS_GET_TRUSTED_INPUT, INS_GET_VK, INS_GET_WALLET_PUBLIC_KEY,
        INS_HASH_INPUT_FINALIZE_FULL, INS_HASH_INPUT_START, INS_HASH_SIGN, INS_PCZT_HEADER,
        INS_PCZT_ORCHARD_ACTION, INS_PCZT_SIGN_ORCHARD, INS_PCZT_SIGN_TRANSPARENT,
        INS_PCZT_TRANSPARENT_INPUT, INS_PCZT_TRANSPARENT_OUTPUT, ZCASH_CLA,
    },
    handlers::{
        get_trusted_input::handler_get_trusted_input,
        pczt::{
            handler_pczt_header, handler_pczt_orchard_action, handler_pczt_sign_orchard,
            handler_pczt_sign_transparent, handler_pczt_transparent_input,
            handler_pczt_transparent_output,
        },
        sign_tx::{handler_hash_input_finalize_full, handler_hash_input_start, handler_hash_sign},
    },
    settings::Settings,
};

// Required for using String, Vec, format!...
extern crate alloc;

ledger_device_sdk::set_panic!(panic_handler);

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AppSW {
    PinRemainingAttempts = 0x63C0,
    ExecutionError = 0x6400,
    WrongApduLength = 0x6700, // Normally we should use StatusWord::BadLen(0x6e03)
    CommandIncompatibleFileStructure = 0x6981,
    // Aliased on purpose: the legacy protocol this app must stay wire-compatible with reports
    // both conditions with the same word.
    SecurityStatusNotSatisfied = StatusWords::NothingReceived as u16,
    IncorrectData = 0x6A80,
    NotEnoughMemorySpace = 0x6A84,
    ReferencedDataNotFound = 0x6A88,
    FileAlreadyExists = 0x6A89,
    SwapWithoutTrustedInputs = 0x6A8A,
    WrongP1P2 = 0x6B00,       // Normally we should use StatusWord::BadP1P2(0x6e02)
    InsNotSupported = 0x6D00, // Normally we should use StatusWord::BadIns(0x6e01)
    ClaNotSupported = StatusWords::BadCla as u16,
    MemoryProblem = 0x9240,
    NoEfSelected = 0x9400,
    InvalidOffset = 0x9402,
    FileNotFound = 0x9404,
    InconsistentFile = 0x9408,
    AlgorithmNotSupported = 0x9484,
    InvalidKcv = 0x9485,
    CodeNotInitialized = 0x9802,
    AccessConditionNotFulfilled = 0x9804,
    ContradictionSecretCodeStatus = 0x9808,
    ContradictionInvalidation = 0x9810,
    CodeBlocked = 0x9840,
    MaxValueReached = 0x9850,
    GpAuthFailed = 0x6300,
    Licensing = 0x6F42,
    Halted = 0x6FAA,
    Deny = StatusWords::UserCancelled as u16,
    // 0x6986, not the 0x6985 an ISO reading would suggest: the legacy protocol uses 0x6985 for a
    // user denial (see `Deny`), so this condition takes the adjacent word.
    ConditionsOfUseNotSatisfied = 0x6986,
    //TxWrongLength = 0x6F00,
    TechnicalProblem = 0x6F00,
    VersionParsingFail = 0x6F01,
    TxParsingFail = 0x6F02,
    BadState = 0xB007,
    Ok = StatusWords::Ok as u16,
}

impl From<AppSW> for Reply {
    fn from(sw: AppSW) -> Reply {
        Reply(sw as u16)
    }
}

/// Possible input commands received through APDUs.
#[derive(Debug)]
pub enum Instruction {
    GetVersion,
    GetPubkey {
        display: bool,
    },
    GetShieldedAddr {
        display: bool,
        mode: P2ShieldedAddrMode,
    },
    GetVk {
        mode: P2VkMode,
        continue_response: bool,
    },
    GetTrustedInput {
        first: bool,
        next: bool,
    },
    HashInputStart {
        first: bool,
        continue_hashing: bool,
    },
    HashFinalizeFull {
        is_change: bool,
    },
    HashSign,
    PcztHeader,
    PcztTransparentInput {
        first: bool,
        last: bool,
    },
    PcztTransparentOutput {
        first: bool,
        last: bool,
    },
    PcztOrchardAction {
        first: bool,
        last: bool,
        finished: bool,
    },
    PcztSignTransparent {
        input_index: usize,
    },
    PcztSignOrchard {
        action_index: usize,
    },
    PcztIronwoodAction {
        first: bool,
        last: bool,
        finished: bool,
    },
    PcztSignIronwood {
        action_index: usize,
    },
    PcztInvalid {
        sw: AppSW,
    },
}

impl TryFrom<ApduHeader> for Instruction {
    type Error = AppSW;

    /// APDU parsing logic.
    ///
    /// Parses INS, P1 and P2 bytes to build an [`Instruction`]. P1 and P2 are translated to
    /// strongly typed variables depending on the APDU instruction code. Invalid INS, P1 or P2
    /// values result in errors with a status word, which are automatically sent to the host by the
    /// SDK.
    ///
    /// This design allows a clear separation of the APDU parsing logic and commands handling.
    ///
    /// Note that CLA is not checked here. Instead the method [`Comm::set_expected_cla`] is used in
    /// [`sample_main`] to have this verification automatically performed by the SDK.
    fn try_from(value: ApduHeader) -> Result<Self, Self::Error> {
        match (value.ins, value.p1, value.p2) {
            (INS_GET_FIRMWARE_VERSION, 0, 0) => Ok(Instruction::GetVersion),
            (
                INS_GET_WALLET_PUBLIC_KEY,
                P1_GET_PUBLIC_KEY_NO_DISPLAY | P1_GET_PUBLIC_KEY_DISPLAY,
                0,
            ) => Ok(Instruction::GetPubkey {
                display: value.p1 == P1_GET_PUBLIC_KEY_DISPLAY,
            }),
            (INS_GET_VK, P1_GET_VK_FIRST | P1_GET_VK_CONTINUE, p2) => Ok(Instruction::GetVk {
                mode: P2VkMode::try_from(p2)?,
                continue_response: value.p1 == P1_GET_VK_CONTINUE,
            }),
            (INS_GET_SHIELD_ADDR, P1_GET_PUBLIC_KEY_NO_DISPLAY | P1_GET_PUBLIC_KEY_DISPLAY, p2) => {
                Ok(Instruction::GetShieldedAddr {
                    mode: P2ShieldedAddrMode::try_from(p2)?,
                    display: (value.p1 & P1_GET_PUBLIC_KEY_DISPLAY) != 0,
                })
            }
            (INS_GET_TRUSTED_INPUT, p1, 0) if p1 == P1_FIRST || p1 == P1_NEXT => {
                Ok(Instruction::GetTrustedInput {
                    first: p1 == P1_FIRST,
                    next: p1 == P1_NEXT,
                })
            }
            (
                INS_HASH_INPUT_START,
                P1_HASH_INPUT_START_FIRST | P1_HASH_INPUT_START_NEXT,
                P2_HASH_INPUT_START_SAPLING | P2_HASH_INPUT_START_CONTINUE,
            ) => Ok(Instruction::HashInputStart {
                first: value.p1 == P1_HASH_INPUT_START_FIRST,
                continue_hashing: value.p1 == P1_HASH_INPUT_START_FIRST
                    && value.p2 == P2_HASH_INPUT_START_CONTINUE,
            }),
            (
                INS_HASH_INPUT_FINALIZE_FULL,
                P1_FINALIZE_FULL_MORE | P1_FINALIZE_FULL_LAST | P1_FINALIZE_FULL_CHANGEINFO,
                P2_FINALIZE_FULL_DEFAULT,
            ) => Ok(Instruction::HashFinalizeFull {
                is_change: value.p1 == P1_FINALIZE_FULL_CHANGEINFO,
            }),
            (INS_HASH_SIGN, 0, 0) => Ok(Instruction::HashSign),
            (INS_PCZT_HEADER, P1_FIRST, P2_PCZT_CONTINUE) => Ok(Instruction::PcztHeader),
            (INS_PCZT_TRANSPARENT_INPUT, p1, P2_PCZT_CONTINUE)
                if p1 == P1_FIRST || p1 == P1_NEXT || p1 == P1_LAST =>
            {
                Ok(Instruction::PcztTransparentInput {
                    first: value.p1 == P1_FIRST,
                    last: value.p1 == P1_LAST,
                })
            }
            (INS_PCZT_TRANSPARENT_OUTPUT, p1, P2_PCZT_CONTINUE)
                if p1 == P1_FIRST || p1 == P1_NEXT || p1 == P1_LAST =>
            {
                Ok(Instruction::PcztTransparentOutput {
                    first: value.p1 == P1_FIRST,
                    last: value.p1 == P1_LAST,
                })
            }
            (INS_PCZT_ORCHARD_ACTION, p1, P2_PCZT_CONTINUE | P2_PCZT_FINISHED)
                if p1 == P1_FIRST || p1 == P1_NEXT || p1 == P1_LAST =>
            {
                Ok(Instruction::PcztOrchardAction {
                    first: value.p1 == P1_FIRST,
                    last: value.p1 == P1_LAST,
                    finished: value.p2 == P2_PCZT_FINISHED,
                })
            }
            (INS_PCZT_SIGN_TRANSPARENT, 0, p2)
                if (p2 as usize) < MAX_PCZT_TRANSPARENT_INPUTS_NUMBER =>
            {
                Ok(Instruction::PcztSignTransparent {
                    input_index: p2 as usize,
                })
            }
            (INS_PCZT_SIGN_ORCHARD, 0, p2) if (p2 as usize) < MAX_PCZT_ORCHARD_ACTIONS_NUMBER => {
                Ok(Instruction::PcztSignOrchard {
                    action_index: p2 as usize,
                })
            }
            (INS_PCZT_IRONWOOD_ACTION, p1, P2_PCZT_CONTINUE | P2_PCZT_FINISHED)
                if p1 == P1_FIRST || p1 == P1_NEXT || p1 == P1_LAST =>
            {
                Ok(Instruction::PcztIronwoodAction {
                    first: value.p1 == P1_FIRST,
                    last: value.p1 == P1_LAST,
                    finished: value.p2 == P2_PCZT_FINISHED,
                })
            }
            (INS_PCZT_SIGN_IRONWOOD, 0, p2) if (p2 as usize) < MAX_PCZT_IRONWOOD_ACTIONS_NUMBER => {
                Ok(Instruction::PcztSignIronwood {
                    action_index: p2 as usize,
                })
            }
            (
                INS_PCZT_HEADER
                | INS_PCZT_TRANSPARENT_INPUT
                | INS_PCZT_TRANSPARENT_OUTPUT
                | INS_PCZT_ORCHARD_ACTION
                | INS_PCZT_SIGN_TRANSPARENT
                | INS_PCZT_SIGN_ORCHARD,
                _,
                _,
            ) => Ok(Instruction::PcztInvalid {
                sw: AppSW::WrongP1P2,
            }),
            (INS_PCZT_IRONWOOD_ACTION | INS_PCZT_SIGN_IRONWOOD, _, _) => {
                Ok(Instruction::PcztInvalid {
                    sw: AppSW::WrongP1P2,
                })
            }
            // A routed instruction reached here because its P1/P2 did not match any of its arms.
            // An unrouted one never had P1/P2 semantics at all, so the reply must not depend on
            // them — otherwise the dispatcher's error contract varies with bytes it never parsed,
            // and a prober can tell the two conditions apart for free.
            (
                INS_GET_WALLET_PUBLIC_KEY
                | INS_GET_TRUSTED_INPUT
                | INS_HASH_INPUT_START
                | INS_HASH_SIGN
                | INS_HASH_INPUT_FINALIZE_FULL
                | INS_GET_FIRMWARE_VERSION
                | INS_GET_VK
                | INS_GET_SHIELD_ADDR,
                _,
                _,
            ) => Err(AppSW::WrongP1P2),
            (_, _, _) => Err(AppSW::InsNotSupported),
        }
    }
}

fn show_status_and_home_if_needed(ins: &Instruction, tx_ctx: &mut TxContext, status: &AppSW) {
    if tx_ctx.swap_params.is_some() {
        return;
    }

    let (show_status, status_type) = match (ins, status) {
        (Instruction::GetPubkey { display: true }, AppSW::Deny | AppSW::Ok) => {
            (true, StatusType::Address)
        }
        (
            Instruction::GetShieldedAddr {
                display: true,
                mode: P2ShieldedAddrMode::UAddress,
            },
            AppSW::Deny | AppSW::Ok,
        ) => (true, StatusType::Address),
        (Instruction::GetVk { .. }, AppSW::Deny | AppSW::Ok) if tx_ctx.is_vk_display_finished => {
            tx_ctx.is_vk_display_finished = false;
            (true, StatusType::Address)
        }
        (Instruction::HashFinalizeFull { .. }, AppSW::Deny)
        | (Instruction::HashSign, AppSW::Ok)
            if tx_ctx.is_finished() =>
        {
            (true, StatusType::Transaction)
        }
        (Instruction::PcztOrchardAction { .. }, AppSW::Deny)
        | (
            Instruction::PcztSignTransparent { .. } | Instruction::PcztSignOrchard { .. },
            AppSW::Ok,
        ) if tx_ctx.is_finished() => (true, StatusType::Transaction),
        (Instruction::PcztIronwoodAction { .. }, AppSW::Deny)
        | (Instruction::PcztSignIronwood { .. }, AppSW::Ok)
            if tx_ctx.is_finished() =>
        {
            (true, StatusType::Transaction)
        }
        (_, _) => (false, StatusType::Transaction),
    };

    if show_status {
        {
            use ledger_device_sdk::nbgl::NbglReviewStatus;

            let success = *status == AppSW::Ok;
            NbglReviewStatus::new()
                .status_type(status_type)
                .show(success);
        }

        // call home.show_and_return() to show home and setting screen
        tx_ctx.home.show_and_return();
    }
}

fn init_trusted_input_key_storage() {
    if Settings.trusted_input_key().is_none() {
        let mut rng = Zeroizing::new([0u8; 32]);
        rand_bytes(&mut rng[..]);

        Settings.set_trusted_input_key(&rng);
        debug!("Initialized trusted input key storage");
    }
}

// --8<-- [start:sample_main]
#[unsafe(no_mangle)]
extern "C" fn sample_main(arg0: u32) {
    if arg0 != 0 {
        // We have been started by the Exchange application through the os_lib_call API
        // We need to answer the command instead of starting the normal app main loop
        swap::swap_main(arg0);
    } else {
        // Normal app mode, start the main loop listening for APDU commands
        normal_main(None);
    }
}
// --8<-- [end:sample_main]

/// Main application entry point.
///
/// Handles both standard execution (user opens app) and library mode execution
/// (Exchange app calls this app for swap).
///
/// # Arguments
///
/// * `swap_params` - Optional swap parameters. If present, the app runs in "swap mode":
///   - UI is bypassed (no main menu, no transaction review)
///   - Transaction is validated against swap params
///   - Returns `true` if signed successfully, `false` otherwise
pub fn normal_main(swap_params: Option<&CreateTxParams>) -> bool {
    // Create the communication manager, and configure it to accept only APDU from the 0xe0 class.
    // If any APDU with a wrong class value is received, comm will respond automatically with
    // BadCla status word.
    let mut comm = Box::new(Comm::new().set_expected_cla(ZCASH_CLA));
    init_comm(&mut comm);

    init_trusted_input_key_storage();

    if swap_params.is_some() {
        debug!("App started in SWAP mode");
    } else {
        debug!("App started");
    }

    static mut TX_CTX: MaybeUninit<TxContext<'static>> = MaybeUninit::uninit();
    // SAFETY: `TX_CTX` is used higher up in this function’s call stack and is initialized before any use.
    let tx_ctx = unsafe {
        let tx_ctx = (&raw mut TX_CTX).cast::<TxContext<'_>>();
        TxContext::init_in_place(tx_ctx, swap_params, Default::default());
        &mut *tx_ctx
    };

    debug!("TxContext size {} bytes", mem::size_of::<TxContext>());

    if swap_params.is_none() {
        tx_ctx.home = ui_menu_main(&mut comm);
        tx_ctx.home.show_and_return();
    }

    loop {
        let ins: Instruction = comm.next_command();

        debug!("Received APDU {:?}", ins);

        let status = match handle_apdu(&mut comm, &ins, tx_ctx) {
            Ok(()) => {
                comm.reply_ok();
                AppSW::Ok
            }
            Err(sw) => {
                comm.reply(sw);
                sw
            }
        };
        show_status_and_home_if_needed(&ins, tx_ctx, &status);

        let is_error = status != AppSW::Ok;
        let is_finished = tx_ctx.is_finished();

        // Reset transaction context in case of error during transaction signing
        if let (
            Instruction::GetTrustedInput { .. }
            | Instruction::HashInputStart { .. }
            | Instruction::HashFinalizeFull { .. }
            | Instruction::HashSign
            | Instruction::PcztHeader
            | Instruction::PcztTransparentInput { .. }
            | Instruction::PcztTransparentOutput { .. }
            | Instruction::PcztOrchardAction { .. }
            | Instruction::PcztSignTransparent { .. }
            | Instruction::PcztSignOrchard { .. }
            | Instruction::PcztInvalid { .. },
            true,
        ) = (&ins, is_error)
        {
            tx_ctx.reset(Default::default());
        }
        if let (
            Instruction::PcztIronwoodAction { .. } | Instruction::PcztSignIronwood { .. },
            true,
        ) = (ins, is_error)
        {
            tx_ctx.reset(Default::default());
        }

        // In swap mode, exit after transaction is finished (signed or rejected) or on any error status,
        // to let the Exchange app handle the post-transaction flow (e.g. broadcasting or showing error to user)
        if tx_ctx.swap_params.is_some() && (is_finished || is_error) {
            return status == AppSW::Ok;
        }
    }
}

fn handle_apdu(comm: &mut Comm, ins: &Instruction, ctx: &mut TxContext) -> Result<(), AppSW> {
    match ins {
        Instruction::GetVersion => handler_get_version(comm),
        Instruction::GetPubkey { display } => handler_get_public_key(comm, *display),
        Instruction::GetVk {
            mode,
            continue_response,
        } => handler_get_vk(comm, ctx, *mode, *continue_response),
        Instruction::GetShieldedAddr { mode, display } => {
            handler_get_shielded_addr(comm, *mode, *display)
        }
        Instruction::GetTrustedInput { first, next } => {
            handler_get_trusted_input(comm, ctx, *first, *next)
        }
        Instruction::HashInputStart {
            first,
            continue_hashing,
        } => handler_hash_input_start(comm, ctx, *first, *continue_hashing),
        Instruction::HashFinalizeFull { is_change } => {
            handler_hash_input_finalize_full(comm, ctx, *is_change)
        }
        Instruction::HashSign => handler_hash_sign(comm, ctx),
        Instruction::PcztHeader => handler_pczt_header(comm, ctx),
        Instruction::PcztTransparentInput { first, last } => {
            handler_pczt_transparent_input(comm, ctx, *first, *last)
        }
        Instruction::PcztTransparentOutput { first, last } => {
            handler_pczt_transparent_output(comm, ctx, *first, *last)
        }
        Instruction::PcztOrchardAction {
            first,
            last,
            finished,
        } => handler_pczt_orchard_action(comm, ctx, *first, *last, *finished),
        Instruction::PcztSignTransparent { input_index } => {
            handler_pczt_sign_transparent(comm, ctx, *input_index)
        }
        Instruction::PcztSignOrchard { action_index } => {
            handler_pczt_sign_orchard(comm, ctx, *action_index)
        }
        Instruction::PcztIronwoodAction {
            first,
            last,
            finished,
        } => handler_pczt_ironwood_action(comm, ctx, *first, *last, *finished),
        Instruction::PcztSignIronwood { action_index } => {
            handler_pczt_sign_ironwood(comm, ctx, *action_index)
        }
        Instruction::PcztInvalid { sw } => {
            ctx.pczt_parser.reset();
            Err(*sw)
        }
    }
}

/// In case of runtime problems, return an internal error and exit the app
pub fn panic_handler(info: &PanicInfo) -> ! {
    if let Some(swap_panic_handler) = get_swap_panic_handler() {
        // This handler is no-return
        swap_panic_handler(info);
    }

    error!("Panicking: {:?}\n", info);
    ledger_device_sdk::exiting_panic(info)
}
