use ledger_device_sdk::io::Comm;

use crate::AppSW;
use crate::consts::{
    MAX_PCZT_IRONWOOD_ACTIONS_NUMBER, MAX_PCZT_ORCHARD_ACTIONS_NUMBER,
    MAX_PCZT_TRANSPARENT_INPUTS_NUMBER,
};
use crate::heap_probe::largest_available_block;

/// Replies with the heap the allocator can still serve and the bundle bounds this build carries.
///
/// Layout: largest free block as a big-endian `u32`, then the Orchard action, Ironwood action and
/// transparent input bounds as big-endian `u16`s.
///
/// The bounds travel with the measurement because a measurement build may carry raised ones, and a
/// figure read without knowing which bound produced it says nothing about either.
///
/// Holds no state and touches no transaction context, so it can be issued at any point of a PCZT
/// session to sample the heap the parser is working against.
pub fn handler_heap_probe(comm: &mut Comm) -> Result<(), AppSW> {
    let available =
        u32::try_from(largest_available_block()).map_err(|_| AppSW::TechnicalProblem)?;
    let max_orchard_actions =
        u16::try_from(MAX_PCZT_ORCHARD_ACTIONS_NUMBER).map_err(|_| AppSW::TechnicalProblem)?;
    let max_ironwood_actions =
        u16::try_from(MAX_PCZT_IRONWOOD_ACTIONS_NUMBER).map_err(|_| AppSW::TechnicalProblem)?;

    let max_transparent_inputs =
        u16::try_from(MAX_PCZT_TRANSPARENT_INPUTS_NUMBER).map_err(|_| AppSW::TechnicalProblem)?;

    comm.append(&available.to_be_bytes());
    comm.append(&max_orchard_actions.to_be_bytes());
    comm.append(&max_ironwood_actions.to_be_bytes());
    comm.append(&max_transparent_inputs.to_be_bytes());

    Ok(())
}
