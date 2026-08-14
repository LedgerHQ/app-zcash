use super::*;

impl PcztParser {
    pub(super) fn parse_pczt_header(
        &mut self,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        let mut magic = [0u8; 4];
        ok!(reader.read_exact(&mut magic));

        if &magic != MAGIC_BYTES {
            return Err(ParserError::from_str("Bad PCZT magic bytes"));
        }

        let version = ok!(reader.read_u32_le());
        if version != PCZT_VERSION_1 && version != PCZT_VERSION_2 {
            return Err(ParserError::from_str("Unsupported PCZT version"));
        }
        self.pczt_version = version;

        debug!("PCZT header: magic {:?}, version {}", magic, version);

        Ok(())
    }

    pub(super) fn parse_global(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        let tx_version_raw = ok!(reader.read_u32_le());
        let version_group_id = ok!(reader.read_u32_le());
        let branch_id_raw = ok!(reader.read_u32_le());

        let is_v5 = tx_version_raw == V5_TX_VERSION && version_group_id == V5_VERSION_GROUP_ID;
        let is_v6 = tx_version_raw == V6_TX_VERSION && version_group_id == V6_VERSION_GROUP_ID;

        if !is_v5 {
            if !is_v6 {
                return Err(ParserError::from_str(
                    "Unsupported PCZT transaction version",
                ));
            }
        }

        let consensus_branch_id = ok!(BranchId::try_from(branch_id_raw));
        let fallback_lock_time = self.read_optional_u32(reader)?;
        let expiry_height = ok!(reader.read_u32_le());
        let coin_type = ok!(reader.read_u32_le());
        let tx_modifiable = ok!(reader.read_u8());

        if coin_type != ZCASH_BIP44_COIN_TYPE {
            return Err(ParserError::from_str("Unsupported PCZT coin_type"));
        }

        debug!(
            "PCZT global: version {}, version_group_id {:08x}, branch {:?}, fallback_lock_time {:?}, expiry_height {}, coin_type {}, tx_modifiable {:02x}",
            tx_version_raw,
            version_group_id,
            consensus_branch_id,
            fallback_lock_time,
            expiry_height,
            coin_type,
            tx_modifiable
        );

        if is_v5 {
            ctx.tx_info.tx_version = Some(TxVersion::V5);
        }
        ctx.tx_info.branch_id = Some(consensus_branch_id);
        ctx.tx_info.branch_id_raw = branch_id_raw;
        ctx.tx_info.locktime = fallback_lock_time.unwrap_or_default();
        ctx.tx_info.expiry_height = expiry_height;
        {
            ctx.tx_info.is_v6 = is_v6;
        }

        if is_v5 && self.pczt_version != PCZT_VERSION_1 {
            return Err(ParserError::from_str(
                "PCZT version 1 required for V5 transaction",
            ));
        }
        if is_v6 && self.pczt_version != PCZT_VERSION_2 {
            return Err(ParserError::from_str(
                "PCZT version 2 required for V6 transaction",
            ));
        }

        Ok(())
    }

    pub(super) fn read_optional_u32(
        &mut self,
        reader: &mut ByteReader<'_>,
    ) -> Result<Option<u32>, ParserError> {
        match ok!(reader.read_u8()) {
            0 => Ok(None),
            1 => Ok(Some(ok!(reader.read_u32_le()))),
            _ => Err(ParserError::from_str("Bad PCZT Option<u32> tag")),
        }
    }

    pub(super) fn review_outputs(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
    ) -> Result<(), ParserError> {
        if ctx.tx_info.outputs.is_empty() {
            return Err(ParserError::from_str(
                "No PCZT outputs to display (no transparent outputs, and no Orchard outputs could be decrypted)",
            ));
        }

        let ironwood_vb: i64 = self.ironwood_value_balance;
        let fees_i128 = i128::from(ctx.tx_info.total_amount)
            + i128::from(self.orchard_value_balance)
            + i128::from(ironwood_vb)
            - i128::from(self.total_output_amount);

        if fees_i128 < 0 {
            return Err(ParserError::from_str("Failed to calculate PCZT fees"));
        }

        let fees = u64::try_from(fees_i128)
            .map_err(|_| ParserError::from_str("PCZT fee value out of range"))?;

        debug!(
            "PCZT fees: {}, transparent_input_total={}, transparent_output_total={}, orchard_value_balance={}, ironwood_value_balance={}",
            fees,
            ctx.tx_info.total_amount,
            self.total_output_amount,
            self.orchard_value_balance,
            ironwood_vb
        );

        // In the case of internal transfers between pools (for example, transparent -> Orchard or Orchard -> transparent),
        // we have to display the internal outputs on the clear-sign screen.
        let has_external_output = ctx.tx_info.outputs.iter().any(|output| !output.is_change);
        let reveal_self_outputs = !has_external_output;
        if reveal_self_outputs {
            debug!("PCZT has no external outputs; displaying self-transfer output");
            // PCZT does not read tx_info.outputs after review; this only affects UI filtering.
            for output in ctx.tx_info.outputs.iter_mut() {
                output.is_change = false;
            }
        }

        let spent_from_public = self.transparent_input_count > 0;
        let spent_from_private = self.orchard_spend_value_sum > 0;
        // Ironwood is a shielded pool; any Ironwood spend must set the from_private flag.
        let spent_from_private = spent_from_private || self.ironwood_spend_value_sum > 0;
        let transfer_type =
            TransferType::classify(spent_from_public, spent_from_private, &ctx.tx_info.outputs);
        let review_result = ui_display_tx(&ctx.tx_info.outputs, fees, transfer_type);

        if !ok!(review_result) {
            return Err(ParserError::user());
        }

        self.outputs_reviewed = true;

        Ok(())
    }
}
