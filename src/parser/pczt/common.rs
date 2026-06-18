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
        if version != PCZT_VERSION_1 {
            return Err(ParserError::from_str("Unsupported PCZT version"));
        }

        debug!("PCZT header: magic {:?}, version {}", magic, version);

        Ok(())
    }

    pub(super) fn parse_global(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        let tx_version = ok!(reader.read_u32_le());
        let version_group_id = ok!(reader.read_u32_le());

        if tx_version != V5_TX_VERSION || version_group_id != V5_VERSION_GROUP_ID {
            return Err(ParserError::from_str(
                "Unsupported PCZT transaction version",
            ));
        }

        let consensus_branch_id = ok!(BranchId::try_from(ok!(reader.read_u32_le())));
        let fallback_lock_time = self.read_optional_u32(reader)?;
        let expiry_height = ok!(reader.read_u32_le());
        let coin_type = ok!(reader.read_u32_le());
        let tx_modifiable = ok!(reader.read_u8());

        if coin_type != ZCASH_BIP44_COIN_TYPE {
            return Err(ParserError::from_str("Unsupported PCZT coin_type"));
        }

        debug!(
            "PCZT global: version {}, version_group_id {:08x}, branch {:?}, fallback_lock_time {:?}, expiry_height {}, coin_type {}, tx_modifiable {:02x}",
            tx_version,
            version_group_id,
            consensus_branch_id,
            fallback_lock_time,
            expiry_height,
            coin_type,
            tx_modifiable
        );

        ctx.tx_info.tx_version = Some(TxVersion::V5);
        ctx.tx_info.branch_id = Some(consensus_branch_id);
        ctx.tx_info.locktime = fallback_lock_time.unwrap_or_default();
        ctx.tx_info.expiry_height = expiry_height;

        Ok(())
    }

    pub(super) fn parse_derivation_path_count(
        data: &[u8],
        count_offset: usize,
        label: &'static str,
    ) -> Result<PathCountParse, ParserError> {
        let min_size = count_offset + 1;
        if data.len() < min_size {
            return Ok(PathCountParse::NeedMore(min_size));
        }

        let mut reader = ByteReader::new(&data[count_offset..]);
        let path_count: usize = match CompactSize::read_t(&mut reader) {
            Ok(path_count) => path_count,
            Err(err) if err.kind() == corez::io::ErrorKind::UnexpectedEof => {
                return Ok(PathCountParse::NeedMore(data.len() + 1));
            }
            Err(err) => {
                return Err(ParserError {
                    source: err.into(),
                    file: file!(),
                    line: line!(),
                });
            }
        };
        let compact_size_len = data[count_offset..].len() - reader.remaining_len();

        if path_count > MAX_ZCASH_BIP32_PATH {
            return Err(ParserError::from_str(label));
        }

        Ok(PathCountParse::Ready {
            path_count,
            path_offset: count_offset + compact_size_len,
        })
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

        let fees_i128 = i128::from(ctx.tx_info.total_amount)
            + i128::from(self.orchard_value_balance)
            - i128::from(self.total_output_amount);

        if fees_i128 < 0 {
            return Err(ParserError::from_str("Failed to calculate PCZT fees"));
        }

        let fees = u64::try_from(fees_i128)
            .map_err(|_| ParserError::from_str("PCZT fee value out of range"))?;

        debug!(
            "PCZT fees: {}, transparent_input_total={}, transparent_output_total={}, orchard_value_balance={}",
            fees, ctx.tx_info.total_amount, self.total_output_amount, self.orchard_value_balance
        );

        if let Some(swap_params) = ctx.swap_params {
            ok!(swap::check_swap_params(
                swap_params,
                &ctx.tx_info.outputs,
                fees
            ));
        } else if !ok!(ui_display_tx(&ctx.tx_info.outputs, fees)) {
            return Err(ParserError::user());
        }

        self.outputs_reviewed = true;

        Ok(())
    }
}
