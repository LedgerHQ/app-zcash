//! In-band secret distribution for Orchard bundles.

use alloc::vec::Vec;
use core::fmt;

use blake2b_simd::{Hash, Params};
use group::ff::PrimeField;
use zcash_note_encryption::{
    BatchDomain, Domain, EphemeralKeyBytes, NotePlaintextBytes, OutPlaintextBytes,
    OutgoingCipherKey, ShieldedOutput, COMPACT_NOTE_SIZE, ENC_CIPHERTEXT_SIZE, NOTE_PLAINTEXT_SIZE,
    OUT_PLAINTEXT_SIZE,
};

use crate::{
    action::Action,
    keys::{
        DiversifiedTransmissionKey, Diversifier, EphemeralPublicKey, EphemeralSecretKey,
        OutgoingViewingKey, PreparedEphemeralPublicKey, PreparedIncomingViewingKey, SharedSecret,
    },
    note::{ExtractedNoteCommitment, NoteVersion, Nullifier, RandomSeed, Rho},
    value::{NoteValue, ValueCommitment},
    Address, Note,
};

const PRF_OCK_ORCHARD_PERSONALIZATION: &[u8; 16] = b"Zcash_Orchardock";

/// Defined in [Zcash Protocol Spec § 5.4.2: Pseudo Random Functions][concreteprfs].
///
/// [concreteprfs]: https://zips.z.cash/protocol/nu5.pdf#concreteprfs
pub(crate) fn prf_ock_orchard(
    ovk: &OutgoingViewingKey,
    cv: &ValueCommitment,
    cmx_bytes: &[u8; 32],
    ephemeral_key: &EphemeralKeyBytes,
) -> OutgoingCipherKey {
    OutgoingCipherKey(
        Params::new()
            .hash_length(32)
            .personal(PRF_OCK_ORCHARD_PERSONALIZATION)
            .to_state()
            .update(ovk.as_ref())
            .update(&cv.to_bytes())
            .update(cmx_bytes)
            .update(ephemeral_key.as_ref())
            .finalize()
            .as_bytes()
            .try_into()
            .unwrap(),
    )
}

fn parse_note_plaintext_without_memo<F>(
    rho: Rho,
    plaintext: &[u8],
    note_version: NoteVersion,
    get_pk_d: F,
) -> Option<(Note, Address)>
where
    F: FnOnce(&Diversifier) -> DiversifiedTransmissionKey,
{
    assert!(plaintext.len() >= COMPACT_NOTE_SIZE);

    // The unwraps below are guaranteed to succeed by the assertion above
    let diversifier = Diversifier::from_bytes(plaintext[1..12].try_into().unwrap());
    let value = NoteValue::from_bytes(plaintext[12..20].try_into().unwrap());
    let rseed = Option::from(RandomSeed::from_bytes(
        plaintext[20..COMPACT_NOTE_SIZE].try_into().unwrap(),
        &rho,
    ))?;

    let pk_d = get_pk_d(&diversifier);

    let recipient = Address::from_parts(diversifier, pk_d);
    let note = Option::from(Note::from_parts(recipient, value, rho, rseed, note_version))?;
    Some((note, recipient))
}

mod sealed {
    /// Marker trait that prevents external `DomainVersion` implementations.
    pub trait Sealed {}
}

trait DomainPolicy {
    fn note_version(&self, plaintext: &[u8]) -> Option<NoteVersion>;
}

/// A sealed marker trait for note encryption domains with a fixed note plaintext version.
///
/// This trait is sealed so that only this crate can define supported note encryption
/// domains.
pub trait DomainVersion: sealed::Sealed + Default {
    /// The note plaintext version accepted by this domain during parsing and decryption.
    const NOTE_VERSION: NoteVersion;
}

impl<V: DomainVersion> DomainPolicy for V {
    fn note_version(&self, plaintext: &[u8]) -> Option<NoteVersion> {
        if plaintext.first().copied() == Some(V::NOTE_VERSION.lead_byte()) {
            Some(V::NOTE_VERSION)
        } else {
            None
        }
    }
}

/// Marker type for Orchard note encryption domains.
#[derive(Default, Debug)]
pub struct OrchardVersion;

impl sealed::Sealed for OrchardVersion {}

impl DomainVersion for OrchardVersion {
    const NOTE_VERSION: NoteVersion = NoteVersion::V2;
}

/// Marker type for Ironwood note encryption domains.
#[derive(Default, Debug)]
pub struct IronwoodVersion;

impl sealed::Sealed for IronwoodVersion {}

impl DomainVersion for IronwoodVersion {
    const NOTE_VERSION: NoteVersion = NoteVersion::V3;
}

#[derive(Debug)]
pub(crate) struct BundleDomainPolicy {
    note_version: NoteVersion,
}

impl DomainPolicy for BundleDomainPolicy {
    fn note_version(&self, plaintext: &[u8]) -> Option<NoteVersion> {
        let note_version = NoteVersion::from_lead_byte(*plaintext.first()?)?;
        if note_version == self.note_version {
            Some(note_version)
        } else {
            None
        }
    }
}

/// Note encryption logic for a note plaintext version policy.
///
/// The policy type `P` selects which note plaintext version is accepted during
/// parsing and decryption. Encryption uses the version recorded by the note.
#[derive(Debug)]
pub struct NoteEncryptionDomain<P> {
    rho: Rho,
    policy: P,
}

impl<P> memuse::DynamicUsage for NoteEncryptionDomain<P> {
    fn dynamic_usage(&self) -> usize {
        self.rho.dynamic_usage()
    }

    fn dynamic_usage_bounds(&self) -> (usize, Option<usize>) {
        self.rho.dynamic_usage_bounds()
    }
}

impl<V: DomainVersion> NoteEncryptionDomain<V> {
    pub(crate) fn from_rho(rho: Rho) -> Self {
        Self {
            rho,
            policy: V::default(),
        }
    }

    /// Constructs a domain that can be used to trial-decrypt this action's output note.
    pub fn for_action<T>(act: &Action<T>) -> Self {
        Self::from_rho(act.rho())
    }

    /// Constructs a domain that can be used to trial-decrypt a PCZT action's output note.
    pub fn for_pczt_action(act: &crate::pczt::Action) -> Self {
        Self::from_rho(Rho::from_nf_old(act.spend().nullifier))
    }

    /// Constructs a domain that can be used to trial-decrypt this compact action's output note.
    pub fn for_compact_action(act: &CompactAction) -> Self {
        Self::from_rho(act.rho())
    }
}

/// Orchard-specific note encryption logic.
///
/// This domain accepts only [`NoteVersion::V2`] note plaintexts, which use lead
/// byte `0x02`.
pub type OrchardDomain = NoteEncryptionDomain<OrchardVersion>;

/// Ironwood-specific note encryption logic.
///
/// This domain is otherwise identical to [`OrchardDomain`], but accepts only
/// [`NoteVersion::V3`] note plaintexts, which use lead byte `0x03`.
pub type IronwoodDomain = NoteEncryptionDomain<IronwoodVersion>;

/// Note encryption logic restricted to a single note plaintext version.
///
/// This domain is used by public bundle helpers that are given the bundle's
/// [`NoteVersion`]. Trial decryption still happens once; after decryption
/// succeeds, the revealed note plaintext lead byte selects the note version, which is
/// enforced to match the expected one.
pub(crate) type BundleDomain = NoteEncryptionDomain<BundleDomainPolicy>;

impl BundleDomain {
    /// Constructs a domain that can be used to trial-decrypt this action's
    /// output note as a note of `note_version`.
    pub(crate) fn for_action<T>(act: &Action<T>, note_version: NoteVersion) -> Self {
        Self {
            rho: act.rho(),
            policy: BundleDomainPolicy { note_version },
        }
    }
}

impl<P: DomainPolicy> Domain for NoteEncryptionDomain<P> {
    type EphemeralSecretKey = EphemeralSecretKey;
    type EphemeralPublicKey = EphemeralPublicKey;
    type PreparedEphemeralPublicKey = PreparedEphemeralPublicKey;
    type SharedSecret = SharedSecret;
    type SymmetricKey = Hash;
    type Note = Note;
    type Recipient = Address;
    type DiversifiedTransmissionKey = DiversifiedTransmissionKey;
    type IncomingViewingKey = PreparedIncomingViewingKey;
    type OutgoingViewingKey = OutgoingViewingKey;
    type ValueCommitment = ValueCommitment;
    type ExtractedCommitment = ExtractedNoteCommitment;
    type ExtractedCommitmentBytes = [u8; 32];
    type Memo = [u8; 512]; // TODO use a more interesting type

    fn derive_esk(note: &Self::Note) -> Option<Self::EphemeralSecretKey> {
        Some(note.esk())
    }

    fn get_pk_d(note: &Self::Note) -> Self::DiversifiedTransmissionKey {
        *note.recipient().pk_d()
    }

    fn prepare_epk(epk: Self::EphemeralPublicKey) -> Self::PreparedEphemeralPublicKey {
        PreparedEphemeralPublicKey::new(epk)
    }

    fn ka_derive_public(
        note: &Self::Note,
        esk: &Self::EphemeralSecretKey,
    ) -> Self::EphemeralPublicKey {
        esk.derive_public(note.recipient().g_d())
    }

    fn ka_agree_enc(
        esk: &Self::EphemeralSecretKey,
        pk_d: &Self::DiversifiedTransmissionKey,
    ) -> Self::SharedSecret {
        esk.agree(pk_d)
    }

    fn ka_agree_dec(
        ivk: &Self::IncomingViewingKey,
        epk: &Self::PreparedEphemeralPublicKey,
    ) -> Self::SharedSecret {
        epk.agree(ivk)
    }

    fn kdf(secret: Self::SharedSecret, ephemeral_key: &EphemeralKeyBytes) -> Self::SymmetricKey {
        secret.kdf_orchard(ephemeral_key)
    }

    fn note_plaintext_bytes(note: &Self::Note, memo: &Self::Memo) -> NotePlaintextBytes {
        let mut np = [0; NOTE_PLAINTEXT_SIZE];
        np[0] = note.version().lead_byte();
        np[1..12].copy_from_slice(note.recipient().diversifier().as_array());
        np[12..20].copy_from_slice(&note.value().to_bytes());
        np[20..52].copy_from_slice(note.rseed().as_bytes());
        np[52..].copy_from_slice(memo);
        NotePlaintextBytes(np)
    }

    fn derive_ock(
        ovk: &Self::OutgoingViewingKey,
        cv: &Self::ValueCommitment,
        cmstar_bytes: &Self::ExtractedCommitmentBytes,
        ephemeral_key: &EphemeralKeyBytes,
    ) -> OutgoingCipherKey {
        prf_ock_orchard(ovk, cv, cmstar_bytes, ephemeral_key)
    }

    fn outgoing_plaintext_bytes(
        note: &Self::Note,
        esk: &Self::EphemeralSecretKey,
    ) -> OutPlaintextBytes {
        let mut op = [0; OUT_PLAINTEXT_SIZE];
        op[..32].copy_from_slice(&note.recipient().pk_d().to_bytes());
        op[32..].copy_from_slice(&esk.0.to_repr());
        OutPlaintextBytes(op)
    }

    fn epk_bytes(epk: &Self::EphemeralPublicKey) -> EphemeralKeyBytes {
        epk.to_bytes()
    }

    fn epk(ephemeral_key: &EphemeralKeyBytes) -> Option<Self::EphemeralPublicKey> {
        EphemeralPublicKey::from_bytes(&ephemeral_key.0).into()
    }

    fn cmstar(note: &Self::Note) -> Self::ExtractedCommitment {
        note.commitment().into()
    }

    fn parse_note_plaintext_without_memo_ivk(
        &self,
        ivk: &Self::IncomingViewingKey,
        plaintext: &[u8],
    ) -> Option<(Self::Note, Self::Recipient)> {
        let note_version = self.policy.note_version(plaintext)?;
        parse_note_plaintext_without_memo(self.rho, plaintext, note_version, |diversifier| {
            DiversifiedTransmissionKey::derive(ivk, diversifier)
        })
    }

    fn parse_note_plaintext_without_memo_ovk(
        &self,
        pk_d: &Self::DiversifiedTransmissionKey,
        plaintext: &NotePlaintextBytes,
    ) -> Option<(Self::Note, Self::Recipient)> {
        let note_version = self.policy.note_version(&plaintext.0)?;
        parse_note_plaintext_without_memo(self.rho, &plaintext.0, note_version, |_| *pk_d)
    }

    fn extract_memo(&self, plaintext: &NotePlaintextBytes) -> Self::Memo {
        plaintext.0[COMPACT_NOTE_SIZE..NOTE_PLAINTEXT_SIZE]
            .try_into()
            .unwrap()
    }

    fn extract_pk_d(out_plaintext: &OutPlaintextBytes) -> Option<Self::DiversifiedTransmissionKey> {
        DiversifiedTransmissionKey::from_bytes(out_plaintext.0[0..32].try_into().unwrap()).into()
    }

    fn extract_esk(out_plaintext: &OutPlaintextBytes) -> Option<Self::EphemeralSecretKey> {
        EphemeralSecretKey::from_bytes(out_plaintext.0[32..OUT_PLAINTEXT_SIZE].try_into().unwrap())
            .into()
    }
}

impl<P: DomainPolicy> BatchDomain for NoteEncryptionDomain<P> {
    fn batch_kdf<'a>(
        items: impl Iterator<Item = (Option<Self::SharedSecret>, &'a EphemeralKeyBytes)>,
    ) -> Vec<Option<Self::SymmetricKey>> {
        batch_kdf(items)
    }
}

fn batch_kdf<'a>(
    items: impl Iterator<Item = (Option<SharedSecret>, &'a EphemeralKeyBytes)>,
) -> Vec<Option<Hash>> {
    let (shared_secrets, ephemeral_keys): (Vec<_>, Vec<_>) = items.unzip();

    SharedSecret::batch_to_affine(shared_secrets)
        .zip(ephemeral_keys)
        .map(|(secret, ephemeral_key)| {
            secret.map(|dhsecret| SharedSecret::kdf_orchard_inner(dhsecret, ephemeral_key))
        })
        .collect()
}

impl<P: DomainPolicy, T> ShieldedOutput<NoteEncryptionDomain<P>, ENC_CIPHERTEXT_SIZE>
    for Action<T>
{
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        EphemeralKeyBytes(self.encrypted_note().epk_bytes)
    }

    fn cmstar_bytes(&self) -> [u8; 32] {
        self.cmx().to_bytes()
    }

    fn enc_ciphertext(&self) -> &[u8; ENC_CIPHERTEXT_SIZE] {
        &self.encrypted_note().enc_ciphertext
    }
}

impl<P: DomainPolicy> ShieldedOutput<NoteEncryptionDomain<P>, ENC_CIPHERTEXT_SIZE>
    for crate::pczt::Action
{
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        EphemeralKeyBytes(self.output().encrypted_note().epk_bytes)
    }

    fn cmstar_bytes(&self) -> [u8; 32] {
        self.output().cmx().to_bytes()
    }

    fn enc_ciphertext(&self) -> &[u8; ENC_CIPHERTEXT_SIZE] {
        &self.output().encrypted_note().enc_ciphertext
    }
}

impl<P: DomainPolicy> ShieldedOutput<NoteEncryptionDomain<P>, COMPACT_NOTE_SIZE> for CompactAction {
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        EphemeralKeyBytes(self.ephemeral_key.0)
    }

    fn cmstar_bytes(&self) -> [u8; 32] {
        self.cmx.to_bytes()
    }

    fn enc_ciphertext(&self) -> &[u8; COMPACT_NOTE_SIZE] {
        &self.enc_ciphertext
    }
}

/// Implementation of in-band secret distribution for Orchard bundles.
///
/// This is the [`NoteEncryption`] instantiation for [`OrchardDomain`]. Encryption
/// behavior is shared with [`IronwoodNoteEncryption`]: the note plaintext lead
/// byte is selected from [`crate::Note::version`], while the domain type
/// controls which note plaintext versions are accepted during parsing and
/// decryption.
///
/// [`NoteEncryption`]: zcash_note_encryption::NoteEncryption
pub type OrchardNoteEncryption = zcash_note_encryption::NoteEncryption<OrchardDomain>;
/// Implementation of in-band secret distribution for Ironwood bundles.
///
/// This is the [`NoteEncryption`] instantiation for [`IronwoodDomain`]. Encryption
/// behavior is shared with [`OrchardNoteEncryption`]: the note plaintext lead
/// byte is selected from [`crate::Note::version`], while the domain type
/// controls which note plaintext versions are accepted during parsing and
/// decryption.
///
/// [`NoteEncryption`]: zcash_note_encryption::NoteEncryption
pub type IronwoodNoteEncryption = zcash_note_encryption::NoteEncryption<IronwoodDomain>;

/// A compact Action for light clients.
#[derive(Clone)]
pub struct CompactAction {
    nullifier: Nullifier,
    cmx: ExtractedNoteCommitment,
    ephemeral_key: EphemeralKeyBytes,
    enc_ciphertext: [u8; 52],
}

impl fmt::Debug for CompactAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CompactAction")
    }
}

impl<T> From<&Action<T>> for CompactAction {
    fn from(action: &Action<T>) -> Self {
        CompactAction {
            nullifier: *action.nullifier(),
            cmx: *action.cmx(),
            ephemeral_key: EphemeralKeyBytes(action.encrypted_note().epk_bytes),
            enc_ciphertext: action.encrypted_note().enc_ciphertext[..52]
                .try_into()
                .unwrap(),
        }
    }
}

impl CompactAction {
    /// Create a CompactAction from its constituent parts
    pub fn from_parts(
        nullifier: Nullifier,
        cmx: ExtractedNoteCommitment,
        ephemeral_key: EphemeralKeyBytes,
        enc_ciphertext: [u8; 52],
    ) -> Self {
        Self {
            nullifier,
            cmx,
            ephemeral_key,
            enc_ciphertext,
        }
    }

    /// Returns the nullifier of the note being spent.
    pub fn nullifier(&self) -> Nullifier {
        self.nullifier
    }

    /// Returns the commitment to the new note being created.
    pub fn cmx(&self) -> ExtractedNoteCommitment {
        self.cmx
    }

    /// Obtains the [`Rho`] value that was used to construct the new note being created.
    pub fn rho(&self) -> Rho {
        Rho::from_nf_old(self.nullifier)
    }
}

/// Utilities for constructing test data.
#[cfg(feature = "test-dependencies")]
pub mod testing {
    use rand::RngCore;
    use zcash_note_encryption::Domain;

    use crate::{
        keys::OutgoingViewingKey,
        note::{ExtractedNoteCommitment, NoteVersion, Nullifier, RandomSeed, Rho},
        value::NoteValue,
        Address, Note,
    };

    use super::{CompactAction, OrchardDomain, OrchardNoteEncryption};

    /// Creates a fake `CompactAction` paying the given recipient the specified value.
    ///
    /// Returns the `CompactAction` and the new note.
    pub fn fake_compact_action<R: RngCore>(
        rng: &mut R,
        nf_old: Nullifier,
        recipient: Address,
        value: NoteValue,
        ovk: Option<OutgoingViewingKey>,
    ) -> (CompactAction, Note) {
        let rho = Rho::from_nf_old(nf_old);
        let rseed = {
            loop {
                let mut bytes = [0; 32];
                rng.fill_bytes(&mut bytes);
                let rseed = RandomSeed::from_bytes(bytes, &rho);
                if rseed.is_some().into() {
                    break rseed.unwrap();
                }
            }
        };
        let note = Note::from_parts(recipient, value, rho, rseed, NoteVersion::V2).unwrap();
        let encryptor = OrchardNoteEncryption::new(ovk, note, [0u8; 512]);
        let cmx = ExtractedNoteCommitment::from(note.commitment());
        let ephemeral_key = OrchardDomain::epk_bytes(encryptor.epk());
        let enc_ciphertext = encryptor.encrypt_note_plaintext();

        (
            CompactAction {
                nullifier: nf_old,
                cmx,
                ephemeral_key,
                enc_ciphertext: enc_ciphertext.as_ref()[..52].try_into().unwrap(),
            },
            note,
        )
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::String;
    use alloc::vec::Vec;
    use rand::rngs::OsRng;
    use std::println;
    use zcash_note_encryption::{
        try_compact_note_decryption, try_note_decryption, try_output_recovery_with_ovk, Domain,
        EphemeralKeyBytes,
    };

    use super::{
        prf_ock_orchard, CompactAction, IronwoodDomain, IronwoodNoteEncryption, OrchardDomain,
        OrchardNoteEncryption,
    };
    use crate::{
        action::Action,
        keys::{
            DiversifiedTransmissionKey, Diversifier, EphemeralSecretKey, IncomingViewingKey,
            OutgoingViewingKey, PreparedIncomingViewingKey, Scope, SpendingKey,
        },
        note::{
            ExtractedNoteCommitment, NoteVersion, Nullifier, RandomSeed, Rho,
            TransmittedNoteCiphertext,
        },
        primitives::redpallas,
        value::{NoteValue, ValueCommitTrapdoor, ValueCommitment, ValueSum},
        Address, Note,
    };

    fn v3_encrypted_action() -> (
        Action<()>,
        PreparedIncomingViewingKey,
        Note,
        Address,
        [u8; 512],
    ) {
        let mut rng = OsRng;
        let sk = SpendingKey::random(&mut rng);
        let fvk = crate::keys::FullViewingKey::from(&sk);
        let incoming_viewing_key = fvk.to_ivk(Scope::External);
        let prepared_ivk = PreparedIncomingViewingKey::new(&incoming_viewing_key);
        let recipient = fvk.address_at(0u32, Scope::External);
        let nf_old = Nullifier::dummy(&mut rng);
        let rho = Rho::from_nf_old(nf_old);
        let note = Note::new(
            recipient,
            NoteValue::from_raw(5),
            rho,
            NoteVersion::V3,
            &mut rng,
        );
        let memo = [7u8; 512];
        let cv_net = ValueCommitment::derive(ValueSum::from_raw(5), ValueCommitTrapdoor::zero());
        let cmx = ExtractedNoteCommitment::from(note.commitment());
        let encryptor = IronwoodNoteEncryption::new(Some(fvk.to_ovk(Scope::External)), note, memo);
        let encrypted_note = TransmittedNoteCiphertext {
            epk_bytes: IronwoodDomain::epk_bytes(encryptor.epk()).0,
            enc_ciphertext: encryptor.encrypt_note_plaintext(),
            out_ciphertext: encryptor.encrypt_outgoing_plaintext(&cv_net, &cmx, &mut rng),
        };
        let action = Action::from_parts(
            nf_old,
            redpallas::VerificationKey::dummy(),
            cmx,
            encrypted_note,
            cv_net,
            (),
        )
        .expect("a dummy verification key is unlikely to be the identity");

        (action, prepared_ivk, note, recipient, memo)
    }

    #[test]
    fn test_vectors() {
        let test_vectors = crate::test_vectors::note_encryption::test_vectors();

        for tv in test_vectors {
            //
            // Load the test vector components
            //

            // Recipient key material
            let ivk = PreparedIncomingViewingKey::new(
                &IncomingViewingKey::from_bytes(&tv.incoming_viewing_key).unwrap(),
            );
            let ovk = OutgoingViewingKey::from(tv.ovk);
            let d = Diversifier::from_bytes(tv.default_d);
            let pk_d = DiversifiedTransmissionKey::from_bytes(&tv.default_pk_d).unwrap();

            // Received Action
            let cv_net = ValueCommitment::from_bytes(&tv.cv_net).unwrap();
            let nf_old = Nullifier::from_bytes(&tv.nf_old).unwrap();
            let rho = Rho::from_nf_old(nf_old);
            let cmx = ExtractedNoteCommitment::from_bytes(&tv.cmx).unwrap();

            let esk = EphemeralSecretKey::from_bytes(&tv.esk).unwrap();
            let ephemeral_key = EphemeralKeyBytes(tv.ephemeral_key);

            // Details about the expected note
            let value = NoteValue::from_raw(tv.v);
            let rseed = RandomSeed::from_bytes(tv.rseed, &rho).unwrap();

            //
            // Test the individual components
            //

            let shared_secret = esk.agree(&pk_d);
            assert_eq!(shared_secret.to_bytes(), tv.shared_secret);

            let k_enc = shared_secret.kdf_orchard(&ephemeral_key);
            assert_eq!(k_enc.as_bytes(), tv.k_enc);

            let ock = prf_ock_orchard(&ovk, &cv_net, &cmx.to_bytes(), &ephemeral_key);
            assert_eq!(ock.as_ref(), tv.ock);

            let recipient = Address::from_parts(d, pk_d);
            let note_version = NoteVersion::V2;
            let note = Note::from_parts(recipient, value, rho, rseed, note_version).unwrap();
            assert_eq!(ExtractedNoteCommitment::from(note.commitment()), cmx);

            let action = Action::from_parts(
                // nf_old is the nullifier revealed by the receiving Action.
                nf_old,
                // We don't need a real rk for this test.
                redpallas::VerificationKey::dummy(),
                cmx,
                TransmittedNoteCiphertext {
                    epk_bytes: ephemeral_key.0,
                    enc_ciphertext: tv.c_enc,
                    out_ciphertext: tv.c_out,
                },
                cv_net.clone(),
                (),
            )
            .expect("a key returned by VerificationKey::dummy() is vanishingly unlikely to be the identity");

            //
            // Test decryption
            // (Tested first because it only requires immutable references.)
            //

            let domain = OrchardDomain::from_rho(rho);

            match try_note_decryption(&domain, &ivk, &action) {
                Some((decrypted_note, decrypted_to, decrypted_memo)) => {
                    assert_eq!(decrypted_note, note);
                    assert_eq!(decrypted_to, recipient);
                    assert_eq!(&decrypted_memo[..], &tv.memo[..]);
                }
                None => panic!("Note decryption failed"),
            }

            match try_compact_note_decryption(&domain, &ivk, &CompactAction::from(&action)) {
                Some((decrypted_note, decrypted_to)) => {
                    assert_eq!(decrypted_note, note);
                    assert_eq!(decrypted_to, recipient);
                }
                None => panic!("Compact note decryption failed"),
            }

            match try_output_recovery_with_ovk(&domain, &ovk, &action, &cv_net, &tv.c_out) {
                Some((decrypted_note, decrypted_to, decrypted_memo)) => {
                    assert_eq!(decrypted_note, note);
                    assert_eq!(decrypted_to, recipient);
                    assert_eq!(&decrypted_memo[..], &tv.memo[..]);
                }
                None => panic!("Output recovery failed"),
            }

            //
            // Test encryption
            //

            let ne = OrchardNoteEncryption::new_with_esk(esk, Some(ovk), note, tv.memo);

            assert_eq!(ne.encrypt_note_plaintext().as_ref(), &tv.c_enc[..]);
            assert_eq!(
                &ne.encrypt_outgoing_plaintext(&cv_net, &cmx, &mut OsRng)[..],
                &tv.c_out[..]
            );
        }
    }

    #[test]
    fn domains_accept_only_their_note_plaintext_versions() {
        let mut rng = OsRng;
        let sk = crate::keys::SpendingKey::random(&mut rng);
        let fvk = crate::keys::FullViewingKey::from(&sk);
        let recipient = fvk.address_at(0u32, crate::keys::Scope::External);
        let rho = Rho::from_nf_old(Nullifier::dummy(&mut rng));
        let memo = [0u8; 512];

        let note_v2 = Note::new(
            recipient,
            NoteValue::from_raw(5),
            rho,
            NoteVersion::V2,
            &mut rng,
        );
        let note_v3 = Note::new(
            recipient,
            NoteValue::from_raw(5),
            rho,
            NoteVersion::V3,
            &mut rng,
        );
        let orchard_domain = OrchardDomain::from_rho(rho);
        let ironwood_domain = IronwoodDomain::from_rho(rho);

        let np_v2 = OrchardDomain::note_plaintext_bytes(&note_v2, &memo);
        let np_v3 = IronwoodDomain::note_plaintext_bytes(&note_v3, &memo);
        let pk_d = recipient.pk_d();

        assert_eq!(
            orchard_domain
                .parse_note_plaintext_without_memo_ovk(pk_d, &np_v2)
                .map(|(note, _)| note),
            Some(note_v2)
        );
        assert_eq!(
            ironwood_domain
                .parse_note_plaintext_without_memo_ovk(pk_d, &np_v3)
                .map(|(note, _)| note),
            Some(note_v3)
        );
        assert!(orchard_domain
            .parse_note_plaintext_without_memo_ovk(pk_d, &np_v3)
            .is_none());
        assert!(ironwood_domain
            .parse_note_plaintext_without_memo_ovk(pk_d, &np_v2)
            .is_none());
    }

    #[test]
    fn ironwood_domain_decrypts_v3_encrypted_outputs() {
        let (action, ivk, note, recipient, memo) = v3_encrypted_action();
        let domain = IronwoodDomain::for_action(&action);

        assert_eq!(
            try_note_decryption(&domain, &ivk, &action),
            Some((note, recipient, memo))
        );
    }

    #[test]
    fn orchard_domain_rejects_v3_encrypted_outputs() {
        let (action, ivk, _, _, _) = v3_encrypted_action();
        let domain = OrchardDomain::for_action(&action);

        assert!(try_note_decryption(&domain, &ivk, &action).is_none());
    }

    #[test]
    fn ironwood_domain_decrypts_v3_compact_outputs() {
        let (action, ivk, note, recipient, _) = v3_encrypted_action();
        let domain = IronwoodDomain::for_action(&action);
        let compact = CompactAction::from(&action);

        assert_eq!(
            try_compact_note_decryption(&domain, &ivk, &compact),
            Some((note, recipient))
        );
    }

    /// Generates deterministic V3 (ZIP 2005) Ironwood note-encryption test vectors for use
    /// in the Ragger Python functional tests (`tests/standalone/test_pczt_ironwood.py`).
    ///
    /// Must be run inside the Ledger dev-tools Docker container (host build, not device build):
    ///
    /// ```sh
    /// HOST=$(rustc -vV | awk '/^host:/ {print $2}')
    /// cargo test --target "$HOST" -- gen_v3_ironwood_test_vectors --nocapture
    /// ```
    ///
    /// The `ledger` feature must be excluded from the build to avoid pulling in the device SDK:
    /// run from within `vendor/orchard/` so the root `Cargo.toml`'s `features = ["ledger"]`
    /// does not apply.
    ///
    /// **Why this is device-compatible:**
    /// The enc_ciphertext is encrypted with `k_enc = KDF(ECDH(esk, pk_d), epk)`.
    /// The device decrypts with `k_enc = KDF(ECDH(ivk, epk), epk) = KDF(ECDH(esk, pk_d), epk)`
    /// because `pk_d = ivk·g_d` and `epk = esk·g_d`, so both DH computations yield `esk·ivk·g_d`.
    /// Therefore the device's IVK will successfully decrypt this enc_ciphertext without us
    /// needing to know the IVK value.
    #[test]
    fn gen_v3_ironwood_test_vectors() {
        // _INTERNAL_RECIPIENT from test_pczt_ironwood.py: 11-byte diversifier + 32-byte pk_d.
        // This is the device's internal address at m/32'/133'/0' (Speculos deterministic seed).
        let recipient_bytes: [u8; 43] = [
            // diversifier (11 bytes)
            0xed, 0xe3, 0xd2, 0xce, 0x08, 0xc1, 0x1d, 0x8c, 0x5c, 0x7b, 0xfe,
            // pk_d (32 bytes)
            0x68, 0x14, 0xce, 0xda, 0xfd, 0x96, 0xc1, 0x60, 0xc3, 0xd8, 0x79, 0xcb, 0x27, 0x09,
            0x46, 0xf1, 0xab, 0x6f, 0xdf, 0x44, 0x2a, 0x15, 0x64, 0x8d, 0x7c, 0x0b, 0x3c, 0x9f,
            0xd0, 0x52, 0xe2, 0x0a,
        ];
        let diversifier = Diversifier::from_bytes(recipient_bytes[..11].try_into().unwrap());
        let pk_d =
            DiversifiedTransmissionKey::from_bytes(recipient_bytes[11..].try_into().unwrap())
                .unwrap();
        let recipient = Address::from_parts(diversifier, pk_d);

        // _DUMMY_NULLIFIER from test_pczt_ironwood.py — spend nullifier of the dummy action.
        // rho = Rho::from_nf_old(nf_old) matches what the device reconstructs from the wire.
        let nullifier_bytes: [u8; 32] = [
            0x57, 0xaa, 0xd2, 0x67, 0x0e, 0x2e, 0x4d, 0xf6, 0x7c, 0xa8, 0x55, 0xc5, 0x39, 0x73,
            0xdb, 0x38, 0xe7, 0x94, 0x2e, 0xfa, 0x8e, 0x90, 0x6e, 0xe9, 0x61, 0xad, 0xb7, 0x19,
            0x55, 0xaa, 0x84, 0x23,
        ];
        let nf_old = Nullifier::from_bytes(&nullifier_bytes).unwrap();
        let rho = Rho::from_nf_old(nf_old);

        // Fixed rseed distinct from _DUMMY_RSEED (0x30) to produce a different V3 cmx.
        let rseed_bytes: [u8; 32] = {
            let mut b = [0u8; 32];
            b[0] = 0x35;
            b
        };
        let rseed = Option::from(RandomSeed::from_bytes(rseed_bytes, &rho)).expect(
            "rseed 0x35... is valid for this rho; if this fails try a different leading byte",
        );

        // V3 (ZIP 2005) note: same Sinsemilla commitment message as V2, but rcm uses BLAKE2b-512
        // over (rseed ‖ 0x0B ‖ g_d ‖ pk_d ‖ value_le ‖ rho ‖ psi) — see note_commitment_v3.
        let value = NoteValue::from_raw(10000); // same as _DUMMY_CHANGE_VALUE
        let note: Note = Option::from(Note::from_parts(
            recipient,
            value,
            rho,
            rseed,
            NoteVersion::V3,
        ))
        .expect("note construction failed — recipient or rho may be invalid");

        // Derive esk from the note's rseed so the device's compact-decryption path can verify
        // that epk == PRF-esk(rseed, rho) · g_d.  Using a fixed scalar here (as the previous
        // version did) would cause that check to fail, making the device reject the note.
        let esk = note.esk();

        let encryptor = IronwoodNoteEncryption::new_with_esk(esk, None, note, [0u8; 512]);
        let cmx = ExtractedNoteCommitment::from(note.commitment());
        let ephemeral_key = IronwoodDomain::epk_bytes(encryptor.epk());
        let enc_ciphertext_array = encryptor.encrypt_note_plaintext();
        let enc_ciphertext: &[u8] = enc_ciphertext_array.as_ref();

        // Helper: format bytes as a Python hex string literal, 64 hex chars per line.
        let hex_lines = |bytes: &[u8]| -> String {
            bytes
                .chunks(32)
                .map(|c| c.iter().map(|b| format!("{:02x}", b)).collect::<String>())
                .collect::<Vec<_>>()
                .join("\"\n    \"")
        };

        println!("\n# ---- V3 Ironwood test vectors (gen_v3_ironwood_test_vectors) ----");
        println!(
            "# Generated with: cargo test -p orchard -- gen_v3_ironwood_test_vectors --nocapture"
        );
        println!("# recipient  = _INTERNAL_RECIPIENT");
        println!("# nullifier  = _DUMMY_NULLIFIER  (rho = Rho::from_nf_old(nullifier))");
        println!("# note_value = 10000  (= _DUMMY_CHANGE_VALUE)");
        println!("# rseed      = 0x35 followed by 31 zero bytes (note rseed, not metadata rseed)");
        println!("# esk        = note.esk() = PRF-esk(rseed, rho) — derived, not fixed");
        println!("# version    = NoteVersion::V3  (plaintext lead byte 0x03)\n");
        println!(
            "_V3_REAL_EPK = bytes.fromhex(\n    \"{}\"\n)",
            hex_lines(&ephemeral_key.0)
        );
        println!(
            "_V3_REAL_CMX = bytes.fromhex(\n    \"{}\"\n)",
            hex_lines(&cmx.to_bytes())
        );
        println!(
            "_V3_REAL_ENC_CIPHERTEXT = bytes.fromhex(\n    \"{}\"\n)",
            hex_lines(enc_ciphertext)
        );

        // Sanity check: the note commitment is stable (not randomised).
        assert_eq!(
            cmx,
            ExtractedNoteCommitment::from(note.commitment()),
            "note commitment must be deterministic"
        );
    }

    /// Compute the V3 note commitment for the zero-value dummy output used in
    /// `test_pczt_v2_0x03_dummy_accepted`.  Outputs the `_V3_DUMMY_CMX` Python constant.
    ///
    /// Run from within `vendor/orchard/` (host target, no `ledger` feature):
    /// ```sh
    /// HOST=$(rustc -vV | awk '/^host:/ {print $2}')
    /// cargo test --target "$HOST" -- gen_v3_dummy_cmx --nocapture
    /// ```
    #[test]
    fn gen_v3_dummy_cmx() {
        // _INTERNAL_RECIPIENT — same as gen_v3_ironwood_test_vectors.
        let recipient_bytes: [u8; 43] = [
            0xed, 0xe3, 0xd2, 0xce, 0x08, 0xc1, 0x1d, 0x8c, 0x5c, 0x7b, 0xfe, 0x68, 0x14, 0xce,
            0xda, 0xfd, 0x96, 0xc1, 0x60, 0xc3, 0xd8, 0x79, 0xcb, 0x27, 0x09, 0x46, 0xf1, 0xab,
            0x6f, 0xdf, 0x44, 0x2a, 0x15, 0x64, 0x8d, 0x7c, 0x0b, 0x3c, 0x9f, 0xd0, 0x52, 0xe2,
            0x0a,
        ];
        let diversifier = Diversifier::from_bytes(recipient_bytes[..11].try_into().unwrap());
        let pk_d =
            DiversifiedTransmissionKey::from_bytes(recipient_bytes[11..].try_into().unwrap())
                .unwrap();
        let recipient = Address::from_parts(diversifier, pk_d);

        // _DUMMY_NULLIFIER — same as gen_v3_ironwood_test_vectors.
        let nullifier_bytes: [u8; 32] = [
            0x57, 0xaa, 0xd2, 0x67, 0x0e, 0x2e, 0x4d, 0xf6, 0x7c, 0xa8, 0x55, 0xc5, 0x39, 0x73,
            0xdb, 0x38, 0xe7, 0x94, 0x2e, 0xfa, 0x8e, 0x90, 0x6e, 0xe9, 0x61, 0xad, 0xb7, 0x19,
            0x55, 0xaa, 0x84, 0x23,
        ];
        let nf_old = Nullifier::from_bytes(&nullifier_bytes).unwrap();
        let rho = Rho::from_nf_old(nf_old);

        // _DUMMY_RSEED = 0x30 followed by 31 zero bytes (distinct from the real-output rseed 0x35).
        let rseed_bytes: [u8; 32] = {
            let mut b = [0u8; 32];
            b[0] = 0x30;
            b
        };
        let rseed = Option::from(RandomSeed::from_bytes(rseed_bytes, &rho))
            .expect("rseed 0x30... is valid for this rho");

        // Zero-value V3 dummy note.
        let note: Note = Option::from(Note::from_parts(
            recipient,
            NoteValue::from_raw(0),
            rho,
            rseed,
            NoteVersion::V3,
        ))
        .expect("note construction failed");

        let cmx = ExtractedNoteCommitment::from(note.commitment());
        let cmx_bytes = cmx.to_bytes();

        println!("\n# ---- V3 dummy cmx (gen_v3_dummy_cmx) ----");
        println!(
            "# Generated with: cargo test --target $HOST -p orchard -- gen_v3_dummy_cmx --nocapture"
        );
        println!("# recipient = _INTERNAL_RECIPIENT, value = 0, nullifier = _DUMMY_NULLIFIER");
        println!("# rseed     = 0x30 followed by 31 zero bytes (_DUMMY_RSEED)\n");
        println!(
            "_V3_DUMMY_CMX = bytes.fromhex(\n    \"{}\"\n)",
            cmx_bytes
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        );
    }
}

#[cfg(test)]
mod gen_v3_ext_vectors {
    //! Generates updated V3 external-recipient action vectors for
    //! test_pczt_ironwood.py after the firmware fix to use V3 note commitment
    //! for spend-nullifier recomputation.
    //!
    //! The external action's spend note is owned by the same Speculos key
    //! (spend_recipient = _SPEND_RECIPIENT), so its nullifier also changes
    //! when the firmware switches from V2 → V3 note commitment.
    //!
    //! Run from the app-zcash worktree root (outside /app to avoid build-std):
    //! ```sh
    //! HOST=$(rustc -vV | awk '/^host:/ {print $2}')
    //! cargo test --manifest-path vendor/orchard/Cargo.toml --target "$HOST" \
    //!   --target-dir /tmp/orchard-host -- gen_v3_ext_action_vectors --nocapture
    //! ```

    use alloc::{string::String, vec::Vec};
    use rand::rngs::OsRng;
    use std::println;
    use zcash_note_encryption::Domain;

    use crate::{
        keys::{Diversifier, DiversifiedTransmissionKey, FullViewingKey, Scope},
        note::{ExtractedNoteCommitment, RandomSeed, Rho},
        note_encryption::{IronwoodDomain, IronwoodNoteEncryption},
        value::{NoteValue, ValueCommitTrapdoor, ValueCommitment},
        Address, Note, NoteVersion,
    };

    const fn hex_decode_96(hex: &[u8; 192]) -> [u8; 96] {
        let mut out = [0u8; 96];
        let mut i = 0;
        while i < 96 {
            let h = if hex[i * 2] >= b'a' { hex[i * 2] - b'a' + 10 } else { hex[i * 2] - b'0' };
            let l = if hex[i * 2 + 1] >= b'a' {
                hex[i * 2 + 1] - b'a' + 10
            } else {
                hex[i * 2 + 1] - b'0'
            };
            out[i] = (h << 4) | l;
            i += 1;
        }
        out
    }

    const fn hex_decode_43(hex: &[u8; 86]) -> [u8; 43] {
        let mut out = [0u8; 43];
        let mut i = 0;
        while i < 43 {
            let h = if hex[i * 2] >= b'a' { hex[i * 2] - b'a' + 10 } else { hex[i * 2] - b'0' };
            let l = if hex[i * 2 + 1] >= b'a' {
                hex[i * 2 + 1] - b'a' + 10
            } else {
                hex[i * 2 + 1] - b'0'
            };
            out[i] = (h << 4) | l;
            i += 1;
        }
        out
    }

    // Speculos Orchard FVK bytes (ak ‖ nk ‖ rivk, 96 bytes) for m/32'/133'/0'
    // on the Speculos default seed.
    // Derived by compute_v3_spend_nullifier_from_speculos_seed in
    // ledger-zcash-utils/crates/zcash-crypto/tests/ironwood_nullifier_version_check.rs
    const FVK_BYTES: [u8; 96] = hex_decode_96(
        b"e129bb7d06ed69a5ac01a664482ec9987fd19c40940bf76d98eb8b952974852949b0128d5072f9f92c7f7e8eb49a5434d2c04b67a30a55946d8322df3e484426f6151235e5897d34196943cb8f968312f1c8fba9ed82830b59f801b6de5da835",
    );

    // _SPEND_RECIPIENT from test_pczt_ironwood.py — also the spend_recipient
    // in _external_recipient_ironwood_action (the external action spends our own note).
    const SPEND_RECIPIENT: [u8; 43] = hex_decode_43(
        b"4a6414bb6f09e4a89469663a081fc2646c083708f552597d524b2f1812272e472d2b28f7414ece124ddf02",
    );

    // _EXT_RECIPIENT — output recipient for the external action.
    const EXT_RECIPIENT: [u8; 43] = hex_decode_43(
        b"4559029c0b5dbf941c5ad181a5fe8f45b34630f29d0c8dd8dc1cc3573386f416cb324133156d723df5e62d",
    );

    const EXT_SPEND_RHO: [u8; 32] = { let mut b = [0u8; 32]; b[0] = 0x07; b };
    const EXT_SPEND_RSEED: [u8; 32] = { let mut b = [0u8; 32]; b[0] = 0x1b; b };
    const EXT_RSEED: [u8; 32] = { let mut b = [0u8; 32]; b[0] = 0x2f; b };
    const EXT_RCV: [u8; 32] = { let mut b = [0u8; 32]; b[0] = 0x43; b };

    fn hex_lines(bytes: &[u8]) -> String {
        bytes
            .chunks(32)
            .map(|c| c.iter().map(|b| format!("{:02x}", b)).collect::<String>())
            .collect::<Vec<_>>()
            .join("\"\n    \"")
    }

    fn hex_str(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Generate updated V3 external-action vectors for test_pczt_ironwood.py.
    #[test]
    fn gen_v3_ext_action_vectors() {
        let fvk = FullViewingKey::from_bytes(&FVK_BYTES)
            .expect("Speculos Orchard FVK must decode");
        let ext_ovk = fvk.to_ovk(Scope::External);

        // ── V3 spend note (spend_value = 200 000) ──────────────────────
        let spend_div = Diversifier::from_bytes(SPEND_RECIPIENT[..11].try_into().unwrap());
        let spend_pk_d =
            DiversifiedTransmissionKey::from_bytes(SPEND_RECIPIENT[11..].try_into().unwrap())
                .expect("spend_recipient pk_d must be valid");
        let spend_addr = Address::from_parts(spend_div, spend_pk_d);

        let ext_spend_rho = Rho::from_bytes(&EXT_SPEND_RHO)
            .into_option()
            .expect("EXT_SPEND_RHO must be valid");
        let ext_spend_rseed =
            Option::from(RandomSeed::from_bytes(EXT_SPEND_RSEED, &ext_spend_rho))
                .expect("EXT_SPEND_RSEED must be valid for rho");
        let spend_note: Note = Option::from(Note::from_parts(
            spend_addr,
            NoteValue::from_raw(200_000),
            ext_spend_rho,
            ext_spend_rseed,
            NoteVersion::V3,
        ))
        .expect("external spend note must be valid");

        let ext_nullifier = spend_note.nullifier(&fvk);
        let ext_nf_bytes = ext_nullifier.to_bytes();
        println!("_EXT_NULLIFIER = bytes.fromhex(\"{}\")", hex_str(&ext_nf_bytes));

        // ── V2 output note (value = 180 000, rho = ext_nullifier) ────────
        let ext_div = Diversifier::from_bytes(EXT_RECIPIENT[..11].try_into().unwrap());
        let ext_pk_d =
            DiversifiedTransmissionKey::from_bytes(EXT_RECIPIENT[11..].try_into().unwrap())
                .expect("ext_recipient pk_d must be valid");
        let ext_addr = Address::from_parts(ext_div, ext_pk_d);

        let ext_output_rho = Rho::from_bytes(&ext_nf_bytes)
            .into_option()
            .expect("ext_nullifier must be a valid field element");
        let ext_rseed = Option::from(RandomSeed::from_bytes(EXT_RSEED, &ext_output_rho))
            .expect("EXT_RSEED must be valid for rho");
        let ext_output_note: Note = Option::from(Note::from_parts(
            ext_addr,
            NoteValue::from_raw(180_000),
            ext_output_rho,
            ext_rseed,
            NoteVersion::V2,
        ))
        .expect("external output note must be valid");

        let ext_cmx = ExtractedNoteCommitment::from(ext_output_note.commitment());
        let ext_cmx_bytes = ext_cmx.to_bytes();
        println!("_EXT_CMX = bytes.fromhex(\"{}\")", hex_str(&ext_cmx_bytes));

        // ── Encrypt output note (external OVK) ───────────────────────────
        let esk = ext_output_note.esk();
        let encryptor = IronwoodNoteEncryption::new_with_esk(
            esk,
            Some(ext_ovk),
            ext_output_note,
            [0u8; 512],
        );
        let epk_bytes = IronwoodDomain::epk_bytes(encryptor.epk());
        println!("_EXT_EPHEMERAL_KEY = bytes.fromhex(\"{}\")", hex_str(&epk_bytes.0));

        let enc_ct = encryptor.encrypt_note_plaintext();
        println!(
            "_EXT_ENC_CIPHERTEXT = bytes.fromhex(\n    \"{}\"\n)",
            hex_lines(enc_ct.as_ref())
        );

        // cv_net = ValueCommitment::derive(net = 20000, rcv = EXT_RCV)
        let ext_rcv = ValueCommitTrapdoor::from_bytes(EXT_RCV)
            .into_option()
            .expect("EXT_RCV must be a valid scalar");
        let value_net = NoteValue::from_raw(200_000) - NoteValue::from_raw(180_000);
        let ext_cv_net = ValueCommitment::derive(value_net, ext_rcv);

        let out_ct = encryptor.encrypt_outgoing_plaintext(&ext_cv_net, &ext_cmx, &mut OsRng);
        println!(
            "_EXT_OUT_CIPHERTEXT = bytes.fromhex(\n    \"{}\"\n)",
            hex_lines(out_ct.as_ref())
        );
    }
}

