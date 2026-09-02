# pylint: disable=C0301

import hashlib

import pytest
from application_client.pczt import (
    PcztGlobal,
    PcztIronwoodAction,
    PcztIronwoodBundle,
    PcztOrchardAction,
    PcztOrchardBundle,
    PcztTransparentInput,
    PcztTransparentOutput,
)
from application_client.zcash_command_sender import (
    CLA,
    P1,
    P2,
    Errors,
    InsType,
    ZcashCommandSender,
)
from application_client.zcash_transaction import split_tx_v5_for_hash_input
from application_client.zcash_utils import ripemd160, write_varint
from ragger.error import ExceptionRAPDU
from ragger.navigator import NavigateWithScenario
from ragger.navigator.navigation_scenario import NavigationScenarioData, UseCase

# NU6.3 (Ironwood) network identifiers
_V6_TX_VERSION = 6
_V6_VERSION_GROUP_ID = 0xD884B698
_NU6_3_BRANCH_ID = 0x37A5165B  # BranchId::Nu6_3

PCZT_V6_GLOBAL = PcztGlobal(
    tx_version=_V6_TX_VERSION,
    version_group_id=_V6_VERSION_GROUP_ID,
    consensus_branch_id=_NU6_3_BRANCH_ID,
)

# Ironwood uses the same RedPallas key derivation as Orchard; these constants are shared.
_SIGNING_PATH = "m/32'/133'/0'"
_ALPHA = (1).to_bytes(32, byteorder="little")
# rk = SpendAuthKey(m/32'/133'/0') * alpha (alpha=1, Speculos deterministic seed)
_RK_ALPHA_1 = bytes.fromhex("e95982b73ab0c2137ec354cce448a75ef39ec0cbdf6907be6df3495297834f89")
_INTERNAL_RECIPIENT = bytes.fromhex("ede3d2ce08c11d8c5c7bfe6814cedafd96c160c3d879cb270946f1ab6fdf442a15648d7c0b3c9fd052e20a")
_SPEND_RECIPIENT = bytes.fromhex("4a6414bb6f09e4a89469663a081fc2646c083708f552597d524b2f1812272e472d2b28f7414ece124ddf02")

# Precomputed action fields that pass all device validation checks.
# cv_net = Commitment(rcv, value=0); nullifier = NullifierDerive(key, spend_rho);
# cmx = NoteCommitment(recipient, value=0, rseed) — verified against device derivation.
# The nullifier and cmx below are the Ironwood (V3) values: the device derives the spend
# nullifier from the V3 note commitment of the spend note, and the output cmx is
# note_commitment_v3.  The Orchard pool keeps deriving both from the V2 commitment, so the
# Orchard action carries its own vectors (_ORCHARD_NULLIFIER / _ORCHARD_CMX) below.
_CV_NET = bytes.fromhex("00b3324110776396d31646041679fd6530d57c353c6be0a93a0cd55b30aa6d8b")
_NULLIFIER = bytes.fromhex("ed37cc733c228dc3dda2cf088ba646f9d204adc9d8d6f95ec36126eb742c3a10")
# V3 note commitment: recipient _INTERNAL_RECIPIENT, value 0, nullifier _NULLIFIER,
# rseed _RSEED. Regenerate with vendor/orchard gen_v3_valid_action_cmx.
_CMX = bytes.fromhex("704b2bfa354eb974b10efe385d7ec56a12abbb906a3a95500bf9d6bbfcb7b73e")
_RCV = bytes.fromhex("4200000000000000000000000000000000000000000000000000000000000000")
_RSEED = bytes.fromhex("2e00000000000000000000000000000000000000000000000000000000000000")
_SPEND_RHO = bytes.fromhex("0600000000000000000000000000000000000000000000000000000000000000")
_SPEND_RSEED = bytes.fromhex("1a00000000000000000000000000000000000000000000000000000000000000")

# Orchard (V2) counterparts of _NULLIFIER and _CMX, for the same spend note, output note and
# signing path.  Orchard derives the spend nullifier from the V2 note commitment and commits
# the output note with note_commitment (V2), so an Orchard action built from the V3 vectors
# above is rejected with SW_INVALID_TRANSACTION.
_ORCHARD_NULLIFIER = bytes.fromhex("08f337fd695cb5ca2ad7ced8ec14afed06d2f8a0e5e3d8b58dffbc69e4f81b2f")
_ORCHARD_CMX = bytes.fromhex("825f806345d7c2ae67fe186120cc5b8a370c2cedb55ccf76527e9efa43c94d30")

# Same, for a dummy padding spend (spend_value = 0) whose output is the change note:
# cv_net = Commitment(_DUMMY_RCV, -_DUMMY_CHANGE_VALUE), and the ciphertexts decrypt
# to that note under the device keys. The action encoding, value commitment and note
# decryption are identical in both pools, so these are the Orchard padding vectors.
_DUMMY_CHANGE_VALUE = 10000
_DUMMY_CV_NET = bytes.fromhex("af7b9a0ad90cecf9dbcf08d1057da0bf8451a189cc8dfa758e1543cffb5edb97")
_DUMMY_NULLIFIER = bytes.fromhex("57aad2670e2e4df67ca855c53973db38e7942efa8e906ee961adb71955aa8423")
_DUMMY_CMX = bytes.fromhex("4d5af089ac858234d3472b545efe5796a609792d06bf18dbb8b3841ac0e9e031")
_DUMMY_RCV = bytes.fromhex("4400000000000000000000000000000000000000000000000000000000000000")
_DUMMY_RSEED = bytes.fromhex("3000000000000000000000000000000000000000000000000000000000000000")
_DUMMY_SPEND_RHO = bytes.fromhex("0800000000000000000000000000000000000000000000000000000000000000")
_DUMMY_SPEND_RSEED = bytes.fromhex("1c00000000000000000000000000000000000000000000000000000000000000")
_DUMMY_EPHEMERAL_KEY = bytes.fromhex("92f7498c759a77b4065f9389d345c755ba241e68f0d8bf6d78f443257167d79f")
_DUMMY_ENC_CIPHERTEXT = bytes.fromhex(
    "183f95348800b0c01daaa128c74ed5a4904024192330114b7b59460db6e332321425e9875e96bf7c1ba1bcb751ab6d8b494bd4b4e2587e177c9b083bf3a015a5879b69eaf2380c26d60501ff825be33eebc8ff3a86dfb04dd6fd1e814ea5e486148518ed256ea064267fbf9bc41ec6f8bf6da17b2bd9a81b42cb92dc398a5876333e64826b62a61dba4a5d9e740cdb6f0f1ac7e5f3bd8bff60c30088334491263b61f88b5e102eeb2d539ca32e45ce8600bcaf37368a2696528ee5e5cc52f8cf52df2c7e98f682ce6a4036527adce9f167df7f90200f3cdc9b451bdb4e36c3a46c2a2c42a0f0036161040267ef5dd267721db87f5b910dccf72afc67e059450db2b3df4789348ca72ddc5c310c4504c3779c5cca6a4ff94a73da8ee09dc06adc1856654b4be95e0adcf4510a0506b8b604bbd7fc340206728018f602060be3966cc0c91f601680b6e9e0f1132188cc217fef595b57c761b9292546d1dfe7148c42e4b8140cb364c23d1f0af6f794daf89c07927ea2d3be5f31ecf3f7d4dd973db806e3c0ef7cfb461848ba8562283c18c572f5e12d20ad8fff16cd0b58530501154a79458a28d2666707938915c95d854a3de8aee39a34d35c65a4e903b6135107726842ff150afa92243751606ec24fc0df246979f93c612a1f694b52863bb652226ceb520984aabda5c9fc60969589d9c894f3deceb448d04f3e61386430275eb4a64cacdf40704ccde93ae6573c1cd02b0bcfa689cf5de779cd2cf47ec13bb2e19c0d736fc0d0b7523b46487a1457e23dc1b473f1846475dc9544a81429c9caa51f3d"
)  # noqa: E501
_DUMMY_OUT_CIPHERTEXT = bytes.fromhex(
    "9f38b7e5c9bee88aa9be8bb44a386bd90fb6f915820f4a6469e120f2764774a3936e69063b514e83e587b9bd7b049d94d002c21dca9e8fa33b75aae1d584e8f4b77a0389e104596e2002aac2571fe384"
)  # noqa: E501

# V3 (ZIP 2005 Ironwood) dummy-output constants.
# cv_net = ValueCommitment(0, rcv=0x44) = 0x44 · R, where R is the Pallas value-commitment
# randomness basepoint.  _DUMMY_RCV (scalar 0x44) is reused as the rcv for V3 dummy actions.
# cmx = note_commitment_v3(_INTERNAL_RECIPIENT, value=0, _DUMMY_NULLIFIER, _DUMMY_RSEED).
# Computed by gen_v3_dummy_cmx in vendor/orchard/src/note_encryption.rs.
_V3_DUMMY_CV_NET = bytes.fromhex("7d042e0903e7984caac7cdc7c081eeaa0289caf7af0ed179815822e2fd8f6e97")
_V3_DUMMY_CMX = bytes.fromhex("f5bc3b62d60bd6ba9af4d7b0fc65cfe2036fa307f5e7a13cb7007c68d4ab300d")

# Real V3 (NoteVersion::V3) output vectors.
# Generated by `gen_v3_ironwood_test_vectors` in vendor/orchard/src/note_encryption.rs.
# esk = PRF-esk(rseed, rho) so the device's derived_epk check passes.
_V3_REAL_EPK = bytes.fromhex("f4232b9b6e17f52b6d5bbdc2b8aeebd6440966d3f15376dbb31fee16f3840f27")
_V3_REAL_CMX = bytes.fromhex("f355e2fceb8d2c79282f01439274efb233ca449253740e60d1249eadaa048c0b")
_V3_REAL_ENC_CIPHERTEXT = bytes.fromhex(
    "103a2805abe85dbe2fb188ce7f2cb22c6392984686c1381d00c81240257a7a52"
    "65313de810bd880646a7a43fe9aadfbb65a74f3b8b64feff433828c860884b2b"
    "f84c42037e11a61ae930606d81043fd0a6ea3be02b04f9671dfad38a0c0ea96d"
    "aacaf94164cfbfaf692c00762d5a425e801f5a15fe0dd25649d275a04666eef4"
    "f519dfa111f311a1ba465293bb6cda14371e80d62ab62ede7f7a571e09801224"
    "df37d28299bd0e228cad27b7bad45431a1173f402e8c47106a30522d5ef6aab8"
    "e5193712ca25b217e9d8a1efe8ac9f38c28f4ae55c7f41db9e0073cfc39fde26"
    "64980e36bd4d100127f9f61a5ed7f9162f288fe5200dc9673550b62ddc06fa11"
    "cacc8a8919047b0dde962b58b29329f8efbda31472a54b04fdf791e9c8cecf5c"
    "e87f8dc3958c9739b96461b7c1193d9e089cc7d4ac3192ef06b0b864eaecf947"
    "c0179cd08f8cbd65df1f7a25dd00b82d5016e3d7319543dba4d7d72aeccaf480"
    "bd0466126830386fba057cc3f57a47a9030108faffdd18d46b290a46af7c1b25"
    "a74ba35189fc8673c68d0e825b0e5ed7f3ac9538b463fae717f19f1199ae025b"
    "0ad9f8dd7f7d8e0ee90246940fa85738bc16e1c4e54d252e8c9ab3a23d505802"
    "b37dcf3d343d1262f8a1ef4fd60946a68b038af33b0b21f8b00592c61a9af1b3"
    "c674ef563aac9955d2fcafff945f67756e79680d2d31ddddcb7392745696e453"
    "eb4cc7b89696e0f59531c88f2e7303de120fe5b585246316ab96e64d7cadc6f7"
    "7e78a46fa9d062eedcaa21992100b57814c3f2ecac8d0bbf5a8891bb6b39e3d2"
    "03f319c1"
)

# External-recipient action constants.  Ironwood uses orchard_decipher_keys and OrchardFvk
# for all note-level operations (nullifier, cv_net, note encryption) — the same primitives as
# Orchard.  The vectors below are therefore identical to the Orchard RECIPIENT_ORCHARD_ACTION
# from _mixed_real_and_dummy_orchard_bundle() in test_pczt.py, which was computed for the same
# Speculos deterministic seed and signing path.
_EXT_RECIPIENT = bytes.fromhex("4559029c0b5dbf941c5ad181a5fe8f45b34630f29d0c8dd8dc1cc3573386f416cb324133156d723df5e62d")
_EXT_CV_NET = bytes.fromhex("2bbcd0793d399b207b228ca760f2b51ac8d6866e2649b3c3ff1e67b454c5a6bf")
_EXT_NULLIFIER = bytes.fromhex("6637a5b7cacadc75ef35dccd84b66b24d15d1f26fa342f13b65dcb577b119e28")
_EXT_CMX = bytes.fromhex("d3498e9df3e18af5621052a94ec68e1a1a828c0145480a5bf049b5eebd696717")
_EXT_EPHEMERAL_KEY = bytes.fromhex("5d8fb211bc79674ad8150af9983a46f3860f34849e6ad71c584f0eda37f8a399")
_EXT_SPEND_RHO = bytes.fromhex("0700000000000000000000000000000000000000000000000000000000000000")
_EXT_SPEND_RSEED = bytes.fromhex("1b00000000000000000000000000000000000000000000000000000000000000")
_EXT_RCV = bytes.fromhex("4300000000000000000000000000000000000000000000000000000000000000")
_EXT_RSEED = bytes.fromhex("2f00000000000000000000000000000000000000000000000000000000000000")
_EXT_ENC_CIPHERTEXT = bytes.fromhex(
    "888c16fa01eb2a60823bdaf4d094e72dc9bd68d073cc4907c292439289457016"
    "e3a630bb9767cd0d79e149f07be066b45bf08a72f983713c1d79e880801da528"
    "3bf62636ec55bc0a0899d68355bac2e45f00a4af4dc5ae1d6ecd383c022e03d3"
    "eb25d881fcead28d32a0b356cf95c590a3208c2f8d7a51b40c5b82a62bb24988"
    "2173a3c3d1ccc2a07072c5315ca42389a39b35ab8a37fcc444734caa81dc2ed4"
    "e56fd8acf51693fa1ead6d4e74b425f97b5c564b4d4dfa2c740dd8e5832b5343"
    "128382bdb8d85893c210e4dab43a3ffe9b2c019733908f2b0d123474881a5293"
    "c3ea34275c50dfa81e8e43a8ff296c6f33ffe1d98c056b57a5e7c70348ecfac4"
    "dbf1d664e19fe406202635229b7bbd46d11f7b01f72e7edc45ddfdaed48fd1d9"
    "4175ef83f0deb229198939b353385d0c500288420b9de7813b00a030baee3e93"
    "a82837c28852b7ebfd6715b0b4bc119f63ab47ec91d315b4eabb2a32308bcb2b"
    "a1d53d1594211cbb855b4cbb381d0ee88dc4feed173dbeaa4ec39a3a534dd42a"
    "75378be411712b20bdaa3bc3df10c103a823681e4a9964d893ae48dde38d79aa"
    "0774b8ea3ee2f803abd744e88f62922a3d4f9546de5c6fda66817a0d20e4f7c2"
    "29a15a5b43cd014d61dfd537285ea480ba47bc0ac637c0b92878469d14e223ae"
    "c4d06cca3d396912344a05d97a32e99bd9b1e8e8eb44d9545decef609515880a"
    "d541dc9271247f1c09a03fc1eed8496f07ce3c83c08109ad071ba81565f416f1"
    "cb50a680ad85a12d7401ff280ad2df7a4165afa22f6ba8a463e5330d0dd08acb"
    "ca1abe2f"
)
_EXT_OUT_CIPHERTEXT = bytes.fromhex(
    "7a475d74d20e5bee07e7dc6ba251750633846d775317a74fe1db731f47ed9d30"
    "4e90a0317ce9ba3aa19aaef3cb4f8ed4df284ca4424228d3287398642c4bc24e"
    "5b6b4e2e0e7be56dda6ccee859e93530"
)

# Memo action constants — identical to the Orchard action in
# test_pczt_sign_tx_v5_transparent_to_orchard_with_memo from test_pczt.py.
# Ironwood uses the same note-encryption primitives (orchard_decipher_keys, OrchardFvk)
# and the same signing path (m/32'/133'/0'), so the enc_ciphertext decrypts via the
# device's external OVK to ASCII memo "PCZT Orchard memo test".
_MEMO_CV_NET = bytes.fromhex("fd87b590de6e73dbf0372fc4e80e4c9a44c6f9b196fd296165276b15f38ca7be")
_MEMO_NULLIFIER = bytes.fromhex("781c4faf960206510fdc72739267fa193d9e012dbc68998d35539837e520ae2a")
_MEMO_SPEND_RHO = bytes.fromhex("0100000000000000000000000000000000000000000000000000000000000000")
_MEMO_SPEND_RSEED = bytes.fromhex("1500000000000000000000000000000000000000000000000000000000000000")
_MEMO_CMX = bytes.fromhex("2c26565e51efead30e17ccde59fbba80f15e727392480ac714d5e6e9c5ce3724")
_MEMO_EPHEMERAL_KEY = bytes.fromhex("7895cdaf491fc7b6754bbe1339eab4f4d142e59fff9cf8d3820217f1e940801b")
_MEMO_ENC_CIPHERTEXT = bytes.fromhex(
    "feebe7c7d7f8e08fd0baffb71f54ca6fad3b8a1b1702be187bcc24f1874a48bc"
    "3013c44c8d0aaadfbdbebeb31c3eda96e539d9853c28766cee658408606d473c"
    "76b102d20e11eb6a69bc90a1cc543f49d32d30b47241d1632e6dcba30492b6a7"
    "bdbaafb9f9dd1e68c2ac12d17b485aed2fb8ba6162f4ec70f8b3c045c4db74fd"
    "7861cfb6ce2dc74c2a4219fa429332ed86e891aeca5cf2dfd0517f99fee0f0dd"
    "cc5a1a2729bac0626f895a1b572fa8eddaf3b72d2cbb6c1681aeb865740d439b"
    "7c90334512faa315207d540eb411dfe8d38b3f6673cb65e12816f42bee50abb9"
    "66437fa386c34ac54611c86cc093ddee1cfe098903f3be4a8de20de1c48fdbd8"
    "ca8a9900eeee734dfff526c39ad353a81de786deb8278bdc870b9d65cc99422e"
    "54d0bf7e8e0fcf88a0a701ee59195aaa130b8950bf39bc598520f913af4bf770"
    "dfcf37e1ed4d19549759e1642945affbe385eb80497b9652e33a5366667b4fd9"
    "c212b061c6c2c47d3f289dee39fea4eba73faf6c91428ca0b97d2be3feb7c0e1"
    "ea5ee0250aed9a96d7fe9e91c525f46debe71ddbbc0f8d05576ea27a2249f5b9"
    "a341561772b6b480404d5e839af42a56d71f20ad5538214b9925f7931d926017"
    "353759398d25a5a2611cf243ff44f732cdc57312b7dfe386118a1e9377f36d7e"
    "e312be7ce3c0efa96228a83653a607e00d556f8e04defbb39a2179bb2ed8a038"
    "9bb157c75913236e6f9ddf21dcc7108b804c1fa194b2603058e03da7ab3f6ee5"
    "dacb4fc3769879d72fc21f68116f0af30414236128f8b21f627ec43a1ef1f920"
    "dece1299"
)  # noqa: E501
_MEMO_OUT_CIPHERTEXT = bytes.fromhex(
    "f72616bdd9af44610bf009b2d0e3fd468904f86490eece0bbc1001346aef8f38"
    "dafd8d7b9ca601541c114be9bf855a030d1426aba8369ae3101d154b99774487"
    "114eb9078bd9589f20ec006ba1efdaba"
)  # noqa: E501
_MEMO_RCV = bytes.fromhex("3d00000000000000000000000000000000000000000000000000000000000000")
_MEMO_RSEED = bytes.fromhex("2900000000000000000000000000000000000000000000000000000000000000")
_MEMO_VALUE = 90000

# Legacy V5 transaction and its prevout, used to drive the legacy signing path
# against leftover V6 state.
_LEGACY_V5_PREVOUT_TX = bytes.fromhex(
    "050000800a27a726b4d0d6c200000000f9081a000198cd6cd9559cd98109ad0622f899bc38805f11648e4f985ebe344b8238f87b13010000006b48304502210095104ae9d53a95105be4ba5a31caddff2ae83ced24b21ab4aec6d735d568fad102206e054b158047529bb736c810902ea7fc8d92f3f604c1b2a8bb0b92f0e6c016a8012102010a560c7325827df0212bca20f5cf6556b1345991b6b64b469c616e758230a5ffffffff021595dd04000000001976a914ca3ba17907dde979bf4e88f5c1be0ddf0847b25d88aca245117c140000001976a914c8b56e00740e62449a053c15bdd4809f720b5cb588ac000000"
)  # noqa: E501
_LEGACY_V5_TX = bytes.fromhex(
    "050000800a27a726b4d0d6c2"  # version, version group id, consensus branch id
    + (0).to_bytes(4, byteorder="big").hex()  # locktime
    + (0).to_bytes(4, byteorder="big").hex()  # expiry
    + "01"  # one input
    + "58854aa4e2e3b82aa2040c0bc3a6dc9b8ac6acb5e15bf0cfeacd09e77249c18a"
    + "00000000"  # prevout hash and index
    + "19"
    + "76a914ca3ba17907dde979bf4e88f5c1be0ddf0847b25d88ac00000000"  # scriptPubKey, sequence
    + "01"  # one output
    + "958ddd0400000000"  # amount
    + "19"
    + "76a91431352ad6f20315d1233d6e6da7ec1d6958f2bf1988ac"  # scriptPubKey
    + "000000"  # empty sapling and orchard bundles
)

# In V6 neither the Orchard nor the Ironwood anchor enters the sighash.
_ORCHARD_ANCHOR_A = bytes.fromhex("699c780066f179ff12b26a5ec5b1af3d418eb0eadec3d3b18f10c91d97b33109")

# Transparent output used by tests that need a displayable output.
# Ironwood-only (one pool): orchard_vb=0 + ironwood_vb=300000 - 299000 = 1000 fee.
_TRANSPARENT_OUTPUT_299K = PcztTransparentOutput(
    value=299000,
    script_pubkey=bytes.fromhex("76a914424242424242424242424242424242424242424288ac"),
)
# Ironwood bundle carrying a dummy padding spend: ironwood_vb=290000 - 289000 = 1000 fee.
_TRANSPARENT_OUTPUT_289K = PcztTransparentOutput(
    value=289000,
    script_pubkey=bytes.fromhex("76a914424242424242424242424242424242424242424288ac"),
)
# V6 migration (two pools): orchard_vb=300000 + ironwood_vb=300000 - 599000 = 1000 fee.
_TRANSPARENT_OUTPUT_599K = PcztTransparentOutput(
    value=599000,
    script_pubkey=bytes.fromhex("76a914424242424242424242424242424242424242424288ac"),
)

# Transparent input used by the shield test: 10000 into Ironwood + 1000 fee = 11000.
_TRANSPARENT_INPUT_11K = PcztTransparentInput(
    prevout_txid=bytes.fromhex("4242424242424242424242424242424242424242424242424242424242424242"),
    prevout_index=0,
    value=11000,
    script_pubkey=bytes.fromhex("76a914424242424242424242424242424242424242424288ac"),
    sequence=bytes.fromhex("ffffffff"),
    signing_path="m/44'/133'/0'/0/0",
)
# Transparent input used by the memo shield test: 90000 into Ironwood + 10000 fee = 100000.
_TRANSPARENT_INPUT_100K = PcztTransparentInput(
    prevout_txid=bytes.fromhex("4242424242424242424242424242424242424242424242424242424242424242"),
    prevout_index=0,
    value=100000,
    script_pubkey=bytes.fromhex("76a914424242424242424242424242424242424242424288ac"),
    sequence=bytes.fromhex("ffffffff"),
    signing_path="m/44'/133'/0'/0/0",
)


def _valid_ironwood_action() -> PcztIronwoodAction:
    return PcztIronwoodAction(
        cv_net=_CV_NET,
        nullifier=_NULLIFIER,
        spend_recipient=_SPEND_RECIPIENT,
        spend_rho=_SPEND_RHO,
        spend_rseed=_SPEND_RSEED,
        rk=_RK_ALPHA_1,
        alpha=_ALPHA,
        signing_path=_SIGNING_PATH,
        cmx=_CMX,
        ephemeral_key=bytes(32),
        enc_ciphertext=bytes(580),
        out_ciphertext=bytes(80),
        rcv=_RCV,
        rseed=_RSEED,
        spend_value=300000,
        value=0,
        recipient=_INTERNAL_RECIPIENT,
    )


def _valid_ironwood_bundle(anchor: bytes = bytes(32)) -> PcztIronwoodBundle:
    return PcztIronwoodBundle(
        actions=[_valid_ironwood_action()],
        flags=3,
        value_balance=300000,
        anchor=anchor,
    )


def _valid_ironwood_bundle_2_actions() -> PcztIronwoodBundle:
    """Two-action Ironwood bundle for replay-guard tests that must not reset on first sign."""
    return PcztIronwoodBundle(
        actions=[_valid_ironwood_action(), _valid_ironwood_action()],
        flags=3,
        value_balance=600000,
        anchor=bytes(32),
    )


def _dummy_ironwood_action() -> PcztIronwoodAction:
    """Dummy padding spend (spend_value == 0) whose output is the change note."""
    return PcztIronwoodAction(
        cv_net=_DUMMY_CV_NET,
        nullifier=_DUMMY_NULLIFIER,
        spend_recipient=_SPEND_RECIPIENT,
        spend_rho=_DUMMY_SPEND_RHO,
        spend_rseed=_DUMMY_SPEND_RSEED,
        rk=_RK_ALPHA_1,
        alpha=_ALPHA,
        signing_path=_SIGNING_PATH,
        cmx=_V3_REAL_CMX,
        ephemeral_key=_V3_REAL_EPK,
        enc_ciphertext=_V3_REAL_ENC_CIPHERTEXT,
        out_ciphertext=_DUMMY_OUT_CIPHERTEXT,
        rcv=_DUMMY_RCV,
        rseed=_DUMMY_RSEED,
        spend_value=0,
        value=_DUMMY_CHANGE_VALUE,
        recipient=_INTERNAL_RECIPIENT,
    )


def _mixed_real_and_dummy_ironwood_bundle() -> PcztIronwoodBundle:
    """Real spend at index 0, dummy padding spend at index 1."""
    actions = [_valid_ironwood_action(), _dummy_ironwood_action()]
    return PcztIronwoodBundle(
        actions=actions,
        value_balance=sum(action.spend_value - action.value for action in actions),
        flags=3,
        anchor=bytes(32),
    )


def _ironwood_shield_bundle() -> PcztIronwoodBundle:
    """Shield (transparent→Ironwood): dummy action receives 10000 zats from the transparent pool.

    spend_value=0 (no Ironwood spend) with an output that decrypts via the internal IVK.
    value_balance=-10000 signals that 10000 flows INTO the Ironwood pool from transparent.
    """
    return PcztIronwoodBundle(
        actions=[_dummy_ironwood_action()],
        flags=3,
        value_balance=-_DUMMY_CHANGE_VALUE,
        anchor=bytes(32),
    )


def _memo_ironwood_action() -> PcztIronwoodAction:
    """Dummy padding spend (spend_value=0) whose output carries an ASCII memo.

    The enc_ciphertext decrypts via the device's external OVK (m/32'/133'/0') to
    ASCII memo "PCZT Orchard memo test", exercising the memo display path.
    Parameters are identical to the Orchard action from
    test_pczt_sign_tx_v5_transparent_to_orchard_with_memo because Ironwood uses the
    same note-encryption primitives and signing path.
    """
    return PcztIronwoodAction(
        cv_net=_MEMO_CV_NET,
        nullifier=_MEMO_NULLIFIER,
        spend_recipient=_SPEND_RECIPIENT,
        spend_rho=_MEMO_SPEND_RHO,
        spend_rseed=_MEMO_SPEND_RSEED,
        rk=_RK_ALPHA_1,
        alpha=_ALPHA,
        signing_path=_SIGNING_PATH,
        cmx=_MEMO_CMX,
        ephemeral_key=_MEMO_EPHEMERAL_KEY,
        enc_ciphertext=_MEMO_ENC_CIPHERTEXT,
        out_ciphertext=_MEMO_OUT_CIPHERTEXT,
        rcv=_MEMO_RCV,
        rseed=_MEMO_RSEED,
        spend_value=0,
        value=_MEMO_VALUE,
        recipient=_EXT_RECIPIENT,
    )


def _ironwood_memo_bundle() -> PcztIronwoodBundle:
    """Shield (transparent→Ironwood) where the single Ironwood output carries an ASCII memo.

    spend_value=0 (dummy padding); value_balance=-90000 signals that 90000 zats flow INTO
    the Ironwood pool from the transparent input.  The output decrypts via the external OVK
    (is_change=False) so the device displays it together with the decoded memo text.
    """
    return PcztIronwoodBundle(
        actions=[_memo_ironwood_action()],
        flags=3,
        value_balance=-_MEMO_VALUE,
        anchor=bytes(32),
    )


def _external_recipient_ironwood_action() -> PcztIronwoodAction:
    """Real spend (spend_value=200000) with a 180000-zat output to an external Ironwood recipient.

    The enc_ciphertext decrypts via the device's external OVK, so the firmware classifies
    this output as is_change=False.  Vectors are the Orchard RECIPIENT_ORCHARD_ACTION from
    _mixed_real_and_dummy_orchard_bundle() — valid for Ironwood because the device uses
    orchard_decipher_keys and OrchardFvk for both pools (same key derivation and encryption).
    """
    return PcztIronwoodAction(
        cv_net=_EXT_CV_NET,
        nullifier=_EXT_NULLIFIER,
        spend_recipient=_SPEND_RECIPIENT,
        spend_rho=_EXT_SPEND_RHO,
        spend_rseed=_EXT_SPEND_RSEED,
        rk=_RK_ALPHA_1,
        alpha=_ALPHA,
        signing_path=_SIGNING_PATH,
        cmx=_EXT_CMX,
        ephemeral_key=_EXT_EPHEMERAL_KEY,
        enc_ciphertext=_EXT_ENC_CIPHERTEXT,
        out_ciphertext=_EXT_OUT_CIPHERTEXT,
        rcv=_EXT_RCV,
        rseed=_EXT_RSEED,
        spend_value=200000,
        value=180000,
        recipient=_EXT_RECIPIENT,
    )


def _ironwood_bundle_with_external_recipient() -> PcztIronwoodBundle:
    """Ironwood bundle with an external-recipient payment and a hidden change note.

    action 0: real spend (spend_value=200000), output 180000 to external recipient;
              enc_ciphertext decrypts via external OVK → is_change=False → shown.
    action 1: dummy padding (spend_value=0), output 10000 to internal IVK;
              enc_ciphertext decrypts via internal IVK → is_change=True → hidden.

    has_external_output=True → reveal_self_outputs=False → change is genuinely hidden.
    value_balance = (200000-180000) + (0-10000) = 10000 (fee; no transparent outputs).
    Mirrors _mixed_real_and_dummy_orchard_bundle() from test_pczt.py.
    """
    actions = [_external_recipient_ironwood_action(), _dummy_ironwood_action()]
    return PcztIronwoodBundle(
        actions=actions,
        value_balance=sum(a.spend_value - a.value for a in actions),
        flags=3,
        anchor=bytes(32),
    )


def _valid_orchard_action() -> PcztOrchardAction:
    return PcztOrchardAction(
        cv_net=_CV_NET,
        nullifier=_ORCHARD_NULLIFIER,
        spend_recipient=_SPEND_RECIPIENT,
        spend_rho=_SPEND_RHO,
        spend_rseed=_SPEND_RSEED,
        rk=_RK_ALPHA_1,
        alpha=_ALPHA,
        signing_path=_SIGNING_PATH,
        cmx=_ORCHARD_CMX,
        ephemeral_key=bytes(32),
        enc_ciphertext=bytes(580),
        out_ciphertext=bytes(80),
        rcv=_RCV,
        rseed=_RSEED,
        spend_value=300000,
        value=0,
        recipient=_INTERNAL_RECIPIENT,
    )


def _valid_orchard_bundle(anchor: bytes = _ORCHARD_ANCHOR_A) -> PcztOrchardBundle:
    return PcztOrchardBundle(
        actions=[_valid_orchard_action()],
        flags=3,
        value_balance=300000,
        anchor=anchor,
    )


def _review_approve(
    scenario_navigator: NavigateWithScenario,
    snapshot_test_name: str,
) -> None:
    scenario = NavigationScenarioData(
        scenario_navigator.device,
        scenario_navigator.backend,
        UseCase.TX_REVIEW,
        True,
    )

    if scenario_navigator.device.touchable:
        scenario.validation = scenario.validation[:-1]

    scenario_navigator.navigator.navigate_until_text_and_compare(
        navigate_instruction=scenario.navigation,
        validation_instructions=scenario.validation,
        text=scenario.pattern,
        path=scenario_navigator.screenshot_path,
        test_case_name=snapshot_test_name,
        screen_change_after_last_instruction=False,
    )


def test_pczt_ironwood_bundle_signing(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    """Ironwood-only V6 transaction: device accepts the bundle and returns a 64-byte spendAuthSig."""
    client = ZcashCommandSender(backend)

    with client.send_pczt(
        pczt_global=PCZT_V6_GLOBAL,
        transparent_inputs=[],
        transparent_outputs=[_TRANSPARENT_OUTPUT_299K],
        ironwood_bundle=_valid_ironwood_bundle(),
    ):
        _review_approve(scenario_navigator, "test_pczt_ironwood_bundle_signing")

    auth_sig = client.pczt_sign_ironwood(action_index=0).data
    assert len(auth_sig) == 64


# One account over, same seed: the device does own the address, which is precisely what lets the
# output pass for change and disappear from the review.
_FOREIGN_CHANGE_PATH = "m/44'/133'/1'/1/0"
# Path and matching P2PKH script of a transparent input the device signs, under account 0.
_TRANSPARENT_INPUT_PATH = "m/44'/133'/0'/0/0"
_TRANSPARENT_INPUT_SCRIPT = bytes.fromhex("76a914ca3ba17907dde979bf4e88f5c1be0ddf0847b25d88ac")
_RECIPIENT_OUTPUT_250K = PcztTransparentOutput(
    value=250000,
    script_pubkey=bytes.fromhex("76a914424242424242424242424242424242424242424288ac"),
)


def _foreign_account_change_output(client: ZcashCommandSender, value: int) -> PcztTransparentOutput:
    """A transparent change output the device owns, but under another account than the one it spends."""
    pubkey = client._compressed_pubkey_from_path(_FOREIGN_CHANGE_PATH)  # pylint: disable=W0212
    pk_hash = ripemd160(hashlib.sha256(pubkey).digest())

    return PcztTransparentOutput(
        value=value,
        script_pubkey=bytes.fromhex("76a914") + pk_hash + bytes.fromhex("88ac"),
        signing_path=_FOREIGN_CHANGE_PATH,
    )


@pytest.mark.parametrize("signing_pool", ["transparent", "orchard", "ironwood"])
def test_pczt_change_in_another_account_yields_no_signature(
    backend,
    scenario_navigator: NavigateWithScenario,
    signing_pool,
):
    """Change returning to another account yields no signature, whichever pool signs.

    The guard sits on `check_change_returns_to_signing_account`, and the three handlers that
    release a signature over the approved digest must all call it: any single unchecked handler is
    enough to redirect the whole change amount. Asserting it on one and trusting the others is how
    the Ironwood path came to miss it, so the three are asserted here as three cases of one test.

    Totals are those of the passing single-output tests, split in two: 300000 in from whichever
    pool, 250000 to the recipient and 49000 to the foreign-account change, leaving the fee at 1000.
    """
    client = ZcashCommandSender(backend)

    transparent_outputs = [_RECIPIENT_OUTPUT_250K, _foreign_account_change_output(client, 49000)]
    transparent_inputs = []
    bundles = {}

    if signing_pool == "transparent":
        # V5: reaching the transparent signing handler needs no shielded pool.
        pczt_global = PcztGlobal()
        transparent_inputs = [
            PcztTransparentInput(
                prevout_txid=bytes.fromhex("58854aa4e2e3b82aa2040c0bc3a6dc9b8ac6acb5e15bf0cfeacd09e77249c18a"),
                prevout_index=0,
                value=300000,
                script_pubkey=_TRANSPARENT_INPUT_SCRIPT,
                sequence=bytes.fromhex("00000000"),
                signing_path=_TRANSPARENT_INPUT_PATH,
            )
        ]
    elif signing_pool == "orchard":
        pczt_global = PcztGlobal()
        bundles = {"orchard_bundle": _valid_orchard_bundle()}
    else:
        pczt_global = PCZT_V6_GLOBAL
        bundles = {"ironwood_bundle": _valid_ironwood_bundle()}

    # The review shows the recipient alone: the foreign-account output is hidden, so the user has
    # nothing to refuse on. Approving is the attacker's premise, not the defence.
    with client.send_pczt(
        pczt_global=pczt_global,
        transparent_inputs=transparent_inputs,
        transparent_outputs=transparent_outputs,
        **bundles,
    ):
        _review_approve(
            scenario_navigator,
            f"test_pczt_change_in_another_account_yields_no_signature_{signing_pool}",
        )

    sign_action = {
        "transparent": client.pczt_sign_transparent,
        "orchard": client.pczt_sign_orchard,
        "ironwood": client.pczt_sign_ironwood,
    }[signing_pool]

    with pytest.raises(ExceptionRAPDU) as error:
        sign_action(0)

    assert error.value.status == Errors.SW_CONDITIONS_OF_USE_NOT_SATISFIED
    assert not error.value.data


def test_pczt_ironwood_dummy_spend_signature_is_refused(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    """The device must refuse to produce a spend-auth signature for an Ironwood
    dummy padding spend, as it already does for Orchard.

    Dummy actions are parsed without the rk and nullifier checks — those derive
    from the host's throwaway key and cannot pass — and the PCZT IoFinalizer
    already self-signs them. Signing one would authorize an action whose spend
    side was never verified.

    The refusal aborts the signing session (the review approval is dropped), so a
    host must skip dummy indices rather than probe them.
    """
    client = ZcashCommandSender(backend)
    IRONWOOD_BUNDLE = _mixed_real_and_dummy_ironwood_bundle()
    DUMMY_ACTION_INDEX = 1
    assert IRONWOOD_BUNDLE.actions[DUMMY_ACTION_INDEX].spend_value == 0

    with client.send_pczt(
        pczt_global=PCZT_V6_GLOBAL,
        transparent_inputs=[],
        transparent_outputs=[_TRANSPARENT_OUTPUT_289K],
        ironwood_bundle=IRONWOOD_BUNDLE,
    ):
        _review_approve(scenario_navigator, "test_pczt_ironwood_dummy_spend_signature_is_refused")

    # Requested before the real spend at index 0, so the signature quota is not
    # exhausted: the rejection comes from the dummy check, not from a done session.
    with pytest.raises(ExceptionRAPDU) as e:
        client.pczt_sign_ironwood(action_index=DUMMY_ACTION_INDEX)

    assert e.value.status == Errors.SW_INVALID_TRANSACTION


def test_pczt_v6_header_then_legacy_continuation_rejected(backend):
    """A legacy continuation must not inherit the V6 state of an abandoned PCZT flow.

    A continuation deliberately keeps the previous round's transaction state, so a
    host can chain a V6 PCZT header into it and drive the legacy parser with a V6
    transaction version — a state the legacy path cannot represent.
    """
    client = ZcashCommandSender(backend)

    trusted_input = client.get_trusted_input(_LEGACY_V5_PREVOUT_TX, 0).data

    client._send_pczt_header(PCZT_V6_GLOBAL)

    client.tx_chunks = split_tx_v5_for_hash_input(_LEGACY_V5_TX)
    client.trusted_inputs = [trusted_input]

    with pytest.raises(ExceptionRAPDU) as e:
        client._send_trusted_inputs_and_header(continue_hashing=True)

    assert e.value.status == Errors.SW_BAD_STATE


def test_pczt_v6_both_pools_sign_independently(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    """V6 tx carrying both an Orchard and an Ironwood bundle: each pool signs independently.

    Ledger Live never builds such a transaction — it spends the sealed Orchard pool,
    and no Ledger account holds Orchard funds — but the host is untrusted and can send
    one, so the device must still handle it: the two bundles are parsed in sequence,
    the fee sums both value balances, and each pool yields its own spendAuthSig.
    """
    client = ZcashCommandSender(backend)

    with client.send_pczt(
        pczt_global=PCZT_V6_GLOBAL,
        transparent_inputs=[],
        transparent_outputs=[_TRANSPARENT_OUTPUT_599K],
        orchard_bundle=_valid_orchard_bundle(),
        ironwood_bundle=_valid_ironwood_bundle(),
    ):
        _review_approve(scenario_navigator, "test_pczt_v6_both_pools_sign_independently")

    orchard_sig = client.pczt_sign_orchard(action_index=0).data
    assert len(orchard_sig) == 64

    ironwood_sig = client.pczt_sign_ironwood(action_index=0).data
    assert len(ironwood_sig) == 64


def test_pczt_v6_orchard_sign_replay_in_session_rejected(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    """In-session SIGN_ORCHARD replay is rejected before any signature is produced.

    The Ironwood side of this guard has its own tests; the Orchard side had none. A V6
    transaction carrying both bundles is what makes the case reachable: the Ironwood action is
    still unsigned once the Orchard one is signed, so the parser is not reset and the replay has
    to be caught by the `action.signed` check in `ensure_signature_digest_for_orchard` rather
    than by the `is_finished()` precondition that would catch it after a reset.

    The empty body is asserted as well as the status word, and that is the point of the test.
    The handler stages the signature in the reply buffer, and a reply carries whatever is already
    staged alongside its status word — so were the replay ever to reach the signing step, the
    device would ship a spend authorization with an error status. The signature is computed from
    the action's `alpha`, which the first signature zeroed, making that leaked signature valid
    under the unrandomized spend validating key.
    """
    client = ZcashCommandSender(backend)

    with client.send_pczt(
        pczt_global=PCZT_V6_GLOBAL,
        transparent_inputs=[],
        transparent_outputs=[_TRANSPARENT_OUTPUT_599K],
        orchard_bundle=_valid_orchard_bundle(),
        ironwood_bundle=_valid_ironwood_bundle(),
    ):
        _review_approve(scenario_navigator, "test_pczt_v6_orchard_sign_replay_in_session_rejected")

    auth_sig = client.pczt_sign_orchard(action_index=0).data
    assert len(auth_sig) == 64

    with pytest.raises(ExceptionRAPDU) as e:
        client.pczt_sign_orchard(action_index=0)

    assert e.value.status == Errors.SW_INVALID_TRANSACTION
    assert not e.value.data


def test_pczt_ironwood_unknown_branch_id_rejected(
    backend,
):
    """Unknown consensus_branch_id is rejected at PCZT header parsing."""
    client = ZcashCommandSender(backend)

    bad_global = PcztGlobal(
        tx_version=_V6_TX_VERSION,
        version_group_id=_V6_VERSION_GROUP_ID,
        consensus_branch_id=0xDEADBEEF,
    )

    with pytest.raises(ExceptionRAPDU) as e:
        with client.send_pczt(
            pczt_global=bad_global,
            transparent_inputs=[],
            transparent_outputs=[],
            ironwood_bundle=_valid_ironwood_bundle(),
        ):
            pytest.fail("Device accepted a PCZT with unknown branch ID")

    assert e.value.status == Errors.SW_INVALID_TRANSACTION


def test_pczt_orchard_path_unaffected(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    """Regression: V5 Orchard-only PCZT still signs correctly after Ironwood code was added."""
    v5_global = PcztGlobal()  # tx_version=5, consensus_branch_id=0xC2D6D0B4 (Nu5)

    client = ZcashCommandSender(backend)

    with client.send_pczt(
        pczt_global=v5_global,
        transparent_inputs=[],
        transparent_outputs=[_TRANSPARENT_OUTPUT_299K],
        orchard_bundle=_valid_orchard_bundle(),
    ):
        _review_approve(scenario_navigator, "test_pczt_orchard_path_unaffected")

    auth_sig = client.pczt_sign_orchard(action_index=0).data
    assert len(auth_sig) == 64


def test_pczt_ironwood_user_rejection(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    """User rejects a PrivateToPublic (deshield) review; device returns Deny, no sig emitted."""
    client = ZcashCommandSender(backend)

    with pytest.raises(ExceptionRAPDU) as e:
        with client.send_pczt(
            pczt_global=PCZT_V6_GLOBAL,
            transparent_inputs=[],
            transparent_outputs=[_TRANSPARENT_OUTPUT_299K],
            ironwood_bundle=_valid_ironwood_bundle(),
        ):
            scenario_navigator.review_reject(test_name="test_pczt_ironwood_user_rejection")

    assert e.value.status == Errors.SW_DENY
    assert len(e.value.data) == 0


def test_pczt_ironwood_display_private_transfer_rejected(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    """User rejects a PrivateToPrivate (Ironwood-only) review; device returns Deny, no sig emitted.

    Guards the review_outputs rejection path for the PrivateToPrivate TransferType variant.
    The APDU sequence is identical to test_pczt_ironwood_display_private_transfer; only the
    user action (reject instead of approve) differs.
    """
    client = ZcashCommandSender(backend)

    with pytest.raises(ExceptionRAPDU) as e:
        with client.send_pczt(
            pczt_global=PCZT_V6_GLOBAL,
            transparent_inputs=[],
            transparent_outputs=[],
            ironwood_bundle=_mixed_real_and_dummy_ironwood_bundle(),
        ):
            scenario_navigator.review_reject(test_name="test_pczt_ironwood_display_private_transfer_rejected")

    assert e.value.status == Errors.SW_DENY
    assert len(e.value.data) == 0


def test_pczt_ironwood_display_shield_rejected(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    """User rejects a PublicToPrivate (shield: transparent→Ironwood) review; device returns Deny.

    Guards the review_outputs rejection path for the PublicToPrivate TransferType variant.
    The APDU sequence is identical to test_pczt_ironwood_display_shield; only the user
    action (reject instead of approve) differs.
    """
    client = ZcashCommandSender(backend)

    with pytest.raises(ExceptionRAPDU) as e:
        with client.send_pczt(
            pczt_global=PCZT_V6_GLOBAL,
            transparent_inputs=[_TRANSPARENT_INPUT_11K],
            transparent_outputs=[],
            ironwood_bundle=_ironwood_shield_bundle(),
        ):
            scenario_navigator.review_reject(test_name="test_pczt_ironwood_display_shield_rejected")

    assert e.value.status == Errors.SW_DENY
    assert len(e.value.data) == 0


def test_pczt_ironwood_zero_actions_rejected(
    backend,
):
    """An Ironwood bundle with zero actions is rejected before the state machine advances."""
    client = ZcashCommandSender(backend)

    empty_ironwood = PcztIronwoodBundle(
        actions=[],
        flags=0,
        value_balance=0,
        anchor=bytes(32),
    )

    with pytest.raises(ExceptionRAPDU) as e:
        with client.send_pczt(
            pczt_global=PCZT_V6_GLOBAL,
            transparent_inputs=[],
            transparent_outputs=[],
            ironwood_bundle=empty_ironwood,
        ):
            pass  # Rejection arrives in async response, checked on context-manager exit

    assert e.value.status == Errors.SW_INVALID_TRANSACTION


def test_pczt_v5_finished_marker_regression(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    """V5 Orchard PCZT with the FINISHED flag set on the last action chunk still produces a valid signature."""
    v5_global = PcztGlobal()

    client = ZcashCommandSender(backend)

    # send_pczt without ironwood_bundle uses P2_PCZT_FINISHED on the last Orchard packet.
    with client.send_pczt(
        pczt_global=v5_global,
        transparent_inputs=[],
        transparent_outputs=[_TRANSPARENT_OUTPUT_299K],
        orchard_bundle=_valid_orchard_bundle(),
    ):
        _review_approve(scenario_navigator, "test_pczt_v5_finished_marker_regression")

    auth_sig = client.pczt_sign_orchard(action_index=0).data
    assert len(auth_sig) == 64


# Expected Orchard spendAuthSig for a V6 migration PCZT on a freshly started Speculos
# session (deterministic RNG starting point, Speculos default seed).  The value is
# constant regardless of the Orchard anchor because NU6.3 excludes the anchor from the
# sighash — only the authorising-data digest includes it, not the sighash.
# The bundle carries both pools, so the Ironwood action fields enter the V6 sighash too:
# regenerating the Ironwood vectors changes this signature as well.
_EXPECTED_V6_ORCHARD_SIG = bytes.fromhex(
    "d8135f4f857948ed5b3bffe37cdf2df87d7be666dbdff5deebc806596383668d"
    "dbc2c635a7e9f004387cd11bcaa5f71801786916fcbc50d809f12b24bf25d23b"
)

# Second anchor: first byte flipped so the Orchard anchor bytes differ in every bit
# that the first byte carries, giving an easy regression signal.
_ORCHARD_ANCHOR_B = bytes([_ORCHARD_ANCHOR_A[0] ^ 0xFF]) + _ORCHARD_ANCHOR_A[1:]


@pytest.mark.parametrize(
    "anchor,test_name",
    [
        (_ORCHARD_ANCHOR_A, "test_pczt_v6_orchard_anchor_exclusion_a"),
        (_ORCHARD_ANCHOR_B, "test_pczt_v6_orchard_anchor_exclusion_b"),
    ],
    ids=["anchor_a", "anchor_b"],
)
def test_pczt_v6_orchard_anchor_exclusion_regression(
    backend,
    scenario_navigator: NavigateWithScenario,
    anchor: bytes,
    test_name: str,
):
    """V6: the Orchard anchor is excluded from the sighash — changing its value must not alter the signature.

    Each parametrised invocation runs in its own Speculos session (fresh deterministic RNG
    start state).  If the Orchard anchor were included in the V6 sighash the signature
    would differ from _EXPECTED_V6_ORCHARD_SIG; if it is correctly excluded both anchors
    produce the same signature.
    """
    client = ZcashCommandSender(backend)
    with client.send_pczt(
        pczt_global=PCZT_V6_GLOBAL,
        transparent_inputs=[],
        transparent_outputs=[_TRANSPARENT_OUTPUT_599K],
        orchard_bundle=_valid_orchard_bundle(anchor=anchor),
        ironwood_bundle=_valid_ironwood_bundle(),
    ):
        _review_approve(scenario_navigator, test_name)
    orchard_sig = client.pczt_sign_orchard(action_index=0).data
    assert orchard_sig == _EXPECTED_V6_ORCHARD_SIG, (
        "Orchard spendAuthSig changed when Orchard anchor changed — "
        f"Orchard anchor incorrectly excluded from V6 sighash.\n"
        f"anchor={anchor.hex()}\n"
        f"got:  {orchard_sig.hex()}\n"
        f"want: {_EXPECTED_V6_ORCHARD_SIG.hex()}"
    )


def test_pczt_ironwood_before_orchard_rejected(backend):
    """IRONWOOD_ACTION sent before Orchard completes is rejected with BadState.

    After PCZT_HEADER the parser is in WaitTransparentInput, not OrchardActionsDone.
    Sending PCZT_IRONWOOD_ACTION at that point must return SW_BAD_STATE, ensuring
    the host cannot skip the mandatory Orchard step in the V6 command sequence.
    """
    client = ZcashCommandSender(backend)
    client._send_pczt_header(PCZT_V6_GLOBAL)

    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA,
            ins=InsType.PCZT_IRONWOOD_ACTION,
            p1=P1.P1_FIRST,
            p2=P2.P2_NONE,
            data=write_varint(1),
        )

    assert e.value.status == Errors.SW_BAD_STATE


def test_pczt_ironwood_sign_replay_in_session_rejected(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    """In-session SIGN_IRONWOOD replay (before all actions are signed) is rejected by the guard.

    Uses a 2-action bundle so the parser is not reset after the first sign.  The second
    call for action 0 must be caught by the action.signed guard inside
    ensure_signature_digest_for_ironwood, not by a parser-reset check.
    """
    client = ZcashCommandSender(backend)

    with client.send_pczt(
        pczt_global=PCZT_V6_GLOBAL,
        transparent_inputs=[],
        transparent_outputs=[_TRANSPARENT_OUTPUT_599K],
        ironwood_bundle=_valid_ironwood_bundle_2_actions(),
    ):
        _review_approve(scenario_navigator, "test_pczt_ironwood_sign_replay_in_session_rejected")

    # First sign of action 0 succeeds; parser is NOT reset (action 1 still pending).
    auth_sig = client.pczt_sign_ironwood(action_index=0).data
    assert len(auth_sig) == 64

    # Replay of action 0 must be caught by the action.signed guard inside
    # ensure_signature_digest_for_ironwood, which maps to SW_INVALID_TRANSACTION (0x6A80).
    # (SW_DENY / 0x6985 applies only to the post-reset path where is_finished() == false.)
    with pytest.raises(ExceptionRAPDU) as e:
        client.pczt_sign_ironwood(action_index=0)

    assert e.value.status == Errors.SW_INVALID_TRANSACTION


# Expected Ironwood spendAuthSig for a V6 Ironwood-only PCZT on a freshly started Speculos
# session (deterministic RNG starting point, Speculos default seed).  Constant regardless of
# the Ironwood anchor because NU6.3 excludes the anchor from the sighash — only the
# authorising-data digest includes it, not the sighash.
# The empty Orchard component uses the V6 personalization b"ZTxIdOrchardH_v6" (ZIP 229),
# not the V5 b"ZTxIdOrchardHash".
_EXPECTED_V6_IRONWOOD_SIG = bytes.fromhex(
    "824a4cf72c60ec42e5269a8b725449f53938ea2dabbe6875296857c234cffebe"
    "526f19bc1c102aadad8970c5e11fbfeb9ed0032563d071e6b2ccada7c4c4431c"
)


@pytest.mark.parametrize(
    "anchor,test_name",
    [
        (bytes(32), "test_pczt_v6_ironwood_anchor_exclusion_a"),
        (bytes([0xFF]) + bytes(31), "test_pczt_v6_ironwood_anchor_exclusion_b"),
    ],
    ids=["anchor_a", "anchor_b"],
)
def test_pczt_v6_ironwood_anchor_exclusion_regression(
    backend,
    scenario_navigator: NavigateWithScenario,
    anchor: bytes,
    test_name: str,
):
    """V6: Ironwood anchor excluded from sighash — changing it must not alter the signature.

    Each parametrised invocation runs in its own Speculos session (fresh deterministic RNG).
    If the Ironwood anchor were included in the V6 sighash the signature would differ from
    _EXPECTED_V6_IRONWOOD_SIG; if correctly excluded both anchors produce the same signature.
    """
    client = ZcashCommandSender(backend)
    with client.send_pczt(
        pczt_global=PCZT_V6_GLOBAL,
        transparent_inputs=[],
        transparent_outputs=[_TRANSPARENT_OUTPUT_299K],
        ironwood_bundle=_valid_ironwood_bundle(anchor=anchor),
    ):
        _review_approve(scenario_navigator, test_name)
    ironwood_sig = client.pczt_sign_ironwood(action_index=0).data
    assert ironwood_sig == _EXPECTED_V6_IRONWOOD_SIG, (
        "Ironwood spendAuthSig changed when Ironwood anchor changed — "
        f"Ironwood anchor incorrectly included in V6 sighash.\n"
        f"anchor={anchor.hex()}\n"
        f"got:  {ironwood_sig.hex()}\n"
        f"want: {_EXPECTED_V6_IRONWOOD_SIG.hex()}"
    )


# ---------------------------------------------------------------------------
# Negative / malicious-input tests for the Ironwood validation paths (F3+F4)
# ---------------------------------------------------------------------------


def test_pczt_ironwood_cv_net_mismatch_rejected(backend):
    """Ironwood action with a cv_net that does not match Commitment(rcv, spend_value-output_value) is rejected.

    The device recomputes cv_net from the provided rcv and value fields; if it differs from the
    transmitted cv_net the transaction is rejected with SW_INVALID_TRANSACTION.
    """
    client = ZcashCommandSender(backend)
    bad_bundle = PcztIronwoodBundle(
        actions=[
            PcztIronwoodAction(
                cv_net=bytes(32),  # wrong: all-zero, doesn't match Commitment(_RCV, 300000)
                nullifier=_NULLIFIER,
                spend_recipient=_SPEND_RECIPIENT,
                spend_rho=_SPEND_RHO,
                spend_rseed=_SPEND_RSEED,
                rk=_RK_ALPHA_1,
                alpha=_ALPHA,
                signing_path=_SIGNING_PATH,
                cmx=_CMX,
                ephemeral_key=bytes(32),
                enc_ciphertext=bytes(580),
                out_ciphertext=bytes(80),
                rcv=_RCV,
                rseed=_RSEED,
                spend_value=300000,
                value=0,
                recipient=_INTERNAL_RECIPIENT,
            )
        ],
        flags=3,
        value_balance=300000,
        anchor=bytes(32),
    )

    with pytest.raises(ExceptionRAPDU) as e:
        with client.send_pczt(
            pczt_global=PCZT_V6_GLOBAL,
            transparent_inputs=[],
            transparent_outputs=[],
            ironwood_bundle=bad_bundle,
        ):
            pass  # device rejects synchronously during action parsing, before review
    assert e.value.status == Errors.SW_INVALID_TRANSACTION


def test_pczt_ironwood_nullifier_mismatch_rejected(backend):
    """Ironwood action with a nullifier that doesn't match NullifierDerive(fvk, spend_note) is rejected.

    The device derives the expected nullifier from the spend note fields and the signing key's FVK.
    """
    client = ZcashCommandSender(backend)
    bad_bundle = PcztIronwoodBundle(
        actions=[
            PcztIronwoodAction(
                cv_net=_CV_NET,
                nullifier=bytes(32),  # wrong: all-zero, doesn't match the derived nullifier
                spend_recipient=_SPEND_RECIPIENT,
                spend_rho=_SPEND_RHO,
                spend_rseed=_SPEND_RSEED,
                rk=_RK_ALPHA_1,
                alpha=_ALPHA,
                signing_path=_SIGNING_PATH,
                cmx=_CMX,
                ephemeral_key=bytes(32),
                enc_ciphertext=bytes(580),
                out_ciphertext=bytes(80),
                rcv=_RCV,
                rseed=_RSEED,
                spend_value=300000,
                value=0,
                recipient=_INTERNAL_RECIPIENT,
            )
        ],
        flags=3,
        value_balance=300000,
        anchor=bytes(32),
    )

    with pytest.raises(ExceptionRAPDU) as e:
        with client.send_pczt(
            pczt_global=PCZT_V6_GLOBAL,
            transparent_inputs=[],
            transparent_outputs=[],
            ironwood_bundle=bad_bundle,
        ):
            pass
    assert e.value.status == Errors.SW_INVALID_TRANSACTION


def test_pczt_ironwood_wrong_enc_ciphertext_length_rejected(backend):
    """Ironwood action with enc_ciphertext length != 580 is rejected before action parsing completes.

    The device enforces ORCHARD_ENC_CIPHERTEXT_SIZE = 580; any other length returns SW_INVALID_TRANSACTION.
    """
    client = ZcashCommandSender(backend)
    bad_bundle = PcztIronwoodBundle(
        actions=[
            PcztIronwoodAction(
                cv_net=_CV_NET,
                nullifier=_NULLIFIER,
                spend_recipient=_SPEND_RECIPIENT,
                spend_rho=_SPEND_RHO,
                spend_rseed=_SPEND_RSEED,
                rk=_RK_ALPHA_1,
                alpha=_ALPHA,
                signing_path=_SIGNING_PATH,
                cmx=_CMX,
                ephemeral_key=bytes(32),
                enc_ciphertext=bytes(500),  # wrong: 500 != 580
                out_ciphertext=bytes(80),
                rcv=_RCV,
                rseed=_RSEED,
                spend_value=300000,
                value=0,
                recipient=_INTERNAL_RECIPIENT,
            )
        ],
        flags=3,
        value_balance=300000,
        anchor=bytes(32),
    )

    with pytest.raises(ExceptionRAPDU) as e:
        with client.send_pczt(
            pczt_global=PCZT_V6_GLOBAL,
            transparent_inputs=[],
            transparent_outputs=[],
            ironwood_bundle=bad_bundle,
        ):
            pass
    assert e.value.status == Errors.SW_INVALID_TRANSACTION


def test_pczt_ironwood_wrong_out_ciphertext_length_rejected(backend):
    """Ironwood action with out_ciphertext length != 80 is rejected before action parsing completes.

    The device enforces ORCHARD_OUT_CIPHERTEXT_SIZE = 80; any other length returns SW_INVALID_TRANSACTION.
    """
    client = ZcashCommandSender(backend)
    bad_bundle = PcztIronwoodBundle(
        actions=[
            PcztIronwoodAction(
                cv_net=_CV_NET,
                nullifier=_NULLIFIER,
                spend_recipient=_SPEND_RECIPIENT,
                spend_rho=_SPEND_RHO,
                spend_rseed=_SPEND_RSEED,
                rk=_RK_ALPHA_1,
                alpha=_ALPHA,
                signing_path=_SIGNING_PATH,
                cmx=_CMX,
                ephemeral_key=bytes(32),
                enc_ciphertext=bytes(580),
                out_ciphertext=bytes(50),  # wrong: 50 != 80
                rcv=_RCV,
                rseed=_RSEED,
                spend_value=300000,
                value=0,
                recipient=_INTERNAL_RECIPIENT,
            )
        ],
        flags=3,
        value_balance=300000,
        anchor=bytes(32),
    )

    with pytest.raises(ExceptionRAPDU) as e:
        with client.send_pczt(
            pczt_global=PCZT_V6_GLOBAL,
            transparent_inputs=[],
            transparent_outputs=[],
            ironwood_bundle=bad_bundle,
        ):
            pass
    assert e.value.status == Errors.SW_INVALID_TRANSACTION


def test_pczt_ironwood_max_actions_exceeded_rejected(backend):
    """An Ironwood bundle with 33 actions (> MAX_PCZT_IRONWOOD_ACTIONS_NUMBER = 32) is rejected.

    The device checks the action count immediately on the header packet; 33 actions returns
    SW_INVALID_TRANSACTION before any action field is parsed. The bound itself is a measured
    capacity — tests/standalone/test_pczt_action_capacity.py drives the counts up to it.
    """
    client = ZcashCommandSender(backend)
    oversize_bundle = PcztIronwoodBundle(
        actions=[_valid_ironwood_action()] * 33,
        flags=3,
        value_balance=300000 * 33,
        anchor=bytes(32),
    )

    with pytest.raises(ExceptionRAPDU) as e:
        with client.send_pczt(
            pczt_global=PCZT_V6_GLOBAL,
            transparent_inputs=[],
            transparent_outputs=[],
            ironwood_bundle=oversize_bundle,
        ):
            pass
    assert e.value.status == Errors.SW_INVALID_TRANSACTION


def test_pczt_ironwood_cmx_mismatch_rejected(backend):
    """Ironwood output with a cmx that does not match NoteCommitment(recipient, value, rseed) is rejected.

    The device recomputes the note commitment from the decrypted note fields; if it differs from
    compact.cmx the decryption is treated as a failure.  When no other decryption path succeeds
    (IVK mismatch, OVK mismatch, value != 0 so dummy branch is skipped), the transaction is
    rejected with SW_INVALID_TRANSACTION.

    This guards the clear-signing invariant: the displayed recipient/value must match compact.cmx,
    the field that enters the signature digest.  Without this check a compromised PCZT builder
    that knows the device's IVK could substitute a different cmx (committing to an attacker-
    controlled recipient) while presenting an honest enc_ciphertext that decrypts correctly.
    """
    client = ZcashCommandSender(backend)

    bad_action = _dummy_ironwood_action()
    bad_action.cmx = bytes(32)  # all-zero: does not match NoteCommitment(recipient, value, rseed)

    bad_bundle = PcztIronwoodBundle(
        actions=[bad_action],
        flags=3,
        value_balance=-_DUMMY_CHANGE_VALUE,  # negative: funds flow in from transparent input
        anchor=bytes(32),
    )

    with pytest.raises(ExceptionRAPDU) as e:
        with client.send_pczt(
            pczt_global=PCZT_V6_GLOBAL,
            transparent_inputs=[_TRANSPARENT_INPUT_11K],
            transparent_outputs=[],
            ironwood_bundle=bad_bundle,
        ):
            pass  # device rejects during action parsing, before review
    assert e.value.status == Errors.SW_INVALID_TRANSACTION


def test_pczt_ironwood_v3_note_tampered_cmx_rejected(backend):
    """ZIP 2005 V3 Ironwood output whose compact.cmx does not match note_commitment_v3() is rejected.

    A V3 enc_ciphertext is constructed by XOR-flipping the first byte of _DUMMY_ENC_CIPHERTEXT:
      - The note is encrypted with ChaCha20, so flipping enc[0] flips plaintext[0].
      - _DUMMY_ENC_CIPHERTEXT decrypts to plaintext[0] = 0x02 (NoteVersion::V2).
      - Flipping enc[0] XOR 0x01 makes the device recover plaintext[0] = 0x03 (NoteVersion::V3).
      - All other plaintext bytes — diversifier, value, rseed — are unchanged (same key, same
        recipient, same esk derivation from _DUMMY_RSEED), so the ephemeral-key check passes.

    The note commitment check then calls note_commitment_v3(g_d, pk_d, value, rho, rseed) which
    produces the real V3 cmx (different from _DUMMY_CMX because rcm derivation differs). Since
    compact.cmx is set to all-zero bytes (0x00 × 32), the mismatch is detected and the action
    is rejected with SW_INVALID_TRANSACTION.

    This directly exercises the clear-signing invariant added in parse_and_validate_note_plaintext:
    a PCZT builder that knows the device's IVK cannot substitute a different cmx while presenting
    a valid enc_ciphertext, because note_commitment_v3 binds the cmx to the exact note content.
    """
    client = ZcashCommandSender(backend)

    # V3 enc_ciphertext: XOR the first byte of the V2 ciphertext so the decrypted lead byte
    # becomes 0x03 instead of 0x02.  ChaCha20 is stream-XOR, so flipping enc[0] XOR 0x01
    # flips plaintext[0] by 0x01, changing 0x02→0x03 without disturbing any other bytes.
    # The _DUMMY_EPHEMERAL_KEY remains valid because esk = PRF_expand(rseed, [0x04]||rho) is
    # version-independent — only the decrypted lead byte changes.
    _v3_enc_ciphertext = bytes([_DUMMY_ENC_CIPHERTEXT[0] ^ 0x01]) + _DUMMY_ENC_CIPHERTEXT[1:]

    bad_action = _dummy_ironwood_action()
    bad_action.enc_ciphertext = _v3_enc_ciphertext
    bad_action.cmx = bytes(32)  # tampered: all-zero, does not match note_commitment_v3(...)
    bad_action.note_plaintext_version = 0x03  # signal V3 decryption path

    bad_bundle = PcztIronwoodBundle(
        actions=[bad_action],
        flags=3,
        value_balance=-_DUMMY_CHANGE_VALUE,
        anchor=bytes(32),
    )

    with pytest.raises(ExceptionRAPDU) as e:
        with client.send_pczt(
            pczt_global=PCZT_V6_GLOBAL,
            transparent_inputs=[_TRANSPARENT_INPUT_11K],
            transparent_outputs=[],
            ironwood_bundle=bad_bundle,
        ):
            pass  # device rejects during action parsing, before review
    assert e.value.status == Errors.SW_INVALID_TRANSACTION


def test_pczt_ironwood_v3_real_output_accepted(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    """ZIP 2005 V3 Ironwood output with the correct note_commitment_v3() cmx is accepted.

    This is the positive counterpart to test_pczt_ironwood_v3_note_tampered_cmx_rejected:
    it verifies that note_commitment_v3 produces the correct output for acceptance, not just
    that a wrong cmx is rejected.
    """
    client = ZcashCommandSender(backend)
    action = PcztIronwoodAction(
        cv_net=_DUMMY_CV_NET,
        nullifier=_DUMMY_NULLIFIER,
        spend_recipient=_SPEND_RECIPIENT,
        spend_rho=_DUMMY_SPEND_RHO,
        spend_rseed=_DUMMY_SPEND_RSEED,
        rk=_RK_ALPHA_1,
        alpha=_ALPHA,
        signing_path=_SIGNING_PATH,
        cmx=_V3_REAL_CMX,
        ephemeral_key=_V3_REAL_EPK,
        enc_ciphertext=_V3_REAL_ENC_CIPHERTEXT,
        out_ciphertext=bytes(80),
        rcv=_DUMMY_RCV,
        rseed=bytes(32),  # metadata rseed unused for IVK-decryptable non-dummy output
        spend_value=0,
        value=_DUMMY_CHANGE_VALUE,
        recipient=_INTERNAL_RECIPIENT,
        note_plaintext_version=0x03,
    )
    bundle = PcztIronwoodBundle(
        actions=[action],
        flags=3,
        value_balance=-_DUMMY_CHANGE_VALUE,
        anchor=bytes(32),
    )

    with client.send_pczt(
        pczt_global=PCZT_V6_GLOBAL,
        transparent_inputs=[_TRANSPARENT_INPUT_11K],
        transparent_outputs=[],
        ironwood_bundle=bundle,
    ):
        _review_approve(scenario_navigator, "test_pczt_ironwood_v3_real_output_accepted")

    auth_sig = client.pczt_sign_transparent(input_index=0).data
    assert len(auth_sig) >= 70


def test_pczt_ironwood_v2_metadata_byte_rejected(backend):
    """A note_plaintext_version metadata byte of 0x02 is rejected in an Ironwood bundle.

    The Ironwood value pool carries V3 note plaintexts only (orchard's
    `BundleVersion::note_version` maps ValuePool::Ironwood to NoteVersion::V3), so a host
    announcing V2 describes a note this bundle cannot hold. The device refuses the action
    instead of parsing on, even though the ciphertext here would decrypt as a valid V3 note.

    That the commitment formula follows the authenticated plaintext[0] rather than this
    metadata byte stays covered by test_pczt_ironwood_dummy_with_v3_metadata_byte_accepted.
    """
    client = ZcashCommandSender(backend)
    action = PcztIronwoodAction(
        cv_net=_DUMMY_CV_NET,
        nullifier=_DUMMY_NULLIFIER,
        spend_recipient=_SPEND_RECIPIENT,
        spend_rho=_DUMMY_SPEND_RHO,
        spend_rseed=_DUMMY_SPEND_RSEED,
        rk=_RK_ALPHA_1,
        alpha=_ALPHA,
        signing_path=_SIGNING_PATH,
        cmx=_V3_REAL_CMX,
        ephemeral_key=_V3_REAL_EPK,
        enc_ciphertext=_V3_REAL_ENC_CIPHERTEXT,
        out_ciphertext=bytes(80),
        rcv=_DUMMY_RCV,
        rseed=bytes(32),  # metadata rseed unused for IVK-decryptable non-dummy output
        spend_value=0,
        value=_DUMMY_CHANGE_VALUE,
        recipient=_INTERNAL_RECIPIENT,
        note_plaintext_version=0x02,  # metadata says V2, but ciphertext decrypts to plaintext[0]=0x03
    )
    bundle = PcztIronwoodBundle(
        actions=[action],
        flags=3,
        value_balance=-_DUMMY_CHANGE_VALUE,
        anchor=bytes(32),
    )

    with pytest.raises(ExceptionRAPDU) as e:
        with client.send_pczt(
            pczt_global=PCZT_V6_GLOBAL,
            transparent_inputs=[_TRANSPARENT_INPUT_11K],
            transparent_outputs=[],
            ironwood_bundle=bundle,
        ):
            pytest.fail("Device accepted a V2 note_plaintext_version in an Ironwood bundle")

    assert e.value.status == Errors.SW_INVALID_TRANSACTION


def test_pczt_ironwood_rk_mismatch_rejected(backend):
    """A real Ironwood spend whose rk does not match alpha and the signing key is refused.

    This is the one check binding a signature to the device's own key. The device recomputes
    rk from the derived spend authorizing key and compares raw bytes, so a wrong rk needs no
    curve arithmetic to construct — flipping one bit is enough, exactly as the Orchard pool's
    test_pczt_sign_tx_orchard_rk_mismatch_rejected does.

    The check only runs for a real spend (spend_value != 0); a dummy padding spend derives no
    ask and is refused at signing time instead.
    """
    client = ZcashCommandSender(backend)
    action = _valid_ironwood_action()
    action.rk = bytes([_RK_ALPHA_1[0] ^ 1]) + _RK_ALPHA_1[1:]
    bundle = PcztIronwoodBundle(
        actions=[action],
        flags=3,
        value_balance=300000,
        anchor=bytes(32),
    )

    with pytest.raises(ExceptionRAPDU) as e:
        with client.send_pczt(
            pczt_global=PCZT_V6_GLOBAL,
            transparent_inputs=[],
            transparent_outputs=[_TRANSPARENT_OUTPUT_299K],
            ironwood_bundle=bundle,
        ):
            pytest.fail("Device accepted a PCZT Ironwood action with mismatched rk")

    assert e.value.status == Errors.SW_INVALID_TRANSACTION


@pytest.mark.skip(
    reason="Unreachable by construction, so there is nothing to exercise. read_ironwood_value "
    "bounds every spend and output value to MAX_MONEY (2.1e15 zatoshis) via "
    "Zatoshis::from_nonnegative_i64_le_bytes, and MAX_PCZT_IRONWOOD_ACTIONS_NUMBER caps a "
    "bundle at 32 actions, so the largest sum finish_current_ironwood_action can accumulate "
    "is 6.7e16 — two orders of magnitude below u64::MAX. The checked_add on the running "
    "sums is defence in depth behind that range check, not an untested path: a host cannot "
    "supply a value large enough to reach it."
)
def test_pczt_ironwood_value_sum_overflow_rejected(backend):
    pass


# ---------------------------------------------------------------------------
# Display / clear-signing tests for Ironwood transfer flows
# ---------------------------------------------------------------------------


def test_pczt_ironwood_display_private_transfer(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    """Ironwood-only V6 PCZT: device signs after displaying the review screens.

    No transparent inputs or outputs — all funds flow within the Ironwood pool.
    The mixed bundle (real spend at action 0, dummy padding spend at action 1 whose
    output note decrypts as change via the internal IVK) is used because the firmware
    requires at least one decryptable output before it can show the review screen.

    With no external output the firmware's reveal_self_outputs path triggers: the internal
    change note is exposed so the user can review the value before signing.

    This also exercises the path that folds ironwood_spend_value_sum into from_private,
    preventing the TransferType from being misclassified as PublicToPublic.

    Note: _mixed_real_and_dummy_ironwood_bundle() is intentionally synthetic — the fee
    (290000 zats) is 29× the output (10000 zats). This tests the reveal_self_outputs path
    in isolation. test_pczt_ironwood_display_private_transfer_with_change is the canonical
    realistic-shape regression baseline (fee 1000 zats, external output 180000 zats).
    """
    client = ZcashCommandSender(backend)

    with client.send_pczt(
        pczt_global=PCZT_V6_GLOBAL,
        transparent_inputs=[],
        transparent_outputs=[],
        ironwood_bundle=_mixed_real_and_dummy_ironwood_bundle(),
    ):
        _review_approve(scenario_navigator, "test_pczt_ironwood_display_private_transfer")

    auth_sig = client.pczt_sign_ironwood(action_index=0).data
    assert len(auth_sig) == 64


def test_pczt_ironwood_display_private_transfer_with_change(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    """Ironwood→Ironwood with a hidden change note — mirrors test_pczt_sign_tx_v5_orchard_to_orchard_with_change.

    action 0 (real spend): output 180000 zats to an external Ironwood recipient; the
    enc_ciphertext decrypts via the device's external OVK → classified as non-change →
    shown on the review screen.

    action 1 (dummy padding, spend_value=0): output 10000 zats to the internal IVK
    → classified as change → hidden from the review screen.

    Because an external decryptable output exists, has_external_output=True and
    reveal_self_outputs=False: the change note is genuinely not revealed to the user.
    """
    client = ZcashCommandSender(backend)

    with client.send_pczt(
        pczt_global=PCZT_V6_GLOBAL,
        transparent_inputs=[],
        transparent_outputs=[],
        ironwood_bundle=_ironwood_bundle_with_external_recipient(),
    ):
        _review_approve(
            scenario_navigator,
            "test_pczt_ironwood_display_private_transfer_with_change",
        )

    auth_sig = client.pczt_sign_ironwood(action_index=0).data
    assert len(auth_sig) == 64


def test_pczt_ironwood_display_private_transfer_with_memo(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    """Transparent→Ironwood (shield) with ASCII memo: memo text displayed on device.

    A transparent input of 100000 zats funds the shield; the Ironwood action receives
    90000 zats (value_balance=-90000, fee=10000). The enc_ciphertext decrypts via the
    device's external OVK (m/32'/133'/0') to ASCII memo "PCZT Orchard memo test",
    exercising ironwood_output_memo_display, ironwood_memo_display,
    is_ironwood_displayable_ascii_memo, and the BLAKE2b memo-hash fallback path.

    The action vector is byte-identical to the Orchard action from
    test_pczt_sign_tx_v5_transparent_to_orchard_with_memo because Ironwood uses the
    same note-encryption primitives (orchard_decipher_keys, OrchardFvk) and signing path.
    """
    client = ZcashCommandSender(backend)

    with client.send_pczt(
        pczt_global=PCZT_V6_GLOBAL,
        transparent_inputs=[_TRANSPARENT_INPUT_100K],
        transparent_outputs=[],
        ironwood_bundle=_ironwood_memo_bundle(),
    ):
        _review_approve(
            scenario_navigator,
            "test_pczt_ironwood_display_private_transfer_with_memo",
        )

    auth_sig = client.pczt_sign_transparent(input_index=0).data
    assert len(auth_sig) >= 70


def test_pczt_ironwood_display_shield(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    """Transparent→Ironwood (shield): device displays 'Transfer from public to private address'.

    A transparent input of 11000 zats funds the PCZT; the Ironwood bundle absorbs 10000 of
    them (value_balance=-10000), leaving 1000 as fee. The single Ironwood action has
    spend_value=0 (dummy padding) so the device produces no Ironwood spend-auth signature;
    it signs the transparent input instead. With no external Ironwood outputs the internal
    change note is revealed, giving TransferType::PublicToPrivate.
    """
    client = ZcashCommandSender(backend)

    with client.send_pczt(
        pczt_global=PCZT_V6_GLOBAL,
        transparent_inputs=[_TRANSPARENT_INPUT_11K],
        transparent_outputs=[],
        ironwood_bundle=_ironwood_shield_bundle(),
    ):
        _review_approve(scenario_navigator, "test_pczt_ironwood_display_shield")

    auth_sig = client.pczt_sign_transparent(input_index=0).data
    assert len(auth_sig) >= 70


# ---------------------------------------------------------------------------
# PCZT v2 header and NoteVersion::V3 output handling
# ---------------------------------------------------------------------------


def test_pczt_v2_header_accepted_for_v6(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    """PCZT version 2 header is accepted for a V6 Ironwood transaction."""
    client = ZcashCommandSender(backend)

    with client.send_pczt(
        pczt_global=PCZT_V6_GLOBAL,
        transparent_inputs=[],
        transparent_outputs=[_TRANSPARENT_OUTPUT_299K],
        ironwood_bundle=_valid_ironwood_bundle(),
    ):
        _review_approve(scenario_navigator, "test_pczt_v2_header_accepted_for_v6")

    auth_sig = client.pczt_sign_ironwood(action_index=0).data
    assert len(auth_sig) == 64


def test_pczt_v1_header_rejected_for_v6(backend):
    """PCZT version 1 header is rejected for a V6 transaction."""
    client = ZcashCommandSender(backend)

    with pytest.raises(ExceptionRAPDU) as e:
        with client.send_pczt(
            pczt_global=PCZT_V6_GLOBAL,
            transparent_inputs=[],
            transparent_outputs=[_TRANSPARENT_OUTPUT_299K],
            ironwood_bundle=_valid_ironwood_bundle(),
            pczt_version=1,
        ):
            pytest.fail("Device accepted PCZT v1 for a V6 transaction")

    assert e.value.status == Errors.SW_INVALID_TRANSACTION


def test_pczt_ironwood_v2_metadata_byte_rejected_on_dummy(backend):
    """The V2 metadata byte is refused on a dummy output too, not only on a real one.

    The 116-byte form carries the version explicitly; announcing 0x02 contradicts the
    Ironwood pool regardless of whether the action is a dummy, so the refusal happens
    before the dummy branch is reached."""
    client = ZcashCommandSender(backend)
    action = _dummy_ironwood_action()
    action.note_plaintext_version = 0x02
    bundle = PcztIronwoodBundle(
        actions=[action],
        flags=3,
        value_balance=action.spend_value - action.value,
        anchor=bytes(32),
    )

    with pytest.raises(ExceptionRAPDU) as e:
        with client.send_pczt(
            pczt_global=PCZT_V6_GLOBAL,
            transparent_inputs=[_TRANSPARENT_INPUT_11K],
            transparent_outputs=[],
            ironwood_bundle=bundle,
        ):
            pytest.fail("Device accepted a V2 note_plaintext_version on an Ironwood dummy")

    assert e.value.status == Errors.SW_INVALID_TRANSACTION


def test_pczt_ironwood_dummy_with_v3_metadata_byte_accepted(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    """A dummy output is accepted with the metadata byte present and set to 0x03.

    The 116-byte metadata packet on a zero-value output: the dummy path, with notePlaintextVersion
    explicitly present rather than left to the parser's default. The pool is V3-only, so the dummy
    path recomputes cmx with the V3 formula and the metadata byte must be 0x03 — this checks that
    supplying it explicitly agrees with defaulting it.

    For the real-spend V3 commitment path see test_pczt_ironwood_v3_real_output_accepted.
    """
    client = ZcashCommandSender(backend)
    action = _dummy_ironwood_action()
    action.note_plaintext_version = 0x03
    bundle = PcztIronwoodBundle(
        actions=[action],
        flags=3,
        value_balance=action.spend_value - action.value,
        anchor=bytes(32),
    )

    with client.send_pczt(
        pczt_global=PCZT_V6_GLOBAL,
        transparent_inputs=[_TRANSPARENT_INPUT_11K],
        transparent_outputs=[],
        ironwood_bundle=bundle,
    ):
        _review_approve(scenario_navigator, "test_pczt_ironwood_dummy_with_v3_metadata_byte_accepted")

    auth_sig = client.pczt_sign_transparent(input_index=0).data
    assert len(auth_sig) >= 70


def test_pczt_v2_0x03_dummy_accepted(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    """Zero-value Ironwood output with note_plaintext_version=0x03 is accepted when
    the host-supplied cmx matches note_commitment_v3(recipient, 0, nullifier, rseed)."""
    client = ZcashCommandSender(backend)

    v3_dummy = PcztIronwoodAction(
        cv_net=_V3_DUMMY_CV_NET,
        nullifier=_DUMMY_NULLIFIER,
        spend_recipient=_SPEND_RECIPIENT,
        spend_rho=_DUMMY_SPEND_RHO,
        spend_rseed=_DUMMY_SPEND_RSEED,
        rk=_RK_ALPHA_1,
        alpha=_ALPHA,
        signing_path=_SIGNING_PATH,
        cmx=_V3_DUMMY_CMX,
        ephemeral_key=_DUMMY_EPHEMERAL_KEY,
        enc_ciphertext=bytes(580),
        out_ciphertext=bytes(80),
        rcv=_DUMMY_RCV,
        rseed=_DUMMY_RSEED,
        spend_value=0,
        value=0,
        recipient=_INTERNAL_RECIPIENT,
        note_plaintext_version=0x03,
    )

    actions = [_valid_ironwood_action(), v3_dummy]
    bundle = PcztIronwoodBundle(
        actions=actions,
        flags=3,
        value_balance=sum(a.spend_value - a.value for a in actions),
        anchor=bytes(32),
    )

    with client.send_pczt(
        pczt_global=PCZT_V6_GLOBAL,
        transparent_inputs=[],
        transparent_outputs=[_TRANSPARENT_OUTPUT_299K],
        ironwood_bundle=bundle,
    ):
        _review_approve(scenario_navigator, "test_pczt_v2_0x03_dummy_accepted")

    auth_sig = client.pczt_sign_ironwood(action_index=0).data
    assert len(auth_sig) == 64


def test_pczt_v1_metadata_backward_compat_in_v2_bundle(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    """115-byte output metadata (no note_plaintext_version) remains valid in a PCZT v2 V6
    transaction — the firmware accepts both 115 and 116 bytes."""
    client = ZcashCommandSender(backend)

    with client.send_pczt(
        pczt_global=PCZT_V6_GLOBAL,
        transparent_inputs=[],
        transparent_outputs=[_TRANSPARENT_OUTPUT_299K],
        ironwood_bundle=_valid_ironwood_bundle(),
    ):
        _review_approve(
            scenario_navigator,
            "test_pczt_v1_metadata_backward_compat_in_v2_bundle",
        )

    auth_sig = client.pczt_sign_ironwood(action_index=0).data
    assert len(auth_sig) == 64
