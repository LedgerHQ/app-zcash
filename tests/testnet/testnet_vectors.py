"""Testnet account 0 of the Speculos default seed, printed by `tests/testnet-vectors` (not read back from the device).

Regenerate outside the repository: cargo run --manifest-path <repo>/tests/testnet-vectors/Cargo.toml --target <host triple>
"""

# pylint: disable=C0301

UFVK_ACCOUNT_0 = "uviewtest1rj0v4x3k66r0jrcvdlwxfqszzuz7jqym5auuagdtkdrk543jsw9kf8rhvp4zckjf6uevx3gg2egerw59vj60fgd8ygpca5etgjqlvudfd0pdt02sh22dl8dqd2tyy99s5my2awd2zmvtuh9ngqh9utnhyklcmcunxlsjchnal08sr6l52rrr89myv383pp7hu89sjvfxfs2x7kna5heu6557s7pqqse58v8q8fkwx8vayrrv9dpyrxg7j2cf0v3krwnfl6nsgxglj494eg0fzdpayd280jlmwy4mw78u"  # noqa: E501
UADDRESS_ACCOUNT_0 = "utest1e837rlupuxvv90arma76yrw0u6gt750j53zq9g9p2xw3pwz879g38qs89e5fzaj62mpqu8568hw3tspnscx5znceg4kzlygq0studgr7"  # noqa: E501
ORCHARD_RAW_ADDRESS_ACCOUNT_0 = bytes.fromhex("668dde16ab04dcdb90f4898ab2dbc96caca2f8382ce5c70499113cc1788ed2c4cf28d9b7ad385724446d01")
ORCHARD_INTERNAL_RECIPIENT_ACCOUNT_0 = bytes.fromhex("8e78769368fbd92d3945165ddf71059b3d6234976e225467e2e7bfd99cbae66ad56168ba155c9085d9e630")
ORCHARD_FVK_ACCOUNT_0 = bytes.fromhex("14d16ccfe694a9ea58426675dda627d9b89cd316037208d9f2413bbb42fa3b01071ae48e470edc0981b6a53823683ac4fd6946ee042bcfa032463fa580d86b0d5a0f9aede5be97d5fe59496214dddadbe134227662188841ecdf3bc2c621851f")

ORCHARD_SPEND_RHO = bytes.fromhex("06" + "00" * 31)
ORCHARD_SPEND_RSEED = bytes.fromhex("1a" + "00" * 31)
ORCHARD_RSEED = bytes.fromhex("2e" + "00" * 31)
ORCHARD_RCV = bytes.fromhex("42" + "00" * 31)
ORCHARD_ALPHA = (1).to_bytes(32, byteorder="little")
ORCHARD_SPEND_VALUE = 300000
ORCHARD_NULLIFIER = bytes.fromhex("51dded408d568e03e7ee2087c3b86f8eeaabaf6dbb6823960582f8a1aedac839")
ORCHARD_CMX = bytes.fromhex("c6f89cc4a83532d5721de540d55d1a47bd3ea192bb80ffd9bbbeb871e0c7932c")
ORCHARD_CV_NET = bytes.fromhex("00b3324110776396d31646041679fd6530d57c353c6be0a93a0cd55b30aa6d8b")
ORCHARD_RK_ALPHA_1 = bytes.fromhex("8d5666ff8b62c0eec61a95c6dd9182e1f5d8d3b79062313965405b4909174918")
# The standalone fixture's anchor: the device cannot relate an anchor to a note.
ORCHARD_ANCHOR = bytes.fromhex("699c780066f179ff12b26a5ec5b1af3d418eb0eadec3d3b18f10c91d97b33109")
