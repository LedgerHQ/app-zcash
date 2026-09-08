"""CompactSize encoding and decoding in the test client.

Host-only, no device involved. The transactions the suite builds never carry 252 of anything and
are never truncated, so a device test cannot reach either defect these cover: the encoder would
have to be asked for the boundary value, and the decoder handed a short buffer.
"""

import pytest
from application_client.zcash_utils import read_compactsize, write_varint


@pytest.mark.parametrize(
    "value, expected",
    [
        (0, b"\x00"),
        (1, b"\x01"),
        (251, b"\xfb"),
        # The boundary. A single byte carries it, because 0xFD, 0xFE and 0xFF are the prefixes of
        # the extended forms and 0xFC is not.
        (252, b"\xfc"),
        (253, b"\xfd\xfd\x00"),
        (0xFFFF, b"\xfd\xff\xff"),
        (0x10000, b"\xfe\x00\x00\x01\x00"),
        (0xFFFFFFFF, b"\xfe\xff\xff\xff\xff"),
        (0x100000000, b"\xff\x00\x00\x00\x00\x01\x00\x00\x00"),
    ],
)
def test_write_varint_is_canonical(value, expected):
    assert write_varint(value) == expected


@pytest.mark.parametrize("value", [0, 1, 251, 252, 253, 0xFFFF, 0x10000, 0xFFFFFFFF])
def test_write_varint_round_trips_through_the_reader(value):
    encoded = write_varint(value)
    decoded, offset = read_compactsize(encoded, 0)

    assert decoded == value
    assert offset == len(encoded)


def test_read_compactsize_refuses_a_truncated_extended_field():
    # Announces a two-byte field and supplies one. This used to convert the short slice and
    # advance the offset by three, so the caller read every later field at a wrong position.
    with pytest.raises(ValueError, match="2-byte CompactSize"):
        read_compactsize(b"\xfd\x01", 0)


def test_read_compactsize_refuses_a_truncated_eight_byte_field():
    with pytest.raises(ValueError, match="8-byte CompactSize"):
        read_compactsize(b"\xff\x01\x02\x03", 0)


def test_read_compactsize_refuses_an_offset_past_the_buffer():
    with pytest.raises(ValueError, match="CompactSize prefix"):
        read_compactsize(b"\x01", 1)


def test_read_compactsize_reads_from_an_offset_inside_a_larger_buffer():
    buf = b"\xaa\xaa" + write_varint(300) + b"\xbb"
    value, offset = read_compactsize(buf, 2)

    assert value == 300
    assert offset == 5
