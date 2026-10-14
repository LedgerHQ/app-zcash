"""Public test vectors from Python arithmetic, independent of the SDK/Rust key code."""
import hashlib
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(root / 'tests'))
from application_client.zcash_verify_sign import (
    PALLAS_BASE_MODULUS as P,
    PALLAS_SCALAR_MODULUS as Q,
    ORCHARD_SPENDAUTHSIG_BASEPOINT_BYTES,
    _pallas_point_from_bytes,
    _pallas_point_to_bytes,
    _pallas_scalar_mul,
)

PERSONALIZATION = b'Zcash_ExpandSeed'
ASK_DOMAIN, NK_DOMAIN, RIVK_DOMAIN = 6, 7, 8
PUBLIC_SEEDS = (1, 2, 3, 4)
base = _pallas_point_from_bytes(ORCHARD_SPENDAUTHSIG_BASEPOINT_BYTES)
rows = []
signs = set()
for seed in PUBLIC_SEEDS:
    sk = bytes([seed]) * 32
    def derive(domain, modulus):
        return int.from_bytes(hashlib.blake2b(sk + bytes([domain]), digest_size=64, person=PERSONALIZATION).digest(), 'little') % modulus
    ask = derive(ASK_DOMAIN, Q)
    ak = _pallas_point_to_bytes(_pallas_scalar_mul(ask, base))
    negative = ak[-1] >> 7
    signs.add(negative)
    if negative:
        ask = Q - ask
        ak = _pallas_point_to_bytes(_pallas_scalar_mul(ask, base))
    nk = derive(NK_DOMAIN, P)
    rivk = derive(RIVK_DOMAIN, Q)
    fvk = ak + nk.to_bytes(32, 'little') + rivk.to_bytes(32, 'little')
    rk = _pallas_point_to_bytes(_pallas_scalar_mul((ask + 1) % Q, base))
    def array(data): return '[' + ', '.join(str(x) for x in data) + ']'
    rows.append(f'    ({seed}, {array(fvk)}, {array(ask.to_bytes(32, "little"))}, {array(rk)}),')
assert signs == {0, 1}, 'Vectors must cover both key-normalization signs'
Path(__file__).with_name('src').joinpath('vectors.rs').write_text('// Generated from public seeds by generate_vectors.py. Both normalization signs are covered.\nconst VECTORS: [(u8, [u8; 96], [u8; 32], [u8; 32]); 4] = [\n' + '\n'.join(rows) + '\n];\n')
print('Generated four public key vectors covering both normalization signs.')
