#!/usr/bin/env python3
"""Strict, bounded validation of CEC containers and 0x6161 envelopes.

Everything that stores, sends, hands to a plugin, or exports a message goes through here.
The permissive parsers in sp_cec (parse_message, parse_stream, find_container_offsets) are
for diagnostics and carving only: they describe what they find and never vouch for it.
"""
import hashlib
import hmac
import struct

ENVELOPE_LEN = 0x14
HDR_LEN = 0x70
TRAILER_LEN = 0x20
MAX_BODY = 0x18000
MAX_TOTAL = 0x19000
MAX_EXHEADERS = 16
MIN_TOTAL = HDR_LEN + 4 + TRAILER_LEN
MAX_ENVELOPE = 1 << 20
MAX_CONTAINERS = 64

CONTAINER_MAGIC = b'\x60\x60'
ENVELOPE_MAGIC = b'\x61\x61'

VALID, INVALID, UNVERIFIED = 'valid', 'invalid', 'unverified'


class Invalid(ValueError):
    """A message that is not a whole, well-formed CEC container or envelope."""


def _u32(b, o):
    return struct.unpack_from('<I', b, o)[0]


def problems(buf, exact=True):
    """-> [str]: every way `buf` fails to be one whole, well-formed container. Never raises.

    With exact=False, bytes past the declared total are allowed (and ignored).
    """
    buf = memoryview(buf)
    if len(buf) < HDR_LEN:
        return ['%d B is shorter than the %#x-byte header' % (len(buf), HDR_LEN)]
    if bytes(buf[:2]) != CONTAINER_MAGIC:
        return ['no 6060 container magic']
    out = []
    total, hsize, bsize, tid = struct.unpack_from('<IIII', buf, 0x04)
    if not (MIN_TOTAL <= total <= MAX_TOTAL):
        out.append('total_size %#x outside [%#x, %#x]' % (total, MIN_TOTAL, MAX_TOTAL))
    if exact and len(buf) != total:
        out.append('%d B present, header declares total_size %d' % (len(buf), total))
    elif len(buf) < total:
        out.append('truncated: %d B present of a declared %d' % (len(buf), total))
    if not (0 < bsize <= MAX_BODY) or bsize & 3:
        out.append('body_size %#x is not 4-byte aligned in (0, %#x]' % (bsize, MAX_BODY))
    if hsize < HDR_LEN or hsize & 3:
        out.append('header_size %#x is not 4-byte aligned and >= %#x' % (hsize, HDR_LEN))
    if hsize + bsize + TRAILER_LEN != total:
        out.append('header_size %#x + body_size %#x + %#x trailer != total_size %#x'
                   % (hsize, bsize, TRAILER_LEN, total))
    if tid == 0:
        out.append('cec_title_id is 0')
    if buf[0x35] >= 4:
        out.append('send mode (header+0x35) = %d must be < 4' % buf[0x35])
    if buf[0x6D] > 1 and buf[0x6C] > 1:
        out.append('header+0x6D and +0x6C are both > 1')
    if not out:
        out.extend(_exheader_problems(buf, hsize))
    return out


def _exheader_problems(buf, hsize):
    p, n = HDR_LEN, 0
    while p < hsize:
        if p + 8 > hsize:
            return ['ex-header table overruns header_size %#x at %#x' % (hsize, p)]
        t, sz = struct.unpack_from('<II', buf, p)
        if t == 0:
            return ['ex-header %d has type 0 before header_size %#x' % (n, hsize)]
        n += 1
        if n > MAX_EXHEADERS:
            return ['more than %d ex-headers' % MAX_EXHEADERS]
        p += 8 + ((sz + 3) & ~3)
    if p != hsize:
        return ['ex-header table ends at %#x, header_size says %#x' % (p, hsize)]
    return []


def check_container(buf, exact=True):
    """-> the container's bytes (trimmed to its total when exact=False); raises Invalid."""
    bad = problems(buf, exact)
    if bad:
        raise Invalid('malformed CEC message: %s' % '; '.join(bad))
    return bytes(buf[:_u32(buf, 0x04)])


def parts(container):
    """A checked container -> (header_size, body_size, title, body, trailer)."""
    total, hsize, bsize, tid = struct.unpack_from('<IIII', container, 0x04)
    return (hsize, bsize, tid, bytes(container[hsize:hsize + bsize]),
            bytes(container[hsize + bsize:total]))


def hmac_ok(container, key):
    """Is the trailer HMAC-SHA256 over the body under `key`? Assumes a checked container."""
    _hs, _bs, _t, body, tag = parts(container)
    return len(tag) == TRAILER_LEN and hmac.compare_digest(
        hmac.new(bytes(key), body, hashlib.sha256).digest(), tag)


def hmac_status(container, key):
    """-> VALID, INVALID (structure or HMAC), or UNVERIFIED (well-formed, but no key)."""
    if problems(container):
        return INVALID
    if key is None:
        return UNVERIFIED
    return VALID if hmac_ok(container, key) else INVALID


def split_envelope(obj, max_containers=MAX_CONTAINERS, max_bytes=MAX_ENVELOPE):
    """A 0x6161 envelope -> [checked container bytes]. Raises Invalid.

    The count, every size and the overall length are checked against what is actually
    there before anything is sliced, and the walk must end exactly at the declared total.
    """
    obj = bytes(obj)
    if len(obj) > max_bytes:
        raise Invalid('envelope is %d B, over the %d B limit' % (len(obj), max_bytes))
    if len(obj) < ENVELOPE_LEN + MIN_TOTAL or obj[:2] != ENVELOPE_MAGIC:
        raise Invalid('not a CEC envelope')
    total, tid, _x0c, count = struct.unpack_from('<IIII', obj, 0x04)
    if total != len(obj):
        raise Invalid('%d B present, envelope declares %d' % (len(obj), total))
    if not 1 <= count <= max_containers:
        raise Invalid('envelope declares %d containers; 1..%d allowed' % (count, max_containers))
    if count > (total - ENVELOPE_LEN) // MIN_TOTAL:
        raise Invalid('envelope declares %d containers in %d B' % (count, total))
    out, off = [], ENVELOPE_LEN
    for i in range(count):
        if off + HDR_LEN > total:
            raise Invalid('envelope declares %d containers, ran out after %d' % (count, i))
        size = _u32(obj, off + 0x04)
        if size < MIN_TOTAL or off + size > total:
            raise Invalid('container %d declares %d B with %d left' % (i, size, total - off))
        c = check_container(obj[off:off + size])
        if _u32(c, 0x10) != tid:
            raise Invalid('container %d is title %08X in an envelope for %08X'
                          % (i, _u32(c, 0x10), tid))
        out.append(c)
        off += size
    if off != total:
        raise Invalid('%d B left over after %d containers' % (total - off, count))
    return out


def containers(message, max_containers=MAX_CONTAINERS):
    """A bare container or an envelope -> [checked container bytes]. Raises Invalid."""
    if bytes(message[:2]) == ENVELOPE_MAGIC:
        return split_envelope(message, max_containers)
    if bytes(message[:2]) == CONTAINER_MAGIC:
        return [check_container(message)]
    raise Invalid('not a CEC message (no 6060 or 6161 magic)')


def _selftest():
    import os, sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import sp_build
    ok = tot = 0

    def chk(n, c, g=''):
        nonlocal ok, tot
        tot += 1; ok += bool(c)
        print('  [%s] %s%s' % ('PASS' if c else 'FAIL', n, ('  %s' % (g,)) if g else ''))

    def raises(fn):
        try:
            fn(); return False
        except Invalid:
            return True

    key = b'v' * 32
    wire = sp_build.build_envelope(b'body' * 64, 0x00030600, key=key, message_id=1,
                                   ex_headers=[(4, b'Hi\x00\x00'), (9, b'abcde')])
    c = wire[ENVELOPE_LEN:]
    chk('a built message is well-formed', problems(c) == [], problems(c))
    chk('and authentic under its key', hmac_status(c, key) == VALID)
    chk('but not under another', hmac_status(c, b'w' * 32) == INVALID)
    chk('and unverified without one', hmac_status(c, None) == UNVERIFIED)

    def bad(off, fmt, value):
        b = bytearray(c)
        struct.pack_into(fmt, b, off, value)
        return bytes(b)

    for name, b in (('header_size 0xFFFFFFF0', bad(0x08, '<I', 0xFFFFFFF0)),
                    ('header_size short by 4', bad(0x08, '<I', _u32(c, 8) - 4)),
                    ('header_size below 0x70', bad(0x08, '<I', 0x6C)),
                    ('body_size 0', bad(0x0C, '<I', 0)),
                    ('body_size unaligned', bad(0x0C, '<I', _u32(c, 0x0C) + 1)),
                    ('total_size over 0x19000', bad(0x04, '<I', MAX_TOTAL + 4)),
                    ('title 0', bad(0x10, '<I', 0)),
                    ('send mode 4', bad(0x35, '<B', 4)),
                    ('an ex-header overrunning the table', bad(HDR_LEN + 4, '<I', 0x1000)),
                    ('an ex-header of type 0', bad(HDR_LEN, '<I', 0)),
                    ('a short container', c[:-4]),
                    ('trailing bytes', c + bytes(4)),
                    ('no magic', b'\x00\x00' + c[2:])):
        chk('refused: %s' % name, problems(b) and raises(lambda: check_container(b)))
    chk('trailing bytes are allowed only when asked',
        check_container(c + bytes(4), exact=False) == c)

    c2 = sp_build.build_envelope(b'two!' * 8, 0x00030600, key=key, ex_headers=[],
                                 message_id=2)[ENVELOPE_LEN:]
    env = sp_build.envelope([c, c2])
    chk('an envelope splits into its containers', split_envelope(env) == [c, c2])
    chk('containers() takes a bare container too', containers(c) == [c])

    def benv(off, fmt, value, src=env):
        b = bytearray(src)
        struct.pack_into(fmt, b, off, value)
        return bytes(b)

    for name, b in (('count 0', benv(0x10, '<I', 0)),
                    ('count 3 for 2', benv(0x10, '<I', 3)),
                    ('count 1 for 2', benv(0x10, '<I', 1)),
                    ('count 0xFFFFFFFF', benv(0x10, '<I', 0xFFFFFFFF)),
                    ('a total that disagrees with its length', benv(0x04, '<I', len(env) + 4)),
                    ('a container of another title', benv(0x08, '<I', 0x00020800)),
                    ('a container size of 0', benv(ENVELOPE_LEN + 4, '<I', 0)),
                    ('a container running past the end', benv(ENVELOPE_LEN + 4, '<I', len(env))),
                    ('a truncated envelope', env[:-1]),
                    ('more than the byte budget', None)):
        if b is None:
            chk('refused: %s' % name, raises(lambda: split_envelope(env, max_bytes=len(env) - 1)))
        else:
            chk('refused: %s' % name, raises(lambda: split_envelope(b)))
    chk('refused: more containers than allowed',
        raises(lambda: split_envelope(env, max_containers=1)))

    import lp_corpus as corpus
    images = [p for p in map(corpus.path, ('console_nand', 'console_nand_2', 'console_nand_3')) if p]
    if not images:
        print('  (no console save image in the corpus; real-message checks skipped)')
    for pa in images:
        import sp_savefs, sp_cecstore
        fs = sp_savefs.SaveFS(open(pa, 'rb').read())
        keys = {t: m['hmac_key'] for t, m in sp_cecstore.title_metadata(fs).items()}
        msgs = [(f['path'], fs.read(f)) for f in fs.files() if f['name'].startswith('_')]
        bad_ = [p for p, m in msgs if problems(m)]
        chk('every message in %s is well-formed (%d)' % (os.path.basename(pa), len(msgs)),
            msgs and not bad_, bad_[:3])
        unauth = [p for p, m in msgs
                  if hmac_status(m, keys.get(_u32(m, 0x10))) == INVALID]
        chk('and none fails its title key', not unauth, unauth[:3])
    print('\n%d/%d checks passed' % (ok, tot))
    return 0 if ok == tot else 1


if __name__ == '__main__':
    import sys
    sys.exit(_selftest())
