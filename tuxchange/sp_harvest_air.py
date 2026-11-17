#!/usr/bin/env python3
"""Recover CEC messages a console sent us, out of an sp_link run log."""
import re, struct, sys, os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sp_yy, sp_cec, sp_cecvalid
from sp_yysession import MAX_OBJECT, object_length


class _Object:
    """One object's bytes as they arrive, with a record of which bytes actually did."""

    def __init__(self):
        self.buf = bytearray()
        self.ranges = []                  # sorted, merged [start, end)
        self.refused = None

    def add(self, seq, data):
        end = seq + len(data)
        if end > MAX_OBJECT:
            self.refused = 'data at offset %d runs past the %d B object limit' % (seq, MAX_OBJECT)
            return
        if end > len(self.buf):
            self.buf.extend(bytes(end - len(self.buf)))
        self.buf[seq:end] = data
        merged = []
        for lo, hi in sorted(self.ranges + [(seq, end)]):
            if merged and lo <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
            else:
                merged.append((lo, hi))
        self.ranges = merged

    def complete(self):
        """-> the object's exact declared bytes if every one of them arrived, else None."""
        have = self.ranges[0][1] if self.ranges and self.ranges[0][0] == 0 else 0
        n = object_length(self.buf[:have])
        return bytes(self.buf[:n]) if n is not None and have >= n else None


def objects_from_log(path, log=None):
    """Every object the console sent whose bytes all appear in the log, by seq. -> [bytes]"""
    out, cur = [], _Object()
    with open(path, errors='replace') as fh:
        for line in fh:
            m = re.search(r'plaintext: ([0-9a-f]+)', line)
            if not m:
                continue
            y = sp_yy.parse(bytes.fromhex(m.group(1)))
            if not y or not y.get('ok'):
                continue
            f = y['flags']
            if f & sp_yy.SYN and not (f & sp_yy.ACK):
                if log and cur.ranges and not cur.refused:
                    log('  an object was left incomplete (%d B arrived); not recovered'
                        % sum(hi - lo for lo, hi in cur.ranges))
                cur = _Object()
                continue
            pl = y.get('payload') or b''
            if not pl or cur.refused:
                continue
            cur.add(y['seq'], pl)
            if cur.refused:
                if log:
                    log('  refusing an object: %s' % cur.refused)
                continue
            if f & sp_yy.URG:                         # END: a whole object, or a window flush
                obj = cur.complete()
                if obj is not None:
                    out.append(obj)
                    cur = _Object()
    return out


def messages_from_log(path, key_for=None, log=None):
    """Every CEC message in the log, as bare 0x6060 containers. -> [(title, container)]

    Each envelope is split and checked strictly. With `key_for(title) -> key or None`, a
    message whose title key is known must also carry a matching HMAC.
    """
    out = []
    for o in objects_from_log(path, log):
        if o[:2] != sp_cecvalid.ENVELOPE_MAGIC:
            continue
        try:
            found = sp_cecvalid.split_envelope(o)
        except sp_cecvalid.Invalid as e:
            if log:
                log('  skipping a malformed %d B message: %s' % (len(o), e))
            continue
        for c in found:
            tid = sp_cecvalid.parts(c)[2]
            k = key_for(tid) if key_for else None
            if k is not None and not sp_cecvalid.hmac_ok(c, k):
                if log:
                    log('  skipping %08X %s: it fails its title HMAC' % (tid, c[0x20:0x28].hex()))
                continue
            out.append((tid, c))
    return out


def verify(container, key):
    """-> True if `container` is well-formed and its trailer is HMAC-SHA256 over the body."""
    return sp_cecvalid.hmac_status(container, key) == sp_cecvalid.VALID


def _selftest():
    ok = tot = 0

    def chk(n, c, g=''):
        nonlocal ok, tot
        tot += 1; ok += bool(c)
        print('  [%s] %s%s' % ('PASS' if c else 'FAIL', n, ('  %s' % (g,)) if g else ''))

    import tempfile, sp_build, sp_yysession

    def write_log(d, objects):
        """objects: [[(seq, payload, end), ...]] -> a log path, one SYN per object."""
        lines = []
        for segs in objects:
            lines.append('plaintext: ' + sp_yysession.build_yy_frame(sp_yy.SYN, 0, 0).hex())
            for seq, pl, end in segs:
                fl = sp_yy.ACK | (sp_yy.URG if end else 0)
                lines.append('plaintext: ' + sp_yysession.build_yy_frame(fl, seq, 0, pl).hex())
        p = os.path.join(d, 'synthetic_%d.log' % len(os.listdir(d)))
        with open(p, 'w') as fh:
            fh.write('\n'.join(lines) + '\n')
        return p

    def segs(obj):
        return [(seq, pl, bool(fl & sp_yy.URG)) for fl, seq, pl in sp_yysession.segment(obj)]

    key = b'h' * 32
    c1 = sp_build.build_envelope(b'one!' * 64, 0x00030600, key=key, ex_headers=[],
                                 message_id=1)[0x14:]
    c2 = sp_build.build_envelope(b'two!' * 4000, 0x00030600, key=key, ex_headers=[],
                                 message_id=2)[0x14:]
    env = sp_build.envelope([c1, c2])
    with tempfile.TemporaryDirectory() as d:
        got = messages_from_log(write_log(d, [segs(env)]))
        chk('every container in an envelope is recovered, exactly',
            [c for _t, c in got] == [c1, c2], len(got))

        wire = sp_build.as_wire(c1)
        gap = [(0, wire[:0x14 + 0x70], False), (0x14 + 0x70 + 4, wire[0x14 + 0x70 + 4:], True)]
        chk('an object with missing bytes is refused, not zero-filled',
            messages_from_log(write_log(d, [gap])) == [])
        w2 = segs(sp_build.as_wire(c2))
        resent = w2[:1] + w2[2:] + w2[1:]
        chk('a lost segment is recovered once the console retransmits it',
            len(w2) > 2 and [c for _t, c in messages_from_log(write_log(d, [resent]))] == [c2])
        notes = []
        far = [(sp_yysession.MAX_OBJECT, b'x' * 16, True)]
        chk('a segment past the object limit is refused without allocating for it',
            messages_from_log(write_log(d, [far, segs(wire)]), log=notes.append)
            == [(0x00030600, c1)] and any('object limit' in n for n in notes), notes)

        bad = bytearray(wire)
        bad[-0x30] ^= 1
        p = write_log(d, [segs(bytes(bad))])
        chk('a well-formed message with a corrupt body is kept when no key is known',
            len(messages_from_log(p)) == 1)
        chk('and refused when its title key is known',
            messages_from_log(p, key_for={0x00030600: key}.get) == [])

        spin = bytearray(0x14 + 0x70 + 4)
        spin[:2], spin[0x14:0x16] = b'aa', b'``'
        struct.pack_into('<I', spin, 4, len(spin))
        struct.pack_into('<I', spin, 0x10, 100000)
        chk('an envelope whose count cannot fit is refused',
            messages_from_log(write_log(d, [segs(bytes(spin))])) == [])
        hs = bytearray(c1)
        struct.pack_into('<I', hs, 8, 0xFFFFFFF0)
        chk('a container whose header_size is impossible is refused',
            messages_from_log(write_log(d, [segs(sp_build.as_wire(bytes(hs)))])) == [])

    import lp_corpus as corpus
    log = corpus.path('air_log_four_titles')
    if log is None:
        print('  (no captured run log in the corpus; real-capture checks skipped)')
    else:
        msgs = messages_from_log(log)
        by = {t: c for t, c in msgs}
        chk('all three messages the console sent are recovered', len(msgs) == 3, len(msgs))
        chk('Mario Kart 7, Mii Plaza and Super Mario Maker',
            sorted(by) == [0x00020800, 0x00030600, 0x001A0400], ['%08X' % t for t in sorted(by)])
        for t, want in ((0x00030600, 0x377C), (0x00020800, 0x7FC8), (0x001A0400, 0x18D44)):
            if t in by:
                chk('%08X is its declared size' % t, len(by[t]) == want,
                    '%#x vs %#x' % (len(by[t]), want))
        pa = corpus.path('console_nand_3') or corpus.path('console_nand')
        if pa:
            import sp_savefs, sp_cecstore
            fs = sp_savefs.SaveFS(open(pa, 'rb').read())
            keys = {k: v['hmac_key'] for k, v in sp_cecstore.title_metadata(fs).items()}
            for t, c in sorted(by.items()):
                if t in keys:
                    chk('%08X body verifies against its MBoxInfo key' % t, verify(c, keys[t]))
    print('\n%d/%d checks passed' % (ok, tot))
    return 0 if ok == tot else 1


if __name__ == '__main__':
    if len(sys.argv) < 2 or sys.argv[1] == '--selftest':
        sys.exit(_selftest())
    outdir = sys.argv[2] if len(sys.argv) > 2 else 'captured'
    os.makedirs(outdir, exist_ok=True)
    for t, c in messages_from_log(sys.argv[1], log=print):
        h = sp_cec.parse_header(c)
        p = os.path.join(outdir, '%08X_%s.bin' % (t, c[0x20:0x28].hex()))
        open(p, 'wb').write(c)
        print('%-52s total=%#-8x body=%#-8x mode=%d' %
              (p, h['total_size'], h['body_size'], h['send_mode']))
