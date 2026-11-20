#!/usr/bin/env python3
"""StreetPass service records: the titles a console advertises, and how cecd derives them.

A record is `u32be cec_id | u8 flags | args`. The flags' low nibble n is the argument width:
the arguments are three arrays of n bytes (A, B, C), so a record is 5 + 3n bytes. Bits 4-5
carry the send mode the title is advertised with.

cecd builds the list from each mailbox's leading outgoing message (the first in box order
with a non-zero header +0x6C). A type-1 header extension on that message is the record
template, copied whole; without one the record is the bare mailbox id. The effective mode
replaces bits 4-5. The same list goes to discovery and to the in-link 0x11 object.
"""
import struct
from collections import namedtuple

import sp_cec

EXH_SERVICE = 1
MAX_WIDTH = 0x0F
MODE_SHIFT, MODE_MASK = 4, 0x30
TLV_MAX = 0xFF
# One vendor IE (length byte 255) holds the OUI and subtype, the 10-byte token TLV and a
# single service TLV header.
DISCOVERY_BYTES = 0xFF - 4 - 10 - 2
# A receive-only title has no outgoing message to give it a mode. Mode 3 pairs with every
# nonzero mode a sender can use.
RECEIVE_MODE = 3


class Service(namedtuple('Service', 'title flags args')):
    """One service record. Still a (title, flags, args) tuple, as the frame builders take."""
    __slots__ = ()

    @property
    def width(self):
        return self.flags & MAX_WIDTH

    @property
    def mode(self):
        return (self.flags & MODE_MASK) >> MODE_SHIFT

    @property
    def size(self):
        return record_len(self.flags)

    def with_mode(self, mode):
        return self._replace(flags=(self.flags & ~MODE_MASK & 0xFF) | ((mode & 3) << MODE_SHIFT))

    def raw(self):
        return struct.pack('>IB', self.title, self.flags) + bytes(self.args)

    def describe(self):
        return {'titleID': '%08x' % self.title, 'flags': hex(self.flags), 'args': self.args.hex()}

    def __str__(self):
        return '%08X/%#04x%s' % (self.title, self.flags, ('/' + self.args.hex()) if self.args else '')


def record_len(flags):
    return 5 + 3 * (flags & MAX_WIDTH)


def check(svc):
    """-> a Service, or ValueError if its arguments do not match the width its flags give."""
    t, f, a = svc
    a = bytes(a)
    if not (0 < t <= 0xFFFFFFFF):
        raise ValueError('bad CEC title id %#x' % t)
    if not (0 <= f <= 0xFF):
        raise ValueError('service flags are one byte, got %#x' % f)
    if len(a) != 3 * (f & MAX_WIDTH):
        raise ValueError('%08X flags %#04x need %d argument bytes, got %d'
                         % (t, f, 3 * (f & MAX_WIDTH), len(a)))
    return Service(t, f, a)


def from_raw(raw):
    """One encoded record -> Service. The whole of `raw` must be exactly one record."""
    raw = bytes(raw)
    if len(raw) < 5 or len(raw) != record_len(raw[4]):
        raise ValueError('a record with flags %s is %s bytes, got %d'
                         % ('%#04x' % raw[4] if len(raw) > 4 else '?',
                            record_len(raw[4]) if len(raw) > 4 else '5+', len(raw)))
    return check((struct.unpack_from('>I', raw)[0], raw[4], raw[5:]))


def encode(services):
    return b''.join(check(s).raw() for s in services)


def decode(data):
    """-> ([Service], problem or None). Stops at a record the data cannot hold."""
    out, i, data = [], 0, bytes(data)
    while i < len(data):
        if i + 5 > len(data):
            return out, 'truncated record header at +%d (%d bytes left)' % (i, len(data) - i)
        n = record_len(data[i + 4])
        if i + n > len(data):
            return out, ('truncated %08X at +%d: flags %#04x need %d bytes, %d left'
                         % (struct.unpack_from('>I', data, i)[0], i, data[i + 4], n,
                            len(data) - i))
        t = struct.unpack_from('>I', data, i)[0]
        out.append(Service(t, data[i + 4], data[i + 5:i + n]))
        i += n
    return out, None


def tlv_header(a, b, length):
    return struct.pack('<H', (length << 8) | (b << 4) | a)


def tlvs(services, a=1, b=1):
    """Service records as TLVs, starting another of the same type before one would pass 255
    bytes. A record is never split across two."""
    out, cur = b'', b''
    for s in services:
        r = check(s).raw()
        if cur and len(cur) + len(r) > TLV_MAX:
            out += tlv_header(a, b, len(cur)) + cur
            cur = b''
        cur += r
    return out + tlv_header(a, b, len(cur)) + cur


def fit(services, budget):
    """-> (kept, dropped): the records, in order, whose encoding fits in `budget` bytes."""
    kept, dropped, used = [], [], 0
    for s in services:
        s = check(s)
        if used + s.size <= budget:
            kept.append(s)
            used += s.size
        else:
            dropped.append(s)
    return kept, dropped


def from_parsed(peer_services):
    """sp_parse's dicts (or Services) -> [Service], skipping anything malformed."""
    out = []
    for s in peer_services or []:
        try:
            if isinstance(s, dict):
                s = (int(s['titleID'], 16), int(s['flags'], 16) if isinstance(s['flags'], str)
                     else s['flags'], bytes.fromhex(s.get('args', '')))
            out.append(check(s))
        except (KeyError, ValueError, TypeError):
            continue
    return out


def modes_match(a, b):
    """cecd's mode check: 0 pairs only with 0, 1 with 2, and 3 with any nonzero mode."""
    if a == 0 or b == 0:
        return a == b
    return a == 3 or b == 3 or {a, b} == {1, 2}


def why_unmatched(local, peer):
    """-> None if cecd would pair these two records, else why not."""
    if local.title != peer.title:
        return 'different titles'
    if local.width != peer.width:
        return 'argument widths %d and %d differ' % (local.width, peer.width)
    if not modes_match(local.mode, peer.mode):
        return 'modes %d and %d do not pair' % (local.mode, peer.mode)
    n = local.width
    la, lb, lc = local.args[:n], local.args[n:2 * n], local.args[2 * n:]
    pa, pb, pc = peer.args[:n], peer.args[n:2 * n], peer.args[2 * n:]
    for i in range(n):
        if la[i] & lc[i] != la[i] & pb[i]:
            return 'the peer\'s arguments fail our mask at byte %d' % i
        if pa[i] & pc[i] != pa[i] & lb[i]:
            return 'our arguments fail the peer\'s mask at byte %d' % i
    return None


def matches(local, peer):
    return why_unmatched(local, peer) is None


def exheaders(container):
    """-> [(type, payload)] from a bare container's extension table, stopping at a malformed
    entry."""
    out = []
    try:
        hs = struct.unpack_from('<I', container, 0x08)[0]
    except struct.error:
        return out
    end, p = min(hs, len(container)), sp_cec.HDR_LEN
    while p + 8 <= end and len(out) < 16:
        t, sz = struct.unpack_from('<II', container, p)
        if t == 0 or p + 8 + sz > end:
            break
        out.append((t, bytes(container[p + 8:p + 8 + sz])))
        p += 8 + ((sz + 3) & ~3)
    return out


def template(container):
    """-> (template Service or None, problem or None) from the type-1 extension."""
    tid = struct.unpack_from('<I', container, 0x10)[0]
    for t, payload in exheaders(container):
        if t != EXH_SERVICE or not payload:
            continue
        try:
            s = from_raw(payload)
        except ValueError as e:
            return None, 'its service extension is malformed (%s)' % e
        if s.title != tid:
            return None, 'its service extension names %08X' % s.title
        return s, None
    return None, None


def leading(containers):
    """The message cecd takes a mailbox's metadata from: the first with a non-zero +0x6C."""
    return next((c for c in containers if c[0x6C]), None)


def has_room(room):
    free_bytes, free_slots = room
    return free_bytes > 0 and free_slots > 0


def effective_mode(mode, room=None):
    """-> the mode cecd advertises for an outgoing `mode` given the inbox room, or None when
    it skips the title. Modes 0 and 1 need room; mode 3 drops to 2 without it."""
    if room is None or has_room(room):
        return mode & 3
    if mode in (0, 1):
        return None
    return 2


def record_for(container, mode=None):
    """-> (Service, problem or None) for one message, at `mode` or its header's own."""
    tid = struct.unpack_from('<I', container, 0x10)[0]
    mode = container[0x35] if mode is None else mode
    tmpl, why = template(container)
    return (tmpl or Service(tid, 0, b'')).with_mode(mode), why


def box_order(c):
    # The store keeps no OBIndex, so creation order stands in for the console's append order.
    return (sp_cec.parse_header(c)['created']['text'], c[0x20:0x28])


def for_messages(containers, mode=None):
    """Messages about to be forwarded -> [(Service, problem)] in first-seen title order."""
    by_title = {}
    for c in containers:
        by_title.setdefault(struct.unpack_from('<I', c, 0x10)[0], []).append(c)
    return [record_for(leading(cs) or cs[0], mode) for cs in by_title.values()]


Derived = namedtuple('Derived', 'service source note')


def derive(store, servable=None):
    """-> {title: Derived} for everything this store advertises, in mailbox order.

    `source` is 'outbox' when a leading outgoing message supplies the record, 'receive' for
    a title enabled to receive without one. A title that advertises nothing is absent.
    `servable(tid, container)` limits which outgoing messages count.
    """
    receiving = set(store.receive_titles())
    out = {}
    for tid in store.titles():
        room = store.inbox_room(tid)
        held = sorted((c for _t, _b, c in store.messages(tid, 'outbox')
                       if servable is None or servable(tid, c)), key=box_order)
        lead = leading(held)
        if lead is not None:
            mode = effective_mode(lead[0x35], room)
            if mode is not None:
                s, why = record_for(lead, mode)
                note = 'from %s' % lead[0x20:0x28].hex()
                if mode != lead[0x35] & 3:
                    note += ', mode %d as %d: inbox full' % (lead[0x35], mode)
                out[tid] = Derived(s, 'outbox', note + ('; ' + why if why else ''))
                continue
        if tid in receiving and has_room(room):
            s, note = receive_record(store, tid)
            out[tid] = Derived(s, 'receive', note)
    return out


def receive_record(store, tid):
    """-> (Service, note) for a title that receives with nothing of its own to send.

    A record set for the title in the store is used as it is. Otherwise the newest held
    message of the title with a service extension lends its arguments, at RECEIVE_MODE.
    """
    explicit = store.service_template(tid)
    if explicit is not None:
        return explicit, 'set for this title'
    for _t, _b, c in sorted(store.messages(tid), key=lambda r: box_order(r[2]), reverse=True):
        tmpl, _why = template(c)
        if tmpl is not None:
            return tmpl.with_mode(RECEIVE_MODE), 'arguments from %s' % c[0x20:0x28].hex()
    return Service(tid, 0, b'').with_mode(RECEIVE_MODE), 'no arguments known'


def parse_record_arg(text):
    """A record typed as hex (`00020500 32 ffffffffffff`, spaces optional) -> Service."""
    return from_raw(bytes.fromhex(''.join(str(text).split())))


# The 12 records a console advertised, as captured in its discovery frames and rebuilt from
# the same console's SAVE image.
CAPTURED_RECORDS = {
    (0x00141000, 0x30, b''), (0x0007AD00, 0x30, b''), (0x00051600, 0x10, b''),
    (0x0008C500, 0x30, b''), (0x0012EC00, 0x30, b''), (0x00030B00, 0x30, b''),
    (0x00020500, 0x32, b'\xff' * 6), (0x0007C800, 0x30, b''), (0x00053F00, 0x30, b''),
    (0x00030600, 0x30, b''), (0x001A0400, 0x10, b''), (0x00020800, 0x00, b''),
}
CAPTURED_MODES = {
    0x00141000: 3, 0x0007AD00: 3, 0x00051600: 1, 0x0008C500: 3, 0x0012EC00: 3, 0x00030B00: 3,
    0x00020500: 3, 0x0007C800: 3, 0x00053F00: 3, 0x00030600: 3, 0x001A0400: 1, 0x00020800: 0,
}
SIX_ARGS = bytes.fromhex('0002050032ffffffffffff')


def _selftest():
    import os, shutil, tempfile, time
    import sp_build, sp_parse, sp_probe_tx, sp_store, sp_link
    ok = tot = 0

    def chk(name, cond, got=''):
        nonlocal ok, tot
        tot += 1; ok += bool(cond)
        print('  [%s] %s%s' % ('PASS' if cond else 'FAIL', name, ('  %r' % (got,)) if got != '' else ''))

    def raises(fn):
        try:
            fn()
        except ValueError:
            return True
        return False

    def syn(t, n, mode=3, fill=0x5A):
        return Service(t, (mode << 4) | n, bytes([fill]) * (3 * n))

    print('codec')
    for n in range(MAX_WIDTH + 1):
        s = syn(0x00123400, n)
        got, why = decode(encode([s, Service(0x00020800, 0, b'')]))
        if not (why is None and got == [s, Service(0x00020800, 0, b'')]):
            break
    chk('records of every width 0-15 round-trip and keep the next one aligned',
        why is None and n == MAX_WIDTH, (n, got, why))
    chk('a six-byte record is width 2: 5 + 3 * 2 bytes',
        from_raw(SIX_ARGS) == (0x00020500, 0x32, b'\xff' * 6) and from_raw(SIX_ARGS).size == 11)
    chk('bits 4-5 change the mode and keep the rest',
        from_raw(SIX_ARGS).with_mode(1) == (0x00020500, 0x12, b'\xff' * 6)
        and Service(1 << 8, 0xC5, b'\0' * 15).with_mode(2).flags == 0xE5)
    chk('arguments that do not match the width are refused',
        raises(lambda: encode([(0x00020500, 0x32, b'\xff' * 5)]))
        and raises(lambda: encode([(0x00020500, 0x30, b'\xff')])))
    chk('a title id of 0 or over 32 bits is refused',
        raises(lambda: check((0, 0x30, b''))) and raises(lambda: check((1 << 32, 0x30, b''))))
    good = encode([(0x00030600, 0x30, b''), from_raw(SIX_ARGS)])
    got, why = decode(good[:-1])
    chk('a record cut short is dropped and reported', got == [(0x00030600, 0x30, b'')]
        and why and 'truncated 00020500' in why, why)
    got, why = decode(good + b'\x00\x01\x02')
    chk('a stray tail shorter than a record header is reported', len(got) == 2 and why, why)
    chk('from_raw wants exactly one record',
        raises(lambda: from_raw(SIX_ARGS + b'\0')) and raises(lambda: from_raw(b'\0\0\0')))
    chk('peer dicts without flags, or with bad arguments, are skipped',
        from_parsed([{'titleID': '00020800'}, {'titleID': '00020500', 'flags': '0x32',
                                                'args': 'ff'},
                     from_raw(SIX_ARGS).describe()]) == [from_raw(SIX_ARGS)])

    print('framing')
    many = [syn(0x00100000 + (i << 8), 4) for i in range(30)]
    body = tlvs(many)
    recs, rest = sp_parse.parse_vendor_tlv(body)
    chk('a long list goes in several service TLVs of at most 255 bytes, whole records each',
        len(recs) > 1 and not rest and all(r['len'] <= TLV_MAX and r['len'] % 17 == 0
                                           for r in recs), [r['len'] for r in recs])
    got, why = sp_parse.services_from_tlvs(recs)
    chk('and every TLV is read back, in order', from_parsed(got) == many and why is None)
    obj = sp_link.build_obj_11(b'\x07' * 8, many)
    recs, rest = sp_parse.parse_vendor_tlv(obj[0x10:])
    chk('the in-link 0x11 object carries the whole list, then the token',
        from_parsed(sp_parse.services_from_tlvs(recs)[0]) == many and not rest
        and (recs[-1]['a'], recs[-1]['b'], recs[-1]['data']) == (0, 0xF, b'\x07' * 8))
    probe = sp_parse.build_probe(b'\x02' * 6, b'\x07' * 8, many)
    inf = sp_probe_tx.probe_info(probe)
    kept, dropped = fit(many, DISCOVERY_BYTES)
    ie = next(v for v in inf['vendor'] if v[:3] == sp_parse.NIN_OUI)
    chk('a probe carries the records that fit in one vendor IE, and still its token',
        from_parsed(inf['services']) == kept and dropped and len(ie) <= 0xFF
        and inf['token'] == '07' * 8, (len(kept), len(dropped), len(ie)))
    edge = ([syn(0x00200000 + (i << 8), 0) for i in range(43)]
            + [syn(0x00300000 + (i << 8), 1) for i in range(3)])
    edge_ie = next(v for v in sp_probe_tx.probe_info(
        sp_parse.build_probe(b'\x02' * 6, b'\x07' * 8, edge))['vendor']
        if v[:3] == sp_parse.NIN_OUI)
    chk('a list of exactly 239 bytes fills the vendor IE to 255 and fits whole',
        len(encode(edge)) == DISCOVERY_BYTES and fit(edge, DISCOVERY_BYTES)[1] == []
        and len(edge_ie) == 0xFF, len(edge_ie))
    chk('one more byte of records and the last record is left out',
        fit(edge + [syn(0x00400000, 0)], DISCOVERY_BYTES)[1] == [syn(0x00400000, 0)])
    bad = sp_parse.NIN_OUI + b'\x01' + tlv_header(1, 1, 8) + SIX_ARGS[:8]
    out = sp_parse.parse_vendor_ie(bad)
    chk('a vendor IE with a truncated record reports it', out.get('services') == []
        and 'services_problem' in out, out)

    print('matching')
    ev = from_raw(SIX_ARGS)
    chk('two six-byte all-ones records pair', matches(ev, ev))
    chk('zero arguments against all-ones do not pair',
        why_unmatched(ev._replace(args=b'\0' * 6), ev) is not None)
    chk('the widths must agree', not matches(Service(0x00020500, 0x30, b''), ev))
    pairs = {(a, b) for a in range(4) for b in range(4) if modes_match(a, b)}
    chk('modes pair as 0/0, 1/2, and 3 with any nonzero',
        pairs == {(0, 0), (1, 2), (2, 1), (1, 3), (3, 1), (2, 3), (3, 2), (3, 3)}, sorted(pairs))
    a = Service(0x00010000, 0x31, bytes([0x0F, 0xFF, 0x03]))
    b = Service(0x00010000, 0x31, bytes([0x00, 0x03, 0x00]))
    chk('each side masks the other\'s B with its own A and C',
        matches(a, b) and not matches(a, b._replace(args=bytes([0, 0x01, 0]))))

    tmp = tempfile.mkdtemp()
    try:
        key = b'k' * 32

        def msg(t, mode, mid, ex=None, count=0xFF, when=None):
            w = sp_build.build_envelope(bytes(0x40), t, key=key, message_id=mid, send_mode=mode,
                                        ex_headers=ex or [], when=when)
            c = bytearray(sp_build.unwrap(w)[0])
            c[0x6C] = count
            return bytes(c)

        print('derivation')
        st = sp_store.Store(os.path.join(tmp, 'captured'))
        base = time.mktime((2024, 1, 1, 0, 0, 0, 0, 0, -1))
        for i, (t, m) in enumerate(CAPTURED_MODES.items()):
            st.add_title(t, hmac_key=key)
            ex = [(EXH_SERVICE, SIX_ARGS)] if t == 0x00020500 else None
            st.add_message(msg(t, m, 0x100 + i, ex, when=time.gmtime(base + i)), 'outbox')
        got = derive(st)
        chk('that console\'s outbox derives its 12 captured records',
            {tuple(d.service) for d in got.values()} == CAPTURED_RECORDS,
            sorted(map(str, (d.service for d in got.values()))))
        chk('the six-byte record comes from the message\'s own extension',
            got[0x00020500].service == ev and got[0x00020500].source == 'outbox')
        chk('and a probe of them parses back to the same set',
            {tuple(s) for s in from_parsed(sp_probe_tx.probe_info(sp_parse.build_probe(
                b'\x02' * 6, b'\x07' * 8, [d.service for d in got.values()]))['services'])}
            == CAPTURED_RECORDS)

        T = 0x00051600
        st2 = sp_store.Store(os.path.join(tmp, 'modes'))
        st2.add_title(T, hmac_key=key)
        st2.add_message(msg(T, 1, 1, when=time.gmtime(base)), 'outbox')
        chk('a mode-1 message advertises 0x10', derive(st2)[T].service.flags == 0x10)
        st2.add_message(msg(T, 3, 2, when=time.gmtime(base + 60)), 'outbox')
        chk('with modes 1 and 3 queued, the older message leads the mixed queue',
            derive(st2)[T].service.flags == 0x10)
        st2.clear_box('outbox')
        st2.add_message(msg(T, 1, 3, count=0, when=time.gmtime(base)), 'outbox')
        st2.add_message(msg(T, 3, 4, when=time.gmtime(base + 60)), 'outbox')
        chk('a message with a zero +0x6C cannot lead, so the mode-3 one does',
            derive(st2)[T].service.flags == 0x30)
        chk('a title whose messages all have a zero +0x6C advertises nothing',
            T not in derive(st2, lambda t, c: c[0x6C] == 0))

        full = os.path.join(tmp, 'full')
        st3 = sp_store.Store(full)
        st3.add_title(0x00020500, hmac_key=key)
        st3.add_title(0x00020800, hmac_key=key)
        st3.add_message(msg(0x00020500, 3, 9, [(EXH_SERVICE, SIX_ARGS)]), 'outbox')
        st3.add_message(msg(0x00020800, 0, 10), 'outbox')
        room = [(1, 1)]
        st3.inbox_room = lambda t: room[0]
        chk('with inbox room, mode 3 and mode 0 advertise as themselves',
            [d.service.flags for d in derive(st3).values()] == [0x32, 0x00])
        room[0] = (0, 5)
        got = derive(st3)
        chk('a full inbox advertises mode 3 as 2, keeping its arguments, and drops mode 0',
            list(got) == [0x00020500] and got[0x00020500].service == ev.with_mode(2)
            and 'inbox full' in got[0x00020500].note, got)
        room[0] = (5, 0)
        chk('a full inbox counts slots as well as bytes', list(derive(st3)) == [0x00020500])
        chk('effective modes: 0 and 1 need room, 2 does not',
            [effective_mode(m, (0, 0)) for m in range(4)] == [None, None, 2, 2]
            and [effective_mode(m, (1, 1)) for m in range(4)] == [0, 1, 2, 3])

        st4 = sp_store.Store(os.path.join(tmp, 'bad'))
        st4.add_title(0x00030600, hmac_key=key)
        st4.add_message(msg(0x00030600, 3, 11, [(EXH_SERVICE, SIX_ARGS)]), 'outbox')
        d = derive(st4)[0x00030600]
        chk('an extension naming another title falls back to the mailbox id',
            d.service == (0x00030600, 0x30, b'') and 'names 00020500' in d.note, d)
        st4.clear_box('outbox')
        st4.add_message(msg(0x00030600, 3, 12, [(EXH_SERVICE, SIX_ARGS[:4].replace(
            b'\x00\x02\x05', b'\x00\x03\x06') + b'\x31\xff')]), 'outbox')
        d = derive(st4)[0x00030600]
        chk('and so does one whose length disagrees with its width',
            d.service == (0x00030600, 0x30, b'') and 'malformed' in d.note, d)

        print('receive-only')
        st5 = sp_store.Store(os.path.join(tmp, 'rx'))
        st5.add_title(0x00020500, hmac_key=key)
        chk('a registered title that does not receive advertises nothing', derive(st5) == {})
        st5.set_receive(0x00020500)
        d = derive(st5)[0x00020500]
        chk('enabled with nothing known, it is the bare mailbox id at mode 3',
            d.service == (0x00020500, 0x30, b'') and d.source == 'receive')
        st5.add_message(msg(0x00020500, 3, 13, [(EXH_SERVICE, SIX_ARGS)]), 'inbox')
        d = derive(st5)[0x00020500]
        chk('a held message of the title lends its arguments', d.service == ev, d)
        rec = Service(0x00020500, 0x31, b'\x01\x02\x03')
        st5.set_service_template(0x00020500, rec)
        chk('a record set for the title wins, as it is',
            derive(st5)[0x00020500].service == rec
            and sp_store.Store(os.path.join(tmp, 'rx')).service_template(0x00020500) == rec)
        chk('a record for another title, or a malformed one, is refused',
            raises(lambda: st5.set_service_template(0x00020500, SIX_ARGS.replace(
                b'\x05', b'\x06', 1)))
            and raises(lambda: st5.set_service_template(0x00020500, SIX_ARGS[:-1])))
        st5.set_service_template(0x00020500, None)
        chk('and clearing it derives the record again', derive(st5)[0x00020500].service == ev)
        st5.inbox_room = lambda t: (0, 0)
        chk('a receive-only title with a full inbox advertises nothing', derive(st5) == {})
        st5.remove_title(0x00020500)
        chk('removing the title forgets its record',
            '00020500' not in st5._load_meta()['service_records'])

        print('forwarding')
        fw = [msg(0x00020500, 3, 20, [(EXH_SERVICE, SIX_ARGS)]), msg(0x00020800, 0, 21),
              msg(0x00020500, 1, 22)]
        chk('forwarded messages derive one record per title from the first that leads',
            [s for s, _w in for_messages(fw)] == [ev, (0x00020800, 0x00, b'')])
        chk('and a --send-mode override sets the advertised mode too',
            [s.mode for s, _w in for_messages(fw, mode=2)] == [2, 2])

        import lp_corpus as corpus
        img = corpus.path('console_nand_3')
        if img is None:
            print('  [SKIP] the console SAVE image derives its captured records: %s'
                  % corpus.why_skipped())
        else:
            import sp_relay
            sx = sp_store.Store(os.path.join(tmp, 'save'))
            sp_relay.import_into(sx, img, log=lambda *_: None)
            got = {tuple(d.service) for d in derive(sx).values()}
            chk('the console SAVE image derives its captured records', got == CAPTURED_RECORDS,
                sorted(got ^ CAPTURED_RECORDS))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print('\n%d/%d checks passed' % (ok, tot))
    return 0 if ok == tot else 1


if __name__ == '__main__':
    import sys
    sys.exit(_selftest() if '--selftest' in sys.argv[1:] else 2)
