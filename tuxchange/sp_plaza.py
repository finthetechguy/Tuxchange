#!/usr/bin/env python3
"""StreetPass Mii Plaza message bodies as editable values, in both directions.

The schema (FIELDS) covers most known fields, for the
expansion build's 0x7280-byte body. The Mii's appearance, the unknown fields and the
padding are not exposed. They come from the Mii data (`mii.mii_data`) and from the
original body (`original`), so editing a received or imported message changes only
what was edited.

This is core code: the built-in miiplaza plugin wraps it, and the daemon's `seed`
command uses it directly, so the daemon never has to load a plugin.
"""
import os, sys, struct

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sp_plugin as P, sp_build, sp_mii, sp_smdh

TITLE_ID = sp_build.PLAZA_TITLE
GAME = 'StreetPass Mii Plaza'
BODY_LEN = sp_build.BODY_LEN            # the expansion build; the base build's 0x60F0 is not supported

# Region A: the featured title.
OFF_TITLE_ID, OFF_LOCKOUT, OFF_RATINGS = 0x0000, 0x0010, 0x0014
OFF_NAMES, NAME_STRIDE = 0x0030, 0x200
SHORT_MAX, LONG_MAX, PUB_MAX = 63, 127, 63          # UTF-16 units, leaving the terminator
OFF_ICON_TYPE, OFF_ICON_PTR = 0x2030, 0x2034
# Sender and location.
OFF_PRESENT, OFF_MII, OFF_ADDR = 0x36B8, 0x36BC, 0x375C
OFF_COUNTRY, OFF_REGION, PLACE_STRIDE, PLACE_MAX = 0x3760, 0x3B60, 0x40, 31
# Profile.
OFF_PROFILE, OFF_GREETING, GREETING_MAX = 0x3F60, 0x3F70, 16
# History.
OFF_MET16, OFF_NAMES_A, OFF_NAMES_B, MET_NAME_STRIDE, MET_NAME_MAX = 0x3F92, 0x4032, 0x4252, 0x22, 16
OFF_CACHE_COUNT, CACHE_MAX, OFF_MET32 = 0x4482, 100, 0x4484
OFF_BUBBLE = sp_build.OFF_BUBBLE
CFPB_HDR = 0x18
MII_NAME_MAX = 10
NAME_FORBID = '%\\'

FAVOURITE_COLOURS = ('red', 'orange', 'yellow', 'light green', 'green', 'blue', 'light blue',
                     'pink', 'purple', 'brown', 'white', 'black')


class MiiId(P.Int):
    """A Mii id the Plaza accepts: bit 5 of the first byte clear, and not zero."""

    def __init__(self, key, label=None, **kw):
        super().__init__(key, label, 1, 0xFFFFFFFF, hex=True, **kw)

    def validate(self, v, path):
        v = super().validate(v, path)
        if (v >> 5) & 1:
            raise P.ValidationError(path, '%#x has bit 5 set; the Plaza drops such Miis' % v)
        return v


def _langs(key, label, max_len, default, **kw):
    return P.List(key, label, P.Str(key, label, max_len=max_len, default=default), count=16,
                  item_labels=P.LANGUAGES, broadcast=True,
                  help=kw.pop('help', 'one value sets every language'), **kw)


def _met(key, count, names):
    item = [P.Int('mii_id', 'Mii id', hex=True), P.Mac('mac', 'Console MAC')]
    if names:
        item += [P.Str('name_a', 'Name A', max_len=MET_NAME_MAX),
                 P.Str('name_b', 'Name B', max_len=MET_NAME_MAX)]
    return P.List(key, 'Met %d' % count, P.Group('entry', 'Entry', item), count=count,
                  advanced=True)


def fields():
    return [
        P.Str('greeting', 'Greeting', max_len=GREETING_MAX, default='Hello, world!',
              help='shown on your Mii card'),
        P.Group('mii', 'Mii Info', [
            P.Str('mii_name', 'Mii name', max_len=MII_NAME_MAX, forbid=NAME_FORBID),
            P.Str('author_name', 'Creator', max_len=MII_NAME_MAX, forbid=NAME_FORBID,
                  help='the "Creator" line on the card'),
            MiiId('mii_id', 'Mii id', advanced=True),
            P.Mac('creator_mac', 'Creator MAC', advanced=True,
                  help='the console the Mii says it was made on'),
            P.Bytes('mii_data', 'Mii data', length=sp_mii.CFL_LEN, hidden=True),
        ]),
        P.Group('profile', 'Profile', [
            P.Int('streetpass_hits', 'StreetPass hits', 0, 999999),
            P.Int('plaza_population', 'Plaza population', 0, 3000),
            P.Int('hat', 'Hat', 0, 203, exclude=sp_build.HAT_EXCLUDED),
            P.Int('pet', 'Pet', 0, 2),
            P.Int('dream', 'Dream', 0, 19),
            P.Int('hobby', 'Hobby', 0, 27),
        ]),
        P.Group('sender', 'Location', [
            _langs('country', 'Country', PLACE_MAX, 'United Kingdom'),
            _langs('region', 'Region', PLACE_MAX, 'England'),
            P.Int('address_code', 'Address code', hex=True, advanced=True,
                  help='the console\'s country/region code'),
            P.Int('presence', 'Presence word', hex=True, advanced=True,
                  help='0x100 from the expansion build, 1 from the base build'),
        ]),
        P.Group('featured', 'Featured software', [
            P.Int('title_id', 'Title id', 1, 0xFFFFFFFFFFFFFFFE, hex=True,
                  help='the title shown on your card; 0 and all-ones are refused'),
            _langs('short_name', 'Short name', SHORT_MAX, 'Tuxchange'),
            _langs('long_name', 'Long name', LONG_MAX, 'StreetPass from Linux'),
            _langs('publisher', 'Publisher', PUB_MAX, 'Tuxchange'),
            P.Image('small_icon', 'Small icon', 24, 24),
            P.Image('large_icon', 'Large icon', 48, 48),
            P.Enum('icon_type', 'Icon type', [0, 1, 2], advanced=True),
            P.Int('region_lockout', 'Region lockout', hex=True, advanced=True),
            P.Bytes('age_ratings', 'Age ratings', length=0x10, advanced=True,
                    help='16 SMDH rating bytes'),
        ]),
        P.Group('history', 'History', [
            _met('met16', 16, True),
            P.Int('mii_cache_count', 'Plaza Mii-cache count', 0, CACHE_MAX, advanced=True),
            _met('met32', 32, False),
        ], advanced=True),
        P.Int('bubble', 'Speech-bubble style', 0, sp_build.BUBBLE_MAX, advanced=True),
        P.Blob('original', 'Original body', max_len=BODY_LEN),
    ]


FIELDS = fields()


def default_values(store_path=None):
    """Fresh values. The Mii's identity is derived from the store path, as the relay's own
    identity always has been, so the same store keeps the same Mii."""
    import sp_identity
    ident = sp_identity.derive(store_path or 'relay_store')
    v = {f.key: f.make_default() for f in FIELDS}
    v['mii'].update(mii_name='Relay', author_name='Tuxchange', mii_id=ident['mii_id'],
                    creator_mac=bytes.fromhex(ident['creator_mac'].replace(':', '')))
    v['mii']['mii_data'] = sp_build.build_cfl(
        mii_name='Relay', author_name='Tuxchange', mii_id=ident['mii_id'],
        creator_mac=ident['creator_mac'], face_shape=ident['face_shape'],
        gender=ident['gender'])
    v['profile'].update(hat=ident['hat'], dream=ident['dream'], hobby=ident['hobby'])
    v['sender']['country'] = ['United Kingdom'] * 16
    v['sender']['region'] = ['England'] * 16
    v['sender']['presence'] = sp_build.PRESENT_FLAG
    f = v['featured']
    f['title_id'] = 0x0004000000000000
    f['short_name'], f['long_name'], f['publisher'] = (
        ['Tuxchange'] * 16, ['StreetPass from Linux'] * 16, ['Tuxchange'] * 16)
    f['small_icon'], f['large_icon'] = sp_build.build_icons()
    f['region_lockout'] = 0x7FFFFFFF
    return v


def validate(values):
    return P._validate_fields(FIELDS, values)


def _put_str(b, off, cap, s):
    e = s.encode('utf-16-le')
    if len(e) > cap - 2:
        raise ValueError('%r is too long for its %d-byte field' % (s, cap))
    b[off:off + cap] = e + b'\x00' * (cap - len(e))


def _get_str(b, off, cap):
    return b[off:off + cap].decode('utf-16-le', 'replace').split('\x00', 1)[0]


def _mac(b):
    return bytes(b) if not isinstance(b, str) else bytes.fromhex(b.replace(':', ''))


def build_body(values):
    """Validated values -> a 0x7280-byte body. Needs your keyslot 0x31 key to wrap the Mii."""
    o = values.get('original') or b''
    b = bytearray(o if len(o) == BODY_LEN else BODY_LEN)
    f = values['featured']
    struct.pack_into('<Q', b, OFF_TITLE_ID, f['title_id'])
    struct.pack_into('<I', b, OFF_LOCKOUT, f['region_lockout'])
    b[OFF_RATINGS:OFF_RATINGS + 0x10] = f['age_ratings']
    for i in range(16):
        base = OFF_NAMES + i * NAME_STRIDE
        _put_str(b, base, sp_smdh.SHORT_LEN, f['short_name'][i])
        _put_str(b, base + sp_smdh.SHORT_LEN, sp_smdh.LONG_LEN, f['long_name'][i])
        _put_str(b, base + sp_smdh.SHORT_LEN + sp_smdh.LONG_LEN, sp_smdh.PUB_LEN,
                 f['publisher'][i])
    struct.pack_into('<I', b, OFF_ICON_TYPE, f['icon_type'])
    struct.pack_into('<I', b, OFF_ICON_PTR, 0)          # zero on the wire; the receiver re-links it
    b[sp_smdh.REGION_B_OFF:sp_smdh.REGION_B_OFF + sp_smdh.REGION_B_LEN] = \
        sp_smdh.build_region_b(small=f['small_icon'], large=f['large_icon'])

    s = values['sender']
    struct.pack_into('<I', b, OFF_PRESENT, s['presence'])
    struct.pack_into('<I', b, OFF_ADDR, s['address_code'])
    for i in range(16):
        _put_str(b, OFF_COUNTRY + i * PLACE_STRIDE, PLACE_STRIDE, s['country'][i])
        _put_str(b, OFF_REGION + i * PLACE_STRIDE, PLACE_STRIDE, s['region'][i])

    p = values['profile']
    struct.pack_into('<IH', b, OFF_PROFILE, p['streetpass_hits'], p['plaza_population'])
    b[OFF_PROFILE + 6:OFF_PROFILE + 10] = bytes((p['hat'], p['pet'], p['dream'], p['hobby']))
    _put_str(b, OFF_GREETING, 0x22, values['greeting'])

    h = values['history']
    for i, e in enumerate(h['met16']):
        struct.pack_into('<I', b, OFF_MET16 + i * 10, e['mii_id'])
        b[OFF_MET16 + i * 10 + 4:OFF_MET16 + i * 10 + 10] = _mac(e['mac'])
        _put_str(b, OFF_NAMES_A + i * MET_NAME_STRIDE, MET_NAME_STRIDE, e['name_a'])
        _put_str(b, OFF_NAMES_B + i * MET_NAME_STRIDE, MET_NAME_STRIDE, e['name_b'])
    b[OFF_CACHE_COUNT] = h['mii_cache_count']
    for i, e in enumerate(h['met32']):
        struct.pack_into('<I', b, OFF_MET32 + i * 10, e['mii_id'])
        b[OFF_MET32 + i * 10 + 4:OFF_MET32 + i * 10 + 10] = _mac(e['mac'])
    b[OFF_BUBBLE] = values['bubble']

    if b[OFF_MII:OFF_MII + 4] not in (sp_mii.MAGIC_CFPB, sp_mii.MAGIC_CFPN):
        struct.pack_into('<4sI', b, OFF_MII, sp_mii.MAGIC_CFPB, 1)
        struct.pack_into('<H', b, OFF_MII + 0x14, 1)
    return sp_mii.write_plaza_mii(bytes(b), mii_cfl(values['mii']))


def mii_cfl(m):
    """The Mii data with the editable parts (names, id, creator) applied, CRC resealed."""
    cfl = m['mii_data']
    if len(cfl) != sp_mii.CFL_LEN or not any(cfl):
        raise ValueError('no Mii data; import a Mii first')
    cfl = sp_mii.set_mii_name(cfl, m['mii_name'])
    cfl = sp_mii.set_author_name(cfl, m['author_name'])
    cfl = sp_mii.set_identity(cfl, mii_id=m['mii_id'], creator_mac=_mac(m['creator_mac']))
    ok, why = sp_mii.validate_cfl(cfl)
    if not ok:
        raise ValueError('the Mii would be refused by the Plaza: %s' % '; '.join(why))
    return cfl


def apply_mii(values, cfl):
    """Take a whole Mii (appearance and identity) into `values`, in place."""
    if len(cfl) != sp_mii.CFL_LEN:
        raise ValueError('Mii data is %#x bytes, expected %#x' % (len(cfl), sp_mii.CFL_LEN))
    ok, why = sp_mii.validate_cfl(cfl)
    if not ok:
        raise ValueError('this Mii would be refused by the Plaza: %s' % '; '.join(why))
    info = sp_mii.parse_cfl(cfl)
    for k in ('mii_name', 'author_name'):
        if len(info[k]) > MII_NAME_MAX or set(info[k]) & set(NAME_FORBID):
            raise ValueError('the Mii\'s %s %r is not one the Plaza accepts'
                             % (k.replace('_', ' '), info[k]))
    values['mii'].update(mii_name=info['mii_name'], author_name=info['author_name'],
                         mii_id=info['mii_id'], creator_mac=bytes(cfl[0x10:0x16]),
                         mii_data=bytes(cfl))
    return values


def _clamp(v, hi, exclude=()):
    """What the receiving Plaza does with an out-of-range value: it zeroes it."""
    return 0 if v > hi or v in exclude else v


def parse_body(body):
    """A received or stored body -> values. Raises PluginParseError if it is not one this
    can edit."""
    if len(body) == sp_cec_base_len():
        raise P.PluginParseError('this is a base-build Mii Plaza message (body 0x60F0); only '
                                 'the expansion build\'s 0x7280-byte body can be edited')
    if len(body) != BODY_LEN:
        raise P.PluginParseError('a Mii Plaza body is %#x bytes, this one is %#x'
                                 % (BODY_LEN, len(body)))
    b = bytes(body)
    try:
        cfl, mac_ok = sp_mii.read_plaza_mii(b)
    except (ValueError, IndexError) as e:
        raise P.PluginParseError('the Mii container is unreadable: %s' % e)
    if not mac_ok:
        raise P.PluginParseError('the Mii did not decrypt: its AES-CCM tag does not match. '
                                 'Is your keyslot 0x31 key right?')
    v = {f.key: f.make_default() for f in FIELDS}
    v['original'] = b
    apply_mii(v, cfl)
    f = v['featured']
    f['title_id'] = struct.unpack_from('<Q', b, OFF_TITLE_ID)[0]
    if f['title_id'] in (0, 0xFFFFFFFFFFFFFFFF):
        f['title_id'] = 0x0004000000000000
    f['region_lockout'] = struct.unpack_from('<I', b, OFF_LOCKOUT)[0]
    f['age_ratings'] = b[OFF_RATINGS:OFF_RATINGS + 0x10]
    for k in ('short_name', 'long_name', 'publisher'):
        f[k] = []
    for i in range(16):
        base = OFF_NAMES + i * NAME_STRIDE
        f['short_name'].append(_get_str(b, base, sp_smdh.SHORT_LEN))
        f['long_name'].append(_get_str(b, base + sp_smdh.SHORT_LEN, sp_smdh.LONG_LEN))
        f['publisher'].append(_get_str(b, base + sp_smdh.SHORT_LEN + sp_smdh.LONG_LEN,
                                       sp_smdh.PUB_LEN))
    f['icon_type'] = _clamp(struct.unpack_from('<I', b, OFF_ICON_TYPE)[0], 2)
    f['small_icon'] = sp_smdh.decode_icon(b, large=False)
    f['large_icon'] = sp_smdh.decode_icon(b, large=True)

    s = v['sender']
    s['presence'] = struct.unpack_from('<I', b, OFF_PRESENT)[0]
    s['address_code'] = struct.unpack_from('<I', b, OFF_ADDR)[0]
    s['country'] = [_get_str(b, OFF_COUNTRY + i * PLACE_STRIDE, PLACE_STRIDE) for i in range(16)]
    s['region'] = [_get_str(b, OFF_REGION + i * PLACE_STRIDE, PLACE_STRIDE) for i in range(16)]

    p = v['profile']
    hits, pop = struct.unpack_from('<IH', b, OFF_PROFILE)
    hat, pet, dream, hobby = b[OFF_PROFILE + 6:OFF_PROFILE + 10]
    p.update(streetpass_hits=_clamp(hits, 999999), plaza_population=_clamp(pop, 3000),
             hat=_clamp(hat, 203, sp_build.HAT_EXCLUDED), pet=_clamp(pet, 2),
             dream=_clamp(dream, 19), hobby=_clamp(hobby, 27))
    v['greeting'] = _get_str(b, OFF_GREETING, 0x22)

    h = v['history']
    h['met16'] = [{'mii_id': struct.unpack_from('<I', b, OFF_MET16 + i * 10)[0],
                   'mac': b[OFF_MET16 + i * 10 + 4:OFF_MET16 + i * 10 + 10],
                   'name_a': _get_str(b, OFF_NAMES_A + i * MET_NAME_STRIDE, MET_NAME_STRIDE),
                   'name_b': _get_str(b, OFF_NAMES_B + i * MET_NAME_STRIDE, MET_NAME_STRIDE)}
                  for i in range(16)]
    h['mii_cache_count'] = _clamp(b[OFF_CACHE_COUNT], CACHE_MAX)
    h['met32'] = [{'mii_id': struct.unpack_from('<I', b, OFF_MET32 + i * 10)[0],
                   'mac': b[OFF_MET32 + i * 10 + 4:OFF_MET32 + i * 10 + 10]}
                  for i in range(32)]
    v['bubble'] = _clamp(b[OFF_BUBBLE], sp_build.BUBBLE_MAX)
    return v


def sp_cec_base_len():
    import sp_cec
    return sp_cec.PLAZA_BODY_SIZE


def mii_summary(cfl):
    """The parts of a Mii worth showing as text, since it cannot be drawn."""
    info = sp_mii.parse_cfl(cfl)
    ap = sp_build.parse_appearance(cfl)
    ok, why = sp_mii.validate_cfl(cfl)
    month, day = ap['birthday_month'], ap['birthday_day']
    col = ap['favourite_colour']
    return {'name': info['mii_name'], 'creator': info['author_name'],
            'gender': ('male', 'female')[ap['gender']],
            'birthday': '%d/%d' % (day, month) if month else 'not set',
            'favourite_colour': FAVOURITE_COLOURS[col] if col < len(FAVOURITE_COLOURS)
            else str(col),
            'height': ap['height'], 'build': ap['build'],
            'mii_id': '%08x' % info['mii_id'], 'creator_mac': info['creator_mac'],
            'valid': ok, 'problems': why}


def _selftest():
    import time, hmac, hashlib
    import lp_keys as _k, sp_identity, sp_cec
    if _k.selftest_keys():
        print('  (no console keys found, so running on generated throwaway keys)')
    ok = tot = 0

    def chk(n, c, g=''):
        nonlocal ok, tot
        tot += 1; ok += bool(c)
        print('  [%s] %s%s' % ('PASS' if c else 'FAIL', n, ('  %s' % (g,)) if g else ''))

    def raises(fn, exc=ValueError):
        try:
            fn()
        except exc:
            return True
        return False

    sp = '/tmp/does-not-matter/relay_store'
    v = default_values(sp)
    chk('the defaults are valid values', validate(v) is not None)
    ident = sp_identity.derive(sp)
    old_mii = sp_build.build_cfl(mii_name='Relay', author_name='Tuxchange',
                                 mii_id=ident['mii_id'], creator_mac=ident['creator_mac'],
                                 face_shape=ident['face_shape'], gender=ident['gender'])
    old = sp_build.build_body(old_mii, greeting='Hello from Linux', profile=sp_build.build_profile(
        hat=ident['hat'], dream=ident['dream'], hobby=ident['hobby']))
    new = build_body(v)
    chk('the default body is byte-identical to the one sp_build always built',
        new == old, [hex(i) for i in range(len(new)) if new[i] != old[i]][:6])

    back = parse_body(new)
    chk('parse then build reproduces the body exactly', build_body(back) == new)
    chk('parse returns every value as it was set',
        {k: back[k] for k in back if k != 'original'} == {k: v[k] for k in v if k != 'original'})
    chk('and keeps the body it read, for the bytes it does not expose', back['original'] == new)

    e = parse_body(new)
    e['greeting'] = 'Edited'
    e['profile']['hat'] = 150
    e['history']['met16'][2] = {'mii_id': 0x12345690, 'mac': b'\x01\x02\x03\x04\x05\x06',
                                'name_a': 'Tux', 'name_b': 'Gnu'}
    e['history']['met32'][31] = {'mii_id': 7, 'mac': b'\xaa' * 6}
    e['sender']['country'][1] = 'Narnia'
    e['featured']['short_name'] = ['Short'] * 16
    validate(e)
    eb = build_body(e)
    diff = {i for i in range(BODY_LEN) if eb[i] != new[i]}
    allowed = (set(range(OFF_GREETING, OFF_GREETING + 0x22)) | {OFF_PROFILE + 6}
               | set(range(OFF_MET16 + 20, OFF_MET16 + 30))
               | set(range(OFF_NAMES_A + 2 * 0x22, OFF_NAMES_A + 3 * 0x22))
               | set(range(OFF_NAMES_B + 2 * 0x22, OFF_NAMES_B + 3 * 0x22))
               | set(range(OFF_MET32 + 310, OFF_MET32 + 320))
               | set(range(OFF_COUNTRY + 0x40, OFF_COUNTRY + 0x80))
               | {o for i in range(16) for o in range(OFF_NAMES + i * NAME_STRIDE,
                                                      OFF_NAMES + i * NAME_STRIDE + 0x80)})
    chk('an edit changes only the bytes of the fields edited', diff and diff <= allowed,
        sorted(hex(i) for i in diff - allowed)[:6])
    pe = parse_body(eb)
    chk('and the edits read back', pe['greeting'] == 'Edited' and pe['profile']['hat'] == 150
        and pe['history']['met16'][2]['name_b'] == 'Gnu' and pe['sender']['country'][1] == 'Narnia'
        and pe['history']['met32'][31]['mii_id'] == 7)
    chk('the Plaza\'s own field map agrees on the history entry',
        [m for m in sp_cec.parse_plaza_body(eb)['met16'] if m['idx'] == 2][0]['name_a'] == 'Tux')

    junk = bytearray(new)
    junk[0x6000:0x6010] = b'\x5a' * 16                 # inside the opaque block 0x45D3
    junk[0x3F6A:0x3F70] = b'\x01\x02\x03\x04\x05\x06'  # the unnamed profile bytes
    jv = parse_body(sp_mii.write_plaza_mii(bytes(junk), sp_mii.read_plaza_mii(new)[0]))
    jv['greeting'] = 'kept?'
    jb = build_body(jv)
    chk('unknown and opaque bytes survive an edit unchanged',
        jb[0x6000:0x6010] == b'\x5a' * 16 and jb[0x3F6A:0x3F70] == b'\x01\x02\x03\x04\x05\x06')

    msg = sp_build.build_message(new, message_id=1, when=time.gmtime(0))
    _h, _ex, mb = sp_cec.split_message(msg)
    chk('a body read back out of a full message parses', parse_body(mb)['greeting']
        == 'Hello from Linux')
    chk('its HMAC is the Plaza key\'s', msg[-0x20:] == hmac.new(
        sp_build.plaza_hmac_key(), mb, hashlib.sha256).digest())

    chk('a base-build body is refused with a reason',
        raises(lambda: parse_body(b'\x00' * 0x60F0), P.PluginParseError))
    chk('a body of the wrong size is refused', raises(lambda: parse_body(b'\x00' * 64),
                                                      P.PluginParseError))
    bad = bytearray(new); bad[OFF_MII + CFPB_HDR + 0x20] ^= 0xFF
    chk('a Mii that fails its CCM tag is refused rather than trusted',
        raises(lambda: parse_body(bytes(bad)), P.PluginParseError))
    bad2 = bytearray(new); bad2[OFF_MII:OFF_MII + 4] = b'XXXX'
    chk('a missing Mii container is refused', raises(lambda: parse_body(bytes(bad2)),
                                                     P.PluginParseError))
    clamp = bytearray(new); clamp[OFF_PROFILE + 6] = 69; clamp[OFF_BUBBLE] = 9
    cv = parse_body(bytes(clamp))
    chk('values the game would zero are read as zero, so the message can still be edited',
        cv['profile']['hat'] == 0 and cv['bubble'] == 0)

    for path, val in (('greeting', 'x' * 17), ('mii.mii_name', 'a%b'), ('mii.mii_id', 0x20),
                      ('profile.hat', 168), ('profile.hat', 204), ('bubble', 6),
                      ('featured.title_id', 0)):
        t = default_values(sp)
        keys = path.split('.')
        P.set_path(t, keys, val)
        chk('%s = %r is refused' % (path, val), raises(lambda: validate(t), P.ValidationError))
    long_country = default_values(sp)
    long_country['sender']['country'][0] = '\U0001F600' * 31   # 62 UTF-16 units
    chk('text that fits in characters but not in bytes is refused at build',
        raises(lambda: build_body(long_country)))

    other = sp_build.build_cfl(mii_name='Other', author_name='Someone', mii_id=0x11223390,
                               creator_mac='b8:ae:6e:aa:bb:cc', birthday_month=4,
                               birthday_day=1, favourite_colour=5)
    av = apply_mii(default_values(sp), other)
    chk('apply_mii takes the name, creator and identity from the Mii',
        (av['mii']['mii_name'], av['mii']['author_name'], av['mii']['mii_id'])
        == ('Other', 'Someone', 0x11223390))
    got = sp_mii.read_plaza_mii(build_body(av))[0]
    chk('and its appearance', sp_build.parse_appearance(got) == sp_build.parse_appearance(other))
    summ = mii_summary(other)
    chk('the Mii summary reads gender, birthday and colour',
        (summ['birthday'], summ['favourite_colour'], summ['valid']) == ('1/4', 'blue', True),
        summ)
    bad_mii = bytearray(other); bad_mii[0x0C] |= 0x20
    chk('a Mii the Plaza would refuse is not imported',
        raises(lambda: apply_mii(default_values(sp), sp_mii.reseal_cfl(bytes(bad_mii)))))
    nom = default_values(sp); nom['mii']['mii_data'] = bytes(0x60)
    chk('building with no Mii data says to import one', raises(lambda: build_body(nom)))
    print('\n%d/%d checks passed' % (ok, tot))
    return 0 if ok == tot else 1


if __name__ == '__main__':
    sys.modules.setdefault('sp_plaza', sys.modules[__name__])
    sys.exit(_selftest())
