#!/usr/bin/env python3
"""Deliver stored messages into a console-shaped CEC folder, as if they had arrived there.

The target is the `CEC/` directory of the CEC system save (`sysdata/00010026/00000000/CEC`). An
emulator such as Azahar keeps it as a plain folder, so writing into it is all a delivery takes.

What a console does when a message arrives, as read from its own save data:

* the message is stored as `<title>/InBox___/_<id>`, its header changed in four places: the
  unopened and new flags (+0x36, +0x37) are set, and two timestamps (+0x48, +0x54) are filled;
* the box's `BoxInfo_____` lists every message's 0x70-byte header, newest first, after a 0x20-byte
  header holding the box's limits and usage;
* the title's `MBoxInfo____` raises two flags (+0x40, +0x41) and records when it last received
  (+0x44).

A message is only delivered to a title that already has an inbox there. A title's box is created
by its game, with its own HMAC key and limits, so one we invent would not be one the game reads.
"""
import os, sys, time, glob, struct, shutil, tarfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sp_cec, sp_cecvalid, sp_store, sp_cecstore

HDR_LEN = sp_cec.HDR_LEN
BOXINFO_HDR = 0x20
BOXINFO_MAGIC = b'bb'
INBOX = sp_store.BOXES['inbox']
EMULATOR_DIRS = {'azahar-emu': 'Azahar', 'azaharplus-emu': 'AzaharPlus', 'citra-emu': 'Citra',
                 'lime3ds-emu': 'Lime3DS'}
EMULATOR_PROCESSES = ('azahar', 'azahar-qt', 'azahar-room', 'azaharplus', 'citra', 'citra-qt',
                      'lime3ds', 'lime3ds-qt')
CEC_SUBPATH = os.path.join('sysdata', '00010026', '00000000', 'CEC')

ADDED, DUPLICATE, NO_BOX, FULL, TOO_BIG = 'added', 'duplicate', 'no-box', 'full', 'too-big'
# Delivered, but the destination holds no key for its title, so its HMAC went unchecked.
UNVERIFIED = 'unverified'
# Not delivered: malformed, or its HMAC does not match the destination title's key.
INVALID = 'invalid'
DELIVERED = (ADDED, UNVERIFIED)


def as_received(container, when=None):
    """The message as the receiving console files it. The HMAC covers only the body, so it holds."""
    c = bytearray(container[:sp_cec.parse_header(container)['total_size']])
    c[0x36] = 1
    c[0x37] = 1
    ts = sp_cec.timestamp(when)
    for off in (0x48, 0x54):
        if not any(c[off:off + 12]):
            c[off:off + 12] = ts
    return bytes(c)


def parse_boxinfo(data):
    """-> (the 0x20-byte header fields, [0x70-byte message headers])."""
    if len(data) < BOXINFO_HDR or data[:2] != BOXINFO_MAGIC:
        raise ValueError('not a BoxInfo (magic %r)' % data[:2])
    f = dict(zip(('size', 'max_bytes', 'used_bytes', 'max_messages', 'num_messages',
                  'max_batch', 'max_message_size'),
                 struct.unpack_from('<7I', data, 4)))
    n = f['num_messages']
    if BOXINFO_HDR + n * HDR_LEN > len(data):
        raise ValueError('BoxInfo lists %d message(s) but holds only %d bytes' % (n, len(data)))
    return f, [bytes(data[BOXINFO_HDR + i * HDR_LEN:BOXINFO_HDR + (i + 1) * HDR_LEN])
               for i in range(n)]


def build_boxinfo(fields, headers):
    used = sum(struct.unpack_from('<I', h, 4)[0] for h in headers)
    b = bytearray(BOXINFO_HDR)
    b[:2] = BOXINFO_MAGIC
    struct.pack_into('<7I', b, 4, BOXINFO_HDR + len(headers) * HDR_LEN, fields['max_bytes'],
                     used, fields['max_messages'], len(headers), fields['max_batch'],
                     fields['max_message_size'])
    return bytes(b) + b''.join(headers)


def _write(path, data):
    """Replace a file atomically, keeping whoever owns the directory as its owner."""
    tmp = path + '.tmp'
    with open(tmp, 'wb') as f:
        f.write(data)
    if os.geteuid() == 0:
        st = os.stat(os.path.dirname(path))
        os.chown(tmp, st.st_uid, st.st_gid)
    os.replace(tmp, path)


def resolve(path):
    """The CEC directory for a path: the folder itself, its CEC/, or an emulator's user folder."""
    path = os.path.abspath(os.path.expanduser(path))
    for cand in (path, os.path.join(path, 'CEC')):
        if os.path.isfile(os.path.join(cand, 'MBoxList____')):
            return cand
    found = sorted(glob.glob(os.path.join(path, 'nand', 'data', '*', CEC_SUBPATH)))
    found = [d for d in found if os.path.isfile(os.path.join(d, 'MBoxList____'))]
    return found[0] if found else None


def find_emulators(home=None):
    """-> [(name, CEC dir)] for every installed 3DS emulator whose CEC save exists."""
    home = home or os.path.expanduser('~')
    bases = [(os.environ.get('XDG_DATA_HOME') or os.path.join(home, '.local', 'share'), '')]
    bases += [(d, ' (Flatpak)') for d in sorted(glob.glob(os.path.join(home, '.var', 'app', '*',
                                                                       'data')))]
    out = []
    for base, how in bases:
        for sub, name in EMULATOR_DIRS.items():
            d = resolve(os.path.join(base, sub))
            if d and d not in [x for _n, x in out]:
                out.append((name + how, d))
    return out


def emulator_running():
    """-> the name of a running 3DS emulator, or None. It would overwrite what we write."""
    for pid in os.listdir('/proc'):
        if not pid.isdigit():
            continue
        try:
            comm = open('/proc/%s/comm' % pid).read().strip().lower()
        except OSError:
            continue
        if comm in EMULATOR_PROCESSES:
            return comm
    return None


class CecFolder:
    """A console's CEC directory, written the way the console writes it."""

    def __init__(self, path):
        self.path = resolve(path)
        if self.path is None:
            raise ValueError('%s holds no CEC data (no MBoxList____ in it, its CEC/, or an '
                             "emulator's nand/data/*/%s)" % (path, CEC_SUBPATH))

    def titles(self):
        info = sp_cecstore.parse_mboxlist(open(os.path.join(self.path, 'MBoxList____'),
                                               'rb').read())
        return [t for t in info['titles'] if t is not None]

    def _title_dir(self, tid):
        for name in ('%08x' % tid, '%08X' % tid):
            d = os.path.join(self.path, name)
            if os.path.isdir(d):
                return d
        return None

    def _inbox(self, tid):
        d = self._title_dir(tid)
        if d is None or tid not in self.titles():
            return None
        box = os.path.join(d, INBOX)
        return box if os.path.isfile(os.path.join(box, 'BoxInfo_____')) else None

    def has_inbox(self, tid):
        return self._inbox(tid) is not None

    def inbox(self, tid):
        """-> the message headers listed in a title's inbox, newest first."""
        box = self._inbox(tid)
        if box is None:
            return []
        return parse_boxinfo(open(os.path.join(box, 'BoxInfo_____'), 'rb').read())[1]

    def title_key(self, tid):
        """The title's HMAC key from its MBoxInfo here, or None."""
        d = self._title_dir(tid)
        try:
            k = sp_cecstore.parse_mboxinfo(open(os.path.join(d, 'MBoxInfo____'), 'rb').read())['hmac_key']
        except (TypeError, OSError, ValueError):
            return None
        return k if len(k) == 0x20 and any(k) else None

    def deliver(self, container, when=None, dry_run=False):
        """File one message in its title's inbox.

        -> ADDED or UNVERIFIED (both delivered), or DUPLICATE, NO_BOX, FULL, TOO_BIG, INVALID.
        """
        if sp_cecvalid.problems(container):
            return INVALID
        h = sp_cec.parse_header(container)
        tid, size = h['cec_title_id'], h['total_size']
        box = self._inbox(tid)
        if box is None:
            return NO_BOX
        key = self.title_key(tid)
        if key is not None and not sp_cecvalid.hmac_ok(container, key):
            return INVALID
        bi = os.path.join(box, 'BoxInfo_____')
        fields, headers = parse_boxinfo(open(bi, 'rb').read())
        name = sp_store.message_filename(container)
        mid = container[0x20:0x28]
        if any(x[0x20:0x28] == mid for x in headers) or os.path.exists(os.path.join(box, name)):
            return DUPLICATE
        if fields['max_message_size'] and size > fields['max_message_size']:
            return TOO_BIG
        used = sum(struct.unpack_from('<I', x, 4)[0] for x in headers)
        if len(headers) >= fields['max_messages'] or used + size > fields['max_bytes']:
            return FULL
        done = ADDED if key is not None else UNVERIFIED
        if dry_run:
            return done
        msg = as_received(container, when)
        _write(os.path.join(box, name), msg)
        _write(bi, build_boxinfo(fields, [msg[:HDR_LEN]] + headers))
        self._mark_received(tid, msg[0x54:0x60])
        return done

    def _mark_received(self, tid, ts):
        p = os.path.join(self._title_dir(tid), 'MBoxInfo____')
        if not os.path.isfile(p):
            return
        info = bytearray(open(p, 'rb').read())
        if len(info) < 0x50:
            return
        info[0x40] = info[0x41] = 1
        info[0x44:0x50] = ts
        _write(p, bytes(info))

    def backup(self, dest_dir):
        """Archive the whole CEC folder into dest_dir. -> the archive's path."""
        made, d = [], os.path.abspath(dest_dir)
        while not os.path.exists(d):
            made.append(d)
            d = os.path.dirname(d)
        os.makedirs(dest_dir, exist_ok=True)
        stem = os.path.join(dest_dir, time.strftime('CEC-%Y%m%d-%H%M%S'))
        out, n = stem + '.tar.gz', 1
        while os.path.exists(out):
            out, n = '%s-%d.tar.gz' % (stem, n), n + 1
        with tarfile.open(out, 'w:gz') as tf:
            tf.add(self.path, arcname='CEC')
        if os.geteuid() == 0:
            # Run through sudo, it belongs to whoever owns the emulator's data, not to root.
            st = os.stat(self.path)
            for p in made + [out]:
                os.chown(p, st.st_uid, st.st_gid)
        return out


def default_backup_dir(home=None):
    """~/.local/share/tuxchange/cec-backups, for `home` (sudo's caller) when given."""
    if home:
        base = os.path.join(home, '.local', 'share')
    else:
        base = os.environ.get('XDG_DATA_HOME') or os.path.join(os.path.expanduser('~'),
                                                               '.local', 'share')
    return os.path.join(base, 'tuxchange', 'cec-backups')


def deliver_all(folder, messages, dry_run=False, log=print):
    """Deliver [(container, when)], oldest first so the newest ends up on top. -> {status: n}."""
    counts = {}
    for c, when in sorted(messages, key=lambda m: m[1] or 0):
        st = folder.deliver(c, when, dry_run=dry_run)
        counts[st] = counts.get(st, 0) + 1
        if st != DUPLICATE and (st != ADDED or dry_run):
            tid = struct.unpack_from('<I', c, 0x10)[0] if len(c) >= 0x14 else 0
            log('  %08X %s: %s' % (tid, bytes(c[0x20:0x28]).hex(),
                                   {ADDED: 'would be delivered', DUPLICATE: 'already there',
                                    UNVERIFIED: '%sdelivered, but there is no key there to check '
                                                'its HMAC' % ('would be ' if dry_run else ''),
                                    INVALID: 'malformed, or its HMAC does not match that '
                                             "title's key; not delivered",
                                    NO_BOX: 'no inbox for this title there (start its game '
                                            'once with StreetPass on)',
                                    FULL: 'that inbox is full',
                                    TOO_BIG: 'larger than that inbox accepts'}[st]))
    return counts


def write_raw(messages, dest, log=None):
    """Write each well-formed message unchanged as <dest>/<TITLE>/_<id>. -> the paths written."""
    out = []
    for c, _when in messages:
        bad = sp_cecvalid.problems(c)
        if bad:
            if log:
                log('  skipped a malformed message: %s' % '; '.join(bad))
            continue
        tid = sp_cec.parse_header(c)['cec_title_id']
        d = os.path.join(dest, '%08X' % tid)
        os.makedirs(d, exist_ok=True)
        p = os.path.join(d, sp_store.message_filename(c))
        _write(p, c)
        out.append(p)
    return out


def _selftest():
    import tempfile
    ok = tot = 0

    def chk(n, c, g=''):
        nonlocal ok, tot
        tot += 1; ok += bool(c)
        print('  [%s] %s%s' % ('PASS' if c else 'FAIL', n, ('  %s' % (g,)) if g else ''))

    ts = sp_cec.parse_timestamp(sp_cec.timestamp(1.7e9 + 0.25), 0)
    lt = time.localtime(1.7e9)
    chk('a CEC timestamp parses back to the local time it was made from',
        (ts['year'], ts['month'], ts['day'], ts['weekday'], ts['hour'], ts['minute'],
         ts['second'], ts['ms'])
        == (lt.tm_year, lt.tm_mon, lt.tm_mday, (lt.tm_wday + 1) % 7, lt.tm_hour, lt.tm_min,
            lt.tm_sec, 250))

    import hashlib, hmac
    KEY = b'K' * 32

    def msg(tid, mid, size=0x200, key=KEY):
        c = bytearray(size)
        struct.pack_into('<HHIII', c, 0, 0x6060, 0, size, HDR_LEN, size - HDR_LEN - 0x20)
        struct.pack_into('<I', c, 0x10, tid)
        c[0x20:0x28] = mid
        c[0x34:0x36] = b'\x03\x03'
        c[0x60:0x6C] = sp_cec.timestamp(1.6e9)
        c[-0x20:] = hmac.new(key, c[HDR_LEN:-0x20], hashlib.sha256).digest()
        return bytes(c)

    def console_title(cec, tid, max_messages=3, max_bytes=0x1000, max_size=0x800, key=KEY):
        d = os.path.join(cec, '%08x' % tid)
        os.makedirs(os.path.join(d, INBOX))
        info = bytearray(0x60)
        info[:2] = b'cc'
        struct.pack_into('<I', info, 4, tid)
        info[0x10:0x30] = key
        open(os.path.join(d, 'MBoxInfo____'), 'wb').write(bytes(info))
        f = dict(max_bytes=max_bytes, max_messages=max_messages, max_batch=max_messages,
                 max_message_size=max_size)
        open(os.path.join(d, INBOX, 'BoxInfo_____'), 'wb').write(build_boxinfo(f, []))

    tmp = tempfile.mkdtemp()
    try:
        emu = os.path.join(tmp, 'azahar-emu')
        cec = os.path.join(emu, 'nand', 'data', '0' * 32, CEC_SUBPATH)
        os.makedirs(cec)
        ml = bytearray(12 + 24 * 16)
        struct.pack_into('<HHII', ml, 0, 0x6868, 0, 1, 1)
        ml[12:20] = b'00020800'
        open(os.path.join(cec, 'MBoxList____'), 'wb').write(bytes(ml))
        console_title(cec, 0x00020800)

        chk('an emulator user folder resolves to its CEC directory', resolve(emu) == cec)
        chk('so does the CEC directory itself, and its parent',
            resolve(cec) == cec and resolve(os.path.dirname(cec)) == cec)
        chk('a folder with no CEC data resolves to nothing', resolve(tmp) is None)
        chk('an emulator under XDG_DATA_HOME is found',
            [d for _n, d in _with_env('XDG_DATA_HOME', tmp, lambda: find_emulators(home=tmp))] == [cec])

        f = CecFolder(emu)
        a, b = msg(0x00020800, b'A' * 8), msg(0x00020800, b'B' * 8)
        chk('a message is delivered to a title with an inbox', f.deliver(a, 1.7e9) == ADDED)
        got = open(os.path.join(cec, '00020800', INBOX, sp_store.message_filename(a)),
                   'rb').read()
        chk('it is filed as unopened and new', got[0x36:0x38] == b'\x01\x01')
        chk('with the time it was received', got[0x48:0x54] == sp_cec.timestamp(1.7e9)
            and got[0x54:0x60] == sp_cec.timestamp(1.7e9))
        chk('and everything else unchanged', got[:0x36] == a[:0x36] and got[0x60:] == a[0x60:])
        chk('the same message is not delivered twice', f.deliver(a) == DUPLICATE)
        chk('a title with no inbox there is refused', f.deliver(msg(0x00030600, b'C' * 8)) == NO_BOX)
        f.deliver(b, 1.8e9)
        hs = f.inbox(0x00020800)
        chk('BoxInfo lists both, newest first',
            [x[0x20:0x28] for x in hs] == [b'B' * 8, b'A' * 8])
        fields, _ = parse_boxinfo(open(os.path.join(cec, '00020800', INBOX, 'BoxInfo_____'),
                                       'rb').read())
        chk('and counts their size and number', fields['num_messages'] == 2
            and fields['used_bytes'] == 0x400 and fields['size'] == 0x20 + 2 * HDR_LEN, fields)
        chk('the limits it holds are kept', fields['max_messages'] == 3
            and fields['max_message_size'] == 0x800)
        info = open(os.path.join(cec, '00020800', 'MBoxInfo____'), 'rb').read()
        chk('MBoxInfo records the arrival', info[0x40:0x42] == b'\x01\x01'
            and info[0x44:0x50] == sp_cec.timestamp(1.8e9))
        chk('a message over the size limit is refused',
            f.deliver(msg(0x00020800, b'D' * 8, 0x900)) == TOO_BIG)
        chk('a dry run changes nothing', f.deliver(msg(0x00020800, b'E' * 8), dry_run=True)
            == ADDED and len(f.inbox(0x00020800)) == 2)
        chk('a message failing the title key there is refused',
            f.deliver(msg(0x00020800, b'X' * 8, key=b'z' * 32)) == INVALID)
        bad = bytearray(msg(0x00020800, b'Y' * 8))
        struct.pack_into('<I', bad, 8, 0xFFFFFFF0)
        chk('so is a malformed message', f.deliver(bytes(bad)) == INVALID)
        chk('and neither was filed', len(f.inbox(0x00020800)) == 2)
        chk('raw export skips the malformed one',
            [os.path.basename(p) for p in write_raw([(bytes(bad), 0), (a, 0)],
                                                    os.path.join(tmp, 'raw'))]
            == [sp_store.message_filename(a)])
        f.deliver(msg(0x00020800, b'E' * 8))
        chk('a full inbox is refused', f.deliver(msg(0x00020800, b'F' * 8)) == FULL)

        f2 = CecFolder(cec)
        console_title(cec, 0x001a0400, key=bytes(32))
        ml[8:12] = struct.pack('<I', 2)
        ml[28:36] = b'001a0400'
        open(os.path.join(cec, 'MBoxList____'), 'wb').write(bytes(ml))
        logged = []
        n = deliver_all(f2, [(msg(0x001a0400, b'G' * 8), 2.0e9), (msg(0x001a0400, b'H' * 8), 1.0e9),
                             (a, 1.0), (msg(0x00030600, b'I' * 8), 1.0)], log=logged.append)
        chk('deliver_all counts each outcome', n == {UNVERIFIED: 2, DUPLICATE: 1, NO_BOX: 1}, n)
        chk('and delivers oldest first, so the newest is listed first',
            [x[0x20:0x28] for x in f2.inbox(0x001a0400)] == [b'G' * 8, b'H' * 8])
        chk('it says why a message was not delivered, but not for each duplicate',
            sum('no inbox' in x for x in logged) == 1 and not any('already' in x for x in logged),
            logged)
        chk('and says which went in without an HMAC check',
            sum('no key there' in x for x in logged) == 2, logged)

        arc = f.backup(os.path.join(tmp, 'bk'))
        with tarfile.open(arc) as tf:
            names = tf.getnames()
        chk('a backup archives the whole CEC folder',
            'CEC/MBoxList____' in names and 'CEC/00020800/%s/BoxInfo_____' % INBOX in names)
        chk('and a second one in the same second does not overwrite it',
            f.backup(os.path.join(tmp, 'bk')) != arc and len(os.listdir(os.path.join(tmp, 'bk'))) == 2)

        raw = write_raw([(a, 1.0)], os.path.join(tmp, 'raw'))
        chk('a raw export writes the message unchanged',
            len(raw) == 1 and open(raw[0], 'rb').read() == a and '/00020800/_' in raw[0])
        chk('backups go under the given home, or XDG_DATA_HOME without one',
            default_backup_dir('/home/u') == '/home/u/.local/share/tuxchange/cec-backups'
            and _with_env('XDG_DATA_HOME', tmp, default_backup_dir)
            == os.path.join(tmp, 'tuxchange', 'cec-backups'))
        chk('a non-BoxInfo is rejected', _raises(lambda: parse_boxinfo(b'zz' + b'\x00' * 30)))
        chk('a BoxInfo shorter than its count is rejected',
            _raises(lambda: parse_boxinfo(build_boxinfo(fields, [])[:0x14] + b'\x05' + b'\x00' * 11)))
        chk('a folder with no CEC data is refused', _raises(lambda: CecFolder(tmp)))

        import lp_corpus as corpus, sp_savefs
        for pa in filter(None, map(corpus.path, ('console_nand', 'console_nand_2',
                                                 'console_nand_3'))):
            fs = sp_savefs.SaveFS(open(pa, 'rb').read())
            files = {x['path']: x for x in fs.files()}
            real = [p for p in files if p.endswith(INBOX + '/BoxInfo_____')]
            for p in real:
                d = fs.read(files[p])
                fl, hs = parse_boxinfo(d)
                if hs:
                    chk('a console\'s own inbox BoxInfo round-trips (%s)' % p.split('/')[1],
                        build_boxinfo(fl, hs) == d)
                    first = fs.read(files['/'.join(p.split('/')[:-1]) + '/'
                                         + sp_store.message_filename(hs[0])])
                    chk('  and its first entry is that message\'s own header',
                        first[:HDR_LEN] == hs[0])
                    break
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print('%d/%d' % (ok, tot))
    return 0 if ok == tot else 1


def _with_env(k, v, fn):
    old = os.environ.get(k)
    os.environ[k] = v
    try:
        return fn()
    finally:
        if old is None:
            os.environ.pop(k)
        else:
            os.environ[k] = old


def _raises(fn):
    try:
        fn()
    except (ValueError, struct.error):
        return True
    return False


if __name__ == '__main__':
    if len(sys.argv) < 2 or sys.argv[1] == '--selftest':
        sys.exit(_selftest())
    f = CecFolder(sys.argv[1])
    for t in f.titles():
        print('%08X  inbox %s' % (t, '%d message(s)' % len(f.inbox(t)) if f.has_inbox(t)
                                  else '-'))
