#!/usr/bin/env python3
"""A CEC message store on disk, shaped like a console's."""
import os, sys, json, stat, time, struct, base64, fcntl, functools, hashlib, tempfile, threading

import sp_cec, sp_cecvalid, sp_service

MBOXLIST_MAGIC, MBOXINFO_MAGIC, BOXINFO_MAGIC = 0x6868, 0x6363, 0x6262
# Kept outside CEC/ so the tree stays byte-comparable with a console's.
META_FILE = 'store_meta.json'
LOCK_FILE = 'store.lock'
IDENTITY_FILE = 'identity.json'
# Stores from before IDENTITY_FILE hashed this with their path. Do not change it, or every
# such store gets a new identity.
LEGACY_IDENTITY_PREFIX = 'sp-relay:'
QUARANTINE_DIR = 'quarantine'
TMP_SUFFIX = '.tmp'
MBOXLIST_HDR, MBOXLIST_ENTRY, MBOXLIST_MAX = 12, 16, 24
BOXES = {'inbox': 'InBox___', 'outbox': 'OutBox__'}
INSTALLED_STORE = '/var/lib/tuxchange'      # where install/install.sh puts the service's store
CHECKOUT_STORE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              'relay_store')


def default_store():
    """The store every tool uses when not given one, matching scripts/sp_monitor.sh:
    $SP_STORE, else relay_store in this checkout, else the installed service's store."""
    env = os.environ.get('SP_STORE')
    if env:
        return env
    if not os.path.isdir(CHECKOUT_STORE) and os.path.isdir(INSTALLED_STORE):
        return INSTALLED_STORE
    return CHECKOUT_STORE
DEFAULT_MAX_BYTES, DEFAULT_MAX_MESSAGES = 0x100000, 24


def _write_private(path, data):
    write_atomic(path, data, 0o600, durable=True)


def write_atomic(path, data, mode=0o600, durable=False, clobber=True):
    """Publish `data` at `path` through a uniquely named temporary file beside it, so a
    concurrent writer never renames our file away and a reader never sees half of it.
    `durable` also syncs the file and its directory, so a crash leaves the old or the new
    contents, never an empty file. Without `clobber`, an existing `path` is kept and
    FileExistsError raised."""
    d, base = os.path.split(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=d, prefix='.%s.' % base, suffix=TMP_SUFFIX)
    try:
        with os.fdopen(fd, 'wb') as f:
            os.fchmod(f.fileno(), mode)
            f.write(data)
            if durable:
                f.flush()
                os.fsync(f.fileno())
        if clobber:
            os.replace(tmp, path)
        else:
            try:
                os.link(tmp, path)
            finally:
                os.unlink(tmp)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    if durable:
        dfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)


def legacy_identity_seed(root):
    """-> the seed a store at `root` had before stores kept their own."""
    return hashlib.sha256((LEGACY_IDENTITY_PREFIX + os.path.abspath(root)).encode()).digest()


def read_identity(root):
    """-> {'seed': 32 bytes, 'source': 'random' | 'legacy' | 'copied'}, or None if the
    store has no identity file."""
    path = os.path.join(root, IDENTITY_FILE)
    try:
        with open(path, 'rb') as f:
            d = json.loads(f.read().decode())
        seed = bytes.fromhex(d['seed'])
    except FileNotFoundError:
        return None
    except (ValueError, KeyError, TypeError, AttributeError) as e:
        raise ValueError('%s is damaged (%s)' % (path, e)) from None
    if len(seed) != 32:
        raise ValueError('%s holds a %d-byte seed, not 32' % (path, len(seed)))
    return {'seed': seed, 'source': d.get('source') or 'random'}


def write_identity(root, seed, source, replace=False):
    """Make `seed` the store's identity. Without `replace`, raise FileExistsError if it has one."""
    data = json.dumps({'version': 1, 'seed': seed.hex(), 'source': source}).encode() + b'\n'
    write_atomic(os.path.join(root, IDENTITY_FILE), data, 0o600, durable=True, clobber=replace)


class KeyConflict(ValueError):
    """A title was offered an HMAC key different from the one it already has."""


class InboxFull(ValueError):
    """A title's inbox has no room for what arrived, so none of it was filed."""


def plan_inbound(entries, room):
    """Retail-style admission of a peer's offer, decided per title as cecd's planner does.

    `entries` are (title, bytes, messages) in the peer's order; `room(title)` gives that
    title's (free bytes, free slots). A title is admitted only if everything it declares fits,
    so a full title is refused while the others go ahead. -> {title: (bytes, messages)} for
    each admitted title; any title not in it is refused.
    """
    want = {}
    for tid, size, count in entries:
        b, n = want.get(tid, (0, 0))
        want[tid] = (b + size, n + count)
    admitted = {}
    for tid, (size, count) in want.items():
        free_bytes, free_slots = room(tid)
        if size <= free_bytes and count <= free_slots:
            admitted[tid] = (size, count)
    return admitted


class StoreBusy(RuntimeError):
    """Another process (normally the daemon) holds the store."""


def store_claimed(root):
    """-> True if some process holds `root` exclusively right now."""
    try:
        fd = os.open(os.path.join(root, LOCK_FILE), os.O_RDONLY | os.O_CLOEXEC)
    except OSError:
        return False
    try:
        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        return False
    except BlockingIOError:
        return True
    except OSError:
        return False
    finally:
        os.close(fd)


def _locked(fn):
    @functools.wraps(fn)
    def run(self, *a, **kw):
        with self.lock:
            return fn(self, *a, **kw)
    return run


def message_filename(container):
    """`_` + base64 of the 8-byte message id, '/' -> '-', unpadded."""
    mid = container[0x20:0x28]
    return '_' + base64.b64encode(mid).decode().rstrip('=').replace('/', '-')


class Store:
    """A directory holding CEC messages, in the console's own shape.

    Every public method holds `self.lock`, so threads sharing one Store see whole operations;
    hold it yourself around a read-then-write. `exclusive=True` also takes the store's
    lifetime lock, refusing with StoreBusy while another process has it, and every writer
    (the daemon, offline imports) opens it that way.
    """

    def __init__(self, root, exclusive=False, log=None):
        self.root = os.path.abspath(root)
        self.lock = threading.RLock()
        self.last_evicted = 0
        self.quarantined = []
        self.log = log or (lambda s: print(s, file=sys.stderr))
        self._lock_fd = None
        self.cec = os.path.join(self.root, 'CEC')
        fresh = not os.path.isdir(self.cec)
        os.makedirs(self.cec, mode=0o700, exist_ok=True)
        if exclusive:
            self.claim()
        self._lock_down()
        self._ensure_identity(fresh)
        if not exclusive and self._may_repair():
            self.recover()
        if not os.path.exists(self._mboxlist_path()):
            self._write_mboxlist([])
        if not os.path.exists(self._meta_path()):
            self._save_meta({'keyed_titles': ['%08x' % t for t in self.titles()], 'origins': {}})

    def claim(self):
        """Hold the store against every other process until release() or exit."""
        if self._lock_fd is not None:
            return
        fd = os.open(os.path.join(self.root, LOCK_FILE),
                     os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            raise StoreBusy('the store at %s is in use by another process '
                            '(is the daemon running?)' % self.root)
        except BaseException:
            os.close(fd)
            raise
        self._lock_fd = fd
        self.recover()

    def release(self):
        if self._lock_fd is not None:
            os.close(self._lock_fd)
            self._lock_fd = None

    @property
    def claimed(self):
        return self._lock_fd is not None

    def _may_repair(self):
        """Only the process holding the store, or any process while nobody does, moves files."""
        return self.claimed or not store_claimed(self.root)

    def _quarantine(self, path, why):
        """Move a damaged store file aside, out of the CEC tree, and say so."""
        rel = os.path.relpath(path, self.root)
        if not self._may_repair():
            self.log('  store: ignoring damaged %s (%s)' % (rel, why))
            return None
        qd = os.path.join(self.root, QUARANTINE_DIR)
        os.makedirs(qd, mode=0o700, exist_ok=True)
        dest = os.path.join(qd, '%s-%s' % (time.strftime('%Y%m%d-%H%M%S'),
                                           rel.replace(os.sep, '_')))
        base, n = dest, 1
        while os.path.exists(dest):
            dest, n = '%s.%d' % (base, n), n + 1
        os.replace(path, dest)
        self.quarantined.append((rel, why, dest))
        self.log('  store: moved damaged %s to %s (%s)' % (rel, dest, why))
        return dest

    def _message_problem(self, tid, fn, c):
        """-> why a stored message file cannot be used, or None if it is sound."""
        bad = sp_cecvalid.problems(c)
        if bad:
            return '; '.join(bad)
        if sp_cecvalid.parts(c)[2] != tid:
            return 'it belongs to title %08X' % sp_cecvalid.parts(c)[2]
        if message_filename(c) != fn:
            return 'its message id does not match its file name'
        return None

    @_locked
    def recover(self):
        """Bring the store back to a usable state after a crash or a damaged file.

        Leftover temporary files go; a damaged MBoxList is rebuilt from the title
        directories; a damaged sidecar, MBoxInfo or message is moved to quarantine/.
        -> how many files were quarantined.
        """
        before = len(self.quarantined)
        for d, _dirs, files in os.walk(self.cec):
            for f in files:
                if f.startswith('.') and f.endswith(TMP_SUFFIX):
                    try:
                        os.unlink(os.path.join(d, f))
                    except OSError:
                        pass
        for f in os.listdir(self.root):
            if f.startswith('.%s.' % META_FILE) and f.endswith(TMP_SUFFIX):
                try:
                    os.unlink(os.path.join(self.root, f))
                except OSError:
                    pass
        if os.path.exists(self._mboxlist_path()):
            try:
                self._read_mboxlist()
            except ValueError as e:
                self._quarantine(self._mboxlist_path(), e)
                found = sorted(int(n, 16) for n in os.listdir(self.cec)
                               if len(n) == 8 and os.path.isdir(os.path.join(self.cec, n))
                               and all(ch in '0123456789abcdef' for ch in n))
                self._write_mboxlist(found[:MBOXLIST_MAX])
        titles = self.titles() if os.path.exists(self._mboxlist_path()) else []
        if os.path.exists(self._meta_path()):
            try:
                m = json.load(open(self._meta_path()))
                if not isinstance(m, dict):
                    raise ValueError('not a JSON object')
            except ValueError as e:
                self._quarantine(self._meta_path(), e)
                # An all-zero key cannot be told from no key at all, so it is not trusted here.
                keyed = []
                for t in titles:
                    try:
                        k = open(os.path.join(self._title_dir(t), 'MBoxInfo____'), 'rb').read()
                    except OSError:
                        continue
                    if k[0x10:0x30].strip(b'\x00'):
                        keyed.append('%08x' % t)
                self._save_meta({'keyed_titles': keyed, 'origins': {}})
        for t in titles:
            p = os.path.join(self._title_dir(t), 'MBoxInfo____')
            if os.path.exists(p):
                info = open(p, 'rb').read()
                if len(info) < 0x30 or struct.unpack_from('<H', info)[0] != MBOXINFO_MAGIC:
                    self._quarantine(p, 'MBoxInfo is %d B or has no magic' % len(info))
                    m = self._load_meta()
                    if '%08x' % t in m['keyed_titles']:
                        m['keyed_titles'].remove('%08x' % t)
                        self._save_meta(m)
                    self.add_title(t)
            self.messages(t)
        return len(self.quarantined) - before

    def _ensure_identity(self, fresh):
        """A new store gets a random identity. One from before identity files keeps the one
        its path always gave it, so consoles that know it still do; see sp_identity."""
        if os.path.exists(os.path.join(self.root, IDENTITY_FILE)):
            return
        seed, source = ((os.urandom(32), 'random') if fresh
                        else (legacy_identity_seed(self.root), 'legacy'))
        try:
            write_identity(self.root, seed, source)
        except (FileExistsError, PermissionError):
            pass

    def _lock_down(self):
        """Close up a store written before its files were private."""
        if stat.S_IMODE(os.stat(self.cec).st_mode) == 0o700:
            return
        try:
            for d, _dirs, files in os.walk(self.cec):
                os.chmod(d, 0o700)
                for f in files:
                    os.chmod(os.path.join(d, f), 0o600)
            if os.path.exists(self._meta_path()):
                os.chmod(self._meta_path(), 0o600)
        except PermissionError:
            pass

    def _meta_path(self):
        return os.path.join(self.root, META_FILE)

    def _load_meta(self):
        try:
            m = json.load(open(self._meta_path()))
        except (OSError, ValueError):
            m = {}
        m.setdefault('keyed_titles', [])
        m.setdefault('origins', {})
        m.setdefault('receive_titles', [])
        m.setdefault('service_records', {})
        legacy = [k for k in m['origins'] if '/' not in k]
        if legacy:
            for k in legacy:
                v = m['origins'].pop(k)
                m['origins'].setdefault('%s/%s' % (v.get('box', 'inbox'), k), v)
            self._save_meta(m)
        return m

    def _save_meta(self, m):
        _write_private(self._meta_path(), json.dumps(m, indent=1, sort_keys=True).encode())

    @staticmethod
    def _okey(mid, box):
        return '%s/%s' % (box, mid.hex() if isinstance(mid, (bytes, bytearray)) else mid)

    @_locked
    def origin(self, container_or_id, box='outbox'):
        """-> {'source', 'when', 'box'} for one message IN ONE BOX, or None if never recorded."""
        mid = (container_or_id[0x20:0x28] if len(container_or_id) > 0x28 else container_or_id)
        m = self._load_meta()['origins']
        return m.get(self._okey(mid, box))

    @_locked
    def origins(self):
        return self._load_meta()['origins']

    @_locked
    def is_from_air(self, container_or_id, box='outbox'):
        o = self.origin(container_or_id, box)
        return bool(o) and str(o.get('source', '')).startswith('air:')

    def _mboxlist_path(self):
        return os.path.join(self.cec, 'MBoxList____')

    def _title_dir(self, tid):
        return os.path.join(self.cec, '%08x' % tid)

    def _box_dir(self, tid, box):
        return os.path.join(self._title_dir(tid), BOXES[box])

    def _make_title_dirs(self, tid):
        os.makedirs(self._title_dir(tid), mode=0o700, exist_ok=True)
        for box in BOXES:
            os.makedirs(self._box_dir(tid, box), mode=0o700, exist_ok=True)

    def _write_mboxlist(self, titles):
        if len(titles) > MBOXLIST_MAX:
            raise ValueError('a store holds at most %d titles, got %d'
                             % (MBOXLIST_MAX, len(titles)))
        b = bytearray(MBOXLIST_HDR + MBOXLIST_MAX * MBOXLIST_ENTRY)
        struct.pack_into('<HHII', b, 0, MBOXLIST_MAGIC, 0, 1, len(titles))
        for i, t in enumerate(titles):
            b[MBOXLIST_HDR + i * MBOXLIST_ENTRY:
              MBOXLIST_HDR + i * MBOXLIST_ENTRY + 8] = ('%08x' % t).encode()
        _write_private(self._mboxlist_path(), bytes(b))

    def _read_mboxlist(self):
        d = open(self._mboxlist_path(), 'rb').read()
        if len(d) < MBOXLIST_HDR + MBOXLIST_MAX * MBOXLIST_ENTRY:
            raise ValueError('MBoxList is %d B, too short' % len(d))
        if struct.unpack_from('<H', d)[0] != MBOXLIST_MAGIC:
            raise ValueError('MBoxList has no magic')
        return d

    @_locked
    def titles(self):
        d = self._read_mboxlist()
        n = struct.unpack_from('<I', d, 8)[0]
        out = []
        for i in range(min(n, MBOXLIST_MAX)):
            s = d[MBOXLIST_HDR + i * MBOXLIST_ENTRY:MBOXLIST_HDR + i * MBOXLIST_ENTRY + 8]
            try:
                out.append(int(s.decode('ascii'), 16))
            except ValueError:
                pass
        return out

    @_locked
    def add_title(self, tid, name=None, hmac_key=None, replace_key=False):
        """Register a title, or fill in its name or key. Idempotent.

        A key different from the one the title already has is refused with KeyConflict
        unless `replace_key`; everything is checked before anything is written.
        """
        if hmac_key is not None:
            hmac_key = bytes(hmac_key)
            if len(hmac_key) != 0x20:
                raise ValueError('an HMAC key is 32 bytes, got %d' % len(hmac_key))
        if name is not None and not isinstance(name, str):
            raise ValueError('a title name is text, got %r' % type(name).__name__)
        titles = self.titles()
        if tid not in titles and len(titles) >= MBOXLIST_MAX:
            raise ValueError('a store holds at most %d titles' % MBOXLIST_MAX)
        held = self.title_key(tid)
        if hmac_key is not None and held is not None and held != hmac_key and not replace_key:
            raise KeyConflict('title %08X already has a different HMAC key' % tid)
        self._make_title_dirs(tid)
        if tid not in titles:
            self._write_mboxlist(titles + [tid])
        p = os.path.join(self._title_dir(tid), 'MBoxInfo____')
        old = open(p, 'rb').read() if os.path.exists(p) else b''
        info = bytearray(old.ljust(0x60, b'\x00'))
        struct.pack_into('<HHI', info, 0, MBOXINFO_MAGIC, 0, 0)
        struct.pack_into('<I', info, 4, tid)
        if hmac_key is not None:
            info[0x10:0x30] = hmac_key
        if bytes(info) != old:
            _write_private(p, bytes(info))
        if hmac_key is not None:
            m = self._load_meta()
            if '%08x' % tid not in m['keyed_titles']:
                m['keyed_titles'].append('%08x' % tid)
                self._save_meta(m)
        if name is not None:
            np = os.path.join(self._title_dir(tid), 'MBoxData.010')
            data = name.encode('utf-16-le') + b'\x00\x00'
            if not os.path.exists(np) or open(np, 'rb').read() != data:
                _write_private(np, data)
        for box in BOXES:
            self._write_boxinfo(tid, box)
        return tid

    @_locked
    def title_key(self, tid):
        """The title's 32-byte HMAC key, or None if we have no MBoxInfo for it."""
        p = os.path.join(self._title_dir(tid), 'MBoxInfo____')
        if not os.path.exists(p):
            return None
        if '%08x' % tid not in self._load_meta()['keyed_titles']:
            return None
        k = open(p, 'rb').read()[0x10:0x30]
        return k if len(k) == 0x20 else None

    @_locked
    def receive_titles(self):
        """-> the registered titles enabled to receive, whether or not their outbox holds anything."""
        on = set(self._load_meta()['receive_titles'])
        return [t for t in self.titles() if '%08x' % t in on]

    @_locked
    def set_receive(self, tid, on=True):
        """Enable or disable receiving for a registered title. -> whether it is now enabled."""
        if on and tid not in self.titles():
            raise ValueError('title %08X is not registered in this store' % tid)
        m = self._load_meta()
        key = '%08x' % tid
        had = key in m['receive_titles']
        if on and not had:
            m['receive_titles'].append(key)
        elif not on and had:
            m['receive_titles'].remove(key)
        if had != bool(on):
            self._save_meta(m)
        return bool(on)

    @_locked
    def service_template(self, tid):
        """-> the service record set for a title to advertise when it only receives, or None."""
        raw = self._load_meta()['service_records'].get('%08x' % tid)
        if raw is None:
            return None
        try:
            s = sp_service.from_raw(bytes.fromhex(raw))
        except ValueError:
            return None
        return s if s.title == tid else None

    @_locked
    def set_service_template(self, tid, record=None):
        """Set (a Service or its encoding) or clear (None) a title's receive-only record."""
        if record is not None:
            if tid not in self.titles():
                raise ValueError('title %08X is not registered in this store' % tid)
            s = (sp_service.from_raw(record) if isinstance(record, (bytes, bytearray))
                 else sp_service.check(record))
            if s.title != tid:
                raise ValueError('the record names %08X, not %08X' % (s.title, tid))
        m = self._load_meta()
        key = '%08x' % tid
        if record is None:
            if m['service_records'].pop(key, None) is not None:
                self._save_meta(m)
            return None
        if m['service_records'].get(key) != s.raw().hex():
            m['service_records'][key] = s.raw().hex()
            self._save_meta(m)
        return s

    @_locked
    def title_name(self, tid):
        p = os.path.join(self._title_dir(tid), 'MBoxData.010')
        if not os.path.exists(p):
            return None
        return sp_cec.decode_utf16_name(open(p, 'rb').read())

    def _write_boxinfo(self, tid, box):
        msgs = self.messages(tid, box)
        used = sum(len(c) for _t, _b, c in msgs)
        b = bytearray(0x20)
        struct.pack_into('<HHI', b, 0, BOXINFO_MAGIC, 0, 0x20)
        struct.pack_into('<IIII', b, 8, DEFAULT_MAX_BYTES, used, DEFAULT_MAX_MESSAGES, len(msgs))
        _write_private(os.path.join(self._box_dir(tid, box), 'BoxInfo_____'), bytes(b))

    def _checked(self, container, key):
        """-> (container, title) if well-formed and, under any key we have, authentic."""
        container = sp_cecvalid.check_container(container)
        tid = sp_cecvalid.parts(container)[2]
        k = key if key is not None else self.title_key(tid)
        if k is not None and not sp_cecvalid.hmac_ok(container, k):
            raise sp_cecvalid.Invalid('%08X message %s fails its title HMAC'
                                      % (tid, container[0x20:0x28].hex()))
        return container, tid

    @_locked
    def add_message(self, container, box='inbox', name=None, key=None, origin=None, evict=True):
        """File one bare 0x6060 container. An inbox drops its oldest to make room unless `evict`
        is False."""
        if container[:2] != b'\x60\x60':
            raise ValueError('add_message takes a bare 0x6060 container; unwrap the envelope first')
        container, tid = self._checked(container, key)
        if tid not in self.titles() or name is not None or key is not None:
            self.add_title(tid, name=name, hmac_key=key)
        else:
            self._make_title_dirs(tid)
        p = os.path.join(self._box_dir(tid, box), message_filename(container))
        _write_private(p, container)
        self.last_evicted = self._trim_inbox(tid, p) if box == 'inbox' and evict else 0
        self._write_boxinfo(tid, box)
        if origin is not None:
            m = self._load_meta()
            m['origins'][self._okey(container[0x20:0x28], box)] = {
                'source': str(origin), 'when': time.time(), 'box': box}
            self._save_meta(m)
        return p

    @_locked
    def replace_outbox(self, container, name=None, key=None, origin=None):
        """Make `container` its title's only outbox message. -> how many it replaced.

        The new message is written before the old ones go, so a failure leaves the
        outbox as it was rather than empty.
        """
        if container[:2] != b'\x60\x60':
            raise ValueError('replace_outbox takes a bare 0x6060 container')
        container, tid = self._checked(container, key)
        old = self.messages(tid, 'outbox')
        self.add_message(container, 'outbox', name=name, key=key, origin=origin)
        keep = container[0x20:0x28]
        n = 0
        for t, b, c in old:
            if c[0x20:0x28] != keep:
                n += bool(self.remove_message(t, b, c))
        return n

    @_locked
    def inbox_room(self, tid):
        """-> (free bytes, free slots) left in a title's inbox under the limits BoxInfo declares."""
        msgs = self.messages(tid, 'inbox')
        used = sum(len(c) for _t, _b, c in msgs)
        return max(0, DEFAULT_MAX_BYTES - used), max(0, DEFAULT_MAX_MESSAGES - len(msgs))

    @_locked
    def file_inbound(self, containers, origin=None):
        """File one title's arrivals in its inbox together, evicting nothing.

        -> (paths, [(container, why)] for each malformed one). Raises InboxFull, filing
        nothing, when the well-formed ones do not all fit in the room left.
        """
        good, bad = [], []
        for c in containers:
            try:
                good.append(self._checked(c, None))
            except ValueError as e:
                bad.append((c, str(e)))
        if len({t for _c, t in good}) > 1:
            raise ValueError('file_inbound files one title at a time')
        if good:
            tid = good[0][1]
            held = {c[0x20:0x28]: len(c) for _t, _b, c in self.messages(tid, 'inbox')}
            new = {}
            for c, _t in good:
                new[c[0x20:0x28]] = len(c)
            slots = sum(1 for mid in new if mid not in held)
            size = sum(n - held.get(mid, 0) for mid, n in new.items())
            free_bytes, free_slots = self.inbox_room(tid)
            if slots > free_slots or size > free_bytes:
                raise InboxFull('%08X inbox has %d slot(s) and %d B free; %d message(s) need '
                                '%d slot(s) and %d B' % (tid, free_slots, free_bytes, len(new),
                                                         slots, size))
        paths = [self.add_message(c, 'inbox', origin=origin, evict=False) for c, _t in good]
        return paths, bad

    def _trim_inbox(self, tid, keep):
        """Hold a title's inbox to the limits BoxInfo declares, dropping the oldest. -> dropped."""
        d = self._box_dir(tid, 'inbox')
        found = []
        for fn in os.listdir(d):
            p = os.path.join(d, fn)
            if fn.startswith('_') and p != keep:
                st = os.stat(p)
                found.append((st.st_mtime_ns, fn, st.st_size, p))
        found.sort()
        count, used, dropped = len(found) + 1, os.stat(keep).st_size, 0
        used += sum(e[2] for e in found)
        for _t, _fn, size, p in found:
            if count <= DEFAULT_MAX_MESSAGES and used <= DEFAULT_MAX_BYTES:
                break
            with open(p, 'rb') as f:
                mid = f.read(0x28)[0x20:]
            self.remove_message(tid, 'inbox', mid)
            count, used, dropped = count - 1, used - size, dropped + 1
        return dropped

    @_locked
    def messages(self, tid=None, box=None):
        """-> [(title, box, container)] for every stored message matching the filters."""
        out = []
        for t in ([tid] if tid is not None else self.titles()):
            for b in ([box] if box is not None else sorted(BOXES)):
                d = self._box_dir(t, b)
                if not os.path.isdir(d):
                    continue
                for fn in sorted(os.listdir(d)):
                    if not fn.startswith('_'):
                        continue
                    p = os.path.join(d, fn)
                    try:
                        c = open(p, 'rb').read()
                    except FileNotFoundError:
                        continue
                    why = self._message_problem(t, fn, c)
                    if why:
                        if self._quarantine(p, why):
                            self._write_boxinfo(t, b)
                        continue
                    out.append((t, b, c))
        return out

    @_locked
    def remove_message(self, tid, box, container_or_id):
        mid = (container_or_id[0x20:0x28] if len(container_or_id) > 0x28 else container_or_id)
        fn = '_' + base64.b64encode(mid).decode().rstrip('=').replace('/', '-')
        p = os.path.join(self._box_dir(tid, box), fn)
        if os.path.exists(p):
            os.remove(p)
            self._write_boxinfo(tid, box)
            m = self._load_meta()
            if m['origins'].pop(self._okey(mid, box), None) is not None:
                self._save_meta(m)
            return True
        return False

    @_locked
    def remove_title(self, tid):
        """Forget a title entirely: its messages, its name, its key, its MBoxList entry."""
        import shutil
        n = 0
        for box in BOXES:
            for t, b, c in self.messages(tid, box):
                n += bool(self.remove_message(t, b, c))
        d = self._title_dir(tid)
        if os.path.isdir(d):
            shutil.rmtree(d, ignore_errors=True)
        self._write_mboxlist([t for t in self.titles() if t != tid])
        m = self._load_meta()
        key = '%08x' % tid
        if (key in m['keyed_titles'] or key in m['receive_titles']
                or key in m['service_records']):
            m['keyed_titles'] = [k for k in m['keyed_titles'] if k != key]
            m['receive_titles'] = [k for k in m['receive_titles'] if k != key]
            m['service_records'].pop(key, None)
            self._save_meta(m)
        return n

    @_locked
    def clear_box(self, box):
        """Empty one box across every title."""
        n = 0
        for t, b, c in self.messages(box=box):
            if self.remove_message(t, b, c):
                n += 1
        return n

    @_locked
    def verify(self, tid, container):
        """-> True/False if we hold the title's key, None if we do not."""
        k = self.title_key(tid)
        if k is None:
            return None
        return sp_cecvalid.hmac_status(container, k) == sp_cecvalid.VALID

    @_locked
    def summary(self):
        og = self.origins()
        lines = []
        for t in self.titles():
            ms = self.messages(t)
            lines.append('  %08X  %-24s %s%d message(s): %s'
                         % (t, (self.title_name(t) or '?')[:24],
                            '' if self.title_key(t) is not None else '(no key) ', len(ms),
                            ', '.join('%s %d B' % (b, len(c)) for _t, b, c in ms) or '-'))
            for _t, b, c in ms:
                o = og.get(self._okey(c[0x20:0x28], b))
                if o:
                    lines.append('              %-6s %s' % (b, o.get('source')))
        return 'store %s, %d title(s)\n%s' % (self.root, len(self.titles()), '\n'.join(lines))


def _selftest():
    import tempfile, shutil, sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import sp_cecstore, sp_savefs
    ok = tot = 0

    def chk(n, c, g=''):
        nonlocal ok, tot
        tot += 1; ok += bool(c)
        print('  [%s] %s%s' % ('PASS' if c else 'FAIL', n, ('  %s' % (g,)) if g else ''))

    tmp = tempfile.mkdtemp()
    try:
        def mode(p):
            return stat.S_IMODE(os.stat(p).st_mode)

        saved = os.environ.pop('SP_STORE', None)
        try:
            here = default_store()
            chk('the default store does not depend on the working directory',
                os.path.isabs(here) and here in (CHECKOUT_STORE, INSTALLED_STORE), here)
            os.environ['SP_STORE'] = os.path.join(tmp, 'from-env')
            chk('and $SP_STORE overrides it, as it does for the shell scripts',
                default_store() == os.path.join(tmp, 'from-env'))
        finally:
            os.environ.pop('SP_STORE', None)
            if saved is not None:
                os.environ['SP_STORE'] = saved

        p0 = Store(os.path.join(tmp, 'private'))
        p0.add_title(0x00020800, name='Mii Plaza', hmac_key=b'k' * 32)
        p0.add_message(_synthetic(0x00020800, 1, key=b'k' * 32), 'inbox', origin='air:test')
        tdir = p0._title_dir(0x00020800)
        chk('the CEC tree is closed to other users', mode(p0.cec) == 0o700)
        chk('a title directory is private', mode(tdir) == 0o700)
        chk('a box directory is private', mode(p0._box_dir(0x00020800, 'inbox')) == 0o700)
        chk('the file holding the HMAC key is private',
            mode(os.path.join(tdir, 'MBoxInfo____')) == 0o600)
        chk('MBoxList, the sidecar and BoxInfo are private',
            {mode(p0._mboxlist_path()), mode(p0._meta_path()),
             mode(os.path.join(p0._box_dir(0x00020800, 'inbox'), 'BoxInfo_____'))} == {0o600})
        msg0 = [n for n in os.listdir(p0._box_dir(0x00020800, 'inbox')) if n.startswith('_')][0]
        chk('a stored message is private',
            mode(os.path.join(p0._box_dir(0x00020800, 'inbox'), msg0)) == 0o600)
        os.chmod(p0.cec, 0o755); os.chmod(tdir, 0o755); os.chmod(p0._meta_path(), 0o644)
        os.chmod(os.path.join(tdir, 'MBoxInfo____'), 0o644)
        Store(p0.root)
        chk('a store from an older version is closed up when it is opened',
            mode(p0.cec) == 0o700 and mode(tdir) == 0o700 and mode(p0._meta_path()) == 0o600
            and mode(os.path.join(tdir, 'MBoxInfo____')) == 0o600)

        idp = os.path.join(p0.root, IDENTITY_FILE)
        first = read_identity(p0.root)
        chk('a new store gets a random identity, kept private',
            first['source'] == 'random' and first['seed'] != legacy_identity_seed(p0.root)
            and mode(idp) == 0o600, first['source'])
        Store(p0.root)
        chk('and keeps it when opened again', read_identity(p0.root) == first)
        again = os.path.join(tmp, 'again')
        Store(again)
        seed_a = read_identity(again)['seed']
        shutil.rmtree(again)
        Store(again)
        chk('a store made afresh at the same path gets a different identity',
            read_identity(again)['seed'] != seed_a)
        old = os.path.join(tmp, 'pre-identity')
        os.makedirs(os.path.join(old, 'CEC'))
        Store(old)
        chk('a store from before identity files keeps the identity its path gave it',
            read_identity(old) == {'seed': legacy_identity_seed(old), 'source': 'legacy'})
        try:
            write_identity(old, b'\0' * 32, 'random')
            kept = False
        except FileExistsError:
            kept = read_identity(old)['source'] == 'legacy'
        chk('an identity is only replaced when asked',
            kept and not [n for n in os.listdir(old) if n.endswith(TMP_SUFFIX)])
        with open(os.path.join(old, IDENTITY_FILE), 'w') as f:
            f.write('{"seed": "zz"}')
        chk('a damaged identity file is an error, not a silent new identity',
            _raises(lambda: read_identity(old)))

        lim =Store(os.path.join(tmp, 'limit'))
        for i in range(1, DEFAULT_MAX_MESSAGES + 7):
            lim.add_message(_synthetic(0x00030600, i), 'inbox', origin='air:test')
            time.sleep(0.005)
        ids = {int.from_bytes(c[0x20:0x28], 'little') for _t, _b, c in lim.messages(box='inbox')}
        chk('an inbox stops at its message limit', len(ids) == DEFAULT_MAX_MESSAGES, len(ids))
        chk('and the oldest messages are the ones dropped', min(ids) == 7 and max(ids) == 30, ids)
        chk('and the last add reports what it dropped', lim.last_evicted == 1, lim.last_evicted)
        chk('a dropped message loses its origin record too',
            len(lim.origins()) == DEFAULT_MAX_MESSAGES)
        lim.add_message(_synthetic(0x00030600, 30), 'inbox', origin='air:test')
        chk('receiving the same message again drops nothing',
            lim.last_evicted == 0 and len(lim.messages(box='inbox')) == DEFAULT_MAX_MESSAGES)
        for i in range(1, DEFAULT_MAX_MESSAGES + 7):
            lim.add_message(_synthetic(0x00030600, i), 'outbox')
        chk('the outbox is not limited', len(lim.messages(box='outbox')) == DEFAULT_MAX_MESSAGES + 6)
        big = Store(os.path.join(tmp, 'limit-bytes'))
        for i in range(1, 13):
            big.add_message(_synthetic(0x00030600, i, sp_cec.MAX_TOTAL), 'inbox')
            time.sleep(0.005)
        used = sum(len(c) for _t, _b, c in big.messages(box='inbox'))
        chk('an inbox stops at its byte limit', used <= DEFAULT_MAX_BYTES, used)
        chk('and still holds the newest message',
            12 in {int.from_bytes(c[0x20:0x28], 'little') for _t, _b, c in big.messages(box='inbox')})
        cap = Store(os.path.join(tmp, 'capacity'))
        TA, TB = 0x00030600, 0x00020800
        for i in range(1, DEFAULT_MAX_MESSAGES - 1):
            cap.add_message(_synthetic(TA, i), 'inbox', origin='air:test')
        chk('the room left counts slots and bytes',
            cap.inbox_room(TA) == (DEFAULT_MAX_BYTES - 0x200 * (DEFAULT_MAX_MESSAGES - 2), 2)
            and cap.inbox_room(TB) == (DEFAULT_MAX_BYTES, DEFAULT_MAX_MESSAGES),
            (cap.inbox_room(TA), cap.inbox_room(TB)))
        plan = plan_inbound([(TA, 0x600, 3), (TB, 0x600, 3)], cap.inbox_room)
        chk('a title with too few slots is refused and the other admitted',
            plan == {TB: (0x600, 3)}, plan)
        chk('an exact fit in slots is admitted',
            plan_inbound([(TA, 0x400, 2)], cap.inbox_room) == {TA: (0x400, 2)})
        fb = cap.inbox_room(TA)[0]
        chk('a title over its free bytes is refused, even with slots free',
            plan_inbound([(TA, fb + 1, 1)], cap.inbox_room) == {})
        chk('an exact fit in bytes is admitted',
            plan_inbound([(TA, fb, 1)], cap.inbox_room) == {TA: (fb, 1)})
        chk('two entries for one title are admitted or refused together',
            plan_inbound([(TA, 0x200, 2), (TA, 0x200, 1)], cap.inbox_room) == {})
        before = {c[0x20:0x28] for _t, _b, c in cap.messages(TA, 'inbox')}
        three = [_synthetic(TA, 100 + i) for i in range(3)]
        chk('arrivals that do not fit are refused whole',
            _raises(lambda: cap.file_inbound(three, origin='air:test'), InboxFull)
            and {c[0x20:0x28] for _t, _b, c in cap.messages(TA, 'inbox')} == before)
        chk('and no unread message is dropped for them', before <= {
            c[0x20:0x28] for _t, _b, c in cap.messages(TA, 'inbox')} and cap.last_evicted == 0)
        paths, bad = cap.file_inbound(three[:2], origin='air:test')
        chk('an exact fit is filed', len(paths) == 2 and not bad and cap.inbox_room(TA)[1] == 0)
        chk('a message already held takes no new slot',
            cap.file_inbound(three[:1], origin='air:test')[0] != [])
        chk('a full title refuses even one more',
            _raises(lambda: cap.file_inbound(three[2:], origin='air:test'), InboxFull))
        cap.remove_message(TA, 'inbox', three[0])
        chk('and admits it once a message is read and removed',
            plan_inbound([(TA, 0x200, 1)], cap.inbox_room) == {TA: (0x200, 1)}
            and len(cap.file_inbound(three[2:], origin='air:test')[0]) == 1)
        junk = bytearray(_synthetic(TB, 7)); junk[4:8] = b'\xff\xff\xff\x7f'
        paths, bad = cap.file_inbound([_synthetic(TB, 8), bytes(junk)], origin='air:test')
        chk('a malformed arrival is reported and the rest filed', len(paths) == 1 and len(bad) == 1)
        chk('arrivals for two titles are not filed as one',
            _raises(lambda: cap.file_inbound([_synthetic(TA, 9), _synthetic(TB, 9)])))
        held = Store(os.path.join(tmp, 'held'), exclusive=True)
        try:
            Store(held.root, exclusive=True)
            second = 'opened'
        except StoreBusy:
            second = 'refused'
        chk('a second writer cannot open a store another process holds', second == 'refused')
        chk('and the store reports itself held', store_claimed(held.root))
        held.release()
        chk('it can be opened again once released',
            not store_claimed(held.root) and Store(held.root, exclusive=True).claimed)

        # Two registrations racing on MBoxList used to lose one title, orphaning its directory.
        reg = Store(os.path.join(tmp, 'race'))
        real_write, errs = reg._write_mboxlist, []

        def slow_write(ts):
            time.sleep(0.01)
            real_write(ts)

        reg._write_mboxlist = slow_write

        def register(base):
            try:
                for i in range(8):
                    reg.add_title(base + i)
            except Exception as e:
                errs.append(e)

        import threading
        ts = [threading.Thread(target=register, args=(b,)) for b in (0x00040000, 0x00050000)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        on_disk = {int(n, 16) for n in os.listdir(reg.cec) if n != 'MBoxList____'}
        chk('titles registered from two threads at once are all listed',
            not errs and set(reg.titles()) == on_disk and len(on_disk) == 16,
            '%d listed, %d on disk %s' % (len(reg.titles()), len(on_disk), errs[:1]))

        mal = bytearray(_synthetic(0x00030600, 77))
        struct.pack_into('<I', mal, 8, 0xFFFFFFF0)
        chk('a container with an impossible header_size is refused',
            _raises(lambda: big.add_message(bytes(mal), 'inbox'))
            and 77 not in {int.from_bytes(c[0x20:0x28], 'little') for _t, _b, c in big.messages()})
        chk('a container with trailing bytes is refused',
            _raises(lambda: big.add_message(_synthetic(0x00030600, 78) + bytes(4), 'inbox')))
        chk('an oversized message is refused for the inbox',
            _raises(lambda: big.add_message(_synthetic(0x00030600, 99, sp_cec.MAX_TOTAL + 4), 'inbox')))
        cap = Store(os.path.join(tmp, 'limit-titles'))
        for i in range(MBOXLIST_MAX):
            cap.add_message(_synthetic(0x00100000 + i, 1), 'inbox')
        over = 0x00100000 + MBOXLIST_MAX
        chk('a title past the store limit is refused',
            _raises(lambda: cap.add_message(_synthetic(over, 1), 'inbox')))
        chk('and leaves no directories behind', not os.path.exists(cap._title_dir(over)))

        rp = Store(os.path.join(tmp, 'replace'))
        rp.add_message(_synthetic(0x00030600, 1), 'outbox')
        rp.add_message(_synthetic(0x00030600, 2), 'outbox')
        rp.add_message(_synthetic(0x00020800, 3), 'outbox')
        rp.add_message(_synthetic(0x00030600, 4), 'inbox')
        n = rp.replace_outbox(_synthetic(0x00030600, 5, key=b'r' * 32), key=b'r' * 32,
                             origin='authored:test')
        out = [int.from_bytes(c[0x20:0x28], 'little') for _t, _b, c in rp.messages(0x00030600, 'outbox')]
        chk('replace_outbox leaves exactly the new message', out == [5], out)
        chk('and reports the two it replaced', n == 2, n)
        chk('other titles and the inbox are untouched',
            len(rp.messages(0x00020800, 'outbox')) == 1 and len(rp.messages(0x00030600, 'inbox')) == 1)
        chk('a message failing its title key is refused',
            _raises(lambda: rp.add_message(_synthetic(0x00030600, 6, key=b'x' * 32), 'outbox')))
        chk('the key it was given is recorded on an existing title', rp.title_key(0x00030600) == b'r' * 32)
        chk('and the origin', rp.origin(_synthetic(0x00030600, 5, key=b'r' * 32))['source'] == 'authored:test')
        chk('replacing a message with itself keeps it',
            rp.replace_outbox(_synthetic(0x00030600, 5, key=b'r' * 32)) == 0
            and len(rp.messages(0x00030600, 'outbox')) == 1)
        chk('replace_outbox on a new title adds it', rp.replace_outbox(_synthetic(0x00141000, 1)) == 0
            and 0x00141000 in rp.titles())
        chk('an enveloped message is refused by replace_outbox',
            _raises(lambda: rp.replace_outbox(b'\x61\x61' + b'\x00' * 200)))

        tk = Store(os.path.join(tmp, 'title-keys'))
        tk.add_message(_synthetic(0x00020800, 1, key=b'p' * 32), 'inbox')
        tk.add_message(_synthetic(0x00020800, 2, key=b'p' * 32), 'outbox', name='Mii Plaza',
                       key=b'p' * 32)
        chk('a key given with a message for a title already received is recorded',
            tk.title_key(0x00020800) == b'p' * 32 and tk.title_name(0x00020800) == 'Mii Plaza')
        other = _synthetic(0x00020800, 3, key=b'q' * 32)
        chk('a different key for a keyed title is refused',
            _raises(lambda: tk.add_message(other, 'outbox', key=b'q' * 32), KeyConflict)
            and _raises(lambda: tk.add_title(0x00020800, hmac_key=b'q' * 32), KeyConflict))
        chk('and neither the key nor the outbox changed',
            tk.title_key(0x00020800) == b'p' * 32 and len(tk.messages(0x00020800, 'outbox')) == 1)
        tk.add_title(0x00020800, hmac_key=b'q' * 32, replace_key=True)
        chk('a key can still be replaced on purpose', tk.title_key(0x00020800) == b'q' * 32)
        chk('a malformed key is refused before the title is created',
            _raises(lambda: tk.add_title(0x00030600, name='x', hmac_key=b'short'))
            and 0x00030600 not in tk.titles() and not os.path.exists(tk._title_dir(0x00030600)))

        fw = Store(os.path.join(tmp, 'failed-write'), log=lambda m: None)
        first = _synthetic(0x00030600, 9, key=b'f' * 32)
        fw.replace_outbox(first, key=b'f' * 32)
        mpath = os.path.join(fw._box_dir(0x00030600, 'outbox'), message_filename(first))
        real_fsync = os.fsync

        def failing_fsync(fd):
            raise OSError(28, 'No space left on device')

        os.fsync = failing_fsync
        try:
            failed = _raises(lambda: fw.replace_outbox(first, key=b'f' * 32), OSError)
        finally:
            os.fsync = real_fsync
        chk('a write that fails part-way leaves the message it was replacing whole',
            failed and open(mpath, 'rb').read() == first)
        chk('and leaves no temporary file behind',
            not [f for f in os.listdir(os.path.dirname(mpath)) if f.endswith(TMP_SUFFIX)])

        fw.add_message(_synthetic(0x00030600, 10, key=b'f' * 32), 'outbox')
        open(mpath, 'wb').close()
        stray = os.path.join(os.path.dirname(mpath), '.%s.abc%s' % (message_filename(first),
                                                                    TMP_SUFFIX))
        open(stray, 'wb').close()
        reopened = Store(fw.root, exclusive=True, log=lambda m: None)
        chk('an empty message file is quarantined when the store is opened, not served',
            [int.from_bytes(c[0x20:0x28], 'little') for _t, _b, c in reopened.messages()] == [10]
            and len(reopened.quarantined) == 1
            and os.path.exists(reopened.quarantined[0][2]), reopened.quarantined)
        chk('and BoxInfo counts what is left',
            _boxinfo_count(reopened, 0x00030600, 'outbox') == 1)
        chk('a temporary file left by a crash is cleaned up', not os.path.exists(stray))
        reopened.release()

        rt = Store(os.path.join(tmp, 'runtime-damage'), log=lambda m: None)
        rt.add_message(_synthetic(0x00030600, 1), 'inbox')
        rt.add_message(_synthetic(0x00030600, 2), 'inbox')
        p2 = os.path.join(rt._box_dir(0x00030600, 'inbox'), message_filename(_synthetic(0x00030600, 2)))
        open(p2, 'r+b').truncate(0x40)
        chk('a message damaged while the store is open is set aside, not raised on',
            [int.from_bytes(c[0x20:0x28], 'little') for _t, _b, c in rt.messages()] == [1]
            and not os.path.exists(p2))

        dm = Store(os.path.join(tmp, 'damaged-meta'), log=lambda m: None)
        dm.add_message(_synthetic(0x00030600, 1, key=b'd' * 32), 'inbox', key=b'd' * 32)
        dm.add_message(_synthetic(0x00020800, 1), 'inbox')
        open(dm._mboxlist_path(), 'wb').close()
        open(dm._meta_path(), 'w').write('{"keyed_ti')
        dm2 = Store(dm.root, log=lambda m: None)
        chk('an empty MBoxList is rebuilt from the title directories',
            sorted(dm2.titles()) == [0x00020800, 0x00030600], dm2.titles())
        chk('a damaged sidecar is rebuilt, keeping the keys MBoxInfo holds',
            dm2.title_key(0x00030600) == b'd' * 32 and dm2.title_key(0x00020800) is None)
        chk('and both damaged files were kept in quarantine/',
            len(dm2.quarantined) == 2
            and all(os.path.exists(q[2]) for q in dm2.quarantined))

        sr = Store(os.path.join(tmp, 'recv'))
        chk('a fresh store receives for no title', sr.receive_titles() == [])
        chk('an unregistered title cannot be enabled to receive',
            _raises(lambda: sr.set_receive(0x00020800)))
        sr.add_title(0x00020800)
        sr.add_title(0x00030600)
        sr.set_receive(0x00020800)
        chk('a registered title with an empty outbox can be enabled to receive',
            sr.receive_titles() == [0x00020800] and sr.messages(0x00020800) == [])
        chk('the setting survives reopening the store',
            Store(os.path.join(tmp, 'recv')).receive_titles() == [0x00020800])
        sr.set_receive(0x00030600)
        sr.set_receive(0x00020800, False)
        chk('it can be turned off per title', sr.receive_titles() == [0x00030600])
        chk('turning off a title that is not enabled is not an error',
            sr.set_receive(0x00020800, False) is False)
        sr.remove_title(0x00030600)
        sr.add_title(0x00030600)
        chk('removing a title forgets that it received',
            sr.receive_titles() == [])

        import lp_corpus as corpus
        src = corpus.path('console_nand') or ''
        if not os.path.exists(src):
            print('  [SKIP] the rest of the suite: it is about importing a real console\n'
                  '         save image, and none is in the corpus (%s)' % corpus.why_skipped())
            print('\n%d/%d checks passed' % (ok, tot))
            return 0 if ok == tot else 1
        fs = sp_savefs.SaveFS(open(src, 'rb').read())
        meta = sp_cecstore.title_metadata(fs)
        files = {x['path']: x for x in fs.files()}

        dump_root = os.path.join(tmp, 'dump')
        s = Store(dump_root)
        chk('a fresh store has no titles', s.titles() == [])
        chk('and its MBoxList parses as version 1, count 0',
            sp_cecstore.parse_mboxlist(open(s._mboxlist_path(), 'rb').read())
            == {'version': 1, 'count': 0, 'entries': [], 'titles': [], 'nonempty': []})

        n = 0
        for p in sorted(x for x in files if '/OutBox__/_' in x or '/InBox___/_' in x):
            c = fs.read(files[p])
            c = c if c[:2] == b'\x60\x60' else c[0x14:]
            t = sp_cec.parse_header(c)['cec_title_id']
            box = 'inbox' if '/InBox___/' in p else 'outbox'
            s.add_message(c, box, name=meta.get(t, {}).get('name'),
                          key=meta.get(t, {}).get('hmac_key'))
            n += 1
        chk('every message from the dump was filed', len(s.messages()) == n, len(s.messages()))
        chk('the title list matches the dump',
            sorted(s.titles()) == sorted(t for t in meta if meta[t]['inbox'] or meta[t]['outbox']),
            len(s.titles()))

        found = sp_cecstore.scan_tree(dump_root)
        chk('sp_cecstore reads the store back', len(found) == n, len(found))
        chk('MBoxList round-trips through the reader',
            sorted(sp_cecstore.parse_mboxlist(open(s._mboxlist_path(), 'rb').read())['titles'])
            == sorted(s.titles()))

        bad = [(t, b) for t, b, c in s.messages() if s.verify(t, c) is False]
        chk('every stored message still verifies its HMAC', not bad, bad)
        chk('every title has its 32-byte key, all-zero ones included',
            all(s.title_key(t) is not None and len(s.title_key(t)) == 0x20 for t in s.titles()))
        chk('the keys are byte-identical to the dump\'s',
            all(s.title_key(t) == meta[t]['hmac_key'] for t in s.titles() if meta[t]['hmac_key']))
        chk("nintendogs' all-zero key is kept, and its message verifies under it",
            s.title_key(0x00030B00) == b'\x00' * 0x20 and
            all(s.verify(t, c) for t, _b, c in s.messages(0x00030B00)))
        chk('so did the names', s.title_name(0x00020800) == 'StreetPass Mii Plaza',
            s.title_name(0x00020800))
        s_odd = Store(os.path.join(tmp, 'oddname'))
        s_odd.add_title(0x001A0400, name=sp_cec.decode_utf16_name(
            'Super Mario Maker'.encode('utf-16-le') + b'\x00'))
        chk('an odd-length name file does not gain a replacement character',
            s_odd.title_name(0x001A0400) == 'Super Mario Maker',
            repr(s_odd.title_name(0x001A0400)))
        chk('and the name survives a rewrite unchanged',
            '\ufffd' not in (s_odd.title_name(0x001A0400) or ''))

        orig = {p.split('/')[-1] for p in files if '/OutBox__/_' in p or '/InBox___/_' in p}
        ours = set()
        for t in s.titles():
            for b in BOXES:
                d = s._box_dir(t, b)
                ours |= {f for f in os.listdir(d) if f.startswith('_')}
        chk('filenames are byte-identical to the console\'s', ours == orig,
            sorted(ours ^ orig)[:4])

        c0 = s.messages(0x00030600, 'outbox')[0][2]
        s.add_message(c0, 'outbox')
        chk('re-filing the same message does not duplicate it',
            len(s.messages(0x00030600, 'outbox')) == 1)
        bi = sp_cecstore.parse_boxinfo(
            open(os.path.join(s._box_dir(0x00030600, 'outbox'), 'BoxInfo_____'), 'rb').read())
        chk('BoxInfo counts the message and its bytes',
            bi['num_messages'] == 1 and bi['used_bytes'] == len(c0), bi)
        chk('a message can be removed', s.remove_message(0x00030600, 'outbox', c0)
            and s.messages(0x00030600, 'outbox') == [])
        chk('removing it again reports nothing to do',
            s.remove_message(0x00030600, 'outbox', c0) is False)
        chk('an enveloped message is refused', _raises(lambda: s.add_message(b'\x61\x61' + b'\x00' * 200)))
        chk('more than 24 titles is refused',
            _raises(lambda: s._write_mboxlist(list(range(25)))))

        s2 = Store(os.path.join(tmp, 'prov'))
        plaza = [c for _t, _b, c in s.messages(0x00020800)][0]
        s2.add_message(plaza, 'inbox', key=meta[0x00020800]['hmac_key'],
                       origin='air:96:58:cb:11:22:33')
        chk('a message records where it came from',
            s2.origin(plaza, 'inbox')['source'] == 'air:96:58:cb:11:22:33', s2.origin(plaza, 'inbox'))
        chk('and an air-sourced message is recognisable as one', s2.is_from_air(plaza, 'inbox'))
        chk('provenance survives reopening the store',
            Store(os.path.join(tmp, 'prov')).is_from_air(plaza, 'inbox'))
        mk7c = [c for _t, _b, c in s.messages(0x0008C500)][0]
        s2.add_message(mk7c, 'outbox', key=meta[0x0008C500]['hmac_key'],
                       origin='console_nand')
        chk('an imported message is NOT air-sourced', not s2.is_from_air(mk7c))
        chk('a message with no recorded origin reports None',
            Store(os.path.join(tmp, 'noprov')).origin(plaza, 'inbox') is None)
        s2.add_message(plaza, 'outbox', origin='/operator/dump.bin')
        chk('importing a copy does NOT erase the air record on the other box',
            s2.is_from_air(plaza, 'inbox') and not s2.is_from_air(plaza, 'outbox'),
            (s2.origin(plaza, 'inbox'), s2.origin(plaza, 'outbox')))
        s2.remove_message(0x00020800, 'inbox', plaza)
        chk('removing a message drops its provenance', s2.origin(plaza, 'inbox') is None)
        chk('and leaves the other box\'s record intact',
            s2.origin(plaza, 'outbox')['source'] == '/operator/dump.bin')

        s3 = Store(os.path.join(tmp, 'nokey'))
        s3.add_message(plaza, 'inbox')
        chk('a title we were never given a key for reports no key',
            s3.title_key(0x00020800) is None, s3.title_key(0x00020800))
        chk('and its message verifies as UNKNOWN, not as forged',
            s3.verify(0x00020800, plaza) is None, s3.verify(0x00020800, plaza))
        s3.add_title(0x00020800, hmac_key=meta[0x00020800]['hmac_key'])
        chk('supplying the key later makes it real',
            s3.title_key(0x00020800) == meta[0x00020800]['hmac_key'])
        chk('and the message now verifies', s3.verify(0x00020800, plaza) is True)
        chk("nintendogs' all-zero key still counts as a real key after the change",
            s.title_key(0x00030B00) == b'\x00' * 0x20)
        s4 = Store(os.path.join(tmp, 'migrate'))
        s4.add_message(plaza, 'outbox', key=meta[0x00020800]['hmac_key'])
        os.remove(s4._meta_path())
        chk('a pre-sidecar store keeps its keys when reopened',
            Store(os.path.join(tmp, 'migrate')).title_key(0x00020800)
            == meta[0x00020800]['hmac_key'])

        s6 = Store(os.path.join(tmp, 'rmtitle'))
        for t, b, c in s.messages():
            s6.add_message(c, b, key=meta.get(t, {}).get('hmac_key'))
        n_t = len(s6.titles())
        n_m = len(s6.messages(0x00020800))
        chk('removing a title reports the messages that went with it',
            s6.remove_title(0x00020800) == n_m, n_m)
        chk('the title is gone from the list',
            0x00020800 not in s6.titles() and len(s6.titles()) == n_t - 1)
        chk('its directory is gone from disk',
            not os.path.exists(s6._title_dir(0x00020800)))
        chk('and the reader agrees the store shrank',
            len(sp_cecstore.parse_mboxlist(open(s6._mboxlist_path(), 'rb').read())['titles'])
            == n_t - 1)
        other = [t for t in s6.titles() if meta.get(t, {}).get('hmac_key')][0]
        chk('other titles keep their keys', s6.title_key(other) == meta[other]['hmac_key'],
            '%08X' % other)
        chk('and their messages', len(s6.messages(other)) == len(s.messages(other)))
        chk('removing a title that is not there is not an error', s6.remove_title(0x00999900) == 0)

        sm = Store(os.path.join(tmp, 'legacy'))
        sm.add_message(plaza, 'inbox', origin='air:11:22:33:44:55:66')
        raw = json.load(open(sm._meta_path()))
        raw['origins'] = {k.split('/', 1)[1]: v for k, v in raw['origins'].items()}
        json.dump(raw, open(sm._meta_path(), 'w'))
        chk('an id-only origin record migrates to a per-box one instead of vanishing',
            Store(os.path.join(tmp, 'legacy')).is_from_air(plaza, 'inbox'),
            json.load(open(sm._meta_path()))['origins'])

        s5 = Store(os.path.join(tmp, 'swap'))
        for t, b, c in s.messages():
            s5.add_message(c, b)
        n_out = len(s5.messages(box='outbox'))
        n_in = len(s5.messages(box='inbox'))
        chk('clear_box empties one box and reports the count',
            s5.clear_box('outbox') == n_out and s5.messages(box='outbox') == [], n_out)
        chk('and leaves the other box alone', len(s5.messages(box='inbox')) == n_in, n_in)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print('\n%d/%d checks passed' % (ok, tot))
    return 0 if ok == tot else 1


def _synthetic(tid, n, size=0x200, key=None):
    """A well-formed bare container of `size` bytes; any excess over a full body is an ex-header."""
    body = min(size - 0x90, sp_cec.MAX_BODY)
    b = bytearray(size)
    struct.pack_into('<HH', b, 0, 0x6060, 0)
    struct.pack_into('<III', b, 4, size, size - body - 0x20, body)
    if size - body - 0x20 > 0x70:
        struct.pack_into('<II', b, 0x70, 1, size - body - 0x20 - 0x78)
    struct.pack_into('<I', b, 0x10, tid)
    b[0x20:0x28] = n.to_bytes(8, 'little')
    if key is not None:
        import hashlib, hmac
        b[size - 0x20:] = hmac.new(key, b[size - body - 0x20:size - 0x20], hashlib.sha256).digest()
    return bytes(b)


def _raises(fn, exc=ValueError):
    try:
        fn(); return False
    except exc:
        return True


def _boxinfo_count(store, tid, box):
    b = open(os.path.join(store._box_dir(tid, box), 'BoxInfo_____'), 'rb').read()
    return struct.unpack_from('<I', b, 0x14)[0]


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2 or sys.argv[1] == '--selftest':
        sys.exit(_selftest())
    print(Store(sys.argv[1]).summary())
