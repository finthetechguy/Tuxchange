#!/usr/bin/env python3
"""Read CEC data to import, safely and within limits.

The daemon runs as root, but whoever asks it to import a path must only get what they could
read themselves. So a control client's import is read by a short-lived worker running with
that client's uid and groups, and the daemon validates what the worker hands back as it would
any untrusted input. Reads go through file descriptors, never follow a symlink below the
chosen path, and only take regular files.
"""
import base64, errno, json, os, re, selectors, stat, subprocess, sys, time

import sp_cec, sp_cecstore, sp_savefs

FILE_MAX = 4 << 20          # a file inside a directory tree
IMAGE_MAX = 64 << 20        # a single file named directly: a save image or a blob
TOTAL_MAX = 512 << 20       # bytes read across the whole import
FILES_MAX = 50000           # files looked at across the whole import
MESSAGES_MAX = 4096
SECONDS = 30.0
OUTPUT_MAX = 48 << 20       # what the daemon accepts back from a worker
META_READ_MAX = 0x1000
NAME_MAX = 64

_OPEN = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_HERE = os.path.dirname(os.path.abspath(__file__))


class Refused(ValueError):
    """An import that was not done; `code` says why, for a client to act on."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class Budget:
    def __init__(self, seconds=SECONDS, total=TOTAL_MAX, files=FILES_MAX):
        self.deadline = time.monotonic() + seconds
        self.total, self.files = total, files
        self.read = self.seen = 0

    def file(self):
        self.seen += 1
        if self.seen > self.files:
            raise Refused('too_many_files', 'more than %d files to look through' % self.files)
        if time.monotonic() > self.deadline:
            raise Refused('timeout', 'reading the import took too long')

    def take(self, n):
        self.read += n
        if self.read > self.total:
            raise Refused('too_large', 'more than %d bytes to read' % self.total)


def _read_fd(fd, limit, budget):
    """-> the regular file's bytes, or None if it is not one or is over `limit`."""
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_size > limit:
        return None
    budget.take(st.st_size)
    chunks, got = [], 0
    while True:
        b = os.read(fd, min(1 << 20, limit + 1 - got))
        if not b:
            break
        chunks.append(b)
        got += len(b)
        if got > limit:
            return None
    return b''.join(chunks)


def _read_at(dir_fd, name, limit, budget):
    budget.file()
    try:
        fd = os.open(name, _OPEN, dir_fd=dir_fd)
    except OSError as e:
        if e.errno in (errno.ELOOP, errno.EACCES, errno.EPERM, errno.ENOENT, errno.ENXIO):
            return None
        raise
    try:
        return _read_fd(fd, limit, budget)
    finally:
        os.close(fd)


def _message(path, box, raw):
    return {'path': path, 'box': box, 'raw': raw}


def _box_of(rel):
    return ('outbox' if sp_cecstore.CEC_FILENAMES['outbox'] in rel else
            'inbox' if sp_cecstore.CEC_FILENAMES['inbox'] in rel else '?')


def _read_tree(top_fd, shown, budget):
    msgs, meta = [], {}
    for dirpath, _dirs, files, dfd in os.fwalk('.', dir_fd=top_fd, follow_symlinks=False):
        rel_dir = os.path.normpath(dirpath)
        parts = os.path.normpath(os.path.join(shown, rel_dir)).split(os.sep)
        tid = None
        if len(parts) >= 2 and parts[-2].upper() == 'CEC' and re.fullmatch(r'[0-9a-fA-F]{8}',
                                                                           parts[-1]):
            tid = int(parts[-1], 16)
        for fn in sorted(files):
            rel = os.path.normpath(os.path.join(rel_dir, fn))
            if tid is not None and fn in ('MBoxInfo____', 'MBoxData.010'):
                data = _read_at(dfd, fn, META_READ_MAX, budget)
                if data is None:
                    continue
                e = meta.setdefault(tid, {'name': None, 'hmac_key': None})
                if fn == 'MBoxInfo____':
                    try:
                        e['hmac_key'] = sp_cecstore.parse_mboxinfo(data)['hmac_key']
                    except ValueError:
                        pass
                else:
                    e['name'] = sp_cec.decode_utf16_name(data)
                continue
            data = _read_at(dfd, fn, FILE_MAX, budget)
            if data is None or len(data) < 0x84:
                continue
            for c in sp_cecstore.find_containers(data):
                msgs.append(_message(rel, _box_of(rel), c['raw']))
                if len(msgs) > MESSAGES_MAX:
                    raise Refused('too_many_messages', 'more than %d messages' % MESSAGES_MAX)
    return msgs, meta


def _read_blob(data, name):
    if data[:4] == sp_savefs.SAVE_MAGIC:
        fs = sp_savefs.SaveFS(data)
        msgs = [_message(m['path'], m['box'], m['raw'])
                for m in sp_cecstore.scan_save_image(data)]
        meta = {t: {'name': e['name'], 'hmac_key': e['hmac_key']}
                for t, e in sp_cecstore.title_metadata(fs).items()}
    else:
        msgs = [_message(name, '?', c['raw']) for c in sp_cecstore.find_containers(data)]
        meta = {}
    if len(msgs) > MESSAGES_MAX:
        raise Refused('too_many_messages', 'more than %d messages' % MESSAGES_MAX)
    return msgs, meta


def read_source(path, budget=None):
    """-> {'messages': [{'path', 'box', 'raw'}], 'meta': {title: {'name', 'hmac_key'}}}.

    Reads with the caller's own rights. `path` itself may be a symlink; nothing under it is
    followed, and a FIFO, device or socket is never opened for reading.
    """
    budget = budget or Budget()
    try:
        st = os.stat(path)
    except OSError as e:
        raise Refused('unreadable', 'cannot read %s: %s' % (path, e.strerror))
    if not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)):
        raise Refused('not_a_file', '%s is not a regular file or a directory' % path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as e:
        raise Refused('unreadable', 'cannot read %s: %s' % (path, e.strerror))
    try:
        st = os.fstat(fd)
        if stat.S_ISDIR(st.st_mode):
            msgs, meta = _read_tree(fd, os.path.abspath(path), budget)
        elif stat.S_ISREG(st.st_mode):
            budget.file()
            data = _read_fd(fd, IMAGE_MAX, budget)
            if data is None:
                raise Refused('too_large', '%s is over %d bytes' % (path, IMAGE_MAX))
            try:
                msgs, meta = _read_blob(data, os.path.basename(path))
            except Refused:
                raise
            except Exception as e:
                raise Refused('unreadable', 'cannot read %s as CEC data: %s' % (path, e))
        else:
            raise Refused('not_a_file', '%s is not a regular file or a directory' % path)
    finally:
        os.close(fd)
    return {'messages': msgs, 'meta': {t: _meta_entry(e.get('name'), e.get('hmac_key'))
                                       for t, e in meta.items()}}


def _meta_entry(name, key):
    if not isinstance(name, str) or len(name) > NAME_MAX:
        name = None
    if not isinstance(key, (bytes, bytearray)) or len(key) != 0x20:
        key = None
    return {'name': name, 'hmac_key': bytes(key) if key else None}


def _encode(source):
    return json.dumps({
        'messages': [{'path': m['path'], 'box': m['box'],
                      'raw': base64.b64encode(m['raw']).decode()} for m in source['messages']],
        'meta': {'%08x' % t: {'name': e.get('name'),
                              'hmac_key': e['hmac_key'].hex() if e.get('hmac_key') else None}
                 for t, e in source['meta'].items()}})


def _decode(text):
    """A worker's reply -> a source, checked as strictly as a request off the socket."""
    try:
        d = json.loads(text)
    except ValueError:
        raise Refused('worker_failed', 'the import reader returned something unreadable')
    if not isinstance(d, dict):
        raise Refused('worker_failed', 'the import reader returned something unreadable')
    if 'error' in d:
        code = d.get('code') if isinstance(d.get('code'), str) else 'worker_failed'
        raise Refused(code[:32], str(d['error'])[:500])
    msgs, meta = d.get('messages'), d.get('meta')
    if not isinstance(msgs, list) or not isinstance(meta, dict) or len(msgs) > MESSAGES_MAX:
        raise Refused('worker_failed', 'the import reader returned a malformed list')
    out = {'messages': [], 'meta': {}}
    for m in msgs:
        if (not isinstance(m, dict) or m.get('box') not in ('inbox', 'outbox', '?')
                or not isinstance(m.get('path'), str) or len(m['path']) > 4096
                or not isinstance(m.get('raw'), str)):
            raise Refused('worker_failed', 'the import reader returned a malformed message')
        try:
            raw = base64.b64decode(m['raw'], validate=True)
        except ValueError:
            raise Refused('worker_failed', 'the import reader returned a malformed message')
        c = sp_cecstore.container_at(raw)
        if not c or c['offset'] != 0 or len(c['raw']) != len(raw):
            raise Refused('worker_failed', 'the import reader returned something not CEC')
        out['messages'].append(_message(m['path'], m['box'], raw))
    for k, e in meta.items():
        if not re.fullmatch(r'[0-9a-f]{8}', k) or not isinstance(e, dict):
            raise Refused('worker_failed', 'the import reader returned malformed title data')
        key = e.get('hmac_key')
        key = bytes.fromhex(key) if isinstance(key, str) and re.fullmatch(r'[0-9a-f]{64}', key) else None
        out['meta'][int(k, 16)] = _meta_entry(e.get('name'), key)
    return out


def credentials(uid, gid=None):
    """-> (uid, gid, supplementary groups) a worker for `uid` should run with."""
    import pwd
    try:
        pw = pwd.getpwuid(uid)
        gid = pw.pw_gid if gid is None else gid
        groups = os.getgrouplist(pw.pw_name, gid)
    except KeyError:
        if gid is None:
            raise Refused('unknown_user', 'uid %d has no account to read as' % uid)
        groups = [gid]
    return uid, gid, groups


def read_source_as(path, uid, gid=None, seconds=SECONDS):
    """read_source(), run in a worker holding `uid`'s rights rather than the daemon's."""
    me = os.geteuid()
    kw = {}
    if me == 0 and uid != 0:
        uid, gid, groups = credentials(uid, gid)
        kw = {'user': uid, 'group': gid, 'extra_groups': groups}
    elif uid != me and uid != 0:
        raise Refused('unreadable', 'the daemon cannot read files as uid %d' % uid)
    boot = ('import sys; sys.path.insert(0, sys.argv[1]); import sp_import; '
            'sys.exit(sp_import.worker_main(sys.argv[2], float(sys.argv[3])))')
    deadline = time.monotonic() + seconds + 2.0
    try:
        p = subprocess.Popen([sys.executable, '-I', '-c', boot, _HERE, path, str(seconds)],
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, cwd='/', close_fds=True,
                             env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}, **kw)
    except OSError as e:
        raise Refused('worker_failed', 'cannot start the import reader: %s' % e)
    buf = bytearray()
    try:
        with selectors.DefaultSelector() as sel:
            sel.register(p.stdout, selectors.EVENT_READ)
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise Refused('timeout', 'reading the import took too long')
                if not sel.select(left):
                    continue
                chunk = os.read(p.stdout.fileno(), 1 << 20)
                if not chunk:
                    break
                buf += chunk
                if len(buf) > OUTPUT_MAX:
                    raise Refused('too_large', 'the import holds too much CEC data')
        try:
            p.wait(max(0.1, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            raise Refused('timeout', 'reading the import took too long')
    finally:
        if p.poll() is None:
            p.kill()
            p.wait()
        p.stdout.close()
    if not buf:
        raise Refused('worker_failed', 'the import reader exited (%s) without a reply'
                      % p.returncode)
    return _decode(buf.decode('utf-8', 'replace'))


def worker_main(path, seconds=SECONDS):
    try:
        out = _encode(read_source(path, Budget(seconds=seconds)))
        code = 0
    except Refused as e:
        out, code = json.dumps({'error': str(e), 'code': e.code}), 1
    except Exception as e:
        out, code = json.dumps({'error': '%s: %s' % (type(e).__name__, e),
                                'code': 'unreadable'}), 1
    sys.stdout.write(out)
    sys.stdout.flush()
    return code
