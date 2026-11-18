#!/usr/bin/env python3
"""Reader for the 3DS "SAVE" inner filesystem (the inner FAT of a DISA container)."""
import struct

import lp_keys

SAVE_MAGIC = b'SAVE'
DIR_ENTRY = 0x28
FILE_ENTRY = 0x30


class SaveFS:
    def __init__(self, data):
        self.d = data
        if data[:4] != SAVE_MAGIC:
            raise ValueError('not a SAVE image (magic %r)' % data[:4])
        fi = struct.unpack_from('<Q', data, 8)[0]
        self.block_size = struct.unpack_from('<I', data, fi + 0x04)[0]
        self.fat_off = struct.unpack_from('<Q', data, fi + 0x28)[0]
        self.fat_count = struct.unpack_from('<I', data, fi + 0x30)[0]
        self.data_off = struct.unpack_from('<Q', data, fi + 0x38)[0]
        self.data_blocks = struct.unpack_from('<I', data, fi + 0x40)[0]
        self.dir_tab = self.data_off + struct.unpack_from('<I', data, fi + 0x48)[0] * self.block_size
        self.max_dirs = struct.unpack_from('<I', data, fi + 0x50)[0]
        self.file_tab = self.data_off + struct.unpack_from('<I', data, fi + 0x58)[0] * self.block_size
        self.max_files = struct.unpack_from('<I', data, fi + 0x60)[0]
        self._check_layout()

    def _check_layout(self):
        n, bs = len(self.d), self.block_size
        if not bs or bs & (bs - 1) or bs > 1 << 20:
            raise ValueError('bad SAVE block size %#x' % bs)
        if self.data_blocks > self.fat_count:
            raise ValueError('SAVE has %d data blocks but only %d FAT entries'
                             % (self.data_blocks, self.fat_count))
        for what, off, size in (('FAT', self.fat_off, (self.fat_count + 1) * 8),
                                ('data region', self.data_off, self.data_blocks * bs),
                                ('directory table', self.dir_tab, self.max_dirs * DIR_ENTRY),
                                ('file table', self.file_tab, self.max_files * FILE_ENTRY)):
            if off + size > n:
                raise ValueError('SAVE %s (%#x + %#x) runs past the %#x-byte image'
                                 % (what, off, size, n))

    def _fat(self, node):
        return struct.unpack_from('<II', self.d, self.fat_off + node * 8)

    def dir_entry(self, i):
        o = self.dir_tab + i * DIR_ENTRY
        return {'parent': struct.unpack_from('<I', self.d, o)[0],
                'name': self.d[o + 4:o + 0x14].split(b'\0')[0].decode('latin1')}

    def file_entry(self, i):
        o = self.file_tab + i * FILE_ENTRY
        return {'parent': struct.unpack_from('<I', self.d, o)[0],
                'name': self.d[o + 4:o + 0x14].split(b'\0')[0].decode('latin1'),
                'block': struct.unpack_from('<I', self.d, o + 0x1C)[0],
                'size': struct.unpack_from('<Q', self.d, o + 0x20)[0]}

    def runs(self, first_block, limit=None):
        """Yield (first, end) data-block ranges for a file, following the FAT lazily.

        Node = block + 1. Raises once the chain would exceed `limit` blocks (at most the
        data region), leaves the data region, overlaps itself or loops.
        """
        limit = self.data_blocks if limit is None else min(limit, self.data_blocks)
        node, count, seen = first_block + 1, 0, bytearray(self.data_blocks + 1)
        while node:
            if not 1 <= node <= self.data_blocks:
                raise ValueError('bad FAT chain at node %d' % node)
            _u, v = self._fat(node)
            end = node
            if v & 0x80000000:
                _su, sv = self._fat(node + 1)
                end = sv & 0x7FFFFFFF
                if not node <= end <= self.data_blocks:
                    raise ValueError('bad run %d..%d' % (node, end))
            count += end - node + 1
            if count > limit:
                raise ValueError('FAT chain longer than %d blocks' % limit)
            if seen.find(1, node, end + 1) != -1:
                raise ValueError('FAT chain revisits nodes %d..%d' % (node, end))
            seen[node:end + 1] = b'\1' * (end - node + 1)
            yield node - 1, end
            node = v & 0x7FFFFFFF

    def chain(self, first_block, limit=None):
        """Data-region block indices for a file, following the FAT."""
        return [b for a, e in self.runs(first_block, limit) for b in range(a, e)]

    def read(self, entry, limit=None):
        size, bs = entry['size'], self.block_size
        if size > self.data_blocks * bs or (limit is not None and size > limit):
            raise ValueError('%r is too large (%d bytes)' % (entry['name'], size))
        out, need = bytearray(), -(-size // bs)
        for a, e in self.runs(entry['block']):
            e = min(e, a + need)
            out += self.d[self.data_off + a * bs:self.data_off + e * bs]
            need -= e - a
            if not need:
                break
        if len(out) < size:
            raise ValueError('short read for %r' % entry['name'])
        return bytes(out[:size])

    def path_of_dir(self, i, _depth=0):
        parts = []
        while i and _depth < 32:
            e = self.dir_entry(i)
            if not e['name']:
                break
            parts.append(e['name'])
            if e['parent'] == i:
                break
            i = e['parent']; _depth += 1
        return '/'.join(reversed(parts))

    def files(self):
        """-> [{'path', 'name', 'size', 'block', 'index'}] for every non-empty file entry."""
        out = []
        for i in range(1, self.max_files):
            try:
                e = self.file_entry(i)
            except struct.error:
                break
            if not e['name'] or not e['size'] or e['size'] > (1 << 32):
                continue
            e['index'] = i
            e['path'] = (self.path_of_dir(e['parent']) + '/' + e['name']).lstrip('/')
            out.append(e)
        return out


def _selftest():
    import os, hashlib, hmac
    ok = tot = 0

    def chk(name, cond, got=''):
        nonlocal ok, tot
        tot += 1; ok += bool(cond)
        print('  [%s] %s%s' % ('PASS' if cond else 'FAIL', name, ('  %s' % (got,)) if got else ''))

    chk('a non-SAVE blob is rejected', _raises(lambda: SaveFS(b'XXXX' + b'\0' * 64)))
    good = _synthetic([(0, 0x80000004), (0, 3), (0, 0), (0, 0)], 4)
    chk('a well-formed synthetic chain reads', SaveFS(good).chain(0) == [0, 1, 2, 3])
    chk('and reads only the blocks its size needs',
        SaveFS(good).read({'name': 'f', 'block': 0, 'size': 5}) == b'\1' * 5)
    chk('a run past the block limit is refused before it is expanded',
        _raises(lambda: SaveFS(good).chain(0, limit=3)))
    huge = _synthetic([(0, 0x80000000), (0, 100000)], 1, fat_count=100000, pad=False)
    chk('a FAT declared past the end of the image is refused', _raises(lambda: SaveFS(huge)))
    chk('a run past the data region is refused',
        _raises(lambda: SaveFS(_synthetic([(0, 0x80000000), (0, 9)], 4)).chain(0)))
    chk('a chain that loops is refused',
        _raises(lambda: SaveFS(_synthetic([(0, 2), (0, 1)], 2)).chain(0)))
    chk('a chain that re-enters a run it already took is refused',
        _raises(lambda: SaveFS(_synthetic([(0, 0x80000002), (0, 3), (0, 0)], 3)).chain(0)))
    chk('data blocks beyond the FAT are refused',
        _raises(lambda: SaveFS(_synthetic([(0, 0)], 4, fat_count=1))))

    import lp_corpus as corpus
    img = corpus.path('console_nand_3') or corpus.path('console_nand') or ''
    if not os.path.exists(img):
        print('  no console save image in the corpus -- structural checks only')
        print('\n%d/%d checks passed' % (ok, tot)); return 0 if ok == tot else 1

    fs = SaveFS(open(img, 'rb').read())
    chk('header parses', fs.block_size == 0x1000 and fs.data_off == 0x13000,
        '%#x %#x' % (fs.block_size, fs.data_off))
    files = {f['path']: f for f in fs.files()}
    chk('the tree is a plausible CEC store (50..500 files)', 50 <= len(files) <= 500, str(len(files)))

    ev = files.get('eventlog.dat')
    chk('eventlog.dat found', ev is not None)
    if ev:
        chk('its size matches the same file in an unrelated emulator NAND',
            ev['size'] == 200020, str(ev['size']))
        chk('its chain is 49 blocks (ceil(200020/4096))', len(fs.chain(ev['block'])) == 49)
        chk('it reads to exactly its stated size', len(fs.read(ev)) == 200020)

    ml = files.get('CEC/MBoxList____')
    chk('CEC/MBoxList____ found', ml is not None)
    if ml:
        d = fs.read(ml)
        chk('it is 396 bytes and starts with the hh magic',
            len(d) == 396 and d[:2] == b'hh', '%d %r' % (len(d), d[:2]))

    import sp_cec
    plaza = [f for p, f in files.items()
             if p.startswith('CEC/00020800/') and f['name'].startswith('_')]
    chk('Mii Plaza box messages found', len(plaza) >= 1, str(len(plaza)))
    good = 0
    for f in plaza:
        try:
            m = fs.read(f)
            h = sp_cec.parse_header(m)
            body = m[h['header_size']:h['header_size'] + h['body_size']]
            tag = m[h['header_size'] + h['body_size']:h['total_size']]
            if tag == hmac.new(lp_keys.plaza_hmac_key(), body, hashlib.sha256).digest():
                good += 1
        except Exception:
            pass
    chk('EVERY Mii Plaza message verifies its HMAC (carving got 1 of 7)',
        good == len(plaza), '%d/%d' % (good, len(plaza)))
    chk('a corrupt chain raises rather than returning junk',
        _raises(lambda: fs.chain(fs.fat_count + 10)))
    print('\n%d/%d checks passed' % (ok, tot))
    return 0 if ok == tot else 1


def _synthetic(fat, data_blocks, fat_count=None, pad=True):
    """A minimal SAVE image: FAT nodes 1.. from `fat` as (u, v), 0x200-byte blocks of 0x01."""
    fi, bs = 0x20, 0x200
    fat_count = len(fat) if fat_count is None else fat_count
    fat_off = 0x100
    data_off = (fat_off + (len(fat) + 1) * 8 + bs - 1) // bs * bs
    hdr = bytearray(data_off)
    hdr[:4] = SAVE_MAGIC
    struct.pack_into('<Q', hdr, 8, fi)
    struct.pack_into('<I', hdr, fi + 0x04, bs)
    struct.pack_into('<QI', hdr, fi + 0x28, fat_off, fat_count)
    struct.pack_into('<QI', hdr, fi + 0x38, data_off, data_blocks)
    for i, (u, v) in enumerate(fat):
        struct.pack_into('<II', hdr, fat_off + (i + 1) * 8, u, v)
    return bytes(hdr) + (b'\1' * bs * data_blocks if pad else b'')


def _raises(fn):
    try:
        fn(); return False
    except (ValueError, struct.error):
        return True


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1 and sys.argv[1] != '--selftest':
        fs = SaveFS(open(sys.argv[1], 'rb').read())
        for f in sorted(fs.files(), key=lambda x: x['path']):
            print('%9d  %s' % (f['size'], f['path']))
        sys.exit(0)
    sys.exit(_selftest())
