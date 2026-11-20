#!/usr/bin/env python3
"""Outbox message plugins: one per game, each creating and editing that game's CEC body.

A plugin manages only the game-specific body inside a CEC message. Tuxchange manages the rest:
the 0x70-byte header, the ex-headers, the HMAC trailer and filing it in the outbox
(sp_build.build_envelope, Store.replace_outbox). Plugin code runs in the GUI or CLI
process as you, never in the root daemon; the daemon is only ever handed the body.

A plugin is a .py file, or a package directory with an __init__.py, that defines

    PLUGIN = MyPlugin()          # an instance of a Plugin subclass

and is found in the built-in plugins/ directory beside this file, then in
$XDG_DATA_HOME/tuxchange/plugins (~/.local/share/tuxchange/plugins). A user plugin with
the same id as a built-in one replaces it. Names starting with '_' or '.' are skipped.

The plugin declares its fields as a schema (Str, Int, Enum, Bool, Bytes, Mac, Image,
List, Group). The schema gives every plugin a CLI (`tuxchange create <id> ...`), a
generated GUI form, validation and JSON import/export, with no extra code.
"""
import os, sys, json, zlib, struct, importlib.util, types, traceback

API_VERSION = 1
HERE = os.path.dirname(os.path.abspath(__file__))
BUILTIN_DIR = os.path.join(HERE, 'plugins')
IMAGE_FILE_MAX = 16 << 20
SEND_MODES = (0, 1, 2, 3)

# The 16 SMDH / CEC language slots, in order.
LANGUAGES = ('Japanese', 'English', 'French', 'German', 'Italian', 'Spanish',
             'Chinese (simplified)', 'Korean', 'Dutch', 'Portuguese', 'Russian',
             'Chinese (traditional)', 'Unused 12', 'Unused 13', 'Unused 14', 'Unused 15')


class PluginError(Exception):
    """A plugin could not do what was asked; the message is meant for the user."""


class PluginParseError(PluginError):
    """A plugin could not read an existing body. Editing starts fresh or is abandoned."""


class ValidationError(PluginError, ValueError):
    def __init__(self, path, msg):
        self.path, self.msg = path, msg
        super().__init__('%s: %s' % (path, msg) if path else msg)


def user_dir():
    base = os.environ.get('XDG_DATA_HOME') or os.path.join(os.path.expanduser('~'),
                                                           '.local', 'share')
    return os.path.join(base, 'tuxchange', 'plugins')


# ---------------------------------------------------------------------------------- schema

class Field:
    """One value in a plugin's schema. Subclasses define what a valid value is."""
    kind = 'field'

    def __init__(self, key, label=None, default=None, help='', advanced=False, hidden=False):
        if not key or '.' in key or '=' in key:
            raise ValueError('bad field key %r' % (key,))
        self.key = key
        self.label = label or key.replace('_', ' ').capitalize()
        self.default = default
        self.help = help
        # advanced: tucked away in the GUI. hidden: never shown or given a flag, but kept
        # in the values, JSON and --set (state a plugin carries between parse and build).
        self.advanced = advanced
        self.hidden = hidden

    def make_default(self):
        d = self.default
        return json.loads(json.dumps(d)) if isinstance(d, (list, dict)) else d

    def validate(self, v, path):
        return v

    def from_text(self, text, path):
        """A command-line string -> a value."""
        return self.validate(text, path)

    def to_text(self, v):
        return str(v)

    def to_json(self, v):
        return v

    def from_json(self, v, path):
        return self.validate(v, path)

    def describe(self):
        return self.kind


class Str(Field):
    kind = 'text'

    def __init__(self, key, label=None, max_len=None, default='', forbid='', multiline=False,
                 **kw):
        super().__init__(key, label, default, **kw)
        self.max_len, self.forbid, self.multiline = max_len, forbid, multiline

    def validate(self, v, path):
        if not isinstance(v, str):
            raise ValidationError(path, 'expected text, got %r' % (v,))
        if self.max_len is not None and len(v) > self.max_len:
            raise ValidationError(path, 'at most %d characters, got %d'
                                  % (self.max_len, len(v)))
        bad = sorted(set(v) & set(self.forbid))
        if bad:
            raise ValidationError(path, 'may not contain %s' % ' '.join(bad))
        return v

    def describe(self):
        return 'text' + (' (max %d)' % self.max_len if self.max_len is not None else '')


class Int(Field):
    kind = 'int'

    def __init__(self, key, label=None, lo=0, hi=0xFFFFFFFF, default=0, exclude=(), hex=False,
                 **kw):
        super().__init__(key, label, default, **kw)
        self.lo, self.hi, self.exclude, self.hex = lo, hi, frozenset(exclude), hex

    def validate(self, v, path):
        if isinstance(v, bool) or not isinstance(v, int):
            raise ValidationError(path, 'expected a whole number, got %r' % (v,))
        if not (self.lo <= v <= self.hi):
            raise ValidationError(path, '%s out of range %s..%s'
                                  % (self.to_text(v), self.to_text(self.lo), self.to_text(self.hi)))
        if v in self.exclude:
            raise ValidationError(path, '%s is not allowed (refused: %s)'
                                  % (self.to_text(v), ', '.join(map(str, sorted(self.exclude)))))
        return v

    def from_text(self, text, path):
        try:
            v = int(text.strip(), 0)
        except ValueError:
            raise ValidationError(path, 'expected a number, got %r' % (text,))
        return self.validate(v, path)

    def to_text(self, v):
        return '%#x' % v if self.hex else str(v)

    def describe(self):
        d = 'int %s..%s' % (self.to_text(self.lo), self.to_text(self.hi))
        return d + (', not %s' % ','.join(map(str, sorted(self.exclude))) if self.exclude else '')


class Enum(Field):
    """One of a fixed set. `choices` is [value, ...] or [(value, label), ...]."""
    kind = 'enum'

    def __init__(self, key, label=None, choices=(), default=None, **kw):
        cs = [c if isinstance(c, tuple) else (c, str(c)) for c in choices]
        if not cs:
            raise ValueError('an Enum needs choices')
        super().__init__(key, label, cs[0][0] if default is None else default, **kw)
        self.choices = cs

    def validate(self, v, path):
        if v not in [c[0] for c in self.choices]:
            raise ValidationError(path, '%r is not one of %s'
                                  % (v, ', '.join(repr(c[0]) for c in self.choices)))
        return v

    def from_text(self, text, path):
        for val, lab in self.choices:
            if text == str(val) or text.lower() == lab.lower():
                return val
        try:
            return self.validate(int(text, 0), path)
        except ValueError:
            pass
        return self.validate(text, path)

    def describe(self):
        return 'one of ' + ', '.join('%s=%s' % c if str(c[0]) != c[1] else c[1]
                                     for c in self.choices)


class Bool(Field):
    kind = 'bool'

    def __init__(self, key, label=None, default=False, **kw):
        super().__init__(key, label, default, **kw)

    def validate(self, v, path):
        if not isinstance(v, bool):
            raise ValidationError(path, 'expected true or false, got %r' % (v,))
        return v

    def from_text(self, text, path):
        t = text.strip().lower()
        if t in ('1', 'true', 'yes', 'on'):
            return True
        if t in ('0', 'false', 'no', 'off'):
            return False
        raise ValidationError(path, 'expected yes or no, got %r' % (text,))

    def describe(self):
        return 'yes/no'


class Bytes(Field):
    """A fixed-length byte string. Text and JSON forms are hex."""
    kind = 'bytes'

    def __init__(self, key, label=None, length=1, default=None, **kw):
        super().__init__(key, label, bytes(length) if default is None else default, **kw)
        self.length = length

    def validate(self, v, path):
        if isinstance(v, str):
            return self.from_text(v, path)
        if not isinstance(v, (bytes, bytearray)) or len(v) != self.length:
            raise ValidationError(path, 'expected %d bytes' % self.length)
        return bytes(v)

    def from_text(self, text, path):
        try:
            b = bytes.fromhex(text.replace(':', '').replace(' ', ''))
        except ValueError:
            raise ValidationError(path, 'expected %d bytes of hex' % self.length)
        if len(b) != self.length:
            raise ValidationError(path, 'expected %d bytes, got %d' % (self.length, len(b)))
        return b

    def to_text(self, v):
        return bytes(v).hex()

    def to_json(self, v):
        return self.to_text(v)

    def make_default(self):
        return bytes(self.default)

    def describe(self):
        return '%d bytes of hex' % self.length


class Blob(Field):
    """Bytes of any length up to max_len, base64 in JSON. Usually hidden: for example the
    original body, so the bytes a plugin does not expose survive an edit unchanged."""
    kind = 'blob'

    def __init__(self, key, label=None, max_len=0x18000, default=b'', **kw):
        kw.setdefault('hidden', True)
        super().__init__(key, label, bytes(default), **kw)
        self.max_len = max_len

    def validate(self, v, path):
        if isinstance(v, str):
            return self.from_text(v, path)
        if not isinstance(v, (bytes, bytearray)) or len(v) > self.max_len:
            raise ValidationError(path, 'expected at most %d bytes' % self.max_len)
        return bytes(v)

    def from_text(self, text, path):
        import base64, binascii
        try:
            return self.validate(base64.b64decode(text, validate=True), path)
        except (binascii.Error, ValueError):
            raise ValidationError(path, 'expected base64')

    def to_text(self, v):
        import base64
        return base64.b64encode(v).decode()

    def to_json(self, v):
        return self.to_text(v)

    def make_default(self):
        return bytes(self.default)

    def describe(self):
        return 'base64 data (max %d bytes)' % self.max_len


class Mac(Bytes):
    """A 6-byte MAC address, written aa:bb:cc:dd:ee:ff."""
    kind = 'mac'

    def __init__(self, key, label=None, default=None, **kw):
        if isinstance(default, str):
            default = bytes.fromhex(default.replace(':', ''))
        super().__init__(key, label, 6, default, **kw)

    def to_text(self, v):
        return ':'.join('%02x' % c for c in v)

    def describe(self):
        return 'MAC address aa:bb:cc:dd:ee:ff'


class Image(Field):
    """A w x h picture, held as rows of RGB565. Text form: a PNG path, or a raw file of
    w*h*2 bytes of 3DS-tiled RGB565 (the SMDH icon format)."""
    kind = 'image'

    def __init__(self, key, label=None, width=48, height=48, default=None, **kw):
        super().__init__(key, label, default, **kw)
        self.width, self.height = width, height

    def make_default(self):
        if self.default is not None:
            return [list(r) for r in self.default]
        return [[0] * self.width for _ in range(self.height)]

    def validate(self, v, path):
        if (not isinstance(v, list) or len(v) != self.height
                or any(not isinstance(r, list) or len(r) != self.width for r in v)
                or any(not isinstance(p, int) or not (0 <= p <= 0xFFFF) for r in v for p in r)):
            raise ValidationError(path, 'expected %dx%d RGB565 pixels' % (self.width, self.height))
        return v

    def from_text(self, text, path):
        try:
            return self.validate(load_image(text, self.width, self.height), path)
        except (OSError, ValueError) as e:
            raise ValidationError(path, str(e))

    def to_text(self, v):
        return '<%dx%d image>' % (self.width, self.height)

    def describe(self):
        return '%dx%d image: PNG, or raw tiled RGB565' % (self.width, self.height)


class Group(Field):
    """Named sub-fields, held as a dict. Shown as one section in the GUI."""
    kind = 'group'

    def __init__(self, key, label=None, fields=(), **kw):
        super().__init__(key, label, None, **kw)
        self.fields = list(fields)
        _check_unique(self.fields)

    def make_default(self):
        return {f.key: f.make_default() for f in self.fields}

    def validate(self, v, path):
        if not isinstance(v, dict):
            raise ValidationError(path, 'expected a group of values')
        return _validate_fields(self.fields, v, path)

    def to_json(self, v):
        return {f.key: f.to_json(v[f.key]) for f in self.fields}

    def from_json(self, v, path):
        if not isinstance(v, dict):
            raise ValidationError(path, 'expected an object')
        out = self.make_default()
        for f in self.fields:
            if f.key in v:
                out[f.key] = f.from_json(v[f.key], _join(path, f.key))
        return out

    def describe(self):
        return 'group'


class List(Field):
    """Exactly `count` items of one field (or of a Group, for records).

    `item_labels` names the slots (e.g. LANGUAGES); `broadcast` lets one CLI flag set
    every slot at once, as for a name given in all 16 languages."""
    kind = 'list'

    def __init__(self, key, label=None, item=None, count=1, item_labels=None, broadcast=False,
                 **kw):
        super().__init__(key, label, None, **kw)
        if item is None:
            raise ValueError('a List needs an item field')
        self.item, self.count = item, count
        self.item_labels = list(item_labels) if item_labels else None
        self.broadcast = broadcast

    def slot_label(self, i):
        return self.item_labels[i] if self.item_labels and i < len(self.item_labels) \
            else '%s %d' % (self.item.label, i)

    def make_default(self):
        return [self.item.make_default() for _ in range(self.count)]

    def validate(self, v, path):
        if not isinstance(v, list) or len(v) != self.count:
            raise ValidationError(path, 'expected exactly %d items' % self.count)
        return [self.item.validate(x, _join(path, str(i))) for i, x in enumerate(v)]

    def to_json(self, v):
        return [self.item.to_json(x) for x in v]

    def from_json(self, v, path):
        if not isinstance(v, list) or len(v) != self.count:
            raise ValidationError(path, 'expected a list of %d' % self.count)
        return [self.item.from_json(x, _join(path, str(i))) for i, x in enumerate(v)]

    def from_text(self, text, path):
        """Only for broadcast lists: one value for every slot."""
        one = self.item.from_text(text, path)
        return [one for _ in range(self.count)]

    def describe(self):
        return 'list of %d %s' % (self.count, self.item.describe())


def _join(path, key):
    return '%s.%s' % (path, key) if path else key


def _check_unique(fields):
    seen = set()
    for f in fields:
        if f.key in seen:
            raise ValueError('duplicate field key %r' % f.key)
        seen.add(f.key)


def _validate_fields(fields, values, path=''):
    known = {f.key for f in fields}
    extra = sorted(set(values) - known)
    if extra:
        raise ValidationError(path, 'unknown field(s) %s' % ', '.join(extra))
    out = {}
    for f in fields:
        p = _join(path, f.key)
        if f.key not in values:
            raise ValidationError(p, 'missing')
        out[f.key] = f.validate(values[f.key], p)
    return out


def resolve(fields, path):
    """'profile.hat' or 'met16.3.name_a' -> (field, [keys...]). Raises KeyError."""
    parts = path.split('.')
    keys, f, cur = [], None, fields
    i = 0
    while i < len(parts):
        name = parts[i]
        if isinstance(f, List):
            try:
                idx = int(name)
            except ValueError:
                raise KeyError(path)
            if not (0 <= idx < f.count):
                raise KeyError(path)
            keys.append(idx)
            f = f.item
            cur = f.fields if isinstance(f, Group) else None
        else:
            match = [x for x in (cur or []) if x.key == name]
            if not match:
                raise KeyError(path)
            f = match[0]
            keys.append(name)
            cur = f.fields if isinstance(f, Group) else None
        i += 1
    if f is None:
        raise KeyError(path)
    return f, keys


def get_path(values, keys):
    for k in keys:
        values = values[k]
    return values


def set_path(values, keys, v):
    for k in keys[:-1]:
        values = values[k]
    values[keys[-1]] = v


def leaves(fields, path='', in_list=False, hidden=False):
    """Every settable path in the schema -> [(path, field, in_list)]. Hidden fields are
    left out unless `hidden`."""
    out = []
    for f in fields:
        if f.hidden and not hidden:
            continue
        p = _join(path, f.key)
        if isinstance(f, Group):
            out += leaves(f.fields, p, in_list, hidden)
        elif isinstance(f, List):
            if f.broadcast:
                out.append((p, f, in_list))
            if isinstance(f.item, Group):
                for i in range(f.count):
                    out += leaves(f.item.fields, _join(p, str(i)), True, hidden)
            else:
                for i in range(f.count):
                    out.append((_join(p, str(i)), f.item, True))
        else:
            out.append((p, f, in_list))
    return out


# --------------------------------------------------------------------------------- plugins

class BuildResult:
    """What a plugin's build() hands back: the body, plus hints for Tuxchange's envelope.

    title_id   CEC title id; defaults to the plugin's first title_ids entry
    info_text  ex-header type 4 text; None for none
    icon       0xC80-byte 40x40 tiled RGB565 CEC icon (ex-header type 2); None for none
    send_mode  header +0x35; defaults to the plugin's send_mode, and must match it
    name       the title's display name in the store
    """

    def __init__(self, body, title_id=None, info_text=None, icon=None, send_mode=None, name=None):
        self.body = bytes(body)
        self.title_id, self.info_text, self.icon = title_id, info_text, icon
        self.send_mode, self.name = send_mode, name


class Importer:
    """Turns outside data into field values: a Mii file, a QR code, an existing message.

    kind 'file'     fn(plugin, values, data: bytes, filename) -> values
    kind 'message'  fn(plugin, values, container: bytes)      -> values
    """

    def __init__(self, key, label, fn, kind='file', patterns=('*',), help=''):
        if kind not in ('file', 'message'):
            raise ValueError('importer kind is file or message')
        self.key, self.label, self.fn, self.kind = key, label, fn, kind
        self.patterns, self.help = tuple(patterns), help


class Plugin:
    """Subclass this, fill in the metadata and fields, and implement build() and parse()."""
    id = None                 # short, lowercase, used on the command line: 'miiplaza'
    game = None               # the name shown in the GUI: 'StreetPass Mii Plaza'
    title_ids = ()            # the CEC title ids this plugin writes and can edit
    versions = ('any',)       # game versions it supports, e.g. ('1.0', '1.1') or ('any',)
    regions = ('any',)        # e.g. ('EUR', 'USA') or ('any',)
    # The send mode (header +0x35, 0..3) the game gives its messages. Required: a message
    # with another mode is dropped by the receiver, and retail treats mode 0 differently.
    send_mode = None
    author = ''
    description = ''
    fields = ()
    importers = ()
    # None: CLI only (shown greyed out in the GUI); 'form': the generated form;
    # or override build_page(ctx) and set gui = 'custom'.
    gui = 'form'
    background = None         # an image path relative to the plugin, for its GUI page
    api_version = API_VERSION

    path = None               # set by the loader
    source = None             # 'builtin' or 'user'

    def __init__(self):
        # Set by the GUI or CLI before defaults() is called. 'store' is the daemon's store
        # path, whose own identity some plugins use as a default; 'identity', when set, is
        # that identity as the running daemon reports it.
        self.context = {}

    def defaults(self):
        return {f.key: f.make_default() for f in self.fields}

    def build(self, values):
        """Validated values -> BuildResult."""
        raise NotImplementedError

    def parse(self, body):
        """An existing body -> values. Raise PluginParseError if it cannot be read."""
        raise PluginParseError('%s cannot edit existing messages' % (self.game or self.id))

    def can_edit(self):
        return type(self).parse is not Plugin.parse

    def build_page(self, ctx):
        """GUI only, for gui = 'custom': -> a Gtk.Widget. ctx.form() gives the generated form."""
        return ctx.form()

    def background_path(self):
        if not self.background or not self.path:
            return None
        base = self.path if os.path.isdir(self.path) else os.path.dirname(self.path)
        p = os.path.join(base, self.background)
        return p if os.path.isfile(p) else None

    def about(self):
        return {'id': self.id, 'game': self.game, 'versions': list(self.versions),
                'regions': list(self.regions), 'author': self.author,
                'description': self.description,
                'title_ids': ['%08X' % t for t in self.title_ids],
                'send_mode': self.send_mode,
                'interface': 'GUI and CLI' if self.gui else 'CLI only',
                'can_edit': self.can_edit(), 'source': self.source, 'path': self.path}


class Broken:
    """A plugin that failed to load. Listed, so the user can see why, never used."""
    gui = None

    def __init__(self, path, source, error):
        self.path, self.source, self.error = path, source, error
        self.id = os.path.splitext(os.path.basename(path.rstrip('/')))[0]
        self.game = self.id

    def __repr__(self):
        return '<broken plugin %s: %s>' % (self.path, self.error.splitlines()[-1])


def check(p):
    """Raise PluginError if `p` breaks the plugin contract."""
    if not isinstance(p, Plugin):
        raise PluginError('PLUGIN must be an instance of sp_plugin.Plugin')
    if p.api_version > API_VERSION:
        raise PluginError('needs plugin API %d, this Tuxchange has %d'
                          % (p.api_version, API_VERSION))
    if not p.id or not isinstance(p.id, str) or not p.id.replace('-', '').replace('_', '').isalnum() \
            or p.id != p.id.lower():
        raise PluginError('id must be lowercase letters, digits, - or _, got %r' % (p.id,))
    if not p.game:
        raise PluginError('game is not set')
    if not p.title_ids or not all(isinstance(t, int) and 0 < t <= 0xFFFFFFFF
                                  for t in p.title_ids):
        raise PluginError('title_ids must list at least one CEC title id')
    if type(p.send_mode) is not int or p.send_mode not in SEND_MODES:
        raise PluginError('send_mode must be the game\'s send mode, 0..3, got %r' % (p.send_mode,))
    if not isinstance(getattr(p, 'context', None), dict):
        p.context = {}
    if p.gui not in (None, 'form', 'custom'):
        raise PluginError("gui must be None, 'form' or 'custom'")
    _check_unique(list(p.fields))
    seen = set()
    for imp in p.importers:
        if not isinstance(imp, Importer):
            raise PluginError('importers must be sp_plugin.Importer instances')
        if imp.key in seen:
            raise PluginError('two importers are called %r' % imp.key)
        seen.add(imp.key)
    _validate_fields(list(p.fields), p.defaults())


def load_path(path, source='user'):
    """Load one plugin file or package. -> Plugin, or Broken."""
    path = os.path.abspath(path)
    base = os.path.basename(path.rstrip('/'))
    stem = os.path.splitext(base)[0]
    name = 'tuxchange_plugins.%s_%s' % (source, ''.join(c if c.isalnum() else '_' for c in stem))
    if 'tuxchange_plugins' not in sys.modules:
        ns = types.ModuleType('tuxchange_plugins')
        ns.__path__ = []
        sys.modules['tuxchange_plugins'] = ns
    try:
        if os.path.isdir(path):
            init = os.path.join(path, '__init__.py')
            spec = importlib.util.spec_from_file_location(name, init,
                                                          submodule_search_locations=[path])
        else:
            spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        try:
            spec.loader.exec_module(mod)
        except BaseException:
            sys.modules.pop(name, None)
            raise
        p = getattr(mod, 'PLUGIN', None)
        if p is None:
            raise PluginError('defines no PLUGIN')
        check(p)
        p.path, p.source = path, source
        return p
    except (Exception, SystemExit):
        return Broken(path, source, traceback.format_exc(limit=-3).strip())


def _candidates(d):
    try:
        names = sorted(os.listdir(d))
    except OSError:
        return []
    out = []
    for n in names:
        if n.startswith(('_', '.')):
            continue
        p = os.path.join(d, n)
        if os.path.isdir(p) and os.path.isfile(os.path.join(p, '__init__.py')):
            out.append(p)
        elif n.endswith('.py') and os.path.isfile(p):
            out.append(p)
    return out


def discover(dirs=None, log=None):
    """-> (plugins, broken). Built-in first; a user plugin with the same id replaces it."""
    if dirs is None:
        dirs = [(BUILTIN_DIR, 'builtin'), (user_dir(), 'user')]
    by_id, broken = {}, []
    for d, source in dirs:
        for p in _candidates(d):
            got = load_path(p, source)
            if isinstance(got, Broken):
                broken.append(got)
                if log:
                    log('plugin %s failed to load: %s' % (p, got.error.splitlines()[-1]))
                continue
            if got.id in by_id and log:
                log('plugin %s (%s) replaces the one at %s'
                    % (got.id, got.path, by_id[got.id].path))
            by_id[got.id] = got
    plugins = sorted(by_id.values(), key=lambda p: (p.game or '').lower())
    return plugins, broken


def find(plugin_id, plugins=None):
    plugins = discover()[0] if plugins is None else plugins
    for p in plugins:
        if p.id == plugin_id:
            return p
    raise PluginError('no plugin %r (have: %s)'
                      % (plugin_id, ', '.join(p.id for p in plugins) or 'none'))


def for_title(title_id, plugins=None):
    """The plugin that can edit messages of `title_id`, or None."""
    plugins = discover()[0] if plugins is None else plugins
    for p in plugins:
        if title_id in p.title_ids and p.can_edit():
            return p
    return None


def validate(plugin, values):
    """-> the values, checked against the schema. Raises ValidationError."""
    return _validate_fields(list(plugin.fields), values)


def values_to_json(plugin, values):
    return {f.key: f.to_json(values[f.key]) for f in plugin.fields}


def values_from_json(plugin, obj):
    """A JSON object (possibly partial) -> full values; missing keys keep their defaults."""
    if not isinstance(obj, dict):
        raise ValidationError('', 'expected a JSON object')
    out = plugin.defaults()
    known = {f.key for f in plugin.fields}
    extra = sorted(set(obj) - known)
    if extra:
        raise ValidationError('', 'unknown field(s) %s' % ', '.join(extra))
    for f in plugin.fields:
        if f.key in obj:
            out[f.key] = f.from_json(obj[f.key], f.key)
    return out


def set_text(plugin, values, path, text):
    """Apply one `path=text` setting from the command line, in place."""
    try:
        f, keys = resolve(list(plugin.fields), path)
    except KeyError:
        raise ValidationError(path, 'no such field (see --info)')
    if isinstance(f, Group) or (isinstance(f, List) and not f.broadcast):
        raise ValidationError(path, 'set its parts, e.g. %s.<part>' % path)
    set_path(values, keys, f.from_text(text, path))


def build(plugin, values):
    """Validate, then build. -> BuildResult with every envelope hint filled in."""
    values = validate(plugin, values)
    r = plugin.build(values)
    if not isinstance(r, BuildResult):
        r = BuildResult(r)
    if r.title_id is None:
        r.title_id = plugin.title_ids[0]
    if r.title_id not in plugin.title_ids:
        raise PluginError('%s built a message for title %08X, which it does not declare'
                          % (plugin.id, r.title_id))
    if r.send_mode is None:
        r.send_mode = plugin.send_mode
    if r.send_mode != plugin.send_mode:
        raise PluginError('%s built a send mode %r message, but declares its game as send mode %d'
                          % (plugin.id, r.send_mode, plugin.send_mode))
    if r.name is None:
        r.name = plugin.game
    if not r.body or len(r.body) & 3:
        raise PluginError('%s built a body of %d bytes; a CEC body is non-empty and 4-byte aligned'
                          % (plugin.id, len(r.body)))
    return r


def parse(plugin, body):
    """Run the plugin's parser, turning any failure into PluginParseError."""
    try:
        values = plugin.parse(bytes(body))
        return validate(plugin, values)
    except PluginParseError:
        raise
    except Exception as e:
        raise PluginParseError('%s could not read this message: %s: %s'
                               % (plugin.game or plugin.id, type(e).__name__, e))


def envelope(result, key=None, message_id=None, when=None):
    """BuildResult -> a complete wire message, for offline use (--out)."""
    import sp_build
    ex = []
    if result.icon is not None:
        ex.append(sp_build.exheader_icon(result.icon))
    if result.info_text is not None:
        ex.append(sp_build.exheader_info_text(result.info_text))
    return sp_build.build_envelope(result.body, result.title_id, key=key, ex_headers=ex,
                                   message_id=message_id, when=when, send_mode=result.send_mode)


# ---------------------------------------------------------------------------------- images

def rgb565(r, g, b):
    return ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)


def rgb565_to_rgb(v):
    r, g, b = (v >> 11) & 0x1F, (v >> 5) & 0x3F, v & 0x1F
    return (r * 255 + 15) // 31, (g * 255 + 31) // 63, (b * 255 + 15) // 31


def read_png(data):
    """A minimal PNG decoder: 8-bit greyscale, RGB, palette, grey+alpha or RGBA, not
    interlaced. -> (width, height, rows of (r, g, b)). Alpha is composited onto white."""
    if data[:8] != b'\x89PNG\r\n\x1a\n':
        raise ValueError('not a PNG file')
    p, idat, plte, trns = 8, [], None, None
    w = h = depth = ctype = interlace = None
    while True:
        if p + 12 > len(data):
            raise ValueError('PNG ends without an IEND chunk')
        ln, typ = struct.unpack_from('>I4s', data, p)
        if p + 12 + ln > len(data):
            raise ValueError('PNG %r chunk is truncated' % typ)
        chunk = data[p + 8:p + 8 + ln]
        if struct.unpack_from('>I', data, p + 8 + ln)[0] != zlib.crc32(typ + chunk):
            raise ValueError('PNG %r chunk has a bad CRC' % typ)
        p += 12 + ln
        if (w is None) != (typ == b'IHDR'):
            raise ValueError('PNG must start with exactly one IHDR chunk')
        if typ == b'IHDR':
            if ln != 13:
                raise ValueError('PNG IHDR is %d bytes, not 13' % ln)
            w, h, depth, ctype, _c, _f, interlace = struct.unpack('>IIBBBBB', chunk)
        elif typ == b'PLTE':
            plte = [tuple(chunk[i:i + 3]) for i in range(0, len(chunk) - 2, 3)]
        elif typ == b'tRNS':
            trns = chunk
        elif typ == b'IDAT':
            idat.append(chunk)
        elif typ == b'IEND':
            break
    if depth != 8 or interlace or ctype not in (0, 2, 3, 4, 6):
        raise ValueError('only 8-bit, non-interlaced PNGs are supported '
                         '(depth %s, colour type %s, interlace %s)' % (depth, ctype, interlace))
    if not w or not h or w * h > 4096 * 4096:
        raise ValueError('PNG is %dx%d; it must be between 1x1 and 4096x4096 pixels' % (w, h))
    bpp = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[ctype]
    stride = w * bpp
    expected = h * (stride + 1)
    z = zlib.decompressobj()
    try:
        raw = z.decompress(b''.join(idat), expected)
        while not z.eof:
            tail = z.unconsumed_tail
            if z.decompress(tail, 1):
                raise ValueError('PNG image data is longer than %dx%d needs' % (w, h))
            if z.unconsumed_tail == tail:
                break
    except zlib.error as e:
        raise ValueError('PNG image data is corrupt: %s' % e)
    if len(raw) < expected or not z.eof:
        raise ValueError('PNG image data is truncated')
    if z.unused_data:
        raise ValueError('PNG image data has trailing bytes')
    rows, prev = [], bytearray(stride)
    for y in range(h):
        f = raw[y * (stride + 1)]
        line = bytearray(raw[y * (stride + 1) + 1:(y + 1) * (stride + 1)])
        for i in range(stride):
            a = line[i - bpp] if i >= bpp else 0
            b = prev[i]
            c = prev[i - bpp] if i >= bpp else 0
            if f == 1:
                line[i] = (line[i] + a) & 0xFF
            elif f == 2:
                line[i] = (line[i] + b) & 0xFF
            elif f == 3:
                line[i] = (line[i] + ((a + b) >> 1)) & 0xFF
            elif f == 4:
                pa, pb, pc = abs(b - c), abs(a - c), abs(a + b - 2 * c)
                pr = a if pa <= pb and pa <= pc else (b if pb <= pc else c)
                line[i] = (line[i] + pr) & 0xFF
            elif f != 0:
                raise ValueError('bad PNG filter %d' % f)
        rows.append(line)
        prev = line

    def over_white(r, g, b, al):
        return tuple((v * al + 255 * (255 - al)) // 255 for v in (r, g, b))

    out = []
    for line in rows:
        px = []
        for x in range(w):
            q = line[x * bpp:(x + 1) * bpp]
            if ctype == 0:
                px.append((q[0],) * 3)
            elif ctype == 2:
                px.append(tuple(q))
            elif ctype == 3:
                if q[0] >= len(plte or ()):
                    raise ValueError('PNG palette index out of range')
                al = trns[q[0]] if trns and q[0] < len(trns) else 255
                px.append(over_white(*plte[q[0]], al))
            elif ctype == 4:
                px.append(over_white(q[0], q[0], q[0], q[1]))
            else:
                px.append(over_white(q[0], q[1], q[2], q[3]))
        out.append(px)
    return w, h, out


def load_image(path_or_data, width, height):
    """A PNG (scaled to fit, nearest neighbour) or raw tiled RGB565 -> rows of RGB565."""
    data = path_or_data
    if isinstance(path_or_data, str):
        with open(path_or_data, 'rb') as fh:
            data = fh.read(IMAGE_FILE_MAX + 1)
        if len(data) > IMAGE_FILE_MAX:
            raise ValueError('%s is over %d bytes' % (path_or_data, IMAGE_FILE_MAX))
    if data[:8] == b'\x89PNG\r\n\x1a\n':
        w, h, rows = read_png(data)
        return [[rgb565(*rows[y * h // height][x * w // width]) for x in range(width)]
                for y in range(height)]
    if len(data) == width * height * 2 and width % 8 == 0 and height % 8 == 0 and width == height:
        import sp_smdh
        fake = bytearray(sp_smdh.REGION_B_OFF + sp_smdh.REGION_B_LEN)
        large = width == sp_smdh.LARGE_ICON_DIM
        if width not in (sp_smdh.SMALL_ICON_DIM, sp_smdh.LARGE_ICON_DIM):
            return _untile(data, width)
        off = sp_smdh.REGION_B_OFF + (sp_smdh.LARGE_ICON_OFF if large else sp_smdh.SMALL_ICON_OFF)
        fake[off:off + len(data)] = data
        return sp_smdh.decode_icon(bytes(fake), large=large)
    raise ValueError('expected a PNG, or %d bytes of tiled RGB565, got %d bytes'
                     % (width * height * 2, len(data)))


def _untile(data, dim):
    import sp_smdh
    px = [[0] * dim for _ in range(dim)]
    i = 0
    for ty in range(0, dim, 8):
        for tx in range(0, dim, 8):
            for k in range(64):
                x, y = sp_smdh._morton8(k)
                px[ty + y][tx + x] = struct.unpack_from('<H', data, i * 2)[0]
                i += 1
    return px


def write_png(path, px):
    """Rows of RGB565 -> a PNG file (for exporting an icon)."""
    h, w = len(px), len(px[0])
    raw = b''.join(b'\x00' + bytes(c for v in row for c in rgb565_to_rgb(v)) for row in px)

    def chunk(t, d):
        return struct.pack('>I', len(d)) + t + d + struct.pack('>I', zlib.crc32(t + d))
    data = (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 2, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(raw)) + chunk(b'IEND', b''))
    with open(path, 'wb') as fh:
        fh.write(data)


# -------------------------------------------------------------------------------- selftest

def _selftest():
    import tempfile, shutil, time
    sys.path.insert(0, HERE)
    import sp_cec, lp_keys as _k
    if _k.selftest_keys():
        print('  (no console keys found, using generated throwaway keys)')
    ok = tot = 0

    def chk(n, c, g=''):
        nonlocal ok, tot
        tot += 1; ok += bool(c)
        print('  [%s] %s%s' % ('PASS' if c else 'FAIL', n, ('  %s' % (g,)) if g else ''))

    def raises(fn, exc=PluginError):
        try:
            fn()
        except exc:
            return True
        return False

    tmp = tempfile.mkdtemp()
    try:
        bdir, udir = os.path.join(tmp, 'builtin'), os.path.join(tmp, 'user')
        os.makedirs(bdir); os.makedirs(udir)
        dummy = '''
import struct, sp_plugin as P
class Dummy(P.Plugin):
    id = 'dummy'
    game = %r
    title_ids = (0x00030600,)
    versions = ('1.0',)
    regions = ('EUR', 'USA')
    send_mode = 3
    gui = %r
    fields = [
        P.Str('greeting', 'Greeting', max_len=8, default='hi'),
        P.Int('score', 'Score', 0, 999, default=5, exclude=(13,)),
        P.Enum('colour', 'Colour', [(0, 'red'), (1, 'green')]),
        P.Bool('shiny', 'Shiny'),
        P.Mac('mac', 'MAC', default='b8:ae:6e:00:00:01'),
        P.Group('card', 'Card', [P.Int('level', 'Level', 1, 9, default=1)]),
        P.List('names', 'Name', P.Str('name', 'Name', max_len=4), count=3,
               item_labels=('A', 'B', 'C'), broadcast=True),
        P.List('met', 'Met', P.Group('m', 'Met', [P.Int('id', 'Id', hex=True),
                                                  P.Mac('mac', 'MAC')]), count=2),
    ]
    def build(self, v):
        g = v['greeting'].encode('utf-16-le').ljust(16, b'\\0')
        n = b''.join(x.encode('utf-16-le').ljust(8, b'\\0') for x in v['names'])
        m = b''.join(struct.pack('<I', e['id']) + e['mac'] for e in v['met'])
        b = (g + struct.pack('<HBBB', v['score'], v['colour'], v['shiny'], v['card']['level'])
             + v['mac'] + n + m)
        return P.BuildResult(b + b'\\0' * (-len(b) %% 4), info_text='dummy')
    def parse(self, b):
        if len(b) < 64:
            raise P.PluginParseError('too short')
        v = self.defaults()
        v['greeting'] = b[:16].decode('utf-16-le').rstrip('\\0')
        v['score'], v['colour'], s, v['card']['level'] = struct.unpack_from('<HBBB', b, 16)
        v['shiny'] = bool(s)
        v['mac'] = b[21:27]
        v['names'] = [b[27 + i * 8:35 + i * 8].decode('utf-16-le').rstrip('\\0') for i in range(3)]
        v['met'] = [{'id': struct.unpack_from('<I', b, 51 + i * 10)[0],
                     'mac': b[55 + i * 10:61 + i * 10]} for i in range(2)]
        return v
PLUGIN = Dummy()
'''
        with open(os.path.join(bdir, 'dummy.py'), 'w') as fh:
            fh.write(dummy % ('Dummy Game', 'form'))
        os.makedirs(os.path.join(bdir, 'pkg'))
        with open(os.path.join(bdir, 'pkg', '__init__.py'), 'w') as fh:
            fh.write('from . import impl\nPLUGIN = impl.make()\n')
        with open(os.path.join(bdir, 'pkg', 'impl.py'), 'w') as fh:
            fh.write('import sp_plugin as P\n'
                     'class C(P.Plugin):\n'
                     '    id = "clionly"; game = "A CLI Game"; title_ids = (0x00141000,)\n'
                     '    send_mode = 1; gui = None\n'
                     '    fields = [P.Int("n", "N", 0, 10)]\n'
                     '    def build(self, v): return bytes([v["n"]]) * 4\n'
                     'def make(): return C()\n')
        with open(os.path.join(bdir, 'broken.py'), 'w') as fh:
            fh.write('raise RuntimeError("deliberately broken")\n')
        with open(os.path.join(bdir, 'noplugin.py'), 'w') as fh:
            fh.write('X = 1\n')
        with open(os.path.join(bdir, 'exits.py'), 'w') as fh:
            fh.write('import sys\nsys.exit(3)\n')
        with open(os.path.join(bdir, '_hidden.py'), 'w') as fh:
            fh.write('raise RuntimeError("should never be imported")\n')

        dirs = [(bdir, 'builtin'), (udir, 'user')]
        plugins, broken = discover(dirs)
        chk('discover finds the file plugin and the package plugin',
            sorted(p.id for p in plugins) == ['clionly', 'dummy'], [p.id for p in plugins])
        chk('a package plugin can import its own submodules',
            find('clionly', plugins).source == 'builtin')
        chk('plugins are listed by game name, not script name',
            [p.game for p in plugins] == ['A CLI Game', 'Dummy Game'])
        chk('a broken plugin, one with no PLUGIN and one calling sys.exit are listed as broken',
            sorted(b.id for b in broken) == ['broken', 'exits', 'noplugin'],
            [b.id for b in broken])
        chk('and the error says why', 'deliberately broken' in
            [b for b in broken if b.id == 'broken'][0].error)
        chk('names starting with _ are skipped', all(b.id != '_hidden' for b in broken))

        with open(os.path.join(udir, 'mine.py'), 'w') as fh:
            fh.write(dummy % ('My Dummy', 'form'))
        msgs = []
        plugins, _b = discover(dirs, log=msgs.append)
        chk('a user plugin with the same id replaces the built-in one',
            find('dummy', plugins).game == 'My Dummy' and find('dummy', plugins).source == 'user')
        chk('and that is logged', any('replaces' in m for m in msgs), msgs)
        os.remove(os.path.join(udir, 'mine.py'))
        plugins, _b = discover(dirs)
        d = find('dummy', plugins)
        chk('find() names the plugins it has when one is missing',
            raises(lambda: find('nope', plugins)))
        chk('for_title finds the plugin that can edit a title',
            for_title(0x00030600, plugins) is d and for_title(0x00141000, plugins) is None)
        chk('a CLI-only plugin says so', find('clionly', plugins).about()['interface'] == 'CLI only')
        chk('About carries game, versions and regions',
            d.about()['versions'] == ['1.0'] and d.about()['regions'] == ['EUR', 'USA'])

        v = d.defaults()
        chk('defaults validate', validate(d, v) is not None)
        chk('the MAC default parsed from text', v['mac'] == bytes.fromhex('b8ae6e000001'))
        set_text(d, v, 'greeting', 'hello')
        set_text(d, v, 'score', '0x20')
        set_text(d, v, 'colour', 'green')
        set_text(d, v, 'shiny', 'yes')
        set_text(d, v, 'card.level', '7')
        set_text(d, v, 'names', 'Tux')
        set_text(d, v, 'names.2', 'Gnu')
        set_text(d, v, 'met.1.id', '0x1234')
        set_text(d, v, 'met.1.mac', '01:02:03:04:05:06')
        chk('dotted paths reach groups, lists and records',
            (v['score'], v['colour'], v['shiny'], v['card']['level'], v['met'][1]['id'])
            == (32, 1, True, 7, 0x1234))
        chk('a broadcast list flag fills every slot, and a slot can then be overridden',
            v['names'] == ['Tux', 'Tux', 'Gnu'])
        for path, text in (('greeting', 'far too long'), ('score', '1000'), ('score', '13'),
                           ('colour', 'blue'), ('shiny', 'maybe'), ('mac', '01:02'),
                           ('nope', '1'), ('met.2.id', '1'), ('card', '1'), ('met', 'x')):
            chk('%s=%r is refused' % (path, text),
                raises(lambda: set_text(d, dict(v), path, text), ValidationError))

        r = build(d, v)
        chk('build fills in the title, name and declared send mode',
            (r.title_id, r.name, r.send_mode) == (0x00030600, 'Dummy Game', 3))
        chk('About carries the send mode', d.about()['send_mode'] == 3)
        wire = envelope(r, key=b'\x22' * 32, message_id=9, when=time.gmtime(0))
        h, ex, body = sp_cec.split_message(wire)
        chk('the envelope carries the plugin\'s send mode and info text',
            h['send_mode'] == 3 and [e['type'] for e in ex] == [4])
        chk('build -> envelope -> split -> parse round-trips every value',
            parse(d, body) == validate(d, v))
        chk('a body the plugin cannot read is a PluginParseError, not a crash',
            raises(lambda: parse(d, b'\x00' * 8), PluginParseError))
        chk('so is a body that makes the parser throw something else',
            raises(lambda: parse(d, b'\xff' * 64), PluginParseError))
        chk('a plugin without parse() cannot edit',
            not find('clionly', plugins).can_edit()
            and raises(lambda: parse(find('clionly', plugins), b'1234'), PluginParseError))

        js = json.loads(json.dumps(values_to_json(d, v)))
        chk('values survive JSON, bytes as hex', values_from_json(d, js) == validate(d, v))
        chk('a partial JSON object keeps the defaults for the rest',
            values_from_json(d, {'score': 9})['greeting'] == 'hi')
        chk('unknown JSON keys are refused', raises(lambda: values_from_json(d, {'zz': 1})))
        chk('wrong JSON types are refused',
            raises(lambda: values_from_json(d, {'score': 'nine'}))
            and raises(lambda: values_from_json(d, {'names': ['a']})))

        hid = Group('g', 'G', [Int('shown', 'S'), Blob('raw', 'Raw', max_len=8)])
        chk('hidden fields get no flag', [p for p, _f, _l in leaves([hid])] == ['g.shown'])
        chk('but are still there when asked for',
            [p for p, _f, _l in leaves([hid], hidden=True)] == ['g.shown', 'g.raw'])
        bl = Blob('raw', 'Raw', max_len=8)
        chk('a Blob takes base64 text', bl.from_text('AAEC', 'raw') == b'\x00\x01\x02')
        chk('and refuses too much, or bad base64',
            raises(lambda: bl.from_text('A' * 16, 'raw'), ValidationError)
            and raises(lambda: bl.from_text('!!', 'raw'), ValidationError))
        chk('and goes to JSON as base64', bl.to_json(b'\x00\x01\x02') == 'AAEC')

        all_paths = [p for p, _f, _l in leaves(list(d.fields))]
        chk('leaves() lists every settable path',
            {'greeting', 'card.level', 'names', 'names.0', 'met.1.mac'} <= set(all_paths),
            all_paths)

        class Bad(Plugin):
            id = 'Bad Id'; game = 'x'; title_ids = (1,); send_mode = 0
        chk('a bad id breaks the contract', raises(lambda: check(Bad())))

        class NoTitle(Plugin):
            id = 'x'; game = 'x'; send_mode = 0
        chk('no title ids breaks the contract', raises(lambda: check(NoTitle())))

        class NoMode(Plugin):
            id = 'x'; game = 'x'; title_ids = (0x100,)
        chk('a plugin that does not declare its send mode breaks the contract',
            raises(lambda: check(NoMode())))
        for bad in (4, -1, True, '0', 0.0):
            NoMode.send_mode = bad
            chk('send_mode = %r breaks the contract' % (bad,), raises(lambda: check(NoMode())))

        class Wrong(Plugin):
            id = 'w'; game = 'w'; title_ids = (0x100,); send_mode = 0
            fields = [Int('n', 'N', 0, 10, default=11)]
        chk('a default outside its own range breaks the contract', raises(lambda: check(Wrong())))

        class OtherTitle(Plugin):
            id = 'o'; game = 'o'; title_ids = (0x100,); send_mode = 0
            def build(self, v): return BuildResult(b'1234', title_id=0x200)
        chk('a body for an undeclared title is refused', raises(lambda: build(OtherTitle(), {})))

        class Odd(Plugin):
            id = 'odd'; game = 'odd'; title_ids = (0x100,); send_mode = 0
            def build(self, v): return b'123'
        chk('an unaligned body is refused', raises(lambda: build(Odd(), {})))

        class OtherMode(Plugin):
            id = 'om'; game = 'om'; title_ids = (0x100,); send_mode = 3
            def build(self, v): return BuildResult(b'1234', send_mode=0)
        chk('a message in a send mode other than the declared one is refused',
            raises(lambda: build(OtherMode(), {}), PluginError))

        pxs = [[rgb565(x * 5, y * 5, 128) for x in range(48)] for y in range(48)]
        pngp = os.path.join(tmp, 'icon.png')
        write_png(pngp, pxs)
        back = load_image(pngp, 48, 48)
        chk('a PNG written from RGB565 reads back to the same pixels', back == pxs)
        chk('a PNG is scaled to the size asked for', len(load_image(pngp, 24, 24)) == 24)
        import sp_smdh
        raw = sp_smdh.encode_icon(pxs)
        chk('raw tiled RGB565 loads too', load_image(raw, 48, 48) == pxs)
        raw40 = sp_smdh.encode_icon([[rgb565(x * 6, 0, y * 6) for x in range(40)] for y in range(40)])
        chk('and at the CEC icon\'s 40x40', load_image(raw40, 40, 40)[39][39] == rgb565(234, 0, 234))
        chk('anything else is refused', raises(lambda: load_image(b'GIF89a' + b'\0' * 9, 48, 48),
                                                ValueError))
        img = Image('icon', 'Icon', 48, 48)
        chk('an Image field takes a PNG path', img.from_text(pngp, 'icon') == pxs)
        chk('and refuses a missing file cleanly',
            raises(lambda: img.from_text(os.path.join(tmp, 'nope.png'), 'icon'), ValidationError))
        # A palette PNG with transparency, written by hand.
        def chunk(t, dd):
            return struct.pack('>I', len(dd)) + t + dd + struct.pack('>I', zlib.crc32(t + dd))
        pal = (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', 2, 1, 8, 3, 0, 0, 0))
               + chunk(b'PLTE', b'\xff\x00\x00\x00\x00\xff') + chunk(b'tRNS', b'\xff\x00')
               + chunk(b'IDAT', zlib.compress(b'\x00\x00\x01')) + chunk(b'IEND', b''))
        chk('palette PNGs decode, with transparency over white',
            read_png(pal)[2] == [[(255, 0, 0), (255, 255, 255)]])

        def grey1(z):
            return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 0, 0, 0, 0))
                    + chunk(b'IDAT', z) + chunk(b'IEND', b''))
        chk('a one-pixel PNG that inflates to 4 MiB is refused without inflating it',
            raises(lambda: read_png(grey1(zlib.compress(b'\0' * (4 << 20)))), ValueError))
        chk('so are data short of the image, and bytes after the stream',
            raises(lambda: read_png(grey1(zlib.compress(b'\0'))), ValueError)
            and raises(lambda: read_png(grey1(zlib.compress(b'\0\0') + b'x')), ValueError))
        chk('and a chunk with a bad CRC', raises(
            lambda: read_png(pal[:20] + bytes([pal[20] ^ 1]) + pal[21:]), ValueError))
        chk('the built-in plugins directory sits beside this module', BUILTIN_DIR.startswith(HERE))
        ex = load_path(os.path.join(BUILTIN_DIR, '_example.py'), 'builtin')
        chk('the example plugin loads and keeps to the contract', isinstance(ex, Plugin),
            getattr(ex, 'error', ''))
        if isinstance(ex, Plugin):
            ev = ex.defaults()
            set_text(ex, ev, 'score', '42')
            set_text(ex, ev, 'card.console', '01:02:03:04:05:06')
            er = build(ex, ev)
            chk('and its build and parse round-trip', parse(ex, er.body) == validate(ex, ev))
        chk('but discover() does not list it', all(
            p.id != 'example' for p in discover([(BUILTIN_DIR, 'builtin')])[0]))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        for k in [k for k in sys.modules if k.startswith('tuxchange_plugins.')]:
            sys.modules.pop(k, None)
    print('\n%d/%d checks passed' % (ok, tot))
    return 0 if ok == tot else 1


if __name__ == '__main__':
    # Plugins `import sp_plugin`; make that this module, not a second copy of it.
    sys.modules.setdefault('sp_plugin', sys.modules[__name__])
    sys.path.insert(0, HERE)
    if len(sys.argv) > 1 and sys.argv[1] == '--selftest':
        sys.exit(_selftest())
    ps, bs = discover()
    for p in ps:
        a = p.about()
        print('%-12s %-28s %-12s %-14s %s' % (p.id, p.game, ','.join(a['versions']),
                                              ','.join(a['regions']), a['interface']))
    for b in bs:
        print('BROKEN %s\n  %s' % (b.path, b.error.splitlines()[-1]))
