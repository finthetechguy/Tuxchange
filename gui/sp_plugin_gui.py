"""GUI of outbox message plugins: the Create picker, full-window plugin pages, the
form generated from a plugin's schema, and Save / Edit against the daemon.

Plugin code runs here, in the GUI process, as you. The daemon is only ever sent the body
the plugin built (sp_create.put -> the daemon's outbox_put).
"""
import os, base64

import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw, GLib, Gio, Gdk        # noqa: E402

import sp_plugin as P                                      # noqa: E402
import sp_create, sp_cec                                   # noqa: E402

# Fields wider than this get a text entry instead of a spin button (and a 64-bit title id
# would lose precision in a double).
SPIN_MAX = 10_000_000


def run_async(fn, on_done=None):
    import threading

    def worker():
        try:
            r = fn()
        except Exception as e:                             # noqa: BLE001 - surfaced in the UI
            r = e
        if on_done is not None:
            GLib.idle_add(on_done, r)
    threading.Thread(target=worker, daemon=True).start()


def texture_from_rgb565(px, scale=1):
    """Rows of RGB565 -> a Gdk.Texture, optionally scaled up (nearest neighbour)."""
    h, w = len(px), len(px[0])
    rows = []
    for row in px:
        line = b''.join(bytes(P.rgb565_to_rgb(v)) * scale for v in row)
        rows.extend([line] * scale)
    data = GLib.Bytes.new(b''.join(rows))
    return Gdk.MemoryTexture.new(w * scale, h * scale, Gdk.MemoryFormat.R8G8B8, data,
                                 w * scale * 3)


_css_done = set()


def background_class(plugin):
    """A CSS class that paints the plugin's background image, or None if it has none."""
    path = plugin.background_path()
    if not path:
        return None
    cls = 'tuxchange-plugin-bg-%s' % plugin.id
    if cls not in _css_done:
        uri = Gio.File.new_for_path(path).get_uri().replace('"', '%22')
        prov = Gtk.CssProvider()
        # A scrim in the theme's own window colour keeps text readable over any picture,
        # in light and dark mode alike.
        prov.load_from_string(
            '.%s { background-image: linear-gradient(alpha(@window_bg_color, 0.62), '
            'alpha(@window_bg_color, 0.62)), url("%s"); background-size: cover; '
            'background-position: center; }' % (cls, uri))
        Gtk.StyleContext.add_provider_for_display(
            Gdk.Display.get_default(), prov, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
        _css_done.add(cls)
    return cls


class Context:
    """What a plugin's GUI page works with. Plugins use:

        ctx.plugin, ctx.values        the plugin and its live values (edited in place)
        ctx.form(page=None)           the generated form, added to `page` or a new
                                      Adw.PreferencesPage, which it returns
        ctx.import_group()            a group with one row per importer
        ctx.reload()                  rebuild the page from ctx.values (after a big change)
        ctx.toast(text), ctx.error(heading, body)
        ctx.window                    the window, for dialogs
    """

    def __init__(self, app, plugin, values, page):
        self.app, self.plugin, self.values, self._page = app, plugin, values, page
        self.errors = {}
        self.dirty = False

    @property
    def window(self):
        return self.app.win

    def toast(self, text):
        self.app.toast(text)

    def error(self, heading, body):
        self.app.error(heading, body)

    def reload(self):
        self.errors.clear()
        self._page.rebuild()

    def changed(self, keys, value):
        P.set_path(self.values, keys, value)
        self.dirty = True

    # -- the generated form --------------------------------------------------------------

    def form(self, page=None, importers=None):
        page = page or Adw.PreferencesPage()
        if importers is None:
            importers = self.plugin.gui == 'form'
        if importers and self.plugin.importers:
            page.add(self.import_group())
        # Top-level fields that are not groups share one untitled group, first on the page.
        loose = Adw.PreferencesGroup()
        loose_adv, n_loose = [], 0
        page.add(loose)
        for f in self.plugin.fields:
            if f.hidden:
                continue
            if isinstance(f, P.Group):
                page.add(self._group(f, [f.key]))
            elif f.advanced:
                loose_adv.append(f)
            else:
                loose.add(self._row(f, [f.key]))
                n_loose += 1
        if loose_adv:
            loose.add(self._advanced(loose_adv, []))
        elif not n_loose:
            page.remove(loose)
        return page

    def _group(self, g, keys):
        pg = Adw.PreferencesGroup(title=g.label)
        if g.help:
            pg.set_description(g.help)
        if g.advanced:
            ex = Adw.ExpanderRow(title='Show %s' % g.label.lower(), use_markup=False)
            ex.set_subtitle('Advanced')
            for f in g.fields:
                if not f.hidden:
                    ex.add_row(self._row(f, keys + [f.key]))
            pg.add(ex)
            return pg
        adv = []
        for f in g.fields:
            if f.hidden:
                continue
            if f.advanced:
                adv.append(f)
            else:
                pg.add(self._row(f, keys + [f.key]))
        if adv:
            pg.add(self._advanced(adv, keys))
        return pg

    def _advanced(self, fields, keys):
        ex = Adw.ExpanderRow(title='Advanced', use_markup=False)
        for f in fields:
            ex.add_row(self._row(f, keys + [f.key]))
        return ex

    def _row(self, f, keys):
        path = '.'.join(map(str, keys))
        v = P.get_path(self.values, keys)
        if isinstance(f, P.List):
            return self._list(f, keys, v)
        if isinstance(f, P.Group):
            ex = Adw.ExpanderRow(title=f.label, use_markup=False)
            for sub in f.fields:
                if not sub.hidden:
                    ex.add_row(self._row(sub, keys + [sub.key]))
            return ex
        if isinstance(f, P.Bool):
            r = Adw.SwitchRow(title=f.label, active=bool(v), use_markup=False)
            r.connect('notify::active', lambda w, _p: self.changed(keys, w.get_active()))
            return self._help(r, f)
        if isinstance(f, P.Enum):
            labels = [lab for _v, lab in f.choices]
            r = Adw.ComboRow(title=f.label, model=Gtk.StringList.new(labels), use_markup=False)
            vals = [cv for cv, _l in f.choices]
            r.set_selected(vals.index(v) if v in vals else 0)
            r.connect('notify::selected', lambda w, _p: self.changed(keys, vals[w.get_selected()]))
            return self._help(r, f)
        if isinstance(f, P.Int) and not f.hex and not f.exclude and f.hi - f.lo <= SPIN_MAX:
            r = Adw.SpinRow.new_with_range(f.lo, f.hi, 1)
            r.set_title(f.label)
            r.set_value(v)
            r.connect('notify::value', lambda w, _p: self.changed(keys, int(w.get_value())))
            return self._help(r, f)
        if isinstance(f, P.Image):
            return self._image(f, keys, v)
        return self._entry(f, keys, path, v)

    def _help(self, r, f):
        if f.help:
            r.set_tooltip_text(f.help)
            if hasattr(r, 'set_subtitle'):
                r.set_subtitle(f.help)
        return r

    def _entry(self, f, keys, path, v):
        r = Adw.EntryRow(title=f.label, use_markup=False)
        r.set_text(f.to_text(v) if not isinstance(f, P.Str) else v)
        if f.help:
            r.set_tooltip_text(f.help)

        def check(w):
            try:
                nv = f.from_text(w.get_text(), path) if not isinstance(f, P.Str) \
                    else f.validate(w.get_text(), path)
            except P.ValidationError as e:
                w.add_css_class('error')
                w.set_tooltip_text(e.msg)
                self.errors[path] = '%s: %s' % (f.label, e.msg)
                return None, False
            w.remove_css_class('error')
            w.set_tooltip_text(f.help or None)
            self.errors.pop(path, None)
            return nv, True

        def on_change(w):
            nv, good = check(w)
            if good:
                self.changed(keys, nv)
        check(r)
        r.connect('changed', on_change)
        return r

    def _list(self, f, keys, v):
        ex = Adw.ExpanderRow(title=f.label, use_markup=False)
        ex.set_subtitle(self._list_summary(f, v))
        if f.broadcast:
            all_row = Adw.EntryRow(title='Set every %s' % f.item.label.lower(),
                                   show_apply_button=True, use_markup=False)
            slot_rows = []

            def apply(w):
                text = w.get_text()
                for sr in slot_rows:
                    sr.set_text(text)
            all_row.connect('apply', apply)
            ex.add_row(all_row)
        for i in range(f.count):
            sub = keys + [i]
            if isinstance(f.item, P.Group):
                inner = Adw.ExpanderRow(title=f.slot_label(i), use_markup=False)
                for sf in f.item.fields:
                    if not sf.hidden:
                        inner.add_row(self._row(sf, sub + [sf.key]))
                ex.add_row(inner)
            else:
                r = self._row(f.item, sub)
                if hasattr(r, 'set_title'):
                    r.set_title(f.slot_label(i))
                if f.broadcast and isinstance(r, Adw.EntryRow):
                    slot_rows.append(r)
                ex.add_row(r)
        return ex

    @staticmethod
    def _list_summary(f, v):
        if not isinstance(f.item, P.Group):
            distinct = sorted({str(x) for x in v if x != ''})
            if len(distinct) == 1:
                return distinct[0]
            return '%d different' % len(distinct) if distinct else 'empty'
        used = sum(1 for x in v if any(val not in (0, '', b'\x00' * 6) for val in x.values()))
        return '%d of %d in use' % (used, f.count)

    def _image(self, f, keys, v):
        r = Adw.ActionRow(title=f.label, use_markup=False)
        r.set_subtitle('%d x %d' % (f.width, f.height))
        pic = Gtk.Picture(can_shrink=False, valign=Gtk.Align.CENTER)
        scale = max(1, 48 // f.width)
        pic.set_paintable(texture_from_rgb565(v, scale))
        r.add_prefix(pic)

        def pick():
            dlg = Gtk.FileDialog(title='Choose a picture for %s' % f.label)
            filt = Gtk.FileFilter(name='PNG pictures')
            filt.add_pattern('*.png')
            filt.add_pattern('*.PNG')
            filters = Gio.ListStore.new(Gtk.FileFilter)
            filters.append(filt)
            dlg.set_filters(filters)

            def done(d, res):
                try:
                    path = d.open_finish(res).get_path()
                except GLib.Error:
                    return

                def loaded(px):
                    if isinstance(px, P.ValidationError):
                        return self.error('Cannot use that picture', px.msg)
                    if isinstance(px, Exception):
                        return self.error('Cannot use that picture', str(px))
                    self.changed(keys, px)
                    pic.set_paintable(texture_from_rgb565(px, scale))
                run_async(lambda: f.from_text(path, '.'.join(map(str, keys))), loaded)
            dlg.open(self.window, None, done)

        b = Gtk.Button(label='Choose…', valign=Gtk.Align.CENTER)
        b.connect('clicked', lambda _b: pick())
        r.add_suffix(b)
        return r

    # -- importers -----------------------------------------------------------------------

    def import_group(self):
        g = Adw.PreferencesGroup(title='Import')
        for imp in self.plugin.importers:
            r = Adw.ActionRow(title=imp.label, use_markup=False)
            if imp.help:
                r.set_subtitle(imp.help)
            b = Gtk.Button(label='Choose…', valign=Gtk.Align.CENTER)
            b.connect('clicked', lambda _b, i=imp: self.run_importer(i))
            r.add_suffix(b)
            r.set_activatable_widget(b)
            g.add(r)
        return g

    def run_importer(self, imp):
        if imp.kind == 'file':
            return self._import_file(imp)
        return self._import_message(imp)

    def _apply_import(self, fn):
        def done(res):
            if isinstance(res, Exception):
                return self.error('Import failed', str(res))
            self.values.clear()
            self.values.update(res)
            self.dirty = True
            self.reload()
            self.toast('Imported')
        work_values = P.values_from_json(self.plugin, P.values_to_json(self.plugin, self.values))
        run_async(lambda: fn(work_values), done)

    def _import_file(self, imp):
        dlg = Gtk.FileDialog(title=imp.label)
        if imp.patterns and imp.patterns != ('*',):
            filt = Gtk.FileFilter(name=imp.label)
            for pat in imp.patterns:
                filt.add_pattern(pat)
            filters = Gio.ListStore.new(Gtk.FileFilter)
            filters.append(filt)
            dlg.set_filters(filters)

        def done(d, res):
            try:
                path = d.open_finish(res).get_path()
            except GLib.Error:
                return

            def work(vals):
                with open(path, 'rb') as fh:
                    data = fh.read()
                return imp.fn(self.plugin, vals, data, os.path.basename(path))
            self._apply_import(work)
        dlg.open(self.window, None, done)

    def _import_message(self, imp):
        """Pick a stored message (received, or in the outbox) or a message file."""
        daemon = self.app.daemon

        def fetch():
            out = []
            titles = ['%08x' % t for t in self.plugin.title_ids]
            rep, _why = daemon.try_call('inbox', titles=titles)
            for m in (rep or {}).get('messages', []):
                out.append(('Received', base64.b64decode(m['data']), m.get('when')))
            for t in titles:
                rep, _why = daemon.try_call('outbox_get', title=t)
                for m in (rep or {}).get('messages', []):
                    out.append(('In the outbox', base64.b64decode(m['data']), None))
            return out

        def show(found):
            if isinstance(found, Exception):
                found = []
            d = Adw.AlertDialog(heading=imp.label,
                                body='Choose a message to take it from.' if found else
                                'The relay holds no %s messages. Choose a message file '
                                'instead.' % self.plugin.game)
            lst = Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE, css_classes=['boxed-list'])
            for where, c, when in found[::-1]:
                try:
                    h = sp_cec.parse_header(c[0x14:] if c[:2] == b'\x61\x61' else c)
                    sub = '%s   ·   %s' % (where, h['created']['text'][:19])
                except ValueError:
                    sub = where
                lst.append(Adw.ActionRow(title='Message %s' % c[0x20:0x28].hex(),
                                         subtitle=sub, use_markup=False))
            if found:
                lst.select_row(lst.get_row_at_index(0))
                sw = Gtk.ScrolledWindow(child=lst, min_content_height=min(240, 60 * len(found)),
                                        propagate_natural_height=True)
                d.set_extra_child(sw)
            d.add_response('cancel', 'Cancel')
            d.add_response('file', 'From a file…')
            if found:
                d.add_response('use', 'Use this one')
                d.set_response_appearance('use', Adw.ResponseAppearance.SUGGESTED)

            def resp(_d, r):
                if r == 'use':
                    sel = lst.get_selected_row()
                    if sel is None:
                        return
                    c = found[::-1][sel.get_index()][1]
                    self._apply_import(lambda vals: imp.fn(self.plugin, vals, c))
                elif r == 'file':
                    fd = Gtk.FileDialog(title=imp.label)

                    def picked(dd, res):
                        try:
                            path = dd.open_finish(res).get_path()
                        except GLib.Error:
                            return

                        def work(vals):
                            with open(path, 'rb') as fh:
                                return imp.fn(self.plugin, vals, fh.read())
                        self._apply_import(work)
                    fd.open(self.window, None, picked)
            d.connect('response', resp)
            d.present(self.window)
        run_async(fetch, show)


class PluginPage(Adw.NavigationPage):
    """One plugin's full-window page: its own content and background, About at the top right,
    and Save."""

    def __init__(self, app, plugin, values, editing=False):
        super().__init__(title=plugin.game, tag='plugin-%s' % plugin.id)
        self.app, self.plugin = app, plugin
        self.ctx = Context(app, plugin, values, self)
        self.editing = editing
        header = Adw.HeaderBar()
        about = Gtk.Button(icon_name='help-about-symbolic', tooltip_text='About this plugin')
        about.connect('clicked', lambda _b: self.show_about())
        save = Gtk.Button(label='Save', tooltip_text='Save it to the Outbox')
        save.add_css_class('suggested-action')
        save.connect('clicked', lambda _b: self.save())
        header.pack_end(about)          # packed first, so it sits furthest right
        header.pack_end(save)
        self.save_button = save
        self.tv = Adw.ToolbarView()
        self.tv.add_top_bar(header)
        cls = background_class(plugin)
        if cls:
            self.tv.add_css_class(cls)
        self.set_child(self.tv)
        self.rebuild()

    def rebuild(self):
        try:
            if self.plugin.gui == 'custom':
                content = self.plugin.build_page(self.ctx)
            else:
                content = self.ctx.form()
        except Exception as e:                             # noqa: BLE001 - a plugin's own bug
            st = Adw.StatusPage(icon_name='dialog-error-symbolic',
                                title='%s could not show its page' % self.plugin.game,
                                description='%s: %s' % (type(e).__name__, e))
            content = st
            self.save_button.set_sensitive(False)
        self.tv.set_content(content)

    def show_about(self):
        a = self.plugin.about()
        d = Adw.Dialog(title='About', content_width=440)
        tv = Adw.ToolbarView()
        tv.add_top_bar(Adw.HeaderBar())
        page = Adw.PreferencesPage()
        g = Adw.PreferencesGroup(title=a['game'], description=a['description'] or None)
        for title, value in (('Game version', ', '.join(a['versions'])),
                             ('Region', ', '.join(a['regions'])),
                             ('CEC title', ', '.join(a['title_ids'])),
                             ('Interface', a['interface']),
                             ('Edits existing messages', 'Yes' if a['can_edit'] else 'No'),
                             ('Author', a['author'] or 'Unknown')):
            r = Adw.ActionRow(title=title, subtitle=value, use_markup=False,
                              css_classes=['property'])
            r.set_subtitle_selectable(True)
            g.add(r)
        page.add(g)
        g2 = Adw.PreferencesGroup(title='Plugin')
        for title, value in (('Id', a['id']), ('Installed', a['source']), ('File', a['path'])):
            r = Adw.ActionRow(title=title, subtitle=value, use_markup=False,
                              css_classes=['property'])
            r.set_subtitle_selectable(True)
            g2.add(r)
        page.add(g2)
        tv.set_content(page)
        d.set_child(tv)
        d.present(self.app.win)

    def save(self):
        if self.ctx.errors:
            body = '\n'.join(msg for _p, msg in sorted(self.ctx.errors.items())[:12])
            return self.app.error('Some fields need fixing', body)
        plugin, values = self.plugin, self.ctx.values
        self.save_button.set_sensitive(False)

        def built(res):
            self.save_button.set_sensitive(True)
            if isinstance(res, Exception):
                return self.app.error('Could not build the message', str(res))
            self.result = res
            self._put(False)
        run_async(lambda: P.build(plugin, values), built)

    def _put(self, replace):
        res, daemon = self.result, self.app.daemon

        def done(rep):
            if isinstance(rep, Exception):
                return self.app.error('Not saved', str(rep))
            if not rep.get('ok') and rep.get('exists'):
                return self._confirm_overwrite(rep['exists'])
            if not rep.get('ok'):
                return self.app.error('Not saved', rep.get('error') or 'the daemon refused it')
            self.ctx.dirty = False
            self.app.toast('%s message saved to the outbox' % self.plugin.game)
            self.app.win.nav.pop()
            self.app.refresh_now()
        run_async(lambda: sp_create.put(daemon.home, self.plugin, res, replace=replace), done)

    def _confirm_overwrite(self, n):
        d = Adw.AlertDialog(
            heading='Overwrite the %s message?' % self.plugin.game,
            body='The outbox already has %s for %s. Saving replaces %s with this one.\n\n'
                 'This cannot be undone.'
                 % ('a message' if n == 1 else '%d messages' % n, self.plugin.game,
                    'it' if n == 1 else 'them'))
        d.add_response('cancel', 'Cancel')
        d.add_response('overwrite', 'Overwrite')
        d.set_response_appearance('overwrite', Adw.ResponseAppearance.DESTRUCTIVE)
        d.connect('response', lambda _d, r: r == 'overwrite' and self._put(True))
        d.present(self.app.win)


class Plugins:
    """The app's view of the installed plugins."""

    def __init__(self, app):
        self.app = app
        self.plugins, self.broken = [], []
        self.identity = None
        self.reload()

    def reload(self):
        self.plugins, self.broken = P.discover()
        for p in self.plugins:
            p.context['store'] = self.app.daemon.store
            p.context['identity'] = self.identity

    def set_identity(self, identity):
        """The running daemon's own identity, for stores this user cannot read."""
        self.identity = identity
        for p in self.plugins:
            p.context['identity'] = identity

    def for_title(self, tid):
        return P.for_title(tid, self.plugins)

    def open(self, plugin, values=None, editing=False):
        if values is None:
            try:
                values = plugin.defaults()
            except Exception as e:                         # noqa: BLE001
                return self.app.error('%s could not start' % plugin.game,
                                      '%s: %s' % (type(e).__name__, e))
        self.app.win.nav.push(PluginPage(self.app, plugin, values, editing))

    def picker(self):
        self.reload()
        d = Adw.Dialog(title='Create', content_width=460)
        tv = Adw.ToolbarView()
        tv.add_top_bar(Adw.HeaderBar())
        page = Adw.PreferencesPage()
        g = Adw.PreferencesGroup(description='Choose a game to make a message for. It is '
                                             'saved to the Outbox and served from the next '
                                             'exchange.')
        for p in self.plugins:
            a = p.about()
            r = Adw.ActionRow(title=p.game, use_markup=False,
                              subtitle='Version %s   ·   region %s' % (
                                  ', '.join(a['versions']), ', '.join(a['regions'])))
            if p.gui is None:
                r.set_sensitive(False)
                r.add_suffix(Gtk.Label(label='CLI', css_classes=['dim-label'],
                                       valign=Gtk.Align.CENTER))
                r.set_tooltip_text('Command line only: tuxchange create %s --info' % p.id)
            else:
                r.set_activatable(True)
                r.add_suffix(Gtk.Image(icon_name='go-next-symbolic'))
                r.connect('activated', lambda _r, pp=p: (d.close(), self.open(pp)))
            g.add(r)
        for b in self.broken:
            r = Adw.ActionRow(title=b.id, use_markup=False,
                              subtitle='Failed to load: %s' % b.error.splitlines()[-1])
            r.set_sensitive(False)
            r.set_tooltip_text(b.path)
            g.add(r)
        if not self.plugins and not self.broken:
            g.add(Adw.ActionRow(title='No plugins installed',
                                subtitle='Put plugins in %s' % P.user_dir()))
        page.add(g)
        tv.set_content(page)
        d.set_child(tv)
        d.present(self.app.win)

    def edit(self, title_hex):
        """Open the plugin for a title with its outbox message loaded."""
        tid = int(title_hex, 16)
        plugin = self.for_title(tid)
        if plugin is None:
            return self.app.error('No plugin can edit this',
                                  'No installed plugin handles title %08X.' % tid)

        def load():
            rep = self.app.daemon.call('outbox_get', title='%08x' % tid)
            if not rep.get('ok'):
                raise RuntimeError(rep.get('error') or 'the daemon closed the connection')
            if not rep['messages']:
                raise RuntimeError('the outbox holds no message for %08X' % tid)
            container = base64.b64decode(rep['messages'][0]['data'])
            try:
                return sp_create.load_existing(plugin, container)
            except P.PluginParseError as e:
                return e

        def loaded(res):
            if isinstance(res, P.PluginParseError):
                why = str(res)
                d = Adw.AlertDialog(heading='%s cannot read this message' % plugin.game,
                                    body='%s\n\nYou can start a new one instead; saving it '
                                         'replaces this message.' % (why[:1].upper() + why[1:]))
                d.add_response('cancel', 'Cancel')
                d.add_response('fresh', 'Start fresh')
                d.connect('response', lambda _d, r: r == 'fresh' and self.open(plugin))
                return d.present(self.app.win)
            if isinstance(res, Exception):
                return self.app.error('Could not load the message', str(res))
            self.open(plugin, res, editing=True)
        run_async(load, loaded)
