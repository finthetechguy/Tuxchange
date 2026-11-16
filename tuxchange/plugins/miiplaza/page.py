"""The Mii Plaza plugin's GUI page: the Mii (shown as text, since it cannot be drawn without
Nintendo's assets), the ways to import one, and then the generated form for the rest."""
import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw                         # noqa: E402

import sp_plaza                                            # noqa: E402


def build(plugin, ctx):
    page = Adw.PreferencesPage()
    page.add(mii_group(plugin, ctx))
    ctx.form(page=page, importers=False)
    return page


def mii_group(plugin, ctx):
    g = Adw.PreferencesGroup(
        title='Mii',
        description='Import a Mii to change it\'s appearence..')
    box = Gtk.Box(spacing=6, valign=Gtk.Align.CENTER)
    for imp, label in zip(plugin.importers, ('Mii data…', 'QR code…', 'From a message…')):
        b = Gtk.Button(label=label, tooltip_text=imp.help or imp.label)
        b.connect('clicked', lambda _b, i=imp: ctx.run_importer(i))
        box.append(b)
    g.set_header_suffix(box)
    try:
        s = sp_plaza.mii_summary(ctx.values['mii']['mii_data'])
    except Exception as e:                                 # noqa: BLE001
        r = Adw.ActionRow(title='No usable Mii', subtitle=str(e), use_markup=False)
        r.add_css_class('error')
        g.add(r)
        return g
    for title, value in (('Gender', s['gender'].capitalize()),
                         ('Birthday', s['birthday']),
                         ('Favourite colour', s['favourite_colour'].capitalize()),
                         ('Height and build', 'Height %d, build %d' % (s['height'], s['build']))):
        r = Adw.ActionRow(title=title, subtitle=value, use_markup=False, css_classes=['property'])
        g.add(r)
    if not s['valid']:
        r = Adw.ActionRow(title='Invalid data',
                          subtitle='; '.join(s['problems']), use_markup=False)
        r.add_css_class('error')
        g.add(r)
    return g
