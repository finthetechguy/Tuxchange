"""StreetPass Mii Plaza: the built-in plugin. The body work lives in sp_plaza (core code,
also used by the daemon's `seed`); this adds the plugin metadata, importers and GUI page."""
import sp_plugin as P, sp_plaza, sp_build, lp_keys

from . import mii_import


class MiiPlaza(P.Plugin):
    id = 'miiplaza'
    game = sp_plaza.GAME
    title_ids = (sp_plaza.TITLE_ID,)
    versions = ('updated (0x7280-byte body)',)
    regions = ('any',)
    author = 'Tuxchange'
    description = ('Your Mii card: greeting, Mii, profile, location, featured software and '
                   'history. The Mii\'s appearance comes from an imported Mii. Only messages '
                   'from the latest updated version can be edited.')
    fields = sp_plaza.FIELDS
    gui = 'custom'
    background = 'background.png'
    importers = [
        P.Importer('mii', 'Import Mii data', mii_import.import_raw,
                   patterns=('*.bin', '*.cfsd', '*.mii', '*'),
                   help='0x60 bytes of decrypted Mii data, or a 0x70-byte wrapped entry'),
        P.Importer('mii_qr', 'Import a Mii QR code', mii_import.import_qr,
                   patterns=('*.png', '*.jpg', '*.jpeg', '*.bmp'),
                   help='a picture of a 3DS Mii QR code; needs zxing-cpp'),
        P.Importer('mii_from', 'Use the Mii from a message', mii_import.import_message,
                   kind='message', help='only the Mii is used.'),
    ]

    def defaults(self):
        return sp_plaza.default_values(self.context.get('store'),
                                       identity=self.context.get('identity'))

    def build(self, values):
        try:
            body = sp_plaza.build_body(values)
        except lp_keys.MissingKey as e:
            raise P.PluginError('wrapping the Mii needs your keyslot 0x31 key.\n%s' % e)
        except ValueError as e:
            raise P.PluginError(str(e))
        return P.BuildResult(body, info_text=sp_build.INFO_TEXT, icon=sp_build.cec_icon(),
                             send_mode=0, name=sp_plaza.GAME)

    def parse(self, body):
        try:
            return sp_plaza.parse_body(body)
        except lp_keys.MissingKey as e:
            raise P.PluginParseError('reading the Mii needs your keyslot 0x31 key.\n%s' % e)

    def build_page(self, ctx):
        from . import page
        return page.build(self, ctx)


PLUGIN = MiiPlaza()
