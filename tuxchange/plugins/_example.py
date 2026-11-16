"""A minimal outbox message plugin, to copy from. It is skipped because its name starts with
'_'; copy it to ~/.local/share/tuxchange/plugins/mygame.py and change it to load it.

The body format here is made up. A real plugin writes the game's own body, byte for byte.
Tuxchange adds the CEC header, ex-headers and HMAC itself; do not include them.

Try:      tuxchange create example --info
          tuxchange create example --greeting Hi --score 7 --out msg.bin
"""
import struct

import sp_plugin as P


class Example(P.Plugin):
    id = 'example'                       # lowercase, used on the command line
    game = 'Example Game'                # what the GUI lists
    title_ids = (0x00141000,)            # the game's CEC title id(s)
    versions = ('any',)                  # e.g. ('1.0', '1.1')
    regions = ('any',)                   # e.g. ('EUR', 'USA')
    author = 'You'
    description = 'Example, not a real game format.'
    gui = 'form'                         # None for CLI only; 'custom' to override build_page()

    fields = [
        P.Str('greeting', 'Greeting', max_len=16, default='Hello'),
        P.Int('score', 'Score', 0, 9999),
        P.Enum('team', 'Team', [(0, 'Red'), (1, 'Blue')]),
        P.Group('card', 'Card', [
            P.Bool('shiny', 'Shiny'),
            P.Mac('console', 'Console MAC', advanced=True),
        ]),
    ]

    def build(self, values):
        g = values['greeting'].encode('utf-16-le').ljust(0x22, b'\x00')
        body = g + struct.pack('<HBB', values['score'], values['team'],
                               values['card']['shiny']) + values['card']['console']
        body += b'\x00' * (-len(body) % 4)          # a CEC body is 4-byte aligned
        # send_mode must be the one the game uses, or the receiver drops the message.
        return P.BuildResult(body, info_text='Example', send_mode=0)

    def parse(self, body):
        if len(body) < 0x2C:
            raise P.PluginParseError('too short to be an Example Game message')
        v = self.defaults()
        v['greeting'] = body[:0x22].decode('utf-16-le', 'replace').split('\x00', 1)[0]
        v['score'], v['team'], shiny = struct.unpack_from('<HBB', body, 0x22)
        v['card'] = {'shiny': bool(shiny), 'console': body[0x26:0x2C]}
        return v


PLUGIN = Example()
