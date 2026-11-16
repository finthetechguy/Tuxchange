"""Getting a Mii into the Plaza plugin: raw Mii data, a 3DS Mii QR code, or a stored message.

All three end in sp_plaza.apply_mii, which takes the Mii's appearance and its identity
(name, creator, Mii id and creator MAC). Decrypting a QR code or a message's Mii uses
your own keyslot 0x31 key; none is shipped.
"""
import io

import sp_plugin as P, sp_plaza, sp_mii, sp_cec, lp_keys

QR_PAYLOAD = sp_mii.ENTRY_LEN       # a 3DS Mii QR code carries a 0x70-byte APT-wrapped entry


def _apply(values, cfl):
    try:
        return sp_plaza.apply_mii(values, cfl)
    except ValueError as e:
        raise P.PluginError(str(e))


def _unwrap(entry, what):
    try:
        cfl, ok = sp_mii.unwrap_entry(entry)
    except lp_keys.MissingKey as e:
        raise P.PluginError('decrypting %s needs your keyslot 0x31 key.\n%s' % (what, e))
    if not ok:
        raise P.PluginError('%s could not decrypt: its AES-CCM tag does not match. Is your '
                            'keyslot 0x31 key correct?' % what)
    return cfl


def import_raw(plugin, values, data, filename=''):
    """A 0x60-byte decrypted Mii (CFLStoreData, as Mii tools save it), or a 0x70-byte
    wrapped entry."""
    if len(data) == sp_mii.CFL_LEN:
        return _apply(values, bytes(data))
    if len(data) == sp_mii.ENTRY_LEN:
        return _apply(values, _unwrap(bytes(data), 'this wrapped Mii'))
    raise P.PluginError('%s is %d bytes; Mii data is %d bytes decrypted or %d wrapped'
                        % (filename or 'the file', len(data), sp_mii.CFL_LEN, sp_mii.ENTRY_LEN))


def import_message(plugin, values, container):
    """The Mii out of a Mii Plaza message: one received, or one in the outbox."""
    try:
        h, _ex, body = sp_cec.split_message(container)
    except ValueError as e:
        raise P.PluginError('not a readable CEC message: %s' % e)
    if h['cec_title_id'] != sp_plaza.TITLE_ID:
        raise P.PluginError('message is for title %08X, not Mii Plaza' % h['cec_title_id'])
    try:
        cfl, ok = sp_mii.read_plaza_mii(body)
    except lp_keys.MissingKey as e:
        raise P.PluginError('reading the Mii needs your keyslot 0x31 key.\n%s' % e)
    except (ValueError, IndexError) as e:
        raise P.PluginError('message holds no readable Mii: %s' % e)
    if not ok:
        raise P.PluginError('Mii in that message did not decrypt (AES-CCM tag mismatch)')
    return _apply(values, cfl)


def grey_image(data):
    """Image bytes -> (width, height, 8-bit greyscale bytes). PNG is read with the
    standard library; JPEG and the rest need Pillow or GdkPixbuf (GTK)."""
    if data[:8] == b'\x89PNG\r\n\x1a\n':
        try:
            w, h, rows = P.read_png(data)
            return w, h, bytes((r * 299 + g * 587 + b * 114) // 1000 for row in rows
                               for r, g, b in row)
        except ValueError:
            pass                                    # e.g. 16-bit or interlaced: try a library
    try:
        from PIL import Image
        im = Image.open(io.BytesIO(data)).convert('L')
        return im.width, im.height, im.tobytes()
    except ImportError:
        pass
    except Exception as e:
        raise P.PluginError('cannot read the image: %s' % e)
    try:
        import gi
        gi.require_version('GdkPixbuf', '2.0')
        from gi.repository import GdkPixbuf
        loader = GdkPixbuf.PixbufLoader()
        loader.write(data)
        loader.close()
        pb = loader.get_pixbuf()
        w, h, n, stride = pb.get_width(), pb.get_height(), pb.get_n_channels(), pb.get_rowstride()
        px = pb.get_pixels()
        out = bytearray(w * h)
        for y in range(h):
            row = px[y * stride:y * stride + w * n]
            for x in range(w):
                r, g, b = row[x * n:x * n + 3]
                out[y * w + x] = (r * 299 + g * 587 + b * 114) // 1000
        return w, h, bytes(out)
    except (ImportError, ValueError):
        pass
    except Exception as e:
        raise P.PluginError('cannot read the image: %s' % e)
    raise P.PluginError('this format image needs Pillow (pip install pillow) or '
                        'GTK\'s GdkPixbuf; or save it as a PNG first')


def decode_qr(data):
    """An image with a QR code in it -> the code's raw bytes."""
    w, h, grey = grey_image(data)
    try:
        import zxingcpp
    except ImportError:
        zxingcpp = None
    if zxingcpp is not None:
        found = zxingcpp.read_barcodes(memoryview(grey).cast('B', (h, w)),
                                       formats=zxingcpp.BarcodeFormat.QRCode)
        if not found:
            raise P.PluginError('no QR code found in the image')
        return bytes(found[0].bytes)
    try:
        from pyzbar import pyzbar
    except ImportError:
        raise P.PluginError('reading QR codes needs zxing-cpp (pip install zxing-cpp, or '
                            'pip install "tuxchange[qr]")')
    found = [r for r in pyzbar.decode((grey, w, h)) if r.type == 'QRCODE']
    if not found:
        raise P.PluginError('no QR code found in the image')
    raw = found[0].data
    if len(raw) != QR_PAYLOAD:
        # zbar may hand binary content back transcoded to UTF-8.
        try:
            raw = raw.decode('utf-8').encode('latin-1')
        except (UnicodeDecodeError, UnicodeEncodeError):
            pass
    return raw


def import_qr(plugin, values, data, filename=''):
    """A picture of a 3DS Mii QR code (as Mii Maker saves it, or a photo)."""
    raw = decode_qr(data)
    if len(raw) < QR_PAYLOAD:
        raise P.PluginError('QR code carries %d bytes; 3DS Mii QR code carries %d'
                            % (len(raw), QR_PAYLOAD))
    return _apply(values, _unwrap(raw[:QR_PAYLOAD], 'Mii QR code'))
