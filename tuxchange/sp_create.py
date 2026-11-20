#!/usr/bin/env python3
"""`tuxchange create`: make or edit an outbox message with a game plugin, from the CLI.

    tuxchange create --list
    tuxchange create miiplaza --info
    tuxchange create miiplaza --greeting 'Hi there' --profile.hat 12
    tuxchange create miiplaza --edit --set met16.0.name_a=Tux
    tuxchange create miiplaza --from-json card.json --out plaza.bin

The plugin turns the values into a body. With --out, Tuxchange wraps it into a message
here and writes it to a file; otherwise the running daemon wraps it, signs it and files
it in the outbox, so it is served from the next exchange.
"""
import os, sys, json, base64, argparse

import sp_plugin as P
import sp_store
import lp_keys


def daemon_call(store, cmd, **kw):
    import sp_relay
    sock = sp_relay.control_socket_path(sp_relay.resolve_store(store))
    try:
        return sp_relay.send_command(sock, cmd, **kw)
    except OSError as e:
        raise P.PluginError('cannot reach the daemon at %s (%s). Is it running? Use --out to '
                            'write a message file without it.' % (sock, e))


def put(store, plugin, result, replace=False):
    """Hand a BuildResult to the daemon. -> its reply ({'ok', 'exists', ...})."""
    req = {'title': '%08x' % result.title_id, 'plugin': plugin.id, 'name': result.name,
           'body': base64.b64encode(result.body).decode(), 'send_mode': result.send_mode,
           'replace': bool(replace)}
    if result.info_text is not None:
        req['info_text'] = result.info_text
    if result.icon is not None:
        req['icon'] = base64.b64encode(result.icon).decode()
    return daemon_call(store, 'outbox_put', **req)


def fetch_outbox(store, title_id):
    """-> [container bytes] the daemon holds in the outbox for `title_id`."""
    r = daemon_call(store, 'outbox_get', title='%08x' % title_id)
    if not r.get('ok'):
        raise P.PluginError(r.get('error') or 'outbox_get failed')
    return [base64.b64decode(m['data']) for m in r['messages']]


def fetch_inbox(store, title_ids):
    r = daemon_call(store, 'inbox', titles=['%08x' % t for t in title_ids])
    if not r.get('ok'):
        raise P.PluginError(r.get('error') or 'inbox failed')
    return [base64.b64decode(m['data']) for m in r['messages']]


def load_existing(plugin, container):
    """A stored message -> values, via the plugin's parser. Raises PluginParseError."""
    import sp_cec
    try:
        h, _ex, body = sp_cec.split_message(container)
    except ValueError as e:
        raise P.PluginParseError('not a readable CEC message: %s' % e)
    if h['cec_title_id'] not in plugin.title_ids:
        raise P.PluginParseError('this message is for title %08X, not one %s handles'
                                 % (h['cec_title_id'], plugin.game))
    return P.parse(plugin, body)


def flag_name(path):
    return '--' + path.replace('_', '-')


def _norm_path(plugin, path):
    """Accept dashes for underscores, as the flags are spelled."""
    try:
        P.resolve(list(plugin.fields), path)
        return path
    except KeyError:
        return path.replace('-', '_')


def describe(plugin, out=print):
    a = plugin.about()
    out('%s  (%s)' % (a['game'], a['id']))
    if a['description']:
        out('  %s' % a['description'])
    out('  versions   %s' % ', '.join(a['versions']))
    out('  regions    %s' % ', '.join(a['regions']))
    out('  titles     %s' % ', '.join(a['title_ids']))
    out('  send mode  %d' % a['send_mode'])
    out('  interface  %s%s' % (a['interface'], ', can edit existing messages'
                               if a['can_edit'] else ''))
    if a['author']:
        out('  author     %s' % a['author'])
    out('  from       %s (%s)' % (a['path'], a['source']))
    out('\nfields (set with the flag, or --set PATH=VALUE for any path):')
    for path, f, in_list in P.leaves(list(plugin.fields)):
        if in_list and not path.endswith('.0') and '.0.' not in path:
            continue
        shown = path if in_list else flag_name(path)
        if in_list:
            shown = '--set ' + path.replace('.0', '.N', 1) + '=...'
        out('  %-34s %s%s' % (shown, f.describe(), ('  - ' + f.help) if f.help else ''))
    for imp in plugin.importers:
        out('  %-34s %s' % ('--import-%s %s' % (imp.key.replace('_', '-'),
                                                 'FILE' if imp.kind == 'file' else 'SOURCE'),
                            imp.label + ('  - ' + imp.help if imp.help else '')))


def make_parser(plugin):
    ap = argparse.ArgumentParser(prog='tuxchange create %s' % plugin.id,
                                 description='Make a %s message. --info lists every field.'
                                             % plugin.game)
    ap.add_argument('--store', default=None,
                    help='the daemon\'s store (default: $SP_STORE, else relay_store in this '
                         'checkout if present, else %s)' % sp_store.INSTALLED_STORE)
    ap.add_argument('--info', action='store_true', help='describe the plugin and its fields')
    ap.add_argument('--edit', action='store_true',
                    help="start from the message already in the daemon's outbox")
    ap.add_argument('--edit-file', metavar='FILE', help='start from a message file')
    ap.add_argument('--from-json', metavar='FILE', help='values from a JSON file (- for stdin)')
    ap.add_argument('--dump-json', metavar='FILE',
                    help='write the final values as JSON (- for stdout) and build nothing')
    ap.add_argument('--set', action='append', default=[], metavar='PATH=VALUE',
                    help='set any field by its dotted path, e.g. met16.3.name_a=Tux')
    ap.add_argument('--out', metavar='FILE',
                    help='write the finished message to FILE instead of filing it via the daemon')
    ap.add_argument('--key', metavar='HEX', help='with --out: the title\'s 32-byte HMAC key '
                                                 '(default: from your key files)')
    g = ap.add_mutually_exclusive_group()
    g.add_argument('--replace', action='store_true', default=None,
                   help='overwrite the message already in the outbox without asking')
    g.add_argument('--no-replace', dest='replace', action='store_false',
                   help='fail rather than overwrite')
    seen = set()
    for path, f, in_list in P.leaves(list(plugin.fields)):
        if in_list:
            continue
        name = flag_name(path)
        if name in seen:
            continue
        seen.add(name)
        ap.add_argument(name, dest='f:' + path, metavar='VALUE', default=None,
                        help=(f.label + ': ' + f.describe() + ('. ' + f.help if f.help else '')
                              ).replace('%', '%%'))
    for imp in plugin.importers:
        ap.add_argument('--import-' + imp.key.replace('_', '-'), dest='i:' + imp.key,
                        metavar='FILE' if imp.kind == 'file' else 'SOURCE', default=None,
                        help=(imp.label + ('. ' + imp.help if imp.help else '')
                              + ('' if imp.kind == 'file' else
                                 '. SOURCE is a message file, "outbox", or "inbox" / "inbox:N" '
                                 'for a received one (newest is inbox:0)')).replace('%', '%%'))
    return ap


def _message_source(store, plugin, src):
    if os.path.exists(src):
        with open(src, 'rb') as fh:
            return fh.read()
    if src == 'outbox':
        got = fetch_outbox(store, plugin.title_ids[0])
        if not got:
            raise P.PluginError('the outbox holds no %s message' % plugin.game)
        return got[0]
    if src == 'inbox' or src.startswith('inbox:'):
        n = int(src.split(':', 1)[1]) if ':' in src else 0
        got = fetch_inbox(store, plugin.title_ids)
        if not (0 <= n < len(got)):
            raise P.PluginError('the inbox holds %d %s message(s); there is no inbox:%d'
                                % (len(got), plugin.game, n))
        return got[-1 - n]
    raise P.PluginError('%s is not a file, "outbox" or "inbox[:N]"' % src)


def confirm(question):
    if not sys.stdin.isatty():
        return False
    try:
        return input(question + ' [y/N] ').strip().lower() in ('y', 'yes')
    except EOFError:
        return False


def run(plugin, argv, out=print):
    a = make_parser(plugin).parse_args(argv)
    if a.store is None:
        a.store = sp_store.default_store()
    if a.info:
        describe(plugin, out)
        return 0
    import sp_relay
    plugin.context['store'] = sp_relay.resolve_store(a.store)
    values = plugin.defaults()
    if a.edit or a.edit_file:
        if a.edit_file:
            with open(a.edit_file, 'rb') as fh:
                existing = [fh.read()]
        else:
            existing = fetch_outbox(a.store, plugin.title_ids[0])
            if not existing:
                raise P.PluginError('the outbox holds no %s message to edit' % plugin.game)
        values = load_existing(plugin, existing[0])
    if a.from_json:
        obj = json.load(sys.stdin if a.from_json == '-' else open(a.from_json))
        merged = P.values_to_json(plugin, values)
        merged.update(obj)
        values = P.values_from_json(plugin, merged)
    for imp in plugin.importers:
        src = getattr(a, 'i:' + imp.key)
        if src is None:
            continue
        if imp.kind == 'file':
            with open(src, 'rb') as fh:
                values = imp.fn(plugin, values, fh.read(), os.path.basename(src))
        else:
            values = imp.fn(plugin, values, _message_source(a.store, plugin, src))
    for path, _f, in_list in P.leaves(list(plugin.fields)):
        if in_list:
            continue
        v = getattr(a, 'f:' + path, None)
        if v is not None:
            P.set_text(plugin, values, path, v)
    for s in a.set:
        if '=' not in s:
            raise P.ValidationError(s, 'expected PATH=VALUE')
        path, text = s.split('=', 1)
        P.set_text(plugin, values, _norm_path(plugin, path.strip()), text)

    if a.dump_json:
        text = json.dumps(P.values_to_json(plugin, P.validate(plugin, values)), indent=1,
                          ensure_ascii=False)
        if a.dump_json == '-':
            out(text)
        else:
            with open(a.dump_json, 'w') as fh:
                fh.write(text + '\n')
            out('wrote %s' % a.dump_json)
        return 0

    result = P.build(plugin, values)
    if a.out:
        key = bytes.fromhex(a.key) if a.key else None
        msg = P.envelope(result, key=key)
        with open(a.out, 'wb') as fh:
            fh.write(msg)
        out('wrote %s: a %s message, %d B (title %08X)'
            % (a.out, plugin.game, len(msg), result.title_id))
        return 0

    reply = put(a.store, plugin, result, replace=bool(a.replace))
    if not reply.get('ok') and reply.get('exists') and a.replace is None:
        if confirm('The outbox already has %d %s message(s). Overwrite?'
                   % (reply['exists'], plugin.game)):
            reply = put(a.store, plugin, result, replace=True)
        else:
            out('left the outbox unchanged (pass --replace to overwrite without asking)')
            return 1
    if not reply.get('ok'):
        raise P.PluginError(reply.get('error') or 'the daemon refused the message')
    out('filed a %s message in the outbox: %d B%s'
        % (plugin.game, reply.get('bytes', 0),
           ', replacing %d' % reply['replaced'] if reply.get('replaced') else ''))
    return 0


def list_plugins(out=print):
    plugins, broken = P.discover()
    if not plugins and not broken:
        out('no plugins found (looked in %s and %s)' % (P.BUILTIN_DIR, P.user_dir()))
    for p in plugins:
        a = p.about()
        out('%-14s %-30s versions %-18s regions %-12s %s'
            % (p.id, p.game, ', '.join(a['versions']), ', '.join(a['regions']), a['interface']))
    for b in broken:
        out('%-14s BROKEN: %s' % (b.id, b.error.splitlines()[-1]))
        out('%-14s   (%s)' % ('', b.path))
    return 0


def main(argv=None, out=print):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ('--list', '-l', 'list'):
        return list_plugins(out)
    if argv[0] in ('-h', '--help'):
        out(__doc__.strip())
        return 0
    try:
        plugins, _b = P.discover()
        return run(P.find(argv[0], plugins), argv[1:], out)
    except P.PluginError as e:
        print('error: %s' % e, file=sys.stderr)
        return 1
    except OSError as e:
        print('error: %s' % e, file=sys.stderr)
        return 1


def _selftest():
    import tempfile, shutil
    import lp_keys as _k, sp_cec, sp_build, sp_mii
    if _k.selftest_keys():
        print('  (no console keys found, so running on generated throwaway keys)')
    ok = tot = skipped = 0

    def chk(n, c, g=''):
        nonlocal ok, tot
        tot += 1; ok += bool(c)
        print('  [%s] %s%s' % ('PASS' if c else 'FAIL', n, ('  %s' % (g,)) if g else ''))

    def skip(n, why):
        nonlocal skipped
        skipped += 1
        print('  [SKIP] %s  (%s)' % (n, why))

    tmp = tempfile.mkdtemp()
    old_xdg = os.environ.get('XDG_DATA_HOME')
    os.environ['XDG_DATA_HOME'] = os.path.join(tmp, 'xdg')      # no user plugins in the way
    lines = []
    quiet = lines.append
    try:
        plugins, broken = P.discover()
        chk('the built-in Mii Plaza plugin loads cleanly',
            [p.id for p in plugins] == ['miiplaza'] and not broken,
            [str(b) for b in broken])
        plaza = P.find('miiplaza', plugins)
        store = sp_store.Store(os.path.join(tmp, 'store')).root

        def go(*argv):
            del lines[:]
            return run(plaza, ['--store', store] + list(argv), quiet)

        out = os.path.join(tmp, 'm.bin')
        chk('--out builds a message without a daemon',
            go('--greeting', 'From the CLI', '--profile.hat', '150', '--sender.country', 'France',
               '--set', 'history.met16.1.name-a=Tux', '--out', out) == 0)
        msg = open(out, 'rb').read()
        h, ex, body = sp_cec.split_message(msg)
        import sp_plaza
        v = sp_plaza.parse_body(body)
        chk('it is a Plaza message carrying what was asked for',
            h['cec_title_id'] == 0x00020800 and v['greeting'] == 'From the CLI'
            and v['profile']['hat'] == 150 and v['sender']['country'] == ['France'] * 16
            and v['history']['met16'][1]['name_a'] == 'Tux')
        chk('with the Plaza\'s icon and info text in its ex-headers',
            [e['type'] for e in ex] == [2, 4] and h['send_mode'] == 0)
        import hmac, hashlib
        chk('signed with the Plaza key', msg[-0x20:] == hmac.new(
            lp_keys.plaza_hmac_key(), body, hashlib.sha256).digest())
        chk('the default Mii is the store\'s own, as `seed` makes it',
            v['mii']['mii_id'] == sp_plaza.default_values(store)['mii']['mii_id'])

        js = os.path.join(tmp, 'v.json')
        chk('--edit-file reads a message back and --dump-json writes its values',
            go('--edit-file', out, '--dump-json', js) == 0
            and json.load(open(js))['greeting'] == 'From the CLI')
        obj = json.load(open(js))
        obj['greeting'] = 'From JSON'
        json.dump(obj, open(js, 'w'))
        out2 = os.path.join(tmp, 'm2.bin')
        go('--from-json', js, '--out', out2)
        v2 = sp_plaza.parse_body(sp_cec.split_message(open(out2, 'rb').read())[2])
        chk('--from-json takes values back in, hidden ones included',
            v2['greeting'] == 'From JSON' and v2['history']['met16'][1]['name_a'] == 'Tux')

        other = sp_build.build_cfl(mii_name='Imported', author_name='Elsewhere',
                                   mii_id=0x10203090, creator_mac='b8:ae:6e:01:02:03')
        rawp = os.path.join(tmp, 'mii.bin')
        open(rawp, 'wb').write(other)
        go('--import-mii', rawp, '--out', out2)
        cfl = sp_mii.read_plaza_mii(sp_cec.split_message(open(out2, 'rb').read())[2])[0]
        chk('--import-mii takes a raw Mii', cfl == sp_mii.reseal_cfl(other))
        open(rawp, 'wb').write(sp_mii.wrap_entry(other))
        go('--import-mii', rawp, '--mii.mii-name', 'Renamed', '--out', out2)
        cfl = sp_mii.read_plaza_mii(sp_cec.split_message(open(out2, 'rb').read())[2])[0]
        chk('and a wrapped one, with a flag still overriding its name',
            sp_mii.parse_cfl(cfl)['mii_name'] == 'Renamed'
            and sp_mii.parse_cfl(cfl)['author_name'] == 'Elsewhere')
        go('--import-mii-from', out, '--out', out2)
        cfl = sp_mii.read_plaza_mii(sp_cec.split_message(open(out2, 'rb').read())[2])[0]
        chk('--import-mii-from takes the Mii out of a message file',
            sp_mii.parse_cfl(cfl)['mii_name'] == 'Relay')
        try:
            import zxingcpp, segno          # noqa: F401  (optional)
            qr = segno.make_qr(sp_mii.wrap_entry(other), mode='byte')
            qp = os.path.join(tmp, 'qr.png')
            qr.save(qp, scale=5)
            go('--import-mii-qr', qp, '--out', out2)
            cfl = sp_mii.read_plaza_mii(sp_cec.split_message(open(out2, 'rb').read())[2])[0]
            chk('--import-mii-qr reads a Mii QR code', cfl == sp_mii.reseal_cfl(other))
        except ImportError:
            skip('--import-mii-qr reads a Mii QR code', 'zxing-cpp and segno not installed')

        def refused(*argv):
            try:
                go(*argv)
            except P.PluginError:
                return True
            return False
        chk('a value the game refuses is an error', refused('--profile.hat', '69', '--out', out2))
        chk('so is an unknown --set path', refused('--set', 'nope=1', '--out', out2))
        chk('so is junk given as a Mii', refused('--import-mii', js, '--out', out2))
        chk('so is a file that is not a message, given to --edit-file',
            refused('--edit-file', js, '--out', out2))

        calls = []
        held = {'n': 1}

        def fake_call(_store, cmd, **kw):
            calls.append((cmd, kw))
            if cmd == 'outbox_put':
                if held['n'] and not kw['replace']:
                    return {'ok': False, 'exists': held['n']}
                held['n'] = 1
                return {'ok': True, 'bytes': 32732, 'replaced': 1}
            if cmd == 'outbox_get':
                return {'ok': True, 'messages': [
                    {'data': base64.b64encode(msg[sp_build.ENVELOPE_LEN:]).decode()}]}
            return {'ok': False, 'error': 'unexpected'}
        real = globals()['daemon_call']
        globals()['daemon_call'] = fake_call
        try:
            chk('without a terminal to ask on, an overwrite is not done', go() == 1
                and [c[1]['replace'] for c in calls] == [False])
            del calls[:]
            chk('--replace overwrites without asking', go('--replace') == 0
                and [c[1]['replace'] for c in calls] == [True])
            del calls[:]
            chk('--no-replace fails rather than overwrite',
                refused('--no-replace') and len(calls) == 1)
            del calls[:]
            go('--edit', '--greeting', 'Edited', '--replace')
            sent = base64.b64decode(calls[-1][1]['body'])
            ev = sp_plaza.parse_body(sent)
            chk('--edit starts from the outbox message and changes only what was asked',
                calls[0][0] == 'outbox_get' and ev['greeting'] == 'Edited'
                and ev['history']['met16'][1]['name_a'] == 'Tux')
            chk('the daemon is sent the body and hints, never a finished message',
                set(calls[-1][1]) == {'title', 'plugin', 'name', 'body', 'send_mode', 'replace',
                                      'info_text', 'icon'} and calls[-1][1]['plugin'] == 'miiplaza')
        finally:
            globals()['daemon_call'] = real
        chk('--info describes the plugin', go('--info') == 0
            and any('--profile.hat' in ln for ln in lines))
    finally:
        if old_xdg is None:
            os.environ.pop('XDG_DATA_HOME', None)
        else:
            os.environ['XDG_DATA_HOME'] = old_xdg
        shutil.rmtree(tmp, ignore_errors=True)
    print('\n%d/%d checks passed%s' % (ok, tot, ', %d skipped' % skipped if skipped else ''))
    return 0 if ok == tot else 1


if __name__ == '__main__':
    sys.modules.setdefault('sp_create', sys.modules[__name__])
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    if sys.argv[1:2] == ['--selftest']:
        sys.exit(_selftest())
    sys.exit(main())
