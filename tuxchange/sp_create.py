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
    ap.add_argument('--store', default='relay_store')
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
    if a.info:
        describe(plugin, out)
        return 0
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


if __name__ == '__main__':
    sys.modules.setdefault('sp_create', sys.modules[__name__])
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    sys.exit(main())
