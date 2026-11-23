# Tuxchange

> [!IMPORTANT]  
> It is recommended to use [ctrpass](https://github.com/finthetechguy/ctrpass) instead.
> It is my new Rust-based library + Linux CLI + GUI, which doesn't rely on `systemd` and Python.
> ctrpass is also more user-friendly and provides a library for the potential of porting to other hardware.


StreetPass a real Nintendo 3DS from a Linux device (with your own data)

Walk past a 3DS with Tuxchange running and the console treats it like any other 3DS. It exchanges
a StreetPass message, blinks its notification LED green, and exchanges title-specific data.

[Skip to getting started with Tuxchange](https://github.com/finthetechguy/Tuxchange/wiki/Hardware)

## Status

This is a hobby project and not yet a completely stable solution, further updates will be made
along the way as I continue developing this project.

**Tuxchange does successfully exchange against retail consoles many times.** However, it
can take a few tries/passes for a full successful exchange depending on what wireless chipset
adapter you are using.

Working end to end:

- A real 3DS receives CEC (StreetPass) data from Linux
  - The notification LED blinks green
  - Individual title data appears in the Notifications applet
- Linux receives CEC data from a 3DS
  - Saved on disk
  - Shown in the GUI's Inbox tab

## What it does

- Discovers 3DS consoles on channels 1, 6 and 11 and answers their StreetPass probes.
- **Completes** the real handshake, derives the CCMP link key, and holds an encrypted link.
- **Exchanges** CEC objects. It sends data you uploaded and receives whatever the
  console offers, for every title both sides have enabled.
- Keeps received messages in a local store you can inspect.
- Runs as a **systemd daemon/service**, with a GTK4 **GUI** on top.
- Execute callback scripts on various events, like a successful exchange.

#### Extra

- Build game CEC data using plugins. StreetPass Mii Plaza built-in.
- Import Outbox CEC messages, from Azahar, console, etc, to send data from different games.
- Export Inbox CEC messages, to import into Azahar, etc, to use recieved data from other consoles.

## What it does not do

- It does not touch your console's firmware, save data, or online account.
- It does not work over the internet. Everything is a local exchange.

## Hardware

| | |
|---|---|
| Radio | An compatible Wi-Fi chipset that supports active monitor or mixed mode. **`ath9k` recommended** |
| Console | Any 3DS-family console. Exchanging does not require homebrew, but dumping the keys needs GodMode9. |

See [COMPATIBILITY](COMPATIBILITY.md) for a list of tested, untested, known-incompatible devices.

## Dependencies

No Python packages are required. `tuxchange/sp_aes.py` is a pure AES-128/CCM implementation
used whenever a faster backend is missing. You need Python 3.10+, plus `iw` and `ip` from your
distro.

Optional:

| Package | What it adds |
|---|---|
| `pycryptodome` | Faster AES.  |
| `scapy` | Reading packet captures: `tools/sp_report.py` and the `--replay` modes. |
| `PyGObject` + GTK4 + libadwaita | The GUI. |

### You must supply your own keys

Tuxchange comes with no console keys and cannot work without them. The protocol is authenticated and
encrypted with keys that come from a console, so you must supply them from your own hardware.

You will need two files in `~/.config/tuxchange/`:

- `aes_keys.txt`: AES keyslots, dumped with GodMode9 on your own console.
- `tuxchange.keys`: two constants read out of your own dumps.

The installer copies them to `/etc/tuxchange/`, where the service looks for them. It does not
replace copies already there, so if you dump new ones, copy them across yourself.

Check if your console data is valid:

```sh
python3 tools/lp_extract_keys.py
```

The wiki page *Getting your keys* walks through setup of this data.

## Quick start

```sh
git clone https://github.com/finthetechguy/Tuxchange && cd Tuxchange
mkdir -p ~/.config/tuxchange
install -m 600 /path/to/aes_keys.txt ~/.config/tuxchange/
python3 tools/lp_extract_keys.py --cecd /path/to/cecd/code.bin \
                                 --cec-store /path/to/your/CEC-partition.bin
sudo ./install/install.sh install       # installs daemon, copies to /opt/tuxchange
sudo systemctl start tuxchange
journalctl -u tuxchange -f              # check the logs to see if it's working
```

Re-run the installer after updating the source, as the daemon runs from a copy in
`/opt/tuxchange`, then `sudo systemctl restart tuxchange`.

To watch in a terminal instead, `sudo ./scripts/tuxchange` runs the daemon in the
foreground.

## FAQ

### "It took 3 tries for an exchange"

That is expected. The console goes quiet after an aborted attempt and has to be put back
into rescanning, which Tuxchange does automatically. If the first try does nothing, leave
it running and it should eventually exchange.

Every 8 hours, the 3DS triggers a rotation of it's MAC address, and clears a list of MAC
addresses that it exchanged with. During the period of 8 hours, the peer console's MAC
is added to this list, meaning it can't exchange again until the filter is cleared.

Tuxchange uses the same concept, with a MAC filter and rotating MAC address, clear the
filter and rotate the MAC on either (or both) consoles, this should allow them to exchange
again.

### Why only Linux + specific chipsets?

StreetPass on the 3DS has a requirement that the chipset must ACK the console's frames within
10~ microseconds, and only hardware can do that, e.g. the `ath9k` with the Linux kernel gives us control 
of that, while many other chipsets cannot. See [Hardware](https://github.com/finthetechguy/Tuxchange/wiki/Hardware)
for potentially supported chipsets.

## Documentation

- [Wiki](https://github.com/finthetechguy/Tuxchange/wiki): setup, hardware, first StreetPass, CLI
  and GUI reference, troubleshooting.

### Build the documentation locally

From the repository root, create a documentation environment and start the live preview.

```bash
python3 -m venv .venv-docs
. .venv-docs/bin/activate
python -m pip install -r requirements-docs.txt
zensical serve --dev-addr 127.0.0.1:8000
```

Open <http://127.0.0.1:8000/>. Run `zensical build --clean --strict` for a production build in
`site/`. The documentation workflow runs the same build on pull requests.

When ready to publish, select **GitHub Actions** under **Settings → Pages → Build and deployment**.
The documentation workflow uploads and deploys its artifact on pushes to `main`. The canonical URL
in `zensical.toml` uses the repository's default GitHub Pages path.

## Legal and ethical notes

Tuxchange is an independent reimplementation built through reverse engineering. It includes no
Nintendo code, console keys, etc.

Use it with your own consoles and with people who know what you are doing. A StreetPass exchange
carries real people's Mii names and greetings, so treat what you receive as their data and do not
publish it.

Nintendo, Nintendo 3DS and StreetPass are trademarks of Nintendo. This project is not affiliated
with or endorsed by Nintendo.

Linux® is the registered trademark of Linus Torvalds in the U.S. and other countries.

### AI Usage Disclaimer
LLMs were used to build this program, through writing scripts and reverse engineering. However,
Tuxchange has been extensively tested on various consoles by a real human (me!)

## Licence

[MIT](LICENSE).
