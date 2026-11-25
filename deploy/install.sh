#!/bin/sh
# Run from a trusted checkout; the installed service never imports that checkout.
set -eu
exec python3 -I - "$0" "$@" <<'PY'
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile

ROOT = Path('/opt/karaali-provisioning')
DATA = Path('/var/lib/karaali-provisioning')
UNIT = Path('/etc/systemd/system/karaali-provisioning.service')
DROPIN = Path(str(UNIT) + '.d/10-kauth.conf')
RECORD = DATA / 'install-record.json'
IDENTITY = DATA / 'identity.json'
STATE = DATA / 'provisioning-state.json'
TOOLS = ('bluetooth_policy.py', 'manage.py', 'reset.sh', 'uninstall.sh')
CARD_FILES = ('make_setup_card.py', 'k-glyph-final.svg')
CHANGING = False
os.umask(0o077)


def fail(message):
    raise RuntimeError(message)


def run(*args, capture=False):
    result = subprocess.run(args, check=True, text=True,
                            stdout=subprocess.PIPE if capture else None,
                            env={**os.environ, 'LC_ALL': 'C', 'PYTHONNOUSERSITE': '1'})
    return result.stdout.strip() if capture else None


def secure(path, private=False, directory=False):
    info = path.lstat()
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(info.st_mode) or info.st_uid != 0 or info.st_mode & (0o077 if private else 0o022):
        fail('Unsafe ownership, permissions or file type: ' + str(path))
    return info


def parents(path):
    for parent in reversed(path.absolute().parents):
        if parent.exists() or parent.is_symlink():
            secure(parent, directory=True)


def mkdir_root(path, mode=0o755):
    parents(path)
    if path.exists() or path.is_symlink():
        secure(path, private=mode == 0o700, directory=True)
    else:
        path.mkdir(mode=mode)


def atomic(path, content, mode):
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as target:
            os.fchmod(target.fileno(), mode)
            target.write(content)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def digest(content):
    return hashlib.sha256(content).hexdigest()


def validate_record(value):
    if (not isinstance(value, dict) or type(value.get('version')) is not int or value['version'] != 1
            or value.get('runtime') != str(ROOT)
            or not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', value.get('interface', ''))
            or not re.fullmatch(r'hci[0-9]+', value.get('adapter', ''))):
        fail('Invalid install ownership record; do not delete it to bypass this check.')
    for key, path in (('unit', UNIT), ('dropin', DROPIN)):
        entry = value.get(key)
        if (not isinstance(entry, dict) or entry.get('path') != str(path)
                or not re.fullmatch(r'[0-9a-f]{64}', entry.get('sha256', ''))):
            fail('Invalid install ownership record.')
    return value


def main():
    global CHANGING
    parser = argparse.ArgumentParser(prog='install.sh', description='Install Kauth on Ubuntu 22.04/24.04 without changing network ownership or upgrading the OS.',
        epilog='Fresh install creates private QR JSON/PNG and an A5 setup card; reruns preserve identity, state and Wi-Fi. Use Ethernet/local console: Bluetooth restarts may disconnect clients. No firmware, HCI or bond changes.')
    parser.add_argument('--device-id', help='Fresh identity label: 1..32 lowercase ASCII letters, digits or hyphens; required on first install')
    parser.add_argument('--interface', help='Existing NetworkManager-managed Wi-Fi interface; auto-select only if unambiguous')
    parser.add_argument('--adapter', help='Powered BLE peripheral adapter, e.g. hci0; auto-select only if unambiguous')
    parser.add_argument('--output-dir', type=Path, help='NEW private QR directory on first install only; default: invoking administrator home/kauth-setup-DEVICE-ID')
    args = parser.parse_args(sys.argv[2:])
    if os.geteuid() != 0:
        fail('Run with sudo from a trusted checkout: sudo ./deploy/install.sh --device-id YOUR-LABEL')
    if sys.platform != 'linux':
        fail('Supported prerequisite: Ubuntu 22.04 or 24.04 with systemd and NetworkManager-managed Wi-Fi.')
    lock_fd = os.open('/run/lock/karaali-provisioning-maintenance.lock',
                      os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    lock_info = os.fstat(lock_fd)
    if not stat.S_ISREG(lock_info.st_mode) or lock_info.st_uid != 0 or lock_info.st_mode & 0o077:
        fail('Unsafe lifecycle lock; root must resolve its ownership and permissions.')
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        fail('Another Kauth install/reset/uninstall is running; wait for it to finish.')
    release = {}
    for line in Path('/etc/os-release').read_text().splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            release[key] = value.strip('"')
    if release.get('ID') != 'ubuntu' or release.get('VERSION_ID') not in ('22.04', '24.04'):
        fail('Supported prerequisite: Ubuntu 22.04 or 24.04. This installer does not reinstall or upgrade the OS.')
    for value, pattern, label in ((args.device_id, r'[a-z0-9-]{1,32}', 'device ID'),
            (args.interface, r'[A-Za-z0-9_.-]{1,15}', 'Wi-Fi interface'),
            (args.adapter, r'hci[0-9]+', 'Bluetooth adapter')):
        if value is not None and re.fullmatch(pattern, value) is None:
            fail('Invalid ' + label + '.')
    source = Path(sys.argv[1]).resolve().parent.parent
    for path in [source / 'pyproject.toml', source / 'deploy/karaali-provisioning.service',
                 *(source / 'deploy' / name for name in TOOLS), *(source / name for name in CARD_FILES)]:
        if not path.is_file() or path.is_symlink():
            fail('Incomplete trusted checkout; missing regular source: ' + str(path))
    if not shutil.which('nmcli') or subprocess.run(['systemctl', 'is-active', '--quiet', 'NetworkManager.service']).returncode:
        fail('NetworkManager must already be installed, active and managing the intended Wi-Fi interface. Arrange that explicitly with your OS administrator; this installer will not take over Ethernet or another network manager.')
    old = None
    if RECORD.exists() or RECORD.is_symlink():
        parents(RECORD)
        secure(RECORD, private=True)
        old = validate_record(json.loads(RECORD.read_text()))
    if args.interface is None and old:
        args.interface = old['interface']
    if args.adapter is None and old:
        args.adapter = old['adapter']
    devices = run('nmcli', '-t', '-f', 'DEVICE,TYPE', 'device', 'status', capture=True).splitlines()
    wifi = []
    for row in devices:
        name, _, kind = row.partition(':')
        if kind == 'wifi' and re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', name):
            if run('nmcli', '-g', 'GENERAL.NM-MANAGED', 'device', 'show', name, capture=True) == 'yes':
                wifi.append(name)
    if args.interface is None:
        if len(wifi) != 1:
            fail('Select exactly one existing NetworkManager-managed Wi-Fi interface with --interface; unmanaged radios will not be taken over.')
        args.interface = wifi[0]
    if args.interface not in wifi:
        fail('Selected Wi-Fi interface is not NetworkManager-managed; resolve this prerequisite without changing unrelated interfaces.')
    adapters = sorted(path.name for path in Path('/sys/class/bluetooth').glob('hci*') if re.fullmatch(r'hci[0-9]+', path.name))
    if args.adapter is None:
        if len(adapters) != 1:
            fail('Select a BLE peripheral radio with --adapter hciN; automatic selection requires exactly one radio.')
        args.adapter = adapters[0]
    if args.adapter not in adapters:
        fail('Selected Bluetooth adapter is absent; install supported hardware/driver separately.')
    fresh = not IDENTITY.exists() and not IDENTITY.is_symlink()
    if fresh and not args.device_id:
        fail('First install requires --device-id YOUR-LABEL; hardware identifiers are never used automatically.')
    if not fresh and args.output_dir is not None:
        fail('--output-dir is only for first installation. Existing identity/QR is preserved; use the explicit IT reset tool for new keys.')
    if fresh and (STATE.exists() or STATE.is_symlink()):
        fail('State exists without identity; recover the original identity or use explicit administrative recovery before installing.')
    invoker = pwd.getpwuid(int(os.environ.get('SUDO_UID', '0')))
    output = (args.output_dir or Path(invoker.pw_dir) / ('kauth-setup-' + (args.device_id or ''))).absolute()
    if fresh:
        if output.exists() or output.is_symlink():
            fail('QR destination must not exist; choose a NEW --output-dir. Nothing is overwritten.')
        # The directory itself is created exclusively later. Do not resolve symlinks silently.
        for parent in output.parents:
            info = parent.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, invoker.pw_uid) or info.st_mode & 0o022:
                fail('QR destination parents must be real directories owned by root/the invoking administrator and not group/world writable.')
    unit_bytes = (source / 'deploy/karaali-provisioning.service').read_bytes()
    dropin_bytes = ('# Owned by Kauth installer; unrelated drop-ins are retained.\n[Service]\nExecStart=\n'
        'ExecStart=/opt/karaali-provisioning/.venv/bin/device-provision serve '
        '--identity /var/lib/karaali-provisioning/identity.json '
        '--state /var/lib/karaali-provisioning/provisioning-state.json '
        '--interface ' + args.interface + ' --adapter ' + args.adapter + '\n').encode()
    for key, path, content in (('unit', UNIT, unit_bytes), ('dropin', DROPIN, dropin_bytes)):
        parents(path)
        if path.exists() or path.is_symlink():
            secure(path)
            expected = old[key]['sha256'] if old else digest(unit_bytes) if key == 'unit' else None
            if digest(path.read_bytes()) != expected:
                fail('Refusing to overwrite an unowned or locally changed service artifact: ' + str(path))
    for path in (ROOT, DATA):
        if path.exists() or path.is_symlink():
            secure(path, private=path == DATA, directory=True)
    for path in (IDENTITY, STATE):
        if path.exists() or path.is_symlink():
            secure(path, private=True)
    # Never adopt writable service code, even on rerun. Venv interpreter symlinks are expected.
    if ROOT.exists():
        for base, dirs, files in os.walk(ROOT, followlinks=False):
            secure(Path(base), directory=True)
            for name in dirs + files:
                path = Path(base) / name
                info = path.lstat()
                if info.st_uid != 0 or (not path.is_symlink() and info.st_mode & 0o022):
                    fail('Runtime contains non-root-owned or writable content: ' + str(path))
                if path.is_symlink():
                    resolved = path.resolve(strict=True)
                    parents(resolved)
                    secure(resolved, directory=resolved.is_dir())
    missing = []
    for package in ('bluez', 'python3-venv', 'python3-pip'):
        result = subprocess.run(['dpkg-query', '-W', '-f=${Status}', package], text=True, capture_output=True)
        if result.returncode or result.stdout.strip() != 'install ok installed':
            missing.append(package)
    if missing:
        run('apt-get', 'update')
        run('apt-get', 'install', '-y', '--no-upgrade', '--no-install-recommends', *missing)
    run('systemctl', 'start', 'bluetooth.service')
    powered = run('busctl', 'get-property', 'org.bluez', '/org/bluez/' + args.adapter,
                  'org.bluez.Adapter1', 'Powered', capture=True)
    if powered != 'b true':
        fail('Selected Bluetooth adapter is powered off. Enable it using the normal OS Bluetooth controls, then rerun.')
    supported = run('busctl', 'get-property', 'org.bluez', '/org/bluez/' + args.adapter,
                    'org.bluez.LEAdvertisingManager1', 'SupportedInstances', capture=True)
    if not re.fullmatch(r'y [1-9][0-9]*', supported):
        fail('Selected adapter does not expose BLE peripheral advertising; use a supported radio/driver.')
    print('Installing Kauth. Bluetooth restart can disconnect clients; use Ethernet/local console.', flush=True)
    CHANGING = True
    if UNIT.exists():
        run('systemctl', 'disable', '--now', 'karaali-provisioning.service')
    mkdir_root(ROOT)
    mkdir_root(DATA, 0o700)
    mkdir_root(ROOT / 'bin')
    mkdir_root(DROPIN.parent)
    record = {'version': 1, 'runtime': str(ROOT), 'unit': {'path': str(UNIT), 'sha256': digest(unit_bytes)},
              'dropin': {'path': str(DROPIN), 'sha256': digest(dropin_bytes)},
              'interface': args.interface, 'adapter': args.adapter}
    atomic(UNIT, unit_bytes, 0o644)
    atomic(DROPIN, dropin_bytes, 0o644)
    atomic(RECORD, (json.dumps(record, indent=2) + '\n').encode(), 0o600)
    # Build/install from a private root-owned snapshot, never an editable user checkout.
    with tempfile.TemporaryDirectory(prefix='kauth-install-', dir=ROOT) as temporary:
        staging = Path(temporary)
        shutil.copyfile(source / 'pyproject.toml', staging / 'pyproject.toml')
        package = source / 'python/device_provision'
        for base, dirs, files in os.walk(package):
            for name in dirs + files:
                if (Path(base) / name).is_symlink():
                    fail('Trusted package source must not contain symlinks.')
        shutil.copytree(package, staging / 'python/device_provision',
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        for base, dirs, files in os.walk(staging):
            os.chmod(base, 0o755)
            for name in files:
                os.chmod(Path(base) / name, 0o644)
        run('python3', '-m', 'venv', str(ROOT / '.venv'))
        run(str(ROOT / '.venv/bin/python'), '-I', '-m', 'pip', '--isolated', 'install', '--disable-pip-version-check', '--no-cache-dir', str(staging))
    for name in TOOLS:
        atomic(ROOT / 'bin' / name, (source / 'deploy' / name).read_bytes(), 0o755)
    for name in CARD_FILES:
        atomic(ROOT / 'bin' / name, (source / name).read_bytes(), 0o644)
    if fresh:
        output.mkdir(mode=0o700)
        run(str(ROOT / '.venv/bin/device-provision'), 'init', '--device-id', args.device_id,
            '--identity', str(IDENTITY), '--qr-json', str(output / 'qr.json'), '--qr-png', str(output / 'qr.png'))
        run(str(ROOT / '.venv/bin/python'), str(ROOT / 'bin/make_setup_card.py'),
            '--qr', str(output / 'qr.json'), '--output', str(output / 'setup-card.html'))
        for path in (output / 'qr.json', output / 'qr.png', output / 'setup-card.html'):
            os.chmod(path, 0o600)
            os.chown(path, invoker.pw_uid, invoker.pw_gid)
        os.chown(output, invoker.pw_uid, invoker.pw_gid)
    else:
        # Validate the original identity and optional ID without printing any key material.
        run(str(ROOT / '.venv/bin/python'), '-I', '-c',
            'import sys; from pathlib import Path; from device_provision.identity import DeviceIdentity; '
            'from device_provision.state import ProvisioningState; '
            'i=DeviceIdentity.load(Path(sys.argv[1])); ProvisioningState(Path(sys.argv[1]).with_name("provisioning-state.json")).read(); '
            'sys.exit("Existing device ID differs; reinstall never rotates identity. Use IT reset for new keys." if sys.argv[2] and i.device_id != sys.argv[2] else 0)',
            str(IDENTITY), args.device_id or '')
    sys.path.insert(0, str(ROOT / 'bin'))
    from bluetooth_policy import apply_policy
    changed = apply_policy(Path('/etc/bluetooth/main.conf'), DATA / 'bluetooth-policy.json')
    run('systemctl', 'daemon-reload')
    # Reapply the live policy after an interrupted prior install/restart as well.
    if changed or json.loads((DATA / 'bluetooth-policy.json').read_text())['changed']:
        run('systemctl', 'restart', 'bluetooth.service')
    run('systemctl', 'start', 'karaali-provisioning.service')
    run('systemctl', 'is-active', '--quiet', 'karaali-provisioning.service')
    run('systemctl', 'enable', 'karaali-provisioning.service')
    print('Service is active; this is not proof of real BLE discovery, authentication or Wi-Fi provisioning.')
    print('Private QR and setup-card directory: ' + str(output) if fresh else 'Existing identity, provisioning state, Wi-Fi profiles and external QR artifacts were preserved.')
    print('IT tools: /opt/karaali-provisioning/bin/reset.sh and uninstall.sh (see --help).')


try:
    main()
except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
    if CHANGING:
        subprocess.run(['systemctl', 'stop', 'karaali-provisioning.service'], check=False)
    print('Install not completed: ' + str(exc), file=sys.stderr)
    print('Existing identity/state are not reset. If installation reached runtime changes, leave provisioning stopped and resolve the error before rerunning.', file=sys.stderr)
    sys.exit(1)
PY
