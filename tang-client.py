#!/usr/bin/env python3
"""Add the replacement EU1 to an already configured Clevis workstation."""
import argparse
import base64
import fcntl
import getpass
import ipaddress
import shlex
import json
import os
from pathlib import Path
import resource
import shutil
import stat
import subprocess
import sys
import tempfile

URL = 'http://192.0.2.1:8080'
SURVIVOR = 'http://192.0.2.1:8080'
CLEVIS_UUID = 'cb6e8904-81ff-40da-a84a-07ab9ab5715e'
# TRUSTED_ADV is appended by the package builder, from verified SSH to nodeeu1.


def run(argv, data=None, timeout=90, fds=(), bind_secrets=None):
    # Never include captured stdout/stderr in exceptions: it may contain a key.
    p = subprocess.run(argv, input=data, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=timeout, pass_fds=fds)
    if p.returncode:
        name = ' '.join(argv[:3] if argv[:2] == ['clevis', 'luks'] else argv[:2])
        detail = ''
        # Only bind emits public diagnostics; never expose pass/decrypt output.
        if argv[:3] == ['clevis', 'luks', 'bind'] and bind_secrets is not None:
            error = p.stderr
            for secret in bind_secrets:
                if secret:
                    error = error.replace(secret, b'[REDACTED]')
            decoded = error.decode('utf-8', errors='replace')
            detail = '\n' + ''.join(c for c in decoded if c in '\n\t' or c.isprintable())[-6000:]
        raise RuntimeError(f'{name}: ошибка (код {p.returncode}).{detail}')
    return p.stdout


def decode(value):
    return json.loads(base64.urlsafe_b64decode(value + '=' * (-len(value) % 4)))


def header(jwe):
    if isinstance(jwe, str):
        jwe = json.loads(jwe) if jwe.startswith('{') else {'protected': jwe.split('.')[0]}
    return decode(jwe['protected'])


def branches(jwe):
    """Only accept OR policies consisting entirely of the two known Tang URLs."""
    h = header(jwe)
    c = h['clevis']
    if c['pin'] == 'tang':
        if c['tang']['url'] not in (URL, SURVIVOR):
            raise ValueError('Неизвестный Tang в политике.')
        return [(jwe, h)]
    if c['pin'] == 'sss' and c['sss']['t'] == 1:
        result = []
        for child in c['sss']['jwe']:
            result.extend(branches(child))
        if result:
            return result
    raise ValueError('Поддерживается только Tang или SSS t=1 с известными Tang.')


def current_target(h, url=URL, adv=None):
    adv = TRUSTED_ADV if adv is None else adv
    t = h['clevis']['tang']
    return t['url'] == url and t['adv'] == decode(adv['payload'])


def inventory(dev):
    try:
        run(['cryptsetup', 'isLuks', '--type', 'luks2', dev])
    except RuntimeError:
        run(['cryptsetup', 'isLuks', '--type', 'luks1', dev])
        try:
            run(['luksmeta', 'test', '-d', dev])
        except RuntimeError:
            return {}  # Fresh LUKS1: the metadata area is initialized by bind -f.
        entries = run(['luksmeta', 'show', '-d', dev]).decode().splitlines()
        return {int(p[0]): run(['luksmeta', 'load', '-d', dev, '-s', p[0],
                               '-u', CLEVIS_UUID]).decode()
                for line in entries if len(p := line.split()) == 3 and p[2] == CLEVIS_UUID}
    meta = json.loads(run(['cryptsetup', 'luksDump', '--dump-json-metadata', dev]))
    return {int(slot): token['jwe'] for token in meta['tokens'].values()
            if token['type'] == 'clevis' for slot in token['keyslots']}


def clean_orphan_tokens(dev, backup):
    """Remove only Clevis tokens with explicitly empty keyslots, after backup."""
    try:
        run(['cryptsetup', 'isLuks', '--type', 'luks2', dev])
    except RuntimeError:
        return
    before = json.loads(run(['cryptsetup', 'luksDump', '--dump-json-metadata', dev]))
    orphan_ids = [token_id for token_id, token in before['tokens'].items()
                  if token.get('type') == 'clevis' and token.get('keyslots') == []]
    if not orphan_ids:
        return
    (backup / 'metadata-before-cleanup.json').write_text(json.dumps(before, indent=2))
    print(f'Осиротевшие Clevis-токены без ключевых слотов: {orphan_ids}. '
          f'Сохраняю копию и освобождаю метаданные; пароли и рабочие привязки остаются.', flush=True)
    for token_id in orphan_ids:
        current = json.loads(run(['cryptsetup', 'token', 'export', '--token-id', token_id, dev]))
        if current != before['tokens'][token_id]:
            raise RuntimeError('Метаданные изменились во время работы. Очистка остановлена.')
        run(['cryptsetup', 'token', 'remove', '--token-id', token_id, dev])
    after = json.loads(run(['cryptsetup', 'luksDump', '--dump-json-metadata', dev]))
    expected = dict(before)
    expected['tokens'] = {k: v for k, v in before['tokens'].items() if k not in orphan_ids}
    if after != expected:
        raise RuntimeError(f'Неожиданное изменение метаданных при очистке. Backup: {backup}')
    (backup / 'removed-orphan-tokens.json').write_text(json.dumps(orphan_ids))


def binding_slot_args(dev):
    try:
        run(['cryptsetup', 'isLuks', '--type', 'luks2', dev])
    except RuntimeError:
        return []  # LUKS1 keeps Clevis' LUKSMeta synchronization logic.
    meta = json.loads(run(['cryptsetup', 'luksDump', '--dump-json-metadata', dev]))
    occupied = {int(slot) for slot in meta['keyslots']}
    free = next((slot for slot in range(32) if slot not in occupied), None)
    if free is None:
        raise RuntimeError('Все 32 слота LUKS2 заняты. Автоматическое удаление паролей запрещено.')
    tokens = {int(token) for token in meta['tokens']}
    token = next((number for number in range(32) if number not in tokens), None)
    if token is None:
        raise RuntimeError('Нет свободного ID токена LUKS2. Нужен отдельный разбор метаданных.')
    print(f'Все занятые LUKS-слоты: {sorted(occupied)}; новый слот: {free}, токен: {token}.', flush=True)
    return ['-s', str(free), '-t', str(token)]


def root_device():
    source = run(['findmnt', '-nro', 'SOURCE', '/']).decode().strip().split('[')[0]
    rows = run(['lsblk', '-srnpo', 'PATH,FSTYPE', source]).decode().splitlines()
    devices = {p[0] for row in rows if len(p := row.split()) == 2 and p[1] == 'crypto_LUKS'}
    if len(devices) != 1:
        raise RuntimeError('Не найден единственный LUKS-родитель /. Укажи --device явно.')
    return devices.pop()


def verify_key(dev, key, slot):
    run(['cryptsetup', 'open', '--test-passphrase', '--key-slot', str(slot),
         '--key-file', '-', dev], data=key)


def decrypt(jwe):
    data = jwe.encode() if isinstance(jwe, str) else json.dumps(jwe).encode()
    return run(['clevis', 'decrypt'], data=data, timeout=45)


def ready_boot(dev):
    for pkg in ('clevis-initramfs', 'cryptsetup-initramfs'):
        if run(['dpkg-query', '-W', '-f=${Status}', pkg]).decode() != 'install ok installed':
            raise RuntimeError(f'Не установлен {pkg}.')
    uuid = run(['cryptsetup', 'luksUUID', dev]).decode().strip()
    lines = [l.split() for l in Path('/etc/crypttab').read_text().splitlines()
             if l.strip() and not l.lstrip().startswith('#')]
    if not any(len(p) >= 4 and (p[1] == f'UUID={uuid}' or os.path.realpath(p[1]) == dev)
               and 'initramfs' in p[3].split(',') for p in lines):
        raise RuntimeError('В crypttab нет этого диска с опцией initramfs. Нужна первоначальная настройка.')


def migrate(dev, apply=False, boot=True, backup_parent='/var/backups',
            url=URL, adv=None, initial_key=None):
    adv = TRUSTED_ADV if adv is None else adv
    before = inventory(dev)
    eligible = {}
    existing = []
    for slot, jwe in before.items():
        try:
            parts = branches(jwe)
        except (KeyError, ValueError, TypeError):
            continue
        eligible[slot] = parts
        if any(current_target(h, url, adv) for _, h in parts):
            existing.append(slot)
    print(f'LUKS: {dev}; Clevis-слоты: {sorted(before)}', flush=True)
    if before and not eligible:
        raise RuntimeError('Существующая политика не поддерживается автоматически: разрешены Tang или SSS t=1 с известными серверами.')
    if boot:
        ready_boot(dev)
    # A real encrypt/decrypt round-trip tests recovery, not just /adv.
    cfg = json.dumps({'url': url, 'adv': adv})
    probe = os.urandom(32)
    encrypted = run(['clevis', 'encrypt', 'tang', cfg], data=probe)
    if decrypt(encrypted.decode()) != probe:
        raise RuntimeError('Новый Tang не прошёл проверку восстановления.')
    print(f'{url}: подлинность и восстановление проверены.', flush=True)
    for slot in existing:
        # Decrypt only the new Tang child, so EU2 cannot mask a failed target.
        # For nested SSS, test the complete slot too; direct slot is the normal case.
        key = run(['clevis', 'luks', 'pass', '-d', dev, '-s', str(slot)], timeout=60)
        verify_key(dev, key, slot)
        key = b''
        print(f'Актуальная привязка уже есть в слоте {slot}; новый слот не нужен.', flush=True)
        if apply and boot:
            run(['update-initramfs', '-u', '-k', 'all'], timeout=600)
        return slot
    # Obtain the original slot secret through its existing policy. No password on disk.
    key = initial_key
    source = None
    for slot, parts in eligible.items():
        if key is not None:
            break
        try:
            candidate = run(['clevis', 'luks', 'pass', '-d', dev, '-s', str(slot)], timeout=60)
            verify_key(dev, candidate, slot)
            key, source = candidate, slot
            break
        except (RuntimeError, subprocess.TimeoutExpired):
            continue
    if key is None and not before and not apply:
        print('Первоначальная установка: при применении понадобится LUKS-пароль.')
        return None
    if key is None:
        raise RuntimeError('Рабочая привязка не восстановилась. Проверь VPN и Tang; либо выбери пункт 3 для ввода LUKS-пароля (--apply --ask-passphrase).')
    print(f'Действующий ключ получен через старую привязку, слот {source}.' if source is not None else 'LUKS-пароль проверен.', flush=True)
    if not apply:
        print('Проверка пройдена. Для добавления запусти с --apply.', flush=True)
        return None
    backup = Path(tempfile.mkdtemp(prefix='tang-rebind-', dir=backup_parent))
    os.chmod(backup, 0o700)
    run(['cryptsetup', 'luksHeaderBackup', dev, '--header-backup-file', str(backup / 'header.bin')])
    (backup / 'before.json').write_text(json.dumps(before, indent=2))
    print(f'Резервная копия заголовка: {backup}', flush=True)
    clean_orphan_tokens(dev, backup)
    slot_args = binding_slot_args(dev)
    # Anonymous RAM-backed fd, inherited only by bind. No key in argv or environment.
    fd = os.memfd_create('clevis-rebind-key', os.MFD_CLOEXEC)
    try:
        os.write(fd, key)
        os.lseek(fd, 0, os.SEEK_SET)
        run(['clevis', 'luks', 'bind', '-f', '-d', dev, *slot_args, '-k', f'/proc/self/fd/{fd}',
             'tang', cfg], timeout=180, fds=(fd,), bind_secrets=(key,))
    except RuntimeError as error:
        report = backup / 'bind-error.txt'
        report.write_text(str(error) + '\n')
        raise RuntimeError(f'{error}\nДиагностика: {report}. '
                           'Слоты автоматически не удаляются. Сохрани этот вывод для разбора.') from error
    finally:
        key = b''
        os.close(fd)
    after = inventory(dev)
    added = set(after) - set(before)
    if any(after.get(s) != j for s, j in before.items()) or len(added) != 1:
        raise RuntimeError(f'Неожиданное изменение слотов. Backup: {backup}. Ничего автоматически не удалено.')
    slot = added.pop()
    if not current_target(header(after[slot]), url, adv):
        raise RuntimeError(f'Новый слот {slot} не совпал с доверенным Tang.')
    recovered = run(['clevis', 'luks', 'pass', '-d', dev, '-s', str(slot)], timeout=60)
    verify_key(dev, recovered, slot)
    recovered = b''
    (backup / 'result.json').write_text(json.dumps({'device': dev, 'source_slot': source, 'new_slot': slot}))
    if boot:
        print('Обновляю initramfs для установленных ядер…', flush=True)
        run(['update-initramfs', '-u', '-k', 'all'], timeout=600)
    print(f'Готово: новый Tang в слоте {slot}, прежние слоты сохранены. Перезагрузка не выполнялась.', flush=True)
    return slot



def package_check(install=False):
    packages = ['clevis', 'clevis-luks', 'clevis-initramfs', 'cryptsetup-initramfs', 'luksmeta']
    missing = []
    for pkg in packages:
        try:
            if run(['dpkg-query', '-W', '-f=${Status}', pkg]).decode() != 'install ok installed':
                missing.append(pkg)
        except RuntimeError:
            missing.append(pkg)
    if missing:
        if not install:
            raise RuntimeError('Нужны пакеты: ' + ' '.join(missing) + '. Выбери установку или запусти --apply.')
        print('Устанавливаю пакеты: ' + ' '.join(missing), flush=True)
        print('Использую существующие индексы APT; общий apt update не запускается.', flush=True)
        try:
            subprocess.run(['apt-get', '-o', 'Acquire::http::Timeout=60',
                            '-o', 'Acquire::https::Timeout=60', '-o', 'Acquire::Retries=2',
                            '-o', 'DPkg::Lock::Timeout=60', 'install', '-y', *missing], check=True)
        except subprocess.CalledProcessError as error:
            raise RuntimeError('APT не смог установить пакеты. Причина приведена выше. '
                               'При тайм-ауте повтори установку; при повторении выбери другое зеркало Ubuntu в Источниках приложений. При ошибке 404 обнови индексы после исправления недоступных '
                               'репозиториев и повтори запуск. Общий apt update автоматически '
                               'не запускается; сторонние репозитории не изменяются.') from error


def network_plan():
    routes = [json.loads(run(['ip', '-j', '-4', 'route', 'get', url.split('/')[2].split(':')[0]]))[0]
              for url in (URL, SURVIVOR)]
    devices = {r['dev'] for r in routes}
    if len(devices) != 1:
        raise RuntimeError('Tang доступны через разные интерфейсы. Нужна отдельная настройка ранней сети.')
    iface = devices.pop()
    sysdev = Path('/sys/class/net') / iface
    if not (sysdev / 'device').exists() or (sysdev / 'wireless').exists():
        raise RuntimeError(f'Маршрут к Tang сейчас идёт через {iface}, а для загрузки нужен проводной путь через офисный MikroTik. Сам включённый VPN допустим: проверь доступ к локальной сети и маршрут к 192.0.2.1/2 вне VPN. VPN внутри ОС ещё не работает на этапе initramfs.')
    if len({r.get('gateway') for r in routes}) != 1:
        raise RuntimeError('У серверов разные шлюзы. Автоматическая настройка такой сети не поддерживается.')
    driver = (sysdev / 'device/driver').resolve().name
    method = None
    if shutil.which('nmcli'):
        try:
            profile = run(['nmcli', '-g', 'GENERAL.CON-UUID', 'device', 'show', iface]).decode().strip()
            method = run(['nmcli', '-g', 'ipv4.method', 'connection', 'show', profile]).decode().strip()
        except RuntimeError:
            pass
    if method not in ('auto', 'manual'):
        raise RuntimeError(f'Не удалось определить DHCP/статику для {iface} через NetworkManager. Нужна проверка сетевого профиля.')
    if method == 'auto':
        ip_arg = f':::::{iface}:dhcp'
    else:
        source = routes[0].get('prefsrc')
        addresses = json.loads(run(['ip', '-j', '-4', 'address', 'show', 'dev', iface]))[0]['addr_info']
        address = next((a for a in addresses if a['local'] == source), None)
        if not address:
            raise RuntimeError('Не удалось определить статический IPv4 для загрузки.')
        mask = str(ipaddress.IPv4Network(f"0.0.0.0/{address['prefixlen']}").netmask)
        ip_arg = f"{source}::{routes[0].get('gateway', '')}:{mask}::{iface}:none"
    boot_kernels(driver)
    run(['modinfo', driver])
    return iface, driver, ip_arg


def boot_kernels(driver):
    kernels = [p.name.removeprefix('vmlinuz-') for p in Path('/boot').glob('vmlinuz-*')]
    if not kernels:
        raise RuntimeError('Не найдены установленные ядра в /boot.')
    latest = run(['sort', '-V'], data=('\n'.join(kernels) + '\n').encode()).decode().splitlines()[-1]
    required = {os.uname().release, latest}
    usable = []
    for kernel in kernels:
        try:
            run(['modinfo', '-k', kernel, driver])
            usable.append(kernel)
        except RuntimeError:
            if kernel in required:
                raise RuntimeError(f'Для текущего/новейшего ядра {kernel} нет драйвера {driver}. Сначала восстанови модуль/DKMS.')
            print(f'Старое резервное ядро {kernel}: нет {driver}; его initramfs оставлен без изменений.', flush=True)
    if not required.issubset(usable):
        raise RuntimeError('Текущее ядро отсутствует среди поддерживаемых образов /boot.')
    return usable


def save_config(path, text, backup, mode=0o644):
    path = Path(path)
    if path.is_symlink():
        raise RuntimeError(f'Неожиданная символическая ссылка: {path}')
    if path.exists() and path.read_text() == text:
        return
    dest = backup / str(path).lstrip('/')
    dest.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        shutil.copy2(path, dest)
    else:
        dest.with_name(dest.name + '.absent').touch()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(text)
            os.fchmod(f.fileno(), mode)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        Path(tmp).unlink(missing_ok=True)


def boot_setup(dev, plan):
    iface, driver, ip_arg = plan
    uuid = run(['cryptsetup', 'luksUUID', dev]).decode().strip()
    backup = Path(tempfile.mkdtemp(prefix='tang-boot-', dir='/var/backups'))
    path = Path('/etc/crypttab')
    rows = path.read_text().splitlines() if path.exists() else []
    found = False
    for i, row in enumerate(rows):
        p = row.split()
        if not p or p[0].startswith('#') or len(p) < 2:
            continue
        if p[1] == f'UUID={uuid}' or os.path.realpath(p[1]) == dev:
            found = True
            while len(p) < 4:
                p.append('none' if len(p) == 2 else 'luks')
            opts = p[3].split(',')
            if 'initramfs' not in opts:
                opts.append('initramfs')
            p[3] = ','.join(opts)
            rows[i] = '\t'.join(p)
    if not found:
        # Find an existing mapper; don't invent a conflicting root name.
        tree = run(['lsblk', '-rnpo', 'PATH,TYPE', dev]).decode().splitlines()
        maps = [Path(p[0]).name for line in tree if len(p := line.split()) == 2 and p[1] == 'crypt']
        if len(maps) != 1:
            raise RuntimeError('Не найден единственный открытый crypt mapper для crypttab.')
        rows.append(f'{maps[0]} UUID={uuid} none luks,initramfs')
    save_config(path, '\n'.join(rows) + '\n', backup)
    modules = Path('/etc/initramfs-tools/modules')
    text = modules.read_text() if modules.exists() else ''
    if driver not in [l.split('#')[0].strip() for l in text.splitlines()]:
        text += f'\n# Tang: driver of {iface}\n{driver}\n'
    save_config(modules, text, backup)
    save_config('/etc/initramfs-tools/conf.d/tang-network', f'DEVICE={shlex.quote(iface)}\nIP={shlex.quote(ip_arg)}\n', backup)
    # Use the initramfs-tools network implementation, including DHCP state that
    # the rest of initramfs consumes. Don't run a second DHCP client in parallel.
    early = '''#!/bin/sh
PREREQ=""
prereqs() { echo "$PREREQ"; }
case "${1:-}" in prereqs) prereqs; exit 0;; esac
. /scripts/functions
configure_networking
[ -n "${DEVICE:-}" ] && touch "/run/tang-early-${DEVICE}"
exit 0
'''
    save_config('/etc/initramfs-tools/scripts/local-top/09-early-net', early, backup, 0o755)
    cleanup = '''#!/bin/sh
PREREQ=""
prereqs() { echo "$PREREQ"; }
case "${1:-}" in prereqs) prereqs; exit 0;; esac
# The local LUKS root is already open. Hand a clean interface to NetworkManager.
IFACE=__IFACE__
if [ -e "/run/tang-early-${IFACE}" ]; then
    ip -4 addr flush dev "$IFACE" scope global || true
    ip -4 route flush dev "$IFACE" || true
    rm -f "/run/tang-early-${IFACE}"
fi
exit 0
'''.replace('__IFACE__', shlex.quote(iface))
    save_config('/etc/initramfs-tools/scripts/init-bottom/zz-tang-network-cleanup', cleanup, backup, 0o755)
    # Keep runtime NM/netplan/DNS intact. The original nm-handover service may
    # still be present; it isn't replaced or invoked over an active SSH link.
    grub = '''# Managed by tang-rebind; runtime network configuration is unchanged.
_tang_cmdline=""
for _tang_arg in $GRUB_CMDLINE_LINUX; do
    case "$_tang_arg" in ip=*|rootdelay=*|rd.neednet=*) ;; *) _tang_cmdline="$_tang_cmdline $_tang_arg";; esac
done
GRUB_CMDLINE_LINUX="$_tang_cmdline rd.neednet=1 rootdelay=30 ip=IPARG"
unset _tang_cmdline _tang_arg
'''.replace('IPARG', ip_arg)
    save_config('/etc/default/grub.d/99-tang-network.cfg', grub, backup)
    print(f'Загрузочная сеть: {iface}, {driver}, {ip_arg}; backup: {backup}', flush=True)
    run(['update-grub'], timeout=180)
    kernels = boot_kernels(driver)
    for kernel in kernels:
        run(['update-initramfs', '-u', '-k', kernel], timeout=600)
    images = [Path('/boot') / f'initrd.img-{kernel}' for kernel in kernels]
    if not images:
        raise RuntimeError('В /boot не найдены initramfs после сборки.')
    for image in images:
        listing = run(['lsinitramfs', str(image)], timeout=90).decode()
        if any(item not in listing for item in ('scripts/local-top/clevis', 'scripts/local-top/09-early-net', 'scripts/init-bottom/zz-tang-network-cleanup')):
            raise RuntimeError(f'{image}: отсутствует Clevis или ранняя сеть.')
        if f'/{driver}.ko' not in listing:
            raise RuntimeError(f'{image}: не найден модуль {driver}.')
    print(f'Проверено initramfs: {len(images)}. Нужна пробная загрузка.', flush=True)


def main():
    p = argparse.ArgumentParser(description='Tang/Clevis: установка с нуля и обновление серверов на Linux Mint/Ubuntu.')
    p.add_argument('--apply', action='store_true', help='установить/дополнить привязки и настроить загрузку')
    p.add_argument('--check', action='store_true', help='только диагностика, без изменений')
    p.add_argument('--ask-passphrase', action='store_true', help='использовать LUKS-пароль вместо работающей привязки')
    p.add_argument('--device', help='LUKS-раздел; по умолчанию определяется по /')
    args = p.parse_args()
    if args.apply and args.check:
        p.error('Выбери один режим.')
    if not args.apply and not args.check and sys.stdin.isatty():
        print('\nTang/Clevis — подключение компьютера\n1. Проверить\n2. Установить / добавить недостающие серверы\n3. Установить с вводом LUKS-пароля вручную\n0. Выход')
        choice = input('Выбор: ').strip()
        if choice == '0':
            return
        if choice not in ('1', '2', '3'):
            p.error('Неизвестный пункт.')
        args.apply = choice in ('2', '3')
        args.ask_passphrase = choice == '3'
    if args.ask_passphrase and not args.apply:
        p.error('--ask-passphrase используется с --apply.')
    if os.geteuid() != 0:
        p.exit(1, 'Запусти через sudo.\n')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    # Use system binaries, never a user-writable executable search path as root.
    os.environ['PATH'] = '/usr/sbin:/usr/bin:/sbin:/bin'
    dev = os.path.realpath(args.device or root_device())
    if not stat.S_ISBLK(os.stat(dev).st_mode):
        p.exit(1, 'Ожидается блочное LUKS-устройство.\n')
    run(['cryptsetup', 'isLuks', dev])
    plan = network_plan()
    print(f'Сеть: интерфейс {plan[0]}, драйвер {plan[1]}, ip={plan[2]}', flush=True)
    with open('/run/lock/tang-rebind.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        package_check(install=args.apply)
        initial = inventory(dev)
        # Preflight both servers before any header change.
        for url, adv in ((URL, TRUSTED_ADV), (SURVIVOR, SURVIVOR_ADV)):
            probe = os.urandom(32)
            enc = run(['clevis', 'encrypt', 'tang', json.dumps({'url': url, 'adv': adv})], data=probe)
            if decrypt(enc.decode()) != probe:
                raise RuntimeError(f'{url}: не прошёл проверку восстановления.')
        password = None
        if args.apply and (not initial or args.ask_passphrase):
            if not sys.stdin.isatty():
                raise RuntimeError('Первичная установка требует терминал для ввода LUKS-пароля.')
            password = getpass.getpass('Пароль зашифрованного диска (LUKS): ').encode()
            run(['cryptsetup', 'open', '--test-passphrase', '--key-file', '-', dev], data=password)
        for url, adv in ((URL, TRUSTED_ADV), (SURVIVOR, SURVIVOR_ADV)):
            migrate(dev, apply=args.apply, boot=False, url=url, adv=adv, initial_key=password)
        password = None
        if args.apply:
            boot_setup(dev, plan)
            print('Установка завершена. Существующие ключи сохранены, оба Tang проверены. Перезагрузку выполняй отдельно.')
        else:
            print('Диагностика завершена; настройки не менялись.')



TRUSTED_ADV = {'payload': 'eyJrZXlzIjogW3siYWxnIjogIkVTNTEyIiwgImt0eSI6ICJFQyIsICJjcnYiOiAiUC01MjEiLCAieCI6ICJBYS1ibzVjM3g3QjNRLXpyNTlqT09FUEd1Zko2a1hDM212ZlNGb3k4Z3BqVHlBdVdJa3dXQUJKZHZFbTVnOUJfRG50VXMzMDVQaHBWRF9JMTFzYW56Y09hIiwgInkiOiAiQUtZaDU5RWx5TDNHd3pqZTNjVTMyaVVIY3ZQVFdFdDBub29ISjdELTVETDgxTFJFbW1FM1l2Z0xLY09IajdTRmJXN1hIQllldEtBOHhtXzN5dkZSQzk4MSIsICJrZXlfb3BzIjogWyJ2ZXJpZnkiXX0sIHsiYWxnIjogIkVDTVIiLCAia3R5IjogIkVDIiwgImNydiI6ICJQLTUyMSIsICJ4IjogIkFkWmhjNTRCM0lGTkVLZnhwM2w3VUhENEhJR3lJdmZ2YnFTajFNX3BsNWdob0VLemFaQkN5MW0wZGlWTldRZ204NndhS2RrdVFrWENEMXZXNmlIeFR1X20iLCAieSI6ICJBQVhCanZkUl9nZmhqUG42Q0tQUzlwSmpvRmJaejY5ZE9yeGlYNzZ5S2EteGFRN3Y5N3F4emphRWdHWEw0ZWdUVzhURkpFR1RXNGh4RTYwWUZUWHZ2TURzIiwgImtleV9vcHMiOiBbImRlcml2ZUtleSJdfV19', 'protected': 'eyJhbGciOiJFUzUxMiIsImN0eSI6Imp3ay1zZXQranNvbiJ9', 'signature': 'AXfH7LD7yFi18vD6Kjv9iR4sUjIR2Zur-twvLImk-MRA17LZZD9FGxyQrafNIyrU3oe4COWhFrvaekuPdyvxChfgAVQw6LJBr3QMeCnYp9Uw-ig9zws-tfaLhZ0M9-uib1OASCw7onDZTzZjiyRAxc_4Wp1ysF17rTNeycOwNWAO-6ST'}
SURVIVOR_ADV = {'payload': 'eyJrZXlzIjogW3siYWxnIjogIkVTNTEyIiwgImt0eSI6ICJFQyIsICJjcnYiOiAiUC01MjEiLCAieCI6ICJBV3d3WDZaNEMtV05jVTJJeVNUX3REN19PejdvdWFKQWxJUDlWX1pwaXlzWWZqYzZ2dlJEN0hvZkY4WEgzXzc5enBGczRqeFprSEJCVFhHUTVjLXB0SWYyIiwgInkiOiAiQUJNMXZNS2hwcld3Zk5ubENKUGM4dWNKM2tVY3VEUVp6eFVjV0t3QzdUNnZRSEZ2Rl9JWXJ4R2hXamE0MlVWWkt1X3VRQVE0V2R3OF8ycWVoeF9iQzgtZiIsICJrZXlfb3BzIjogWyJ2ZXJpZnkiXX0sIHsiYWxnIjogIkVDTVIiLCAia3R5IjogIkVDIiwgImNydiI6ICJQLTUyMSIsICJ4IjogIkFHcDJxa1hFRzNMNTJONldUWWJqR1pkVFV6T0U1ekdBZ0wtMVp2RkhsWEhhVEVrNDV2R09iQ3EtUFRjSGF0djRMRWxPOWM1dVBSQmJiMjNLeWp4TkhuLXoiLCAieSI6ICJBTG1uZkNpMHg4UXN3ZkhyNnJITHhCdXJpLVdxYUhCdnNkb05oNnExZUhsaFFmbHk3RWQ4d01vRFZtSm9WOXA2b1FxZGY3b1NjX04yeDE4OVBzQ05mdk9uIiwgImtleV9vcHMiOiBbImRlcml2ZUtleSJdfV19', 'protected': 'eyJhbGciOiJFUzUxMiIsImN0eSI6Imp3ay1zZXQranNvbiJ9', 'signature': 'ASUWHrz-fFEDN1SK3XLORuNNBQCFGUb7ac2eWtl0tmqTFTR2bqQ6hWqLKResqpX4IcyMoUNz-lhKuf4xurU4OvaxAWyFzc2tmgKp_RLKzkUGBoUgeG8dQKgyBlViv9HJlwumZS_rUE3_DiYyzHGXus2lnwYOVmeANusrZHbXqcXSR-ST'}

if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
        print(f'Ошибка: {e}', file=sys.stderr)
        sys.exit(1)
