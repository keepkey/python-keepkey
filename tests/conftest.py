"""
conftest.py -- pytest plugin for per-test OLED screenshot directories.

When KEEPKEY_SCREENSHOT=1, patches KeepKeyTest.setUp to set per-test
screenshot directories. Fixture-only wipe/import captures are cleared before
the test action begins, so they cannot masquerade as the test's OLED evidence.

FAIL-FAST: If KEEPKEY_SCREENSHOT=1 and zero PNGs are captured after
all tests complete, the session exits non-zero. This prevents silent
screenshot pipeline failures from going unnoticed.
"""
import pytest
import os
import glob
import hashlib
import json
import shutil
import socket
import sys

import requests


def pytest_collection_modifyitems(config, items):
    """Select exact report test IDs for the screenshot-only pytest phase."""
    if os.environ.get('KEEPKEY_SCREENSHOT') != '1':
        return
    encoded = os.environ.get('KEEPKEY_SCREENSHOT_TESTS', '')
    if not encoded:
        raise pytest.UsageError(
            'KEEPKEY_SCREENSHOT_TESTS must list exact module::method pairs')
    selected_pairs = set()
    for line in encoded.splitlines():
        if not line:
            continue
        parts = line.split('::')
        if len(parts) != 2 or not all(parts):
            raise pytest.UsageError(
                'invalid KEEPKEY_SCREENSHOT_TESTS entry %r' % line)
        selected_pairs.add(tuple(parts))
    selected = []
    deselected = []
    for item in items:
        module = os.path.splitext(os.path.basename(item.location[0]))[0]
        method = getattr(item, 'originalname', None) or item.name.split('[', 1)[0]
        if (module, method) in selected_pairs:
            selected.append(item)
        else:
            deselected.append(item)
    if deselected:
        config.hook.pytest_deselected(items=deselected)
    items[:] = selected


def _screenshot_dir_for_item(item):
    module = os.path.splitext(os.path.basename(item.location[0]))[0]
    method = getattr(item, 'originalname', None) or item.name.split('[', 1)[0]
    return os.path.join(
        os.environ.get('SCREENSHOT_DIR', 'screenshots'),
        module.replace('test_', '', 1), method)


def _remove_skipped_screenshot_evidence(item):
    """Delete every frame captured before a test became skipped.

    Kept as a small named boundary so the release mutation controls can plant
    fixture residue and prove that this exact cleanup still runs fail-closed.
    """
    path = _screenshot_dir_for_item(item)
    try:
        shutil.rmtree(path)
    except FileNotFoundError:
        return
    if os.path.lexists(path):
        raise OSError('screenshot directory still exists after cleanup: %s' %
                      path)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """A skipped case must never retain setup/policy frames as evidence."""
    outcome = yield
    report = outcome.get_result()
    if (os.environ.get('KEEPKEY_SCREENSHOT') == '1' and report.skipped):
        try:
            _remove_skipped_screenshot_evidence(item)
        except OSError as exc:
            raise RuntimeError(
                'failed to remove skipped OLED evidence for %s: %s' %
                (item.nodeid, exc))

if os.environ.get('KEEPKEY_SCREENSHOT') == '1':
    import common

    _orig_setUp = common.KeepKeyTest.setUp

    def _patched_setUp(self):
        # Derive the per-test directory before setUp. common.KeepKeyTest.setUp
        # clears fixture-only frames after its initial wipe completes.
        test_id = self.id()
        # pytest: "tests.test_msg_wipedevice.TestDeviceWipe.test_wipe_device"
        # unittest: "test_msg_wipedevice.TestDeviceWipe.test_wipe_device"
        # Extract module basename and test method name
        parts = test_id.split('.')
        test_name = parts[-1] if parts else 'unknown'
        # Find the module part (starts with test_msg_)
        module = 'unknown'
        for p in parts:
            if p.startswith('test_msg_') or p.startswith('test_sign_') or p.startswith('test_verify_'):
                module = p.replace('test_', '', 1)  # strip first test_ only
                break
        screenshot_dir = os.path.join(
            os.environ.get('SCREENSHOT_DIR', 'screenshots'),
            module, test_name
        )
        os.makedirs(screenshot_dir, exist_ok=True)

        # Now run original setUp (creates client, calls wipe_device)
        _orig_setUp(self)

        # Set screenshot dir on the client that setUp just created
        if hasattr(self, 'client') and self.client:
            self.client.screenshot_dir = screenshot_dir
            self.client.screenshot_id = 0

    common.KeepKeyTest.setUp = _patched_setUp


def _configured_emulator_endpoints(getaddrinfo):
    """Return the exact UDP names and addresses configured by the test harness."""
    names = set()
    addresses = set()
    for variable, default in (
            ('KK_TRANSPORT_MAIN', '127.0.0.1:11044'),
            ('KK_TRANSPORT_DEBUG', '127.0.0.1:11045')):
        endpoint = os.environ.get(variable, default)
        try:
            host, port_text = endpoint.rsplit(':', 1)
            port = int(port_text)
        except (AttributeError, TypeError, ValueError):
            raise RuntimeError(
                '%s must be a host:port UDP emulator endpoint, got %r' %
                (variable, endpoint))
        names.add((host, port))
        for result in getaddrinfo(host, port, type=socket.SOCK_DGRAM):
            sockaddr = result[4]
            addresses.add((sockaddr[0], sockaddr[1]))
    return names, addresses


@pytest.fixture(autouse=True)
def deny_external_network(monkeypatch, request):
    """Allow only local sockets and the harness's exact UDP emulator endpoints."""
    nodeid = request.node.nodeid
    original_getaddrinfo = socket.getaddrinfo
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex
    original_sendto = socket.socket.sendto
    emulator_names, emulator_addresses = _configured_emulator_endpoints(
        original_getaddrinfo)

    def denied(destination):
        raise AssertionError(
            'authoritative test attempted external network access: '
            'test=%s destination=%r' % (nodeid, destination))

    def guarded_getaddrinfo(host, *args, **kwargs):
        port = args[0] if args else kwargs.get('port')
        if (host, port) not in emulator_names:
            denied((host, port))
        return original_getaddrinfo(host, *args, **kwargs)

    def allowed_socket_address(sock, address):
        if not isinstance(address, tuple) or len(address) < 2:
            return False
        # No Unix sockets, TCP loopback, or arbitrary localhost ports. The
        # authoritative suite may talk only to the two exact UDP transports
        # configured for this emulator run.
        if sock.family not in (socket.AF_INET, socket.AF_INET6):
            return False
        if (sock.type & 0x0f) != socket.SOCK_DGRAM:
            return False
        endpoint = (address[0], address[1])
        return endpoint in emulator_names or endpoint in emulator_addresses

    def guarded_connect(sock, address):
        if not allowed_socket_address(sock, address):
            denied(address)
        return original_connect(sock, address)

    def guarded_connect_ex(sock, address):
        if not allowed_socket_address(sock, address):
            denied(address)
        return original_connect_ex(sock, address)

    def guarded_sendto(sock, data, *args):
        address = args[-1]
        if not allowed_socket_address(sock, address):
            denied(address)
        return original_sendto(sock, data, *args)

    def guarded_request(session, method, url, *args, **kwargs):
        raise AssertionError(
            'authoritative test attempted HTTP access: test=%s method=%s '
            'url=%s' % (nodeid, method, url))

    monkeypatch.setattr(socket, 'getaddrinfo', guarded_getaddrinfo)
    monkeypatch.setattr(socket.socket, 'connect', guarded_connect)
    monkeypatch.setattr(socket.socket, 'connect_ex', guarded_connect_ex)
    monkeypatch.setattr(socket.socket, 'sendto', guarded_sendto)
    monkeypatch.setattr(requests.sessions.Session, 'request', guarded_request)


def pytest_sessionfinish(session, exitstatus):
    """Fail-fast: if screenshots were requested but none captured, fail the session."""
    if os.environ.get('KEEPKEY_SCREENSHOT') != '1':
        return
    screenshot_dir = os.environ.get('SCREENSHOT_DIR', 'screenshots')
    pngs = glob.glob(os.path.join(screenshot_dir, '**', '*.png'), recursive=True)
    count = len(pngs)
    if count == 0:
        print("FATAL: KEEPKEY_SCREENSHOT=1 but 0 PNGs captured. Screenshot pipeline is broken.", file=sys.stderr)
        session.exitstatus = 1
        return

    try:
        sequence_count = 0
        for directory, _subdirs, files in os.walk(screenshot_dir):
            if not any(name.endswith('.png') for name in files):
                if 'frames.json' in files:
                    raise AssertionError(
                        'frame manifest has no PNG sequence: %s' % directory)
                continue
            other = sorted(name for name in files
                           if name != 'frames.json')
            expected = ['btn%05d.png' % i for i in range(len(other))]
            if other != expected:
                raise AssertionError(
                    'non-contiguous or unexpected OLED frames in %s: '
                    'found=%r expected=%r' % (directory, other, expected))
            frames = []
            for name in expected:
                path = os.path.join(directory, name)
                with open(path, 'rb') as handle:
                    digest = hashlib.sha256(handle.read()).hexdigest()
                frames.append({'file': name, 'sha256': digest})
            manifest = {
                'schema': 1,
                'group': os.path.basename(directory),
                'frame_count': len(frames),
                'frames': frames,
            }
            manifest_path = os.path.join(directory, 'frames.json')
            if os.path.isfile(manifest_path):
                with open(manifest_path, 'r') as handle:
                    existing = json.load(handle)
                if existing != manifest:
                    raise AssertionError(
                        'frame manifest disagrees with capture: %s' %
                        manifest_path)
            else:
                with open(manifest_path, 'w') as handle:
                    json.dump(manifest, handle, sort_keys=True, indent=2)
                    handle.write('\n')
            sequence_count += 1
    except (IOError, OSError, ValueError, AssertionError) as exc:
        print('FATAL: OLED sequence manifest failure: %s' % exc,
              file=sys.stderr)
        session.exitstatus = 1
        return

    print("[SCREENSHOT] Session complete: %d PNGs in %d manifested sequences" %
          (count, sequence_count), file=sys.stderr)
