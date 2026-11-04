import os
import pathlib
import shutil
import signal
import socket
import subprocess
import tempfile
import time

ROOT = pathlib.Path(os.environ.get('ROOTFS', pathlib.Path.home() / 'minibox-rootfs')).resolve()
RUNTIME = str(pathlib.Path('runtime').resolve())


def eventually(predicate, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(0.05)
    raise AssertionError('Timed out waiting for condition')


with tempfile.TemporaryDirectory(prefix='minibox-test-') as temp:
    env = dict(os.environ, XDG_RUNTIME_DIR=temp)
    base = pathlib.Path(temp) / f'minibox-{os.getuid()}'
    containers = []
    daemon_pid = None

    def run(*args, code=0):
        result = subprocess.run([RUNTIME, *map(str, args)], env=env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15)
        assert result.returncode == code, (args, result.returncode, result.stdout)
        return result.stdout

    def request(command, pid):
        connection = socket.socket(socket.AF_UNIX)
        connection.settimeout(8)
        connection.connect(str(base / 'socket'))
        connection.sendall(f'{command}\n{pid}\n'.encode())
        return connection

    def status(pid):
        with request('wait', pid) as connection:
            return int(connection.recv(100).strip())

    def start(*args):
        pid = int(run('run', '-d', *args).strip())
        containers.append(pid)
        return pid

    def logs_contain(pid, text):
        return text in run('logs', pid)

    try:
        run('daemon')
        eventually(lambda: (base / 'daemon.pid').exists())
        daemon_pid = int((base / 'daemon.pid').read_text())
        output = run('run', ROOT, '/bin/sh', '-c', 'echo hello; echo PID=$$; exit 7', code=7)
        assert 'hello' in output and 'PID=1' in output
        print('PASS: command, PID 1, exit code')

        pid = start(ROOT, '/bin/sh', '-c',
                    "trap 'echo stopped; exit 0' TERM; echo ready; while :; do sleep 1; done")
        eventually(lambda: logs_contain(pid, 'ready'))
        assert f'{pid} running' in run('list').splitlines()
        with request('follow', pid) as follow:
            data = b''
            while b'ready' not in data:
                data += follow.recv(4096)
            # This output is generated only AFTER subscription, unlike the old test.
            assert run('kill', pid).strip() == 'ok'
            while b'stopped' not in data:
                chunk = follow.recv(4096)
                assert chunk, data
                data += chunk
        eventually(lambda: status(pid) == 0)
        print('PASS: detached, list, logs, live follow, graceful kill')

        pid = start(ROOT, '/bin/sh')
        result = subprocess.run([RUNTIME, 'attach', str(pid)], env=env,
                                input="printf '%s%s\\n' ATTACH_ VERIFIED\nexit\n",
                                text=True, stdout=subprocess.PIPE, timeout=8)
        assert result.returncode == 0
        # Echoed command does not contain this contiguous result.
        assert 'ATTACH_VERIFIED' in result.stdout
        eventually(lambda: status(pid) == 0)
        print('PASS: attach command execution')

        pid = start(ROOT, '/bin/sh', '-c', "trap '' TERM; echo ready; while :; do sleep 1; done")
        eventually(lambda: logs_contain(pid, 'ready'))
        run('kill', pid)
        eventually(lambda: status(pid) == 137)
        print('PASS: forced kill timeout')

        lower = pathlib.Path(temp) / 'lower'
        shutil.copytree(ROOT, lower, symlinks=True)
        (lower / 'overlay-original').write_text('original\n')
        (lower / 'overlay-delete').write_text('keep\n')
        pid = start('--overlay', lower, '/bin/sh', '-c',
                    'echo changed > /overlay-original; rm /overlay-delete; '
                    'echo new > /overlay-new; test ! -e /overlay-delete || exit 1; echo READY; sleep 30')
        eventually(lambda: logs_contain(pid, 'READY'))
        assert (lower / 'overlay-original').read_text() == 'original\n'
        assert (lower / 'overlay-delete').read_text() == 'keep\n'
        assert not (lower / 'overlay-new').exists()
        layer = pathlib.Path((base / f'{pid}.layer').read_text().strip())
        assert (layer / 'upper/overlay-original').read_text() == 'changed\n'
        output = run('run', '--overlay', lower, '/bin/sh', '-c',
                     'test ! -e /overlay-new && test -e /overlay-delete && cat /overlay-original')
        assert output.strip() == 'original'
        run('kill', pid)
        eventually(lambda: status(pid) >= 0)
        assert not pathlib.Path(f'/proc/{pid}').exists()
        assert (layer / 'upper/overlay-new').read_text() == 'new\n'
        invalid_lower = pathlib.Path(temp) / 'invalid,lower'
        invalid_lower.mkdir()
        error = run('run', '--overlay', invalid_lower, '/bin/true', code=125)
        assert 'setup failed' in error
        failed_pid = int(error.split()[-1])
        eventually(lambda: status(failed_pid) >= 0)
        assert 'unsupported character in overlay path' in run('logs', failed_pid)
        assert not list(invalid_lower.iterdir())
        print('PASS: OverlayFS copy-up, deletion, separate layers, teardown, failed setup')

        server = start('--overlay', ROOT, '/bin/sh', '-c',
                       'exec nc -ll -p 18080 -e /bin/cat')
        client_script = ('i=0; while :; do '
                         'result=$(printf NETWORK_OK | nc -w 1 127.0.0.1 18080); '
                         'test "$result" = NETWORK_OK && { echo "$result"; exit 0; }; '
                         'i=$((i+1)); test "$i" -lt 5 || exit 1; sleep 1; done')
        output = run('run', '--overlay', '--network', server, ROOT, '/bin/sh', '-c', client_script)
        assert 'NETWORK_OK' in output
        output = run('run', '--overlay', ROOT, '/bin/sh', '-c',
                     'result=$(printf NETWORK_OK | nc -w 1 127.0.0.1 18080); '
                     'test "$result" != NETWORK_OK && echo ISOLATED')
        assert 'ISOLATED' in output
        member = start('--overlay', '--network', server, ROOT, '/bin/sleep', '30')
        for ns in ('net', 'user'):
            assert os.readlink(f'/proc/{server}/ns/{ns}') == os.readlink(f'/proc/{member}/ns/{ns}')
        for ns in ('mnt', 'uts', 'ipc', 'pid_for_children'):
            assert os.readlink(f'/proc/{server}/ns/{ns}') != os.readlink(f'/proc/{member}/ns/{ns}')
        run('kill', server)
        eventually(lambda: status(server) >= 0)
        assert status(member) == -1
        run('run', '--overlay', '--network', member, ROOT, '/bin/true')
        run('run', '--network', server, ROOT, '/bin/true', code=125)
        run('run', '--network', '2147483647', ROOT, '/bin/true', code=125)
        run('run', '--network', 'invalid', ROOT, '/bin/true', code=125)
        print('PASS: shared network TCP, isolated network, namespace identities, owner exit, invalid targets')
    finally:
        for pid in containers:
            try:
                if status(pid) < 0:
                    run('kill', pid)
                    eventually(lambda: status(pid) >= 0)
            except (OSError, AssertionError, ValueError):
                pass
        if daemon_pid:
            os.kill(daemon_pid, signal.SIGTERM)
