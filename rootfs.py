#!/usr/bin/env python3
import hashlib, pathlib, subprocess, urllib.request, sys

version = '3.20.3'
arch = subprocess.check_output(['uname', '-m'], text=True).strip()
name = f'alpine-minirootfs-{version}-{arch}.tar.gz'
url = f'https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/{arch}/{name}'
target = pathlib.Path(sys.argv[1] if len(sys.argv)>1 else pathlib.Path.home()/'minibox-rootfs')
target.mkdir(parents=True, exist_ok=True)

if any(target.iterdir()):
    raise SystemExit('Target must be empty')

archive = target.parent/name
urllib.request.urlretrieve(url, archive)
expected = urllib.request.urlopen(url+'.sha256').read().decode().split()[0]

assert hashlib.sha256(archive.read_bytes()).hexdigest() == expected
subprocess.run(['tar','--no-same-owner','-xzf',str(archive),'-C',str(target)],check=True)
print(target)
