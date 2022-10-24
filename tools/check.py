#!/usr/bin/python3

import glob
import os
import subprocess

import distro_info

STABLE = distro_info.DebianDistroInfo().stable()

testing = set()
proc = subprocess.Popen(['apt-cache', 'pkgnames'],
                        universal_newlines=True,
                        stdout=subprocess.PIPE)
for line in proc.stdout:
    testing.add(line.rstrip())

# Add RaspBian
testing.add('raspberrypi-bootloader')
testing.add('libraspberrypi0')

# Google repository
testing.add('google-earth-stable')

# Add Stable, remove cache file to trigger download
if not os.path.isfile('tools/Packages_amd64'):
    subprocess.check_call(['ben', 'download',
                           '--archs', 'amd64',
                           '--suite', 'stable'],
                          cwd='tools')
    os.unlink('tools/Sources')

stable = set()
with open('tools/Packages_amd64', 'r', encoding='utf8') as p:
    for line in p:
        if line.startswith('Package:'):
            stable.add(line.split(':', 1)[1].strip())


filters = set([os.path.basename(f) for f in glob.glob('rules/*')])
explain = set([os.path.basename(f) for f in glob.glob('explain/*') if f == f.lower()])

def process(category, packages, testing, stable, archive):
    unknown = packages - testing
    deprecated = unknown & stable
    unknown = unknown - stable
    print('[%s]:' % category)
    print('moved to %s:' % STABLE, sorted(deprecated))
    for item in deprecated:
        destdir = os.path.join('archive', archive)
        if not os.path.isdir(destdir):
            os.makedirs(destdir)
        subprocess.call(['git', 'mv', os.path.join(category, item), destdir])
    print('unknown:', sorted(unknown))

process('rules', filters, testing, stable, STABLE)
print()
process('explain', explain, testing, stable, 'explain')