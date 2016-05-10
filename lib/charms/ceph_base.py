
#
# Copyright 2012-2016 Canonical Ltd.
#
# Authors:
#  James Page <james.page@ubuntu.com>
#  Paul Collins <paul.collins@canonical.com>
#  Chris MacNaughton <chris.macnaughton@canonical.com>
#

# Imports from ceph.py
import ctypes
import ctypes.util
import errno
import json
import subprocess
import time
import os
import re
import sys
import shutil
from charmhelpers.cli.host import mounts
from charmhelpers.core.host import (
    mkdir,
    chownr,
    cmp_pkgrevno,
    lsb_release,
    service_stop,
    service_restart)
from charmhelpers.core.hookenv import (
    log,
    ERROR,
    WARNING,
    DEBUG,
    cached,
    status_set,
)
from charmhelpers.fetch import (
    apt_cache
)
from charmhelpers.contrib.storage.linux.utils import (
    zap_disk,
    is_block_device,
    is_device_mounted,
)
# from utils import (
#     get_unit_hostname,
# )

# Imports from utils.py
import socket
import re
from charmhelpers.core.hookenv import (
    unit_get,
    cached,
    config,
    status_set,
)
from charmhelpers.fetch import (
    apt_install,
    filter_installed_packages
)

from charmhelpers.core.host import (
    lsb_release
)

from charmhelpers.contrib.network.ip import (
    get_address_in_network,
    get_ipv6_addr
)

# try:
#     import dns.resolver
# except ImportError:
#     apt_install(filter_installed_packages(['python-dnspython']),
#                 fatal=True)
#     import dns.resolver
import dns.resolver
### This is migrated from hooks/utils.py

def enable_pocket(pocket):
    apt_sources = "/etc/apt/sources.list"
    with open(apt_sources, "r") as sources:
        lines = sources.readlines()
    with open(apt_sources, "w") as sources:
        for line in lines:
            if pocket in line:
                sources.write(re.sub('^# deb', 'deb', line))
            else:
                sources.write(line)


@cached
def get_unit_hostname():
    return socket.gethostname()


@cached
def get_host_ip(hostname=None):
    if config('prefer-ipv6'):
        return get_ipv6_addr()[0]

    hostname = hostname or unit_get('private-address')
    try:
        # Test to see if already an IPv4 address
        socket.inet_aton(hostname)
        return hostname
    except socket.error:
        # This may throw an NXDOMAIN exception; in which case
        # things are badly broken so just let it kill the hook
        answers = dns.resolver.query(hostname, 'A')
        if answers:
            return answers[0].address


def get_networks(config_opt='ceph-public-network'):
    """Get all configured networks from provided config option.

    If public network(s) are provided, go through them and return those for
    which we have an address configured.
    """
    networks = config(config_opt)
    if networks:
        networks = networks.split()
        return [n for n in networks if get_address_in_network(n)]

    return []


def get_public_addr():
    return get_network_addrs('ceph-public-network')[0]


def get_network_addrs(config_opt):
    """Get all configured public networks addresses.

    If public network(s) are provided, go through them and return the
    addresses we have configured on any of those networks.
    """
    addrs = []
    networks = config(config_opt)
    if networks:
        networks = networks.split()
        addrs = [get_address_in_network(n) for n in networks]
        addrs = [a for a in addrs if a]

    if not addrs:
        if networks:
            msg = ("Could not find an address on any of '%s' - resolve this "
                   "error to retry" % (networks))
            status_set('blocked', msg)
            raise Exception(msg)
        else:
            return [get_host_ip()]

    return addrs


def assert_charm_supports_ipv6():
    """Check whether we are able to support charms ipv6."""
    if lsb_release()['DISTRIB_CODENAME'].lower() < "trusty":
        raise Exception("IPv6 is not supported in the charms for Ubuntu "
                        "versions less than Trusty 14.04")


### This is migrated from hooks/ceph.py

LEADER = 'leader'
PEON = 'peon'
QUORUM = [LEADER, PEON]

PACKAGES = ['ceph', 'gdisk', 'ntp', 'btrfs-tools', 'python-ceph', 'xfsprogs']


def ceph_user():
    if get_version() > 1:
        return 'ceph'
    else:
        return "root"


class CrushLocation(object):
    def __init__(self,
                 name,
                 identifier,
                 host,
                 rack,
                 row,
                 datacenter,
                 chassis,
                 root):
        self.name = name
        self.identifier = identifier
        self.host = host
        self.rack = rack
        self.row = row
        self.datacenter = datacenter
        self.chassis = chassis
        self.root = root

    def __str__(self):
        return "name: {} id: {} host: {} rack: {} row: {} datacenter: {} " \
               "chassis :{} root: {}".format(self.name, self.identifier,
                                             self.host, self.rack, self.row,
                                             self.datacenter, self.chassis,
                                             self.root)

    def __eq__(self, other):
        return not self.name < other.name and not other.name < self.name

    def __ne__(self, other):
        return self.name < other.name or other.name < self.name

    def __gt__(self, other):
        return self.name > other.name

    def __ge__(self, other):
        return not self.name < other.name

    def __le__(self, other):
        return self.name < other.name


def get_osd_tree(service):
    """
    Returns the current osd map in JSON.
    :return: List. :raise: ValueError if the monmap fails to parse.
      Also raises CalledProcessError if our ceph command fails
    """
    try:
        tree = subprocess.check_output(
            ['ceph', '--id', service,
             'osd', 'tree', '--format=json'])
        try:
            json_tree = json.loads(tree)
            crush_list = []
            # Make sure children are present in the json
            if not json_tree['nodes']:
                return None
            child_ids = json_tree['nodes'][0]['children']
            for child in json_tree['nodes']:
                if child['id'] in child_ids:
                    crush_list.append(
                        CrushLocation(
                            name=child.get('name'),
                            identifier=child['id'],
                            host=child.get('host'),
                            rack=child.get('rack'),
                            row=child.get('row'),
                            datacenter=child.get('datacenter'),
                            chassis=child.get('chassis'),
                            root=child.get('root')
                        )
                    )
            return crush_list
        except ValueError as v:
            log("Unable to parse ceph tree json: {}. Error: {}".format(
                tree, v.message))
            raise
    except subprocess.CalledProcessError as e:
        log("ceph osd tree command failed with message: {}".format(
            e.message))
        raise


def get_local_osd_ids():
    """
    This will list the /var/lib/ceph/osd/* directories and try
    to split the ID off of the directory name and return it in
    a list

    :return: list.  A list of osd identifiers :raise: OSError if
     something goes wrong with listing the directory.
    """
    osd_ids = []
    osd_path = os.path.join(os.sep, 'var', 'lib', 'ceph', 'osd')
    if os.path.exists(osd_path):
        try:
            dirs = os.listdir(osd_path)
            for osd_dir in dirs:
                osd_id = osd_dir.split('-')[1]
                osd_ids.append(osd_id)
        except OSError:
            raise
    return osd_ids


def get_local_mon_ids():
    """
    This will list the /var/lib/ceph/mon/* directories and try
    to split the ID off of the directory name and return it in
    a list

    :return: list.  A list of monitor identifiers :raise: OSError if
     something goes wrong with listing the directory.
    """
    mon_ids = []
    mon_path = os.path.join(os.sep, 'var', 'lib', 'ceph', 'mon')
    if os.path.exists(mon_path):
        try:
            dirs = os.listdir(mon_path)
            for mon_dir in dirs:
                # Basically this takes everything after ceph- as the monitor ID
                match = re.search('ceph-(?P<mon_id>.*)', mon_dir)
                if match:
                    mon_ids.append(match.group('mon_id'))
        except OSError:
            raise
    return mon_ids


def get_version():
    '''Derive Ceph release from an installed package.'''
    import apt_pkg as apt

    cache = apt_cache()
    package = "ceph"
    try:
        pkg = cache[package]
    except:
        # the package is unknown to the current apt cache.
        e = 'Could not determine version of package with no installation ' \
            'candidate: %s' % package
        error_out(e)

    if not pkg.current_ver:
        # package is known, but no version is currently installed.
        e = 'Could not determine version of uninstalled package: %s' % package
        error_out(e)

    vers = apt.upstream_version(pkg.current_ver.ver_str)

    # x.y match only for 20XX.X
    # and ignore patch level for other packages
    match = re.match('^(\d+)\.(\d+)', vers)

    if match:
        vers = match.group(0)
    return float(vers)


def error_out(msg):
    log("FATAL ERROR: %s" % msg,
        level=ERROR)
    sys.exit(1)


def is_quorum():
    asok = "/var/run/ceph/ceph-mon.{}.asok".format(get_unit_hostname())
    cmd = [
        "sudo",
        "-u",
        ceph_user(),
        "ceph",
        "--admin-daemon",
        asok,
        "mon_status"
    ]
    if os.path.exists(asok):
        try:
            result = json.loads(subprocess.check_output(cmd))
        except subprocess.CalledProcessError:
            return False
        except ValueError:
            # Non JSON response from mon_status
            return False
        if result['state'] in QUORUM:
            return True
        else:
            return False
    else:
        return False


def is_leader():
    asok = "/var/run/ceph/ceph-mon.{}.asok".format(get_unit_hostname())
    cmd = [
        "sudo",
        "-u",
        ceph_user(),
        "ceph",
        "--admin-daemon",
        asok,
        "mon_status"
    ]
    if os.path.exists(asok):
        try:
            result = json.loads(subprocess.check_output(cmd))
        except subprocess.CalledProcessError:
            return False
        except ValueError:
            # Non JSON response from mon_status
            return False
        if result['state'] == LEADER:
            return True
        else:
            return False
    else:
        return False


def wait_for_quorum():
    while not is_quorum():
        time.sleep(3)


def add_bootstrap_hint(peer):
    asok = "/var/run/ceph/ceph-mon.{}.asok".format(get_unit_hostname())
    cmd = [
        "sudo",
        "-u",
        ceph_user(),
        "ceph",
        "--admin-daemon",
        asok,
        "add_bootstrap_peer_hint",
        peer
    ]
    if os.path.exists(asok):
        # Ignore any errors for this call
        subprocess.call(cmd)


DISK_FORMATS = [
    'xfs',
    'ext4',
    'btrfs'
]

CEPH_PARTITIONS = [
    '4FBD7E29-9D25-41B8-AFD0-5EC00CEFF05D',  # ceph encrypted osd data
    '4FBD7E29-9D25-41B8-AFD0-062C0CEFF05D',  # ceph osd data
    '45B0969E-9B03-4F30-B4C6-B4B80CEFF106',  # ceph osd journal
]


def umount(mount_point):
    """
    This function unmounts a mounted directory forcibly.  This will
    be used for unmounting broken hard drive mounts which may hang.
    If umount returns EBUSY this will lazy unmount.
    :param mount_point: str.  A String representing the filesystem mount point
    :return: int.  Returns 0 on success.  errno otherwise.
    """
    libc_path = ctypes.util.find_library("c")
    libc = ctypes.CDLL(libc_path, use_errno=True)

    # First try to umount with MNT_FORCE
    ret = libc.umount(mount_point, 1)
    if ret < 0:
        err = ctypes.get_errno()
        if err == errno.EBUSY:
            # Detach from try.  IE lazy umount
            ret = libc.umount(mount_point, 2)
            if ret < 0:
                err = ctypes.get_errno()
                return err
            return 0
        else:
            return err
    return 0


def replace_osd(dead_osd_number,
                dead_osd_device,
                new_osd_device,
                osd_format,
                osd_journal,
                reformat_osd=False,
                ignore_errors=False):
    """
    This function will automate the replacement of a failed osd disk as much
    as possible. It will revoke the keys for the old osd, remove it from the
    crush map and then add a new osd into the cluster.
    :param dead_osd_number: The osd number found in ceph osd tree. Example: 99
    :param dead_osd_device: The physical device.  Example: /dev/sda
    :param osd_format:
    :param osd_journal:
    :param reformat_osd:
    :param ignore_errors:
    """
    host_mounts = mounts()
    mount_point = None
    for mount in host_mounts:
        if mount[1] == dead_osd_device:
            mount_point = mount[0]
    # need to convert dev to osd number
    # also need to get the mounted drive so we can tell the admin to
    # replace it
    try:
        # Drop this osd out of the cluster. This will begin a
        # rebalance operation
        status_set('maintenance', 'Removing osd {}'.format(dead_osd_number))
        subprocess.check_output(['ceph', 'osd', 'out',
                                 'osd.{}'.format(dead_osd_number)])

        # Kill the osd process if it's not already dead
        if systemd():
            service_stop('ceph-osd@{}'.format(dead_osd_number))
        else:
            subprocess.check_output(['stop', 'ceph-osd', 'id={}'.format(
                dead_osd_number)]),
        # umount if still mounted
        ret = umount(mount_point)
        if ret < 0:
            raise RuntimeError('umount {} failed with error: {}'.format(
                mount_point, os.strerror(ret)))
        # Clean up the old mount point
        shutil.rmtree(mount_point)
        subprocess.check_output(['ceph', 'osd', 'crush', 'remove',
                                 'osd.{}'.format(dead_osd_number)])
        # Revoke the OSDs access keys
        subprocess.check_output(['ceph', 'auth', 'del',
                                 'osd.{}'.format(dead_osd_number)])
        subprocess.check_output(['ceph', 'osd', 'rm',
                                 'osd.{}'.format(dead_osd_number)])
        status_set('maintenance', 'Setting up replacement osd {}'.format(
            new_osd_device))
        osdize(new_osd_device,
               osd_format,
               osd_journal,
               reformat_osd,
               ignore_errors)
    except subprocess.CalledProcessError as e:
        log('replace_osd failed with error: ' + e.output)


def is_osd_disk(dev):
    try:
        info = subprocess.check_output(['sgdisk', '-i', '1', dev])
        info = info.split("\n")  # IGNORE:E1103
        for line in info:
            for ptype in CEPH_PARTITIONS:
                sig = 'Partition GUID code: {}'.format(ptype)
                if line.startswith(sig):
                    return True
    except subprocess.CalledProcessError:
        pass
    return False


def start_osds(devices):
    # Scan for ceph block devices
    rescan_osd_devices()
    if cmp_pkgrevno('ceph', "0.56.6") >= 0:
        # Use ceph-disk activate for directory based OSD's
        for dev_or_path in devices:
            if os.path.exists(dev_or_path) and os.path.isdir(dev_or_path):
                subprocess.check_call(['ceph-disk', 'activate', dev_or_path])


def rescan_osd_devices():
    cmd = [
        'udevadm', 'trigger',
        '--subsystem-match=block', '--action=add'
    ]

    subprocess.call(cmd)


_bootstrap_keyring = "/var/lib/ceph/bootstrap-osd/ceph.keyring"
_upgrade_keyring = "/var/lib/ceph/osd/ceph.client.osd-upgrade.keyring"


def is_bootstrapped():
    return os.path.exists(_bootstrap_keyring)


def wait_for_bootstrap():
    while (not is_bootstrapped()):
        time.sleep(3)


def import_osd_bootstrap_key(key):
    if not os.path.exists(_bootstrap_keyring):
        cmd = [
            "sudo",
            "-u",
            ceph_user(),
            'ceph-authtool',
            _bootstrap_keyring,
            '--create-keyring',
            '--name=client.bootstrap-osd',
            '--add-key={}'.format(key)
        ]
        subprocess.check_call(cmd)


def import_osd_upgrade_key(key):
    if not os.path.exists(_upgrade_keyring):
        cmd = [
            "sudo",
            "-u",
            ceph_user(),
            'ceph-authtool',
            _upgrade_keyring,
            '--create-keyring',
            '--name=client.osd-upgrade',
            '--add-key={}'.format(key)
        ]
        subprocess.check_call(cmd)


def generate_monitor_secret():
    cmd = [
        'ceph-authtool',
        '/dev/stdout',
        '--name=mon.',
        '--gen-key'
    ]
    res = subprocess.check_output(cmd)

    return "{}==".format(res.split('=')[1].strip())


# OSD caps taken from ceph-create-keys
_osd_bootstrap_caps = {
    'mon': [
        'allow command osd create ...',
        'allow command osd crush set ...',
        r'allow command auth add * osd allow\ * mon allow\ rwx',
        'allow command mon getmap'
    ]
}

_osd_bootstrap_caps_profile = {
    'mon': [
        'allow profile bootstrap-osd'
    ]
}


def parse_key(raw_key):
    # get-or-create appears to have different output depending
    # on whether its 'get' or 'create'
    # 'create' just returns the key, 'get' is more verbose and
    # needs parsing
    key = None
    if len(raw_key.splitlines()) == 1:
        key = raw_key
    else:
        for element in raw_key.splitlines():
            if 'key' in element:
                key = element.split(' = ')[1].strip()  # IGNORE:E1103
    return key


def get_osd_bootstrap_key():
    try:
        # Attempt to get/create a key using the OSD bootstrap profile first
        key = get_named_key('bootstrap-osd',
                            _osd_bootstrap_caps_profile)
    except:
        # If that fails try with the older style permissions
        key = get_named_key('bootstrap-osd',
                            _osd_bootstrap_caps)
    return key


_radosgw_keyring = "/etc/ceph/keyring.rados.gateway"


def import_radosgw_key(key):
    if not os.path.exists(_radosgw_keyring):
        cmd = [
            "sudo",
            "-u",
            ceph_user(),
            'ceph-authtool',
            _radosgw_keyring,
            '--create-keyring',
            '--name=client.radosgw.gateway',
            '--add-key={}'.format(key)
        ]
        subprocess.check_call(cmd)

# OSD caps taken from ceph-create-keys
_radosgw_caps = {
    'mon': ['allow rw'],
    'osd': ['allow rwx']
}
_upgrade_caps = {
    'mon': ['allow rwx']
}

def get_radosgw_key():
    return get_named_key('radosgw.gateway', _radosgw_caps)


_default_caps = {
    'mon': ['allow rw'],
    'osd': ['allow rwx']
}
admin_caps = {
    'mds': ['allow'],
    'mon': ['allow *'],
    'osd': ['allow *']
}
osd_upgrade_caps = {
    'mon': ['allow command "config-key"',
            'allow command "osd tree"',
            'allow command "config-key list"',
            'allow command "config-key put"',
            'allow command "config-key get"',
            'allow command "config-key exists"',
            ]
}
def get_upgrade_key():
    return get_named_key('upgrade-osd', _upgrade_caps)


def get_named_key(name, caps=None):
    caps = caps or _default_caps
    cmd = [
        "sudo",
        "-u",
        ceph_user(),
        'ceph',
        '--name', 'mon.',
        '--keyring',
        '/var/lib/ceph/mon/ceph-{}/keyring'.format(
            get_unit_hostname()
        ),
        'auth', 'get-or-create', 'client.{}'.format(name),
    ]
    # Add capabilities
    for subsystem, subcaps in caps.iteritems():
        cmd.extend([
            subsystem,
            '; '.join(subcaps),
        ])
    return parse_key(subprocess.check_output(cmd).strip())  # IGNORE:E1103


def upgrade_key_caps(key, caps):
    """ Upgrade key to have capabilities caps """
    if not is_leader():
        # Not the MON leader OR not clustered
        return
    cmd = [
        "sudo", "-u", ceph_user(), 'ceph', 'auth', 'caps', key
    ]
    for subsystem, subcaps in caps.iteritems():
        cmd.extend([subsystem, '; '.join(subcaps)])
    subprocess.check_call(cmd)


@cached
def systemd():
    return (lsb_release()['DISTRIB_CODENAME'] >= 'vivid')


def bootstrap_monitor_cluster(secret):
    hostname = get_unit_hostname()
    path = '/var/lib/ceph/mon/ceph-{}'.format(hostname)
    done = '{}/done'.format(path)
    if systemd():
        init_marker = '{}/systemd'.format(path)
    else:
        init_marker = '{}/upstart'.format(path)

    keyring = '/var/lib/ceph/tmp/{}.mon.keyring'.format(hostname)

    if os.path.exists(done):
        log('bootstrap_monitor_cluster: mon already initialized.')
    else:
        # Ceph >= 0.61.3 needs this for ceph-mon fs creation
        mkdir('/var/run/ceph', owner=ceph_user(),
              group=ceph_user(), perms=0o755)
        mkdir(path, owner=ceph_user(), group=ceph_user())
        # end changes for Ceph >= 0.61.3
        try:
            subprocess.check_call(['ceph-authtool', keyring,
                                   '--create-keyring', '--name=mon.',
                                   '--add-key={}'.format(secret),
                                   '--cap', 'mon', 'allow *'])

            subprocess.check_call(['ceph-mon', '--mkfs',
                                   '-i', hostname,
                                   '--keyring', keyring])
            chownr(path, ceph_user(), ceph_user())
            with open(done, 'w'):
                pass
            with open(init_marker, 'w'):
                pass

            if systemd():
                subprocess.check_call(['systemctl', 'enable', 'ceph-mon'])
                service_restart('ceph-mon')
            else:
                service_restart('ceph-mon-all')
        except:
            raise
        finally:
            os.unlink(keyring)


def update_monfs():
    hostname = get_unit_hostname()
    monfs = '/var/lib/ceph/mon/ceph-{}'.format(hostname)
    if systemd():
        init_marker = '{}/systemd'.format(monfs)
    else:
        init_marker = '{}/upstart'.format(monfs)
    if os.path.exists(monfs) and not os.path.exists(init_marker):
        # Mark mon as managed by upstart so that
        # it gets start correctly on reboots
        with open(init_marker, 'w'):
            pass


def maybe_zap_journal(journal_dev):
    if is_osd_disk(journal_dev):
        log('Looks like {} is already an OSD data'
            ' or journal, skipping.'.format(journal_dev))
        return
    zap_disk(journal_dev)
    log("Zapped journal device {}".format(journal_dev))


def get_partitions(dev):
    cmd = ['partx', '--raw', '--noheadings', dev]
    try:
        out = subprocess.check_output(cmd).splitlines()
        log("get partitions: {}".format(out), level=DEBUG)
        return out
    except subprocess.CalledProcessError as e:
        log("Can't get info for {0}: {1}".format(dev, e.output))
        return []


def find_least_used_journal(journal_devices):
    usages = map(lambda a: (len(get_partitions(a)), a), journal_devices)
    least = min(usages, key=lambda t: t[0])
    return least[1]


def osdize(dev, osd_format, osd_journal, reformat_osd=False,
           ignore_errors=False, encrypt=False):
    if dev.startswith('/dev'):
        osdize_dev(dev, osd_format, osd_journal,
                   reformat_osd, ignore_errors, encrypt)
    else:
        osdize_dir(dev, encrypt)


def osdize_dev(dev, osd_format, osd_journal, reformat_osd=False,
               ignore_errors=False, encrypt=False):
    if not os.path.exists(dev):
        log('Path {} does not exist - bailing'.format(dev))
        return

    if not is_block_device(dev):
        log('Path {} is not a block device - bailing'.format(dev))
        return

    if is_osd_disk(dev) and not reformat_osd:
        log('Looks like {} is already an'
            ' OSD data or journal, skipping.'.format(dev))
        return

    if is_device_mounted(dev):
        log('Looks like {} is in use, skipping.'.format(dev))
        return

    status_set('maintenance', 'Initializing device {}'.format(dev))
    cmd = ['ceph-disk', 'prepare']
    # Later versions of ceph support more options
    if cmp_pkgrevno('ceph', '0.60') >= 0:
        if encrypt:
            cmd.append('--dmcrypt')
    if cmp_pkgrevno('ceph', '0.48.3') >= 0:
        if osd_format:
            cmd.append('--fs-type')
            cmd.append(osd_format)
        if reformat_osd:
            cmd.append('--zap-disk')
        cmd.append(dev)
        if osd_journal:
            least_used = find_least_used_journal(osd_journal)
            cmd.append(least_used)
    else:
        # Just provide the device - no other options
        # for older versions of ceph
        cmd.append(dev)
        if reformat_osd:
            zap_disk(dev)

    try:
        log("osdize cmd: {}".format(cmd))
        subprocess.check_call(cmd)
    except subprocess.CalledProcessError as e:
        if ignore_errors:
            log('Unable to initialize device: {}'.format(dev), WARNING)
        else:
            log('Unable to initialize device: {}'.format(dev), ERROR)
            raise e


def osdize_dir(path, encrypt=False):
    if os.path.exists(os.path.join(path, 'upstart')):
        log('Path {} is already configured as an OSD - bailing'.format(path))
        return

    if cmp_pkgrevno('ceph', "0.56.6") < 0:
        log('Unable to use directories for OSDs with ceph < 0.56.6',
            level=ERROR)
        raise

    mkdir(path, owner=ceph_user(), group=ceph_user(), perms=0o755)
    chownr('/var/lib/ceph', ceph_user(), ceph_user())
    cmd = [
        'sudo', '-u', ceph_user(),
        'ceph-disk',
        'prepare',
        '--data-dir',
        path
    ]
    if cmp_pkgrevno('ceph', '0.60') >= 0:
        if encrypt:
            cmd.append('--dmcrypt')
    log("osdize dir cmd: {}".format(cmd))
    subprocess.check_call(cmd)


def filesystem_mounted(fs):
    return subprocess.call(['grep', '-wqs', fs, '/proc/mounts']) == 0


def get_running_osds():
    """Returns a list of the pids of the current running OSD daemons"""
    cmd = ['pgrep', 'ceph-osd']
    try:
        result = subprocess.check_output(cmd)
        return result.split()
    except subprocess.CalledProcessError:
        return []



def emit_cephconf(mon_hosts):
    networks = get_networks('ceph-public-network')
    public_network = ', '.join(networks)

    networks = get_networks('ceph-cluster-network')
    cluster_network = ', '.join(networks)

    cephcontext = {
        'auth_supported': config('auth-supported'),
        'mon_hosts': ' '.join(mon_hosts),
        'fsid': leader_get('fsid'),
        'old_auth': cmp_pkgrevno('ceph', "0.51") < 0,
        'osd_journal_size': config('osd-journal-size'),
        'use_syslog': str(config('use-syslog')).lower(),
        'ceph_public_network': public_network,
        'ceph_cluster_network': cluster_network,
        'loglevel': config('loglevel'),
        'dio': str(config('use-direct-io')).lower(),
    }

    if config('prefer-ipv6'):
        dynamic_ipv6_address = get_ipv6_addr()[0]
        if not public_network:
            cephcontext['public_addr'] = dynamic_ipv6_address
        if not cluster_network:
            cephcontext['cluster_addr'] = dynamic_ipv6_address

    if az_info():
        cephcontext['crush_location'] = "root=default rack={} host={}" \
            .format(az_info(), socket.gethostname())

    # Install ceph.conf as an alternative to support
    # co-existence with other charms that write this file
    charm_ceph_conf = "/var/lib/charm/{}/ceph.conf".format(service_name())
    mkdir(os.path.dirname(charm_ceph_conf), owner=ceph.ceph_user(),
          group=ceph.ceph_user())
    render('ceph.conf', charm_ceph_conf, cephcontext, perms=0o644)
    install_alternative('ceph.conf', '/etc/ceph/ceph.conf',
                        charm_ceph_conf, 100)


def get_fsid():
    return get_conf('fsid')


def get_auth():
    return get_conf('auth')


def get_conf(name):
    for relid in relation_ids('mon'):
        for unit in related_units(relid):
            conf = relation_get(name,
                                unit, relid)
            if conf:
                return conf
    return None
