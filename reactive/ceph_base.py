from charms.reactive import when, when_not, set_state
import charms.apt

from charms.ceph_base import (
    get_networks,
    get_public_addr,
    assert_charm_supports_ipv6
)

from charmhelpers.contrib.hardening.harden import harden

@when_not('ceph.installed')
@harden()
def install_ceph_base():
    charms.apt.add_source(config('source'), key=config('key'))
    charms.apt.queue_install(['ceph', 'gdisk', 'ntp', 'btrfs-tools', 'python3-ceph', 'xfsprogs'])

    set_state('ceph.installed')


@when('config.changed')
@harden()
def config_changed():
    # # Check if an upgrade was requested
    # check_for_upgrade()
    # ^^ Need to handle this in the dependant charms

    if config('prefer-ipv6'):
        assert_charm_supports_ipv6()

    sysctl_dict = config('sysctl')
    if sysctl_dict:
        create_sysctl(sysctl_dict, '/etc/sysctl.d/50-ceph-osd-charm.conf')

    e_mountpoint = config('ephemeral-unmount')
    if e_mountpoint and ceph.filesystem_mounted(e_mountpoint):
        umount(e_mountpoint)
    prepare_disks_and_activate()
