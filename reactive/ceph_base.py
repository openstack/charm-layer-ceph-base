from charms import reactive
from charms.reactive import when, when_not, set_state, is_state
import charms.apt

from charms.ceph_base import (
    # get_networks,
    # get_public_addr,
    get_mon_hosts,
    is_bootstrapped,
    is_quorum,
    get_running_osds,
    assert_charm_supports_ipv6
)

# from charmhelpers.core.host import (
#     umount,
# )
from charmhelpers.core import hookenv
from charmhelpers.core.hookenv import (
    # log,
    config,
    relation_ids,
    related_units,
    relation_get,
    status_set,
    local_unit
)

from charmhelpers.core.sysctl import create as create_sysctl

# from charmhelpers.contrib.hardening.harden import harden


@when_not('ceph.installed')
# @harden()
def install_ceph_base():
    charms.apt.add_source(config('source'), key=config('key'))
    charms.apt.queue_install(charms.ceph_base.PACKAGES)
    charms.apt.install_queued()
    set_state('ceph.installed')


@when('config.changed', 'ceph.installed')
# @harden()
def config_changed():
    # # Check if an upgrade was requested
    # check_for_upgrade()
    # ^^ Need to handle this in the dependant charms

    if config('prefer-ipv6'):
        assert_charm_supports_ipv6()

    sysctl_dict = config('sysctl')
    if sysctl_dict:
        create_sysctl(sysctl_dict, '/etc/sysctl.d/50-ceph-charm.conf')
    # if relations_of_type('nrpe-external-master'):
    #     update_nrpe_config()

    # sysctl_dict = config('sysctl')
    # if sysctl_dict:
    #     create_sysctl(sysctl_dict, '/etc/sysctl.d/50-ceph-osd-charm.conf')

    # e_mountpoint = config('ephemeral-unmount')
    # if e_mountpoint and ceph.filesystem_mounted(e_mountpoint):
    #     umount(e_mountpoint)
    # prepare_disks_and_activate()


def assess_status():
    '''Assess status of current unit'''
    # is_state('ceph_mon.bootstrapped')
    statuses = set([])
    messages = set([])
    if is_state('ceph_mon.installed'):
        (status, message) = log_monitor()
        statuses.add(status)
        messages.add(message)
    if is_state('ceph_osd.installed'):
        (status, message) = log_osds()
        statuses.add(status)
        messages.add(message)
    if 'blocked' in statuses:
        status = 'blocked'
    elif 'waiting' in statuses:
        status = 'waiting'
    else:
        status = 'active'
    message = '; '.join(messages)
    status_set(status, message)


def get_conf(name):
    for relid in relation_ids('mon'):
        for unit in related_units(relid):
            conf = relation_get(name,
                                unit, relid)
            if conf:
                return conf
    return None


def log_monitor():
    moncount = int(config('monitor-count'))
    units = get_peer_units()
    # not enough peers and mon_count > 1
    if len(units.keys()) < moncount:
        return ('blocked', 'Insufficient peer units to bootstrap'
                           ' cluster (require {})'.format(moncount))

    # mon_count > 1, peers, but no ceph-public-address
    ready = sum(1 for unit_ready in units.values() if unit_ready)
    if ready < moncount:
        return ('waiting', 'Peer units detected, waiting for addresses')

    # active - bootstrapped + quorum status check
    if is_bootstrapped() and is_quorum():
        return ('active', 'Unit is ready and clustered')
    else:
        # Unit should be running and clustered, but no quorum
        # TODO: should this be blocked or waiting?
        return ('blocked', 'Unit not clustered (no quorum)')
        # If there's a pending lock for this unit,
        # can i get the lock?
        # reboot the ceph-mon process


def get_peer_units():
    """
    Returns a dictionary of unit names from the mon peer relation with
    a flag indicating whether the unit has presented its address
    """
    units = {}
    units[local_unit()] = True
    for relid in relation_ids('mon'):
        for unit in related_units(relid):
            addr = relation_get('ceph-public-address', unit, relid)
            units[unit] = addr is not None
    return units


def log_osds():
    if not is_state('ceph_mon.installed'):
        # Check for mon relation
        if len(relation_ids('mon')) < 1:
            status_set('blocked', 'Missing relation: monitor')
            return

        # Check for monitors with presented addresses
        # Check for bootstrap key presentation
        monitors = get_mon_hosts()
        if len(monitors) < 1 or not get_conf('osd_bootstrap_key'):
            status_set('waiting', 'Incomplete relation: monitor')
            return

    # Check for OSD device creation parity i.e. at least some devices
    # must have been presented and used for this charm to be operational
    running_osds = get_running_osds()
    if not running_osds:
        return ('blocked',
                'No block devices detected using current configuration')
    else:
        return ('active',
                'Unit is ready ({} OSD)'.format(len(running_osds)))


# Per https://github.com/juju-solutions/charms.reactive/issues/33,
# this module may be imported multiple times so ensure the
# initialization hook is only registered once. I have to piggy back
# onto the namespace of a module imported before reactive discovery
# to do this.
if not hasattr(reactive, '_ceph_log_registered'):
    # We need to register this to run every hook, not just during install
    # and config-changed, to protect against race conditions. If we don't
    # do this, then the config in the hook environment may show updates
    # to running hooks well before the config-changed hook has been invoked
    # and the intialization provided an opertunity to be run.
    hookenv.atexit(assess_status)
    reactive._ceph_log_registered = True
