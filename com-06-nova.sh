#!/bin/bash
source com-config.cfg

## ceilometer
if [ "$IS_TELEMETRY" -eq 1 ]; then
NOTI_TELEMETRY="[oslo_messaging_notifications]
driver = messagingv2"

NOVA_TELEMETRY="instance_usage_audit = True
instance_usage_audit_period = hour
notify_on_state_change = vm_and_task_state"
fi

if [ "$IS_MLNX" -gt 0 ]; then
PCI_PASSTHROUGH_WHITELIST="{\"devname\": \"$DEVNAME\", \"physical_network\": \"$PHYSICAL_NETWORK\"}"
SCHEDULER_AVAILABLE_FILTERS="nova.scheduler.filters.all_filters"
SCHEDULER_DEFAULT_FILTERS="RetryFilter, AvailabilityZoneFilter, RamFilter, ComputeFilter, ComputeCapabilitiesFilter, ImagePropertiesFilter, PciPassthroughFilter"

PCI_WHITELIST="pci_passthrough_whitelist=$PCI_PASSTHROUGH_WHITELIST"
fi

echo "########## INSTALL NOVA ################"
apt-get -y install nova-compute

filename=/etc/nova/nova.conf
test -f $filename.org || cp $filename $filename.org
rm -f $filename

cat << EOF > $filename
[DEFAULT]
debug = false

rpc_backend = rabbit

#log_dir = /var/log/nova
logdir = /var/log/nova

dhcpbridge_flagfile = /etc/nova/nova.conf
state_path = /var/lib/nova
instances_path = \$state_path/instances
force_dhcp_release = True
enabled_apis = osapi_compute, metadata
rootwrap_config = /etc/nova/rootwrap.conf
api_paste_config = /etc/nova/api-paste.ini

my_ip = $COM_IP

linuxnet_interface_driver = openvswitch
firewall_driver = nova.virt.firewall.NoopFirewallDriver

resume_guests_state_on_host_boot = True
allow_resize_to_same_host = True

vif_plugging_is_fatal = True
vif_plugging_timeout = 300
compute_driver = libvirt.LibvirtDriver

use_neutron = True

## ceilometer
$NOVA_TELEMETRY

## SR-IOV
##scheduler_available_filters = $SCHEDULER_AVAILABLE_FILTERS
##scheduler_default_filters = $SCHEDULER_DEFAULT_FILTERS
##pci_passthrough_whitelist = $PCI_PASSTHROUGH_WHITELIST
$PCI_WHITELIST

[api_database]
connection = mysql+pymysql://nova:$DEFAULT_PASS@controller/nova_api

[database]
connection = mysql+pymysql://nova:$DEFAULT_PASS@controller/nova

[keystone_authtoken]
auth_uri = http://controller:5000
auth_url = http://controller:35357
memcached_servers = controller:11211
auth_type = password
project_domain_name = default
user_domain_name = default
project_name = service
username = nova
password = $DEFAULT_PASS

[oslo_concurrency]
lock_path = /var/lib/nova/tmp

[oslo_messaging_rabbit]
rabbit_host = controller
rabbit_userid = openstack
rabbit_password = $DEFAULT_PASS

[vnc]
enabled = True
vncserver_listen = 0.0.0.0
vncserver_proxyclient_address = \$my_ip
novncproxy_base_url = http://$MGMT_IP:8080/vnc_auto.html

[glance]
api_servers = http://controller:9292

[neutron]
url = http://controller:9696
auth_url = http://controller:35357
auth_strategy = keystone
auth_type = password
project_domain_name = default
user_domain_name = default
region_name = RegionOne
project_name = service
username = neutron
password = $DEFAULT_PASS

service_metadata_proxy = True
metadata_proxy_shared_secret = $DEFAULT_PASS

[libvirt]
#inject_key : Inject the ssh public key at boot time
#inject_partition : The partition to inject to : -2 => disable,
# -1 => inspect(libguestfs only),
#  0 => not partitioned,
# >0 => partition number
#inject_password : Inject the admin password at boot time, without an agent.
inject_key = False
inject_partition = -2
inject_password = False

[cinder]
os_region_name = RegionOne

## ceilometer
$NOTI_TELEMETRY
EOF

chown nova:nova $filename

rm -f /var/lib/nova/nova.sqlite


echo "##### HARDWARE ACCELERATION #####"
cpu_count=$(egrep -c '(vmx|svm)' /proc/cpuinfo)

# virtual server : virt_type=kvm to virt_type=qemu
filename=/etc/nova/nova-compute.conf
if [ "$cpu_count" -eq 0 ]; then
test -f $filename.org || cp $filename $filename.org
rm -f $filename

cat << EOF > $filename
[DEFAULT]
compute_driver=libvirt.LibvirtDriver
[libvirt]
virt_type=qemu
EOF
fi
chown nova:nova $filename

service nova-compute restart

exit 0