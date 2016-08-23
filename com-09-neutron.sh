#!/bin/bash
source com-config.cfg

if [ "$IS_OVN" -gt 0 ]; then
exit 0
fi

echo "########## INSTALL NEUTRON ##########"

CORE_PLUGIN="ml2"
MECHANISM_DRIVERS="openvswitch"

if [ "$IS_MLNX" -gt 0 ]; then

#CORE_PLUGIN="neutron.plugins.ml2.plugin.Ml2Plugin"
MECHANISM_DRIVERS="sriovnicswitch,openvswitch"

apt-get -y install neutron-sriov-agent

## sr-iov bug fix:
## https://www.mirantis.com/blog/carrier-grade-mirantis-openstack-the-mirantis-nfv-initiative-part-1-single-root-io-virtualization-sr-iov/
wget -c https://launchpad.net/ubuntu/+archive/primary/+files/libnl-3-200_3.2.24-2_amd64.deb
wget -c https://launchpad.net/ubuntu/+archive/primary/+files/libnl-genl-3-200_3.2.24-2_amd64.deb
wget -c https://launchpad.net/ubuntu/+archive/primary/+files/libnl-route-3-200_3.2.24-2_amd64.deb

dpkg -i --force-overwrite libnl-3-200_3.2.24-2_amd64.deb
dpkg -i --force-overwrite libnl-genl-3-200_3.2.24-2_amd64.deb
dpkg -i --force-overwrite libnl-route-3-200_3.2.24-2_amd64.deb

service libvirt-bin restart

ML2_SRIOV="[ml2_sriov]
supported_pci_vendor_devs = $PCI_VENDOR_DEVS"

fi

apt-get -y install neutron-openvswitch-agent

filename=/etc/neutron/neutron.conf
test -f $filename.org || cp $filename $filename.org
rm -f $filename

cat << EOF > $filename
[DEFAULT]
debug = false

rpc_backend = rabbit
auth_strategy = keystone

state_path = /var/lib/neutron
core_plugin = $CORE_PLUGIN
service_plugins = router
allow_overlapping_ips = True

[agent]
##root_helper_daemon = sudo /usr/bin/neutron-rootwrap-daemon /etc/neutron/rootwrap.conf
root_helper = sudo /usr/bin/neutron-rootwrap /etc/neutron/rootwrap.conf

[database]
connection = mysql+pymysql://neutron:$DEFAULT_PASS@controller/neutron

[keystone_authtoken]
auth_uri = http://controller:5000
auth_url = http://controller:35357
memcached_servers = controller:11211
auth_type = password
project_domain_name = default
user_domain_name = default
project_name = service
username = neutron
password = $DEFAULT_PASS

[nova]
auth_url = http://controller:35357
auth_type = password
project_domain_name = default
user_domain_name = default
region_name = RegionOne
project_name = service
username = nova
password = $DEFAULT_PASS

[oslo_concurrency]
lock_path = \$state_path/lock

[oslo_messaging_rabbit]
rabbit_host = controller
rabbit_userid = openstack
rabbit_password = $DEFAULT_PASS
EOF
chown neutron:neutron $filename

######### set interface for bridge ######### 
br_list=($BR_LIST)
vlan_br_list=($VLAN_BR_LIST)
br_mapping_list=($BR_MAPPING_LIST)

flat_networks=
network_vlan_ranges=
bridge_mappings=
ranges=$VLAN_START

for x in "${br_list[@]}"
do
	if [ "$flat_networks" == "" ]; then
		flat_networks="ext_$x"
	else
		flat_networks="$flat_networks,ext_$x"
	fi
done

for x in "${vlan_br_list[@]}"
do
	if [ "$network_vlan_ranges" == "" ]; then
		network_vlan_ranges="ext_$x:$ranges:$(($ranges+99))"
	else
		network_vlan_ranges="$network_vlan_ranges,ext_$x:$ranges:$(($ranges+99))"
	fi
	ranges=$(($ranges+99+1))
done

for x in "${br_mapping_list[@]}"
do
	if [ "$bridge_mappings" == "" ]; then
		bridge_mappings="ext_$x:$x"
	else
		bridge_mappings="$bridge_mappings,ext_$x:$x"
	fi
done
######### set interface for bridge ######### 

filename=/etc/neutron/plugins/ml2/openvswitch_agent.ini
test -f $filename.org || cp $filename $filename.org
rm -f $filename

cat << EOF > $filename
[DEFAULT]

[agent]
tunnel_types = gre,vxlan

[ovs]
local_ip = $LOCAL_IP
bridge_mappings = $bridge_mappings

[securitygroup]
#enable_security_group = True
#firewall_driver=neutron.agent.firewall.NoopFirewallDriver
#firewall_driver = neutron.agent.linux.iptables_firewall.OVSHybridIptablesFirewallDriver
EOF
chown neutron:neutron $filename

if [ "$IS_MLNX" -gt 0 ]; then
## Edit the following file: sriov_agent.ini
filename=/etc/neutron/plugins/ml2/sriov_agent.ini
test -f $filename.org || cp $filename $filename.org
rm $filename

cat << EOF > $filename
[DEFAULT]

[sriov_nic]
physical_device_mappings = $PHYSICAL_NETWORK:$DEVNAME

[securitygroup]
enable_security_group = False
firewall_driver = neutron.agent.firewall.NoopFirewallDriver
EOF

service neutron-sriov-agent restart
fi

service nova-compute restart
service neutron-openvswitch-agent restart

exit 0