#!/bin/bash
source aio-config.cfg
source ~/admin-openrc.sh

if [ "$IS_OVN" -eq 0 ]; then
exit 0
fi

echo "########## INSTALL NETWORKING-OVN ##########"

#########################################################
## install package
## apt-get -y install ovn-central ovn-host ovn-docker ovn-common

rm -rf /usr/local/lib/python2.7/dist-packages/neutron*

## install networking-ovnc
apt-get -y install git python-dev python-pip python-tox

mkdir -p /opt/stack
cd /opt/stack
rm -rf networking-ovn

git clone http://git.openstack.org/openstack/networking-ovn.git
cd networking-ovn
##pip install -r requirements.txt
##pip install -r test-requirements.txt
##tox -egenconfig
##sed -i "s/neutron#egg=neutron/neutron@stable\/mitaka#egg=neutron/g" ./tools/tox_install.sh
./tools/tox_install.sh .

mkdir -p /etc/neutron/plugins/networking-ovn

cd src/neutron
##./tools/generate_config_file_samples.sh

cp etc/api-paste.ini /etc/neutron
cp etc/rootwrap.conf /etc/neutron
cp etc/policy.json /etc/neutron
cp -r etc/neutron/rootwrap.d /etc/neutron

#########################################################
## config setting
filename=/etc/neutron/neutron.conf
test -f $filename.org || cp $filename $filename.org
rm -f $filename

cat << EOF > $filename
[DEFAULT]
debug = False

rpc_backend = rabbit
auth_strategy = keystone

state_path = /var/lib/neutron
core_plugin = networking_ovn.plugin.OVNPlugin
service_plugins = qos
allow_overlapping_ips = True

notify_nova_on_port_status_changes = True
notify_nova_on_port_data_changes = True

[agent]
root_helper_daemon = sudo /usr/local/bin/neutron-rootwrap-daemon /etc/neutron/rootwrap.conf
root_helper = sudo /usr/local/bin/neutron-rootwrap /etc/neutron/rootwrap.conf

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
memcached_servers = controller:11211
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

[oslo_policy]
policy_file = /etc/neutron/policy.json
EOF


filename=/etc/neutron/plugins/networking-ovn/networking-ovn.ini
test -f $filename.org || cp $filename $filename.org
rm -f $filename

cat << EOF > $filename
[DEFAULT]

[ovn]
ovn_l3_mode = True
ovsdb_connection = tcp:$MGMT_IP:6640
EOF


echo "dhcp-option-force=26,1442" > /etc/neutron/dnsmasq-neutron.conf

echo "log-facility = /var/log/neutron/dnsmasq.log" >> /etc/neutron/dnsmasq-neutron.conf
echo "log-dhcp" >> /etc/neutron/dnsmasq-neutron.conf
killall dnsmasq | awk '{print $1}' 1>&2

filename=/etc/neutron/dhcp_agent.ini
test -f $filename.org || cp $filename $filename.org
rm -f $filename

cat << EOF > $filename
[DEFAULT]
debug = True
verbose = True
interface_driver = openvswitch
##dhcp_driver = neutron.agent.linux.dhcp.Dnsmasq
dnsmasq_config_file = /etc/neutron/dnsmasq-neutron.conf
dhcp_agent_manager = neutron.agent.dhcp_agent.DhcpAgentWithStateReport
##ovs_use_veth = False
enable_metadata_network = False
enable_isolated_metadata = True

[AGENT]
root_helper_daemon = sudo /usr/local/bin/neutron-rootwrap-daemon /etc/neutron/rootwrap.conf
root_helper = sudo /usr/local/bin/neutron-rootwrap /etc/neutron/rootwrap.conf
EOF


filename=/etc/neutron/metadata_agent.ini
test -f $filename.org || cp $filename $filename.org
rm -f $filename

cat << EOF > $filename
[DEFAULT]
nova_metadata_ip = $MGMT_IP
metadata_proxy_shared_secret = $DEFAULT_PASS

[AGENT]
root_helper_daemon = sudo /usr/local/bin/neutron-rootwrap-daemon /etc/neutron/rootwrap.conf
root_helper = sudo /usr/local/bin/neutron-rootwrap /etc/neutron/rootwrap.conf
EOF

#########################################################
## networking-ovn config
## refer : http://docs.openstack.org/developer/networking-ovn/install.html
ovs-appctl -t ovsdb-server ovsdb-server/add-remote ptcp:6640:$MGMT_IP
ovs-vsctl set open . external-ids:ovn-remote=tcp:$MGMT_IP:6640
ovs-vsctl set open . external-ids:ovn-encap-type=geneve
##ovs-vsctl set open . external-ids:ovn-encap-type=geneve,vxlan
ovs-vsctl set open . external-ids:ovn-encap-ip=$LOCAL_IP

######### set interface for bridge ######### 
br_mapping_list=($BR_MAPPING_LIST)
bridge_mappings=
for x in "${br_mapping_list[@]}"
do
	if [ "$bridge_mappings" == "" ]; then
        bridge_mappings="ext_$x:$x"
	else
        bridge_mappings="$bridge_mappings,ext_$x:$x"
	fi
done
echo $bridge_mappings

##ovs-vsctl remove open . external-ids ovn-bridge-mappings
ovs-vsctl set open . external-ids:ovn-bridge-mappings=$bridge_mappings

##/usr/share/openvswitch/scripts/ovs-ctl restart
##/usr/share/openvswitch/scripts/ovn-ctl restart_northd
##/usr/share/openvswitch/scripts/ovn-ctl restart_controller

#ovs-appctl -t ovsdb-server ovsdb-server/add-db /etc/openvswitch/ovnnb_db.db
#ovs-appctl -t ovsdb-server ovsdb-server/add-db /etc/openvswitch/ovnsb_db.db

#########################################################
## init db
/bin/sh -c "neutron-db-manage --config-file /etc/neutron/neutron.conf \
--config-file /etc/neutron/plugins/networking-ovn/networking-ovn.ini \
upgrade head" neutron

neutron-ovn-db-sync-util --config-file /etc/neutron/neutron.conf \
--config-file /etc/neutron/plugins/networking-ovn/networking-ovn.ini

##neutron-ovn-db-sync-util --ovn-neutron_sync_mode=repair


#########################################################
## user setting (/etc/passwd)
word_count=`grep -c "neutron" /etc/passwd`
if [ "$word_count" -eq 0 ]; then

u_id=`tail -n 1 /etc/passwd | awk -F: '{ print $3 }'`
g_id=`tail -n 1 /etc/passwd | awk -F: '{ print $4 }'`
s_id=`grep -r "rabbitmq" /etc/shadow | awk -F: '{ print $3 }'`
echo "neutron:x:$(($u_id+1)):$(($g_id+1))::/var/lib/neutron:/bin/false" >> /etc/passwd
echo "neutron:x:$(($g_id+1)):" >> /etc/group
echo "horizon:*:$(($s_id+1)):0:99999:7:::" >> /etc/shadow

fi

#########################################################
## create init script (neutron-server)
## /usr/local/bin/neutron-server --config-file=/etc/neutron/neutron.conf
filename=/etc/init/neutron-server.conf
test -f $filename.org || cp $filename $filename.org
rm -f $filename

cat << EOF > $filename
# vim:set ft=upstart ts=2 et:
description "Neutron API Server"
author "Chuck Short <zulcss@ubuntu.com>"

start on runlevel [2345]
stop on runlevel [!2345]

respawn

chdir /var/run

pre-start script
    for i in lock run log lib ; do
        mkdir -p /var/\$i/neutron
        chown neutron:neutron /var/\$i/neutron
    done
end script

exec start-stop-daemon --start --chuid root --exec /usr/local/bin/neutron-server \
-- --config-file=/etc/neutron/neutron.conf \
--config-file=/etc/neutron/plugins/networking-ovn/networking-ovn.ini \
--log-file=/var/log/neutron/neutron-server.log
EOF

ln -sf /lib/init/upstart-job /etc/init.d/neutron-server
update-rc.d -f neutron-server remove
update-rc.d neutron-server defaults


#########################################################
## create init script (neutron-dhcp-agent)
filename=/etc/init/neutron-dhcp-agent.conf
test -f $filename.org || cp $filename $filename.org
rm -f $filename

cat << EOF > $filename
description "Neutron DHCP Agent"
author "Chuck Short <zulcss@ubuntu.com>"

start on runlevel [2345]
stop on runlevel [!2345]

respawn

chdir /var/run

pre-start script
    for i in lock run log lib ; do
        mkdir -p /var/\$i/neutron
        chown neutron:neutron /var/\$i/neutron
    done
    if status neutron-ovs-cleanup; then
        start wait-for-state WAIT_FOR=neutron-ovs-cleanup WAIT_STATE=running WAITER=neutron-dhcp-agent
    fi
end script

exec start-stop-daemon --start --chuid root --exec /usr/local/bin/neutron-dhcp-agent \
-- --config-file=/etc/neutron/neutron.conf --config-file=/etc/neutron/dhcp_agent.ini \
--log-file=/var/log/neutron/dhcp-agent.log
EOF

ln -sf /lib/init/upstart-job /etc/init.d/neutron-dhcp-agent
update-rc.d -f neutron-dhcp-agent remove
update-rc.d neutron-dhcp-agent defaults


#########################################################
## create init script (neutron-metadata-agent)
filename=/etc/init/neutron-metadata-agent.conf
test -f $filename.org || cp $filename $filename.org
rm -f $filename

cat << EOF > $filename
description "OpenStack Neutron Metadata Agent"
author "Thomas Goirand <zigo@debian.org>"

start on runlevel [2345]
stop on runlevel [!2345]

respawn

chdir /var/run

pre-start script
    for i in lock run log lib ; do
        mkdir -p /var/\$i/neutron
        chown neutron:neutron /var/\$i/neutron
    done
end script

exec start-stop-daemon --start --chuid root --exec /usr/local/bin/neutron-metadata-agent -- \
--config-file=/etc/neutron/neutron.conf --config-file=/etc/neutron/metadata_agent.ini \
--log-file=/var/log/neutron/neutron-metadata-agent.log
EOF

ln -sf /lib/init/upstart-job /etc/init.d/neutron-metadata-agent
update-rc.d -f neutron-metadata-agent remove
update-rc.d neutron-metadata-agent defaults


chown neutron:neutron -R /etc/neutron
chown root:root -R /etc/neutron/rootwrap.d

#########################################################
## service restart
service nova-api restart
service nova-compute restart
service neutron-server restart
service neutron-dhcp-agent restart
service neutron-metadata-agent restart

ovn-sbctl show

exit 0