#!/bin/bash
source aio-config.cfg
source ~/admin-openrc.sh

if [ "$IS_OVN" -gt 0 ]; then
exit 0
fi

echo "########## INSTALL NEUTRON ##########"
apt-get -y install neutron-server neutron-plugin-ml2 neutron-openvswitch-agent \
neutron-l3-agent neutron-dhcp-agent neutron-metadata-agent

CORE_PLUGIN="ml2"
MECHANISM_DRIVERS="openvswitch,l2population"
DHCP_DRIVER="neutron.agent.linux.dhcp.Dnsmasq"
ESWITCH=""

if [ "$IS_MLNX" -gt 0 ]; then

CORE_PLUGIN="neutron.plugins.ml2.plugin.Ml2Plugin"
MECHANISM_DRIVERS="mlnx,openvswitch,l2population"
##DHCP_DRIVER="mlnx_dhcp.MlnxDnsmasq"
ESWITCH="[eswitch]
vnic_type = hostdev"

# /etc/init/neutron-mlnx-agent.conf
# /etc/init/networking-mlnx-eswitchd.conf
apt-get -y install python-zmq python-ethtool neutron-mlnx-agent networking-mlnx-eswitchd python-networking-mlnx

fi

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

notify_nova_on_port_status_changes = True
notify_nova_on_port_data_changes = True

max_fixed_ips_per_port = 30

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
chown root:neutron $filename


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

filename=/etc/neutron/plugins/ml2/ml2_conf.ini
test -f $filename.org || cp $filename $filename.org
rm -f $filename

cat << EOF > $filename
[ml2]
extension_drivers = port_security
type_drivers = local,flat,vlan,gre,vxlan
tenant_network_types = flat,vxlan,gre,vlan
mechanism_drivers = $MECHANISM_DRIVERS

[ml2_type_flat]
flat_networks = $flat_networks

[ml2_type_vlan]
network_vlan_ranges = $network_vlan_ranges

[ml2_type_gre]
tunnel_id_ranges = 1:1000

[ml2_type_vxlan]
vni_ranges = 10:10000


[securitygroup]
enable_security_group = True
enable_ipset = True
#firewall_driver=neutron.agent.firewall.NoopFirewallDriver
firewall_driver = neutron.agent.linux.iptables_firewall.OVSHybridIptablesFirewallDriver

$ESWITCH
EOF
chown root:neutron $filename

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
EOF
chown root:neutron $filename

echo "dhcp-option-force=26,1500" > /etc/neutron/dnsmasq-neutron.conf
killall dnsmasq | awk '{print $1}' 1>&2
chown root:neutron /etc/neutron/dnsmasq-neutron.conf

filename=/etc/neutron/metadata_agent.ini
test -f $filename.org || cp $filename $filename.org
rm -f $filename

cat << EOF > $filename
[DEFAULT]
nova_metadata_ip = controller
metadata_proxy_shared_secret = $DEFAULT_PASS
EOF
chown root:neutron $filename

filename=/etc/neutron/dhcp_agent.ini
test -f $filename.org || cp $filename $filename.org
rm -f $filename

cat << EOF > $filename
[DEFAULT]
interface_driver = openvswitch
dhcp_driver = $DHCP_DRIVER
dnsmasq_config_file = /etc/neutron/dnsmasq-neutron.conf
EOF
chown root:neutron $filename

filename=/etc/neutron/l3_agent.ini
test -f $filename.org || cp $filename $filename.org
rm -f $filename

cat << EOF > $filename
[DEFAULT]
interface_driver = openvswitch
gateway_external_network_id =
EOF
chown root:neutron $filename

if [ "$IS_MLNX" -gt 0 ]; then

filename=/etc/neutron/plugins/ml2/eswitchd.conf
test -f $filename.org || cp $filename $filename.org
rm $filename

cat << EOF >> $filename
[DEFAULT]
#verbose = True
#debug = True

[DAEMON]
fabrics=$FABRICS
EOF

## Edit the following file: mlnx_conf.ini
filename=/etc/neutron/plugins/mlnx/mlnx_conf.ini
test -f $filename.org || cp $filename $filename.org
rm $filename

cat << EOF > $filename
[eswitch]
physical_interface_mappings = $FABRICS

[agent]
EOF

fi


echo "##### DB SYNC #####"
su -s /bin/sh -c "neutron-db-manage --config-file /etc/neutron/neutron.conf \
  --config-file /etc/neutron/plugins/ml2/ml2_conf.ini upgrade head" neutron

service nova-api restart
service nova-compute restart

service neutron-server restart
service neutron-l3-agent restart
service neutron-dhcp-agent restart
service neutron-metadata-agent restart
service neutron-openvswitch-agent restart

if [ "$IS_MLNX" -gt 0 ]; then
service networking-mlnx-eswitchd restart
service neutron-mlnx-agent restart
fi

exit 0




########################################################
###################### old method ######################
########################################################
if [ "$IS_MLNX" -gt 0 ]; then

CORE_PLUGIN="neutron.plugins.ml2.plugin.Ml2Plugin"
MECHANISM_DRIVERS="mlnx,openvswitch"
INTERFACE_DRIVER=neutron.agent.linux.interface.OVSInterfaceDriver
ESWITCH="[eswitch]
vnic_type = hostdev"

echo "deb [arch=amd64] http://www.mellanox.com/repository/solutions/openstack/liberty/ubuntu/14.04 openstack-mellanox main" > /etc/apt/sources.list.d/mellanox-openstack-repository.list

apt-get update
##apt-get install -y python-networking-mlnx
apt-get install -y --force-yes eswitchd
apt-get install networking-mlnx-common


apt-get install python-dev python-pip python-ethtool

cd ~/
rm -rf networking-mlnx
git clone $MLNX_VERSION https://github.com/openstack/networking-mlnx.git

cd networking-mlnx

pip install -r requirements.txt
python setup.py install --record uninstall.txt
##pip install networking_mlnx

## remove 
## cat uninstall.txt | xargs rm -rf

cd ~/

###########################################################
#### user setting (/etc/passwd)
##word_count=`grep -c "eswitch" /etc/passwd`
##if [ "$word_count" -eq 0 ]; then
##u_id=`tail -n 1 /etc/passwd | awk -F: '{ print $3 }'`
##g_id=`tail -n 1 /etc/passwd | awk -F: '{ print $4 }'`
##s_id=`grep -r "rabbitmq" /etc/shadow | awk -F: '{ print $3 }'`
##echo "eswitch:x:$(($u_id+1)):$(($g_id+1))::/var/lib/eswitch:/bin/false" >> /etc/passwd
##echo "eswitch:x:$(($g_id+1)):" >> /etc/group
##echo "eswitch:*:$(($s_id+1)):0:99999:7:::" >> /etc/shadow
##fi

###########################################################
#### create default (eswitchd)
##echo "OPENSTACK=yes" > /etc/default/eswitchd

#########################################################
## create init script (eswitchd)
filename=/etc/init/eswitchd.conf
test -f $filename.org || cp $filename $filename.org
rm -f $filename

cat << EOF > $filename
#!/bin/bash
description "Mellanox Eswitchd"
author "Mellanox Openstack <openstack@mellanox.com>"

start on (started openibd and started libvirt-bin)
stop on runlevel [016]

chdir /var/run

pre-start script
        for i in run log ; do
         mkdir -p /var/\$i/eswitchd
         chown eswitch:root /var/\$i/eswitchd
        done
end script

script
        ESWITCHD_CONF=/etc/eswitchd/eswitchd.conf
        . /etc/default/eswitchd
        exec start-stop-daemon --start --exec /usr/local/bin/eswitchd -- --config-file \$ESWITCHD_CONF
        #exec start-stop-daemon --start --chuid eswitch --exec /usr/local/bin/eswitchd -- --config-file \$ESWITCHD_CONF
end script

post-start script
       if [ -x /etc/init.d/neutron-plugin-mlnx-agent ] ; then
        exec /etc/init.d/neutron-plugin-mlnx-agent restart
       fi
       if [ -x /etc/init.d/nova-compute ] ;then
        exec /etc/init.d/nova-compute restart
       fi
end script
EOF

cp /usr/local/etc/neutron/rootwrap.d/eswitchd.filters /etc/neutron/rootwrap.d
cp /usr/local/etc/neutron/eswitchd-rootwrap.conf /etc/neutron

##chown eswitch:eswitch /etc/neutron/rootwrap.d/eswitchd.filters
##chown eswitch:eswitch /etc/neutron/eswitchd-rootwrap.conf

ln -sf /lib/init/upstart-job /etc/init.d/eswitchd
update-rc.d -f eswitchd remove
update-rc.d eswitchd defaults


#########################################################
## create init script (neutron-mlnx-agent)
filename=/etc/init/neutron-mlnx-agent.conf
test -f $filename.org || cp $filename $filename.org
rm -f $filename

cat << EOF > $filename
description "OpenStack Neutron Mellanox Plugin Agent"
author "Thomas Goirand <zigo@debian.org>"

start on runlevel [2345]
stop on runlevel [!2345]

chdir /var/run

respawn
limit nofile 65535 65535

pre-start script
        for i in lock run log lib ; do
         mkdir -p /var/\$i/neutron
         chown neutron:root /var/\$i/neutron
        done
end script

script
        [ -x "/usr/local/bin/neutron-mlnx-agent" ] || exit 0
        DAEMON_ARGS="--config-file=/etc/neutron/plugins/mlnx/mlnx_conf.ini"
        [ -r /etc/default/openstack ] && . /etc/default/openstack
        [ -r /etc/default/\$UPSTART_JOB ] && . /etc/default/\$UPSTART_JOB
        [ "x\$USE_SYSLOG" = "xyes" ] && DAEMON_ARGS="\$DAEMON_ARGS --use-syslog"
        [ "x\$USE_LOGFILE" != "xno" ] && DAEMON_ARGS="\$DAEMON_ARGS --log-file=/var/log/neutron/neutron-mlnx-agent.log"

        exec start-stop-daemon --start --chdir /var/lib/neutron \
                --chuid neutron:neutron --make-pidfile --pidfile /var/run/neutron/neutron-mlnx-agent.pid \
                --exec /usr/local/bin/neutron-mlnx-agent -- --config-file=/etc/neutron/neutron.conf \${DAEMON_ARGS}
end script
EOF

ln -sf /lib/init/upstart-job /etc/init.d/neutron-mlnx-agent
update-rc.d -f neutron-mlnx-agent remove
update-rc.d neutron-mlnx-agent defaults

fi


wget http://www.mellanox.com/downloads/ofed/MLNX_OFED-3.2-2.0.0.0/MLNX_OFED_LINUX-3.2-2.0.0.0-ubuntu14.04-x86_64.tgz



apt-get install python-zmq python-ethtool