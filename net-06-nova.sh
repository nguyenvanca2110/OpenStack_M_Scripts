#!/bin/bash
source net-config.cfg
source ~/admin-openrc.sh

echo "########## INSTALL NOVA ################"
apt-get -y install nova-api nova-cert nova-conductor nova-consoleauth \
nova-novncproxy nova-scheduler

filename=/etc/nova/nova.conf
test -f $filename.org || cp $filename $filename.org
rm -f $filename

cat << EOF > $filename
[DEFAULT]
debug = false

rpc_backend = rabbit

dhcpbridge_flagfile = /etc/nova/nova.conf
state_path = /var/lib/nova
instances_path = \$state_path/instances
force_dhcp_release = True
enabled_apis = osapi_compute, metadata
rootwrap_config = /etc/nova/rootwrap.conf
api_paste_config = /etc/nova/api-paste.ini

my_ip = $MGMT_IP

linuxnet_interface_driver = openvswitch
firewall_driver = nova.virt.firewall.NoopFirewallDriver

resume_guests_state_on_host_boot = True
allow_resize_to_same_host = True

use_neutron = True

novncproxy_host = 0.0.0.0
novncproxy_port = 8080

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
vncserver_listen = \$my_ip
vncserver_proxyclient_address = \$my_ip

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
EOF

chown nova:nova $filename

rm -f /var/lib/nova/nova.sqlite

echo "##### DB SYNC #####"
nova-manage api_db sync
nova-manage db sync

service nova-api restart
service nova-cert restart
service nova-consoleauth restart
service nova-scheduler restart
service nova-conductor restart
service nova-novncproxy restart

openstack compute service list

exit 0

/usr/bin/python /usr/bin/nova-compute --config-file=/etc/nova/nova.conf --config-file=/etc/nova/nova.conf --config-file=/etc/nova/nova-compute.conf