#!/bin/bash
source aio-config.cfg

##find ./*.sh -exec sed -i 's/project_domain_id = default/project_domain_name = default/g' {} \;
##find ./*.sh -exec sed -i 's/user_domain_id = default/user_domain_name = default/g' {} \;

if [ "$REMOVE_PACKAGE" == "1" ]; then

echo "########## Remove OPENSTACK PACKAGES(liberty) ##########"

apt-get -y --purge remove --auto-remove \
chrony rabbitmq-server mysql* mariadb-server python-pymysql keystone \
python-openstackclient apache2 libapache2-mod-wsgi memcached python-memcache \
glance nova-api nova-cert nova-conductor nova-consoleauth nova-novncproxy \
nova-scheduler nova-compute ceilometer-agent-compute cinder-api cinder-scheduler \
lvm2 cinder-volume neutron-server neutron-plugin-ml2 neutron-openvswitch-agent \
neutron-l3-agent neutron-dhcp-agent neutron-metadata-agent neutron-sriov-agent \
heat-api heat-api-cfn heat-engine mongodb-server mongodb-clients python-pymongo \
ceilometer-api ceilometer-collector ceilometer-agent-central \
ceilometer-agent-notification python-ceilometerclient aodh-api aodh-evaluator \
aodh-notifier aodh-listener aodh-expirer python-ceilometerclient \
openstack-dashboard

##dpkg --purge --ignore-depends=libnl-3-200 libnl-3-200
##dpkg --purge --ignore-depends=libnl-genl-3-200 libnl-genl-3-200
##dpkg --purge --ignore-depends=libnl-route-3-200 libnl-route-3-200

fi

filename=/etc/hosts
test -f $filename.org || cp $filename $filename.org
rm -f $filename

echo "########## SET HOSTNAME ##########"

hostname $HOSTNAME
echo "$HOSTNAME" > /etc/hostname

cat << EOF > $filename
127.0.0.1 localhost
$MGMT_IP $HOSTNAME
EOF


filename=/etc/sysctl.conf
test -f $filename.org || cp $filename $filename.org
rm -f $filename

# Enable IP forwarding
cat << EOF > $filename
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
EOF

sysctl -p

echo "########## INSTALL NTP ##########"
apt-get -y install chrony

filename=/etc/chrony/chrony.conf
test -f $filename.org || cp $filename $filename.org
rm -f $filename

cat << EOF > $filename
server controller iburst
keyfile /etc/chrony/chrony.keys
commandkey 1
driftfile /var/lib/chrony/chrony.drift
log tracking measurements statistics
logdir /var/log/chrony
maxupdateskew 100.0
dumponexit
dumpdir /var/lib/chrony
local stratum 10
allow 10/8
allow 192.168/16
allow 172.16/12
logchange 0.5
rtconutc
EOF

service chrony restart

echo "########## SET RABBITMQ ##########"
apt-get -y --purge remove rabbitmq-server
apt-get -y install rabbitmq-server

rabbitmqctl delete_user openstack
rabbitmqctl add_user openstack $DEFAULT_PASS
rabbitmqctl set_permissions openstack ".*" ".*" ".*"

service rabbitmq-server restart

exit 0