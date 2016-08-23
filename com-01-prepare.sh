#!/bin/bash
source com-config.cfg

##find ./*.sh -exec sed -i 's/project_domain_id = default/project_domain_name = default/g' {} \;
##find ./*.sh -exec sed -i 's/user_domain_id = default/user_domain_name = default/g' {} \;

if [ "$REMOVE_PACKAGE" == "1" ]; then

echo "########## Remove OPENSTACK PACKAGES(liberty) ##########"

apt-get -y remove chrony rabbitmq-server \
keystone python-openstackclient apache2 libapache2-mod-wsgi \
memcached python-memcache glance nova-api nova-cert nova-conductor \
nova-consoleauth nova-novncproxy nova-scheduler nova-compute ceilometer-agent-compute \
cinder-api lvm2 cinder-volume neutron-server neutron-plugin-ml2 neutron-plugin-openvswitch-agent \
neutron-l3-agent neutron-dhcp-agent neutron-metadata-agent openstack-dashboard \
heat-api heat-api-cfn heat-engine python-pip git mongodb-server mongodb-clients python-pymongo \
aodh-api aodh-evaluator aodh-notifier aodh-listener aodh-expirer python-ceilometerclient --purge 

apt-get -y remove mysql* --purge

apt-get -y autoremove --purge

fi

filename=/etc/hosts
test -f $filename.org || cp $filename $filename.org
rm -f $filename

echo "########## SET HOSTNAME ##########"

hostname $COM_NAME
echo "$COM_NAME" > /etc/hostname

cat << EOF > $filename
127.0.0.1 localhost
$CON_IP $CON_NAME

$COM_IP $COM_NAME
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

exit 0