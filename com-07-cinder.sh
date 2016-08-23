#!/bin/bash
source com-config.cfg

## ceilometer
if [ "$IS_TELEMETRY" -eq 1 ]; then
NOTI_TELEMETRY="[oslo_messaging_notifications]
driver = messagingv2"
fi

echo "########## INSTALL CINDER ##########"
apt-get -y install lvm2 cinder-volume

is_disk=$(fdisk -l /dev/$CINDER_VOLUME | egrep -c '(Disk)')
if [ "$is_disk" -gt 0 ]; then

echo "########## VOLUME CREATE FOR CINDER ##########"
vgremove cinder-volumes
pvremove /dev/$CINDER_VOLUME

pvcreate /dev/$CINDER_VOLUME
vgcreate cinder-volumes /dev/$CINDER_VOLUME

sed_str="s#(filter = )(\[ \\\"a/\.\*/\\\" \])#\1[\\\"a\/$CINDER_VOLUME\/\\\", \\\"r/\.\*\/\\\"]#g"
#echo $sed_str
sed -r -i "$sed_str" /etc/lvm/lvm.conf

fi


filename=/etc/cinder/cinder.conf
test -f $filename.org || cp $filename $filename.org
rm -f $filename

cat << EOF > $filename
[DEFAULT]
debug = false

rootwrap_config = /etc/cinder/rootwrap.conf
api_paste_confg = /etc/cinder/api-paste.ini

rpc_backend = rabbit
auth_strategy = keystone
my_ip = $MGMT_IP
enabled_backends = lvm

##os_region_name = RegionOne
##os_privileged_user_tenant = service
##os_privileged_user_password = $DEFAULT_PASS
##os_privileged_user_name = nova

glance_api_servers = http://controller:9292

[database]
connection = mysql+pymysql://cinder:$DEFAULT_PASS@controller/cinder
 
[keystone_authtoken]
auth_uri = http://controller:5000
auth_url = http://controller:35357
memcached_servers = controller:11211
auth_type = password
project_domain_name = default
user_domain_name = default
project_name = service
username = cinder
password = $DEFAULT_PASS

[oslo_messaging_rabbit]
rabbit_host = controller
rabbit_userid = openstack
rabbit_password = $DEFAULT_PASS

[oslo_concurrency]
lock_path = /var/lib/cinder/tmp

[lvm]
volume_driver = cinder.volume.drivers.lvm.LVMVolumeDriver
volume_name_template = volume-%s
volumes_dir = /var/lib/cinder/volumes
volume_group = cinder-volumes
iscsi_protocol = iscsi
iscsi_helper = tgtadm

## ceilometer
$NOTI_TELEMETRY
EOF

chown cinder:cinder $filename

rm -f /var/lib/cinder/cinder.sqlite

service tgt restart
service cinder-volume restart

if [ "$IS_MLNX" -gt 0 ]; then
service tgt stop
update-rc.d -f tgt remove
fi

exit 0