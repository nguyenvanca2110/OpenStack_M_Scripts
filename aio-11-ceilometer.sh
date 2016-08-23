#!/bin/bash
source aio-config.cfg
source ~/admin-openrc.sh

## ceilometer
if [ "$IS_TELEMETRY" -eq 0 ]; then
exit 0
fi


# Install and configure MongoDB

apt-get -y remove --purge mongodb-*
apt-get install -y mongodb-server mongodb-clients python-pymongo

filename=/etc/mongodb.conf
test -f $filename.org || cp $filename $filename.org

sed -i "s/bind\_ip\ =\ 127\.0\.0\.1/bind_ip = $MGMT_IP/g" /etc/mongodb.conf
sed -i '2 i\smallfiles\ =\ true' /etc/mongodb.conf

service mongodb stop
rm -f /var/lib/mongodb/journal/prealloc.*
sleep 2

service mongodb start

# MongDB Connection
# mongo --host [ipaddress] ex)10.0.0.166
sleep 3

mongo --host controller --eval "
  db = db.getSiblingDB(\"ceilometer\");
  db.addUser({user: \"ceilometer\",
  pwd: \"$DEFAULT_PASS\",
  roles: [ \"readWrite\", \"dbAdmin\" ]})"

# Install and configure Ceilometer Components

apt-get install -y ceilometer-api ceilometer-collector \
  ceilometer-agent-central ceilometer-agent-notification \
  python-ceilometerclient

cp event_*.yaml /etc/ceilometer/
chown ceilometer:ceilometer /etc/ceilometer/event_*.yaml

filename=/etc/ceilometer/ceilometer.conf
test -f $filename.org || cp $filename $filename.org

cat << EOF > $filename
[DEFAULT]
logging_exception_prefix = %(color)s%(asctime)s.%(msecs)03d TRACE %(name)s [01;35m%(instance)s[00m
logging_debug_format_suffix = [00;33mfrom (pid=%(process)d) %(funcName)s %(pathname)s:%(lineno)d[00m
logging_default_format_string = %(asctime)s.%(msecs)03d %(color)s%(levelname)s %(name)s [[00;36m-%(color)s] [01;35m%(instance)s%(color)s%(message)s[00m
logging_context_format_string = %(asctime)s.%(msecs)03d %(color)s%(levelname)s %(name)s [[01;36m%(request_id)s [00;36m%(user_name)s %(project_name)s%(color)s] [01;35m%(instance)s%(color)s%(message)s[00m
debug = true

rpc_backend = rabbit
auth_strategy = keystone

[database]
connection = mongodb://ceilometer:$DEFAULT_PASS@controller:27017/ceilometer
##metering_connection = mongodb://ceilometer:$DEFAULT_PASS@controller:27017/ceilometer
##event_connection = mongodb://ceilometer:$DEFAULT_PASS@controller:27017/ceilometer

[keystone_authtoken]
auth_uri = http://controller:5000
auth_url = http://controller:35357
memcached_servers = controller:11211
auth_type = password
project_domain_name = default
user_domain_name = default
project_name = service
username = ceilometer
password = $DEFAULT_PASS

[oslo_messaging_rabbit]
rabbit_host = controller
rabbit_userid = openstack
rabbit_password = $DEFAULT_PASS

[service_credentials]
os_auth_url = http://controller:5000/v2.0
os_username = ceilometer
os_tenant_name = service
os_password = $DEFAULT_PASS
interface = internalURL
region_name = RegionOne
##os_endpoint_type = internalURL
##os_region_name = RegionOne

[notification]
store_events = True

##[oslo_messaging_notifications]
##driver = messagingv2
##topics = notifications
EOF
chown ceilometer:ceilometer $filename

##### Restart the Telemetry services ####

service ceilometer-agent-central restart
service ceilometer-agent-notification restart
service ceilometer-api restart
service ceilometer-collector restart

exit 0

source ~/admin-openrc.sh

IMAGE_ID=$(glance image-list | grep 'cirros' | awk '{ print $2 }')
glance image-download $IMAGE_ID > /tmp/cirros.img

ceilometer meter-list
ceilometer statistics -m image.download -p 60
rm -f /tmp/cirros.img
