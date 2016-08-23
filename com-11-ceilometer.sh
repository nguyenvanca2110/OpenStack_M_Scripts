#!/bin/bash
source net-config.cfg

## ceilometer
if [ "$IS_TELEMETRY" -eq 0 ]; then
exit 0
fi


# Install and configure Ceilometer Components

apt-get -y install ceilometer-agent-compute

filename=/etc/ceilometer/ceilometer.conf
test -f $filename.org || cp $filename $filename.org

cat << EOF > $filename
[DEFAULT]
debug = false

rpc_backend = rabbit
auth_strategy = keystone

[database]
connection = mongodb://ceilometer:$DEFAULT_PASS@controller:27017/ceilometer

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
EOF
chown ceilometer:ceilometer $filename

##### Restart the Telemetry services ####

service ceilometer-agent-compute restart
service nova-compute restart

exit 0