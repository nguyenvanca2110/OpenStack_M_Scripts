#!/bin/bash
source aio-config.cfg
source ~/admin-openrc.sh

## ceilometer
if [ "$IS_TELEMETRY" -eq 0 ]; then
exit 0
fi

# Install and configure MongoDB
mongo --host controller --eval "
  db = db.getSiblingDB(\"aodh\");
  db.addUser({user: \"aodh\",
  pwd: \"$DEFAULT_PASS\",
  roles: [ \"readWrite\", \"dbAdmin\" ]})"

apt-get install -y aodh-api aodh-evaluator aodh-notifier \
  aodh-listener aodh-expirer python-ceilometerclient

filename=/etc/aodh/aodh.conf
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
connection = mongodb://aodh:$DEFAULT_PASS@controller:27017/aodh
#connection = mysql+pymysql://aodh:$DEFAULT_PASS@controller/aodh

[keystone_authtoken]
auth_uri = http://controller:5000
auth_url = http://controller:35357
memcached_servers = controller:11211
auth_type = password
project_domain_name = default
user_domain_name = default
project_name = service
username = aodh
password = $DEFAULT_PASS

[oslo_messaging_rabbit]
rabbit_host = controller
rabbit_userid = openstack
rabbit_password = $DEFAULT_PASS

[service_credentials]
os_auth_url = http://controller:5000/v2.0
os_username = aodh
os_tenant_name = service
os_password = $DEFAULT_PASS
interface = internalURL
region_name = RegionOne
##os_endpoint_type = internalURL
##os_region_name = RegionOne

##[oslo_messaging_notifications]
##driver = messagingv2
##topics = notifications
EOF
chown aodh:aodh $filename

filename=/etc/aodh/api_paste.ini
test -f $filename.org || cp $filename $filename.org

word_count=`grep -c "oslo_config_project = aodh" $filename`
if [ "$word_count" -eq 0 ]; then
sed -i 's/\[filter\:authtoken\]/\[filter\:authtoken\]\
oslo_config_project = aodh/g' $filename
fi

##### Restart the Alarming services ####

service aodh-api restart
service aodh-evaluator restart
service aodh-notifier restart
service aodh-listener restart

exit 0

########################
## alarm test 
## check alarm log
tail -f /var/log/ceilometer/ceilometer-agent-notification.log /var/log/aodh/aodh-notifier.log

## another cli window
. ~/admin-openrc.sh
ceilometer alarm-delete $(ceilometer alarm-list | grep event_alarm1 | awk '{print $2}')
ceilometer alarm-event-create --name event_alarm1 --repeat-actions True --alarm-action 'log://' --event-type image.update  -q 'traits.name=string::cirros-0.3.4-x86_64'
glance image-update --property progress=102 $(glance image-list | grep cirros-0.3.4-x86_64 | awk '{print $2}')