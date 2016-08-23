#!/bin/bash
source net-config.cfg
source ~/admin-openrc.sh

if [ "$IS_TACKER" -eq 0 ]; then
exit 0
fi

echo "########## INSTALL TACKER ################"
apt-get -y install python-pip git

## Ensure entry for extensions drivers in ml2_conf.ini

word_count=`grep -c "port_security" /etc/neutron/plugins/ml2/ml2_conf.ini`
if [ "$word_count" == "0" ]; then
sed -i 's/\[ml2\]/\[ml2\]\
\# For Tacker \
extension_drivers = port_security/g' /etc/neutron/plugins/ml2/ml2_conf.ini
fi

## Clone tacker repository.
rm -rf /usr/local/lib/python2.7/dist-packages/tosca*
rm -rf /usr/local/lib/python2.7/dist-packages/tacker*

cd ~/
rm -rf tacker

git clone $TACKER_VERSION https://github.com/openstack/tacker
cd tacker

filename=requirements.txt
test -f $filename.org || cp $filename $filename.org

if [ "$TACKER_VERSION" == "-b stable/mitaka" ]; then
sed -i 's/Routes!=2.0/#Routes!=2.0/g' $filename
sed -i 's/#Routes!=2.0,>=1.12.3/Routes!=2.0,>=1.12.3#/g' $filename
else
sed -i 's/Routes!=2.0/#Routes!=2.0/g' $filename
sed -i 's/#Routes!=2.0,>=1.12.3/Routes!=2.0,!=2.3.0,>=1.12.3#/g' $filename
fi

# requirements install only master version
pip install -r requirements.txt
pip install tosca-parser
python setup.py install

# bugfix call vim_keystone (project_domain_id to project_domain_name, user_domain_id to user_domain_name)
filename=/usr/local/lib/python2.7/dist-packages/tacker/nfvo/drivers/vim/openstack_driver.py
test -f $filename.org || cp $filename $filename.org

word_count=`grep -c "project_domain_id" $filename`
if [ "$word_count" -gt 0 ]; then
sed -i 's/project_domain_id/project_domain_name/g' $filename
fi

word_count=`grep -c "user_domain_id" $filename`
if [ "$word_count" -gt 0 ]; then
sed -i 's/user_domain_id/user_domain_name/g' $filename
fi

rm -rf /var/log/tacker
rm -rf /var/cache/tacker
mkdir -p /var/log/tacker
mkdir -p /var/cache/tacker

## Configuration tacker.conf
filename=/usr/local/etc/tacker/tacker.conf
test -f $filename.org || cp $filename $filename.org
rm -f $filename

cat << EOF > $filename
[DEFAULT]
logging_exception_prefix = %(color)s%(asctime)s.%(msecs)03d TRACE %(name)s [01;35m%(instance)s[00m
logging_debug_format_suffix = [00;33mfrom (pid=%(process)d) %(funcName)s %(pathname)s:%(lineno)d[00m
logging_default_format_string = %(asctime)s.%(msecs)03d %(color)s%(levelname)s %(name)s [[00;36m-%(color)s] [01;35m%(instance)s%(color)s%(message)s[00m
logging_context_format_string = %(asctime)s.%(msecs)03d %(color)s%(levelname)s %(name)s [[01;36m%(request_id)s [00;36m%(user_name)s %(project_name)s%(color)s] [01;35m%(instance)s%(color)s%(message)s[00m
debug = true
#verbose =  True

auth_strategy = keystone
policy_file = /usr/local/etc/tacker/policy.json
state_path = /var/lib/tacker

service_plugins = vnfm,nfvo
notification_driver = tacker.openstack.common.notifier.rpc_notifier

[oslo_concurrency]
lock_path = \$state_path/lock

[keystone_authtoken]
auth_uri = http://controller:5000
auth_url = http://controller:35357
memcached_servers = controller:11211
auth_type = password
auth_plugin = password
project_domain_name = default
user_domain_name = default
project_name = service
username = tacker
password = $DEFAULT_PASS

[agent]
root_helper = sudo /usr/local/bin/tacker-rootwrap /usr/local/etc/tacker/rootwrap.conf

[database]
connection = mysql+pymysql://tacker:$DEFAULT_PASS@controller/tacker

[tacker]
# Specify drivers for hosting device
infra_driver = heat,nova,noop

# Specify drivers for mgmt
mgmt_driver = noop,openwrt

# Specify drivers for monitoring
monitor_driver = ping, http_ping

[nfvo_vim]
# Supported VIM drivers, resource orchestration controllers such as OpenStack, kvm
#Default VIM driver is OpenStack
vim_drivers = openstack
#Default VIM placement if vim id is not provided
default_vim = VIM0

[vim_keys]
#openstack = /etc/tacker/vim/fernet_keys

[tacker_nova]
auth_url = http://controller:35357
auth_type = password
auth_plugin = password
project_domain_id = default
user_domain_id = default
region_name = RegionOne
project_name = service
username = nova
password = $DEFAULT_PASS

[tacker_heat]
heat_uri = http://controller:8004/v1
#stack_retries = 60
#stack_retry_wait = 5
EOF

#chown tacker:tacker $filename

rm -f /var/lib/tacker/tacker.sqlite

echo "##### Ubuntu Operating System #####"
/usr/local/bin/tacker-db-manage --config-file /usr/local/etc/tacker/tacker.conf upgrade head

echo "##### Install Tacker client #####"
cd ~/
rm -rf python-tackerclient
git clone $TACKER_VERSION https://github.com/openstack/python-tackerclient
cd python-tackerclient
python setup.py install

echo "##### Install Tacker horizon #####"
cd ~/
rm -rf tacker-horizon
## used master version
git clone $TACKER_VERSION https://github.com/openstack/tacker-horizon
cd tacker-horizon
python setup.py install

cp openstack_dashboard_extensions/* /usr/share/openstack-dashboard/openstack_dashboard/enabled/

service apache2 stop
service apache2 restart

echo "##### Create Service script #####"
##sed -i 's/tacker:x:199:199::/var/lib/tacker:/bin/false//g' /etc/passwd
##echo "tacker:x:199:199::/var/lib/tacker:/bin/false" >> /etc/passwd

##chown tacker:adm /var/log/tacker
##chown tacker:adm /var/cache/tacker

filename=/etc/init/tacker-server.conf
test -f $filename.org || cp $filename $filename.org
rm -f $filename

cat << EOF > $filename
# vim:set ft=upstart ts=2 et:
description "Tacker API Server"

start on runlevel [2345]
stop on runlevel [!2345]

respawn

chdir /var/run

pre-start script
  mkdir -p /var/run/tacker
  chown root:root /var/run/tacker
end script

script
  [ -x "/usr/local/bin/tacker-server" ] || exit 0
  [ -r /etc/default/openstack ] && . /etc/default/openstack
  [ "x$USE_SYSLOG" = "xyes" ] && DAEMON_ARGS="$DAEMON_ARGS --use-syslog"
  [ "x$USE_LOGFILE" != "xno" ] && DAEMON_ARGS="$DAEMON_ARGS --log-file=/var/log/tacker/tacker.log"
  exec start-stop-daemon --start --chuid root --exec /usr/local/bin/tacker-server -- \
  --config-file=/usr/local/etc/tacker/tacker.conf \${DAEMON_ARGS}
end script
EOF

ln -sf /lib/init/upstart-job /etc/init.d/tacker-server
update-rc.d -f tacker-server remove
update-rc.d tacker-server defaults

echo "##### Neutron service restart #####"
service neutron-server restart
service neutron-l3-agent restart
service neutron-dhcp-agent restart
service neutron-metadata-agent restart
service neutron-openvswitch-agent restart

echo "##### Tacker service restart #####"
service tacker-server restart

openstack role add --project nfv --user admin _member_

exit 0

#######################################
### create networks 
#######################################
source ~/admin-openrc.sh

neutron net-delete net_mgmt
neutron net-create net_mgmt \
--shared --provider:network_type flat \
--provider:physical_network ext_br-tacker

neutron subnet-create --name net_mgmt_sub \
--gateway 192.168.120.1 \
--dns-nameserver 8.8.8.8 \
net_mgmt 192.168.120.0/24

source ~/admin-openrc.sh nfv

neutron net-delete net0
neutron net-delete net1
neutron net-create net0
neutron net-create net1

neutron subnet-create --name net0_sub \
--gateway 10.10.11.1 \
--dns-nameserver 8.8.8.8 \
net0 10.10.11.0/24
neutron subnet-create --name net1_sub \
--gateway 10.10.12.1 \
--dns-nameserver 8.8.8.8 \
net1 10.10.12.0/24

#######################################
### Registering default VIM
#######################################

cat << EOF > config.yaml
auth_url: http://$MGMT_IP:5000
username: nfv_user
password: "$DEFAULT_PASS"
project_name: nfv
EOF

source ~/admin-openrc.sh nfv

tacker vim-register --config-file config.yaml --name VIM0 \
--description "This is default vim"

cat << EOF > sample-vnfd-http-monitor.yaml
template_name: sample-vnfd-http-monitor
description: demo-example

service_properties:
  Id: sample-vnfd
  vendor: tacker
  version: 1

vdus:
  vdu1:
    id: vdu1
    vm_image: cirros-0.3.4-x86_64
    instance_type: m1.tiny

    network_interfaces:
      management:
        network: net_mgmt
        management: true
      pkt_in:
        network: net0
      pkt_out:
        network: net1

    placement_policy:
      availability_zone: nova

    auto-scaling: noop
    monitoring_policy:
      http_ping:
        monitoring_params:
          retry: 5
          timeout: 10
          port: 8000
        actions:
          failure: respawn

    config:
      param0: key0
      param1: key1
EOF

tacker vnfd-create --name sample-vnfd-http-monitor --vnfd-file sample-vnfd-http-monitor.yaml
