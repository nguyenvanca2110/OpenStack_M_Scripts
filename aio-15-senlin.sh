#!/bin/bash
source aio-config.cfg
source ~/admin-openrc.sh

if [ "$IS_SENLIN" -eq 0 ]; then
exit 0
fi

cd ~
git clone http://git.openstack.org/openstack/senlin.git
cd ~/senlin
sudo pip install -e .

source ~/admin-openrc.sh
echo "################# Setup Senlin Service ##################"
echo "#########################################################"

openstack service create --name senlin --description 'Senlin Clustering Service V1' clustering

openstack endpoint create --region RegionOne senlin public http://controller:8778
openstack endpoint create --region RegionOne senlin internal http://controller:8778
openstack endpoint create --region RegionOne senlin admin http://controller:8778

openstack user create --domain default --password "$DEFAULT_PASS" --email yangun@dcn.ssu.ac.kr senlin

openstack role create service

openstack role add --project service --user senlin admin
openstack role add --project demo --user senlin service

cd ~/senlin
tools/gen-config
sudo mkdir /etc/senlin
sudo cp etc/senlin/api-paste.ini /etc/senlin
sudo cp etc/senlin/policy.json /etc/senlin
sudo cp etc/senlin/senlin.conf.sample /etc/senlin/senlin.conf

filename=/etc/senlin/senlin.conf
test -f $filename.org || cp $filename $filename.org
rm -f $filename

cat << EOF > $filename
[DEFAULT]

[authentication]
auth_url = http://controller:5000/v3
service_username = senlin
service_password = $DEFAULT_PASS
service_project_name = service

[database]
connection = mysql+pymysql://senlin:$DEFAULT_PASS@controller/senlin

[keystone_authtoken]

auth_uri = http://controller:5000
auth_url = http://controller:35357
memcached_servers = controller:11211
auth_type = password
project_domain_name = default
user_domain_name = default
project_name = service
username = senlin
password = $DEFAULT_PASS


[matchmaker_redis]

[oslo_messaging_amqp]

[oslo_messaging_notifications]

[oslo_messaging_rabbit]
rabbit_userid = openstack
rabbit_hosts = controller
rabbit_password = $DEFAULT_PASS

[oslo_policy]

[revision]

[ssl]

[webhook]
EOF

echo "################# Setup Senlin Database ##################"
echo "##########################################################"
echo "Recreating 'senlin' database."
cat << EOF | mysql -uroot -p$DEFAULT_PASS
DROP DATABASE IF EXISTS senlin;
CREATE DATABASE senlin DEFAULT CHARACTER SET utf8;
GRANT ALL ON senlin.* TO 'senlin'@'localhost' IDENTIFIED BY '$DEFAULT_PASS';
GRANT ALL ON senlin.* TO 'senlin'@'%' IDENTIFIED BY '$DEFAULT_PASS';
flush privileges;
EOF

senlin-manage db_sync

#senlin-engine --config-file /etc/senlin/senlin.conf &
#senlin-api --config-file /etc/senlin/senlin.conf &

cd ~
git clone http://git.openstack.org/openstack/python-senlinclient.git
cd python-senlinclient
sudo python setup.py install

mkdir -p /var/log/senlin

echo "############## Set up runlevel of Senlin-engine ################"
echo "################################################################"

filename=/etc/init/senlin-engine.conf
test -f $filename.org || cp $filename $filename.org
rm -f $filename

cat << EOF > $filename
# vim:set ft=upstart ts=2 et:
description "Senlin-engine Server"

start on runlevel [2345]
stop on runlevel [!2345]

respawn

chdir /var/run

pre-start script
  mkdir -p /var/run/senlin-engine
  chown root:root /var/run/senlin-engine
end script

script
  [ -x "/usr/local/bin/senlin-engine" ] || exit 0
  [ -r /etc/default/openstack ] && . /etc/default/openstack
  [ "x$USE_SYSLOG" = "xyes" ] && DAEMON_ARGS="$DAEMON_ARGS --use-syslog"
  [ "x$USE_LOGFILE" != "xno" ] && DAEMON_ARGS="$DAEMON_ARGS --log-file=/var/log/senlin/senlin-engine.log"
  exec start-stop-daemon --start --chuid root --exec /usr/local/bin/senlin-engine -- \
  --config-file=/etc/senlin/senlin.conf \${DAEMON_ARGS}
end script
EOF

ln -sf /lib/init/upstart-job /etc/init.d/senlin-engine
update-rc.d -f senlin-engine remove
update-rc.d senlin-engine defaults

echo "############## Set up runlevel of Senlin-api ################"
echo "#############################################################"

filename=/etc/init/senlin-api.conf
test -f $filename.org || cp $filename $filename.org
rm -f $filename

cat << EOF > $filename
# vim:set ft=upstart ts=2 et:
description "Senlin-api Server"

start on runlevel [2345]
stop on runlevel [!2345]

respawn

chdir /var/run

pre-start script
  mkdir -p /var/run/senlin-api
  chown root:root /var/run/senlin-api
end script

script
  [ -x "/usr/local/bin/senlin-api" ] || exit 0
  [ -r /etc/default/openstack ] && . /etc/default/openstack
  [ "x$USE_SYSLOG" = "xyes" ] && DAEMON_ARGS="$DAEMON_ARGS --use-syslog"
  [ "x$USE_LOGFILE" != "xno" ] && DAEMON_ARGS="$DAEMON_ARGS --log-file=/var/log/senlin/senlin-api.log"
  exec start-stop-daemon --start --chuid root --exec /usr/local/bin/senlin-api -- \
  --config-file=/etc/senlin/senlin.conf \${DAEMON_ARGS}
end script
EOF

ln -sf /lib/init/upstart-job /etc/init.d/senlin-api
update-rc.d -f senlin-api remove
update-rc.d senlin-api defaults

echo "############## Finish runlevel setting of Senlin ###############"
echo "################################################################"

service senlin-engine start
service senlin-api start

echo "################## Verify Senlin Installation ######################"
sleep 5
openstack cluster build info
