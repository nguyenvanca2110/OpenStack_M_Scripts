#!/bin/bash
source aio-config.cfg

echo "########## INSTALL DASHBOARD ##########"
apt-get -y install openstack-dashboard
apt-get -y purge --auto-remove openstack-dashboard-ubuntu-theme
##apt-get -y install openstack-dashboard && dpkg --purge openstack-dashboard-ubuntu-theme

filename=/var/www/html/index.html
test -f $filename.org || cp $filename $filename.org
rm -f $filename

##touch $filename
##
##cat << EOF >> $filename
##<html>
##<head>
##<META HTTP-EQUIV="Refresh" Content="0.5; URL=http://$MASTER/horizon">
##</head>
##<body>
##<center> <h1>Forwarding to Dashboard of OpenStack</h1> </center>
##</body>
##</html>
##EOF

sed -i "s/OPENSTACK_HOST = \"127.0.0.1\"/OPENSTACK_HOST = \"controller\"/g" /etc/openstack-dashboard/local_settings.py
sed -i "s/ALLOWED_HOSTS = '\*'/ALLOWED_HOSTS = ['\*', ]/g" /etc/openstack-dashboard/local_settings.py
sed -i "s/'LOCATION': '127.0.0.1:11211'/'LOCATION': 'controller:11211'/g" /etc/openstack-dashboard/local_settings.py
sed -i "s/v2.0/v3/g" /etc/openstack-dashboard/local_settings.py
sed -i "s/#OPENSTACK_KEYSTONE_DEFAULT_DOMAIN = 'default'/OPENSTACK_KEYSTONE_DEFAULT_DOMAIN = 'default'/g" /etc/openstack-dashboard/local_settings.py

sed -i 's/#OPENSTACK_API_VERSIONS = {/OPENSTACK_API_VERSIONS = {/g' /etc/openstack-dashboard/local_settings.py
sed -i 's/#    \"data-processing\": 1.1,/    \"data-processing\": 1.1,/g' /etc/openstack-dashboard/local_settings.py
sed -i 's/#    \"identity\": 3,/    \"identity\": 3,/g' /etc/openstack-dashboard/local_settings.py
sed -i 's/#    \"volume\": 2,/    \"volume\": 2,/g' /etc/openstack-dashboard/local_settings.py
sed -i 's/#    \"compute\": 2,/    \"compute\": 2}/g' /etc/openstack-dashboard/local_settings.py

##sed -i "s/#OPENSTACK_KEYSTONE_MULTIDOMAIN_SUPPORT = False/OPENSTACK_KEYSTONE_MULTIDOMAIN_SUPPORT = True/g" /etc/openstack-dashboard/local_settings.py

service apache2 reload

echo "########## HORIZON INFORMANTION ##########"
echo "URL: http://$MGMT_IP/horizon"
echo "User: admin"
echo "Password:" $DEFAULT_PASS

exit 0
