#!/bin/bash
source net-config.cfg

echo "##### INSTALL KEYSTONE ##### "

echo "manual" > /etc/init/keystone.override

apt-get -y install keystone python-openstackclient apache2 libapache2-mod-wsgi \
memcached python-memcache

sed -i "s/-l 127.0.0.1/-l controller/g" /etc/memcached.conf
service memcached restart

filename=/etc/keystone/keystone.conf
test -f $filename.org || cp $filename $filename.org

cat << EOF > $filename
[DEFAULT]
debug = false

rpc_backend=rabbit
admin_token=$DEFAULT_PASS

[assignment]
driver = sql

[cache]
memcache_servers = controller:11211
backend = oslo_cache.memcache_pool
enabled = True

[catalog]
caching = False

[database]
connection = mysql+pymysql://keystone:$DEFAULT_PASS@controller/keystone

[fernet_tokens]
key_repository = /etc/keystone/fernet-keys/

[identity]
driver = sql

[memcache]
servers = controller:11211

[oslo_messaging_rabbit]
rabbit_host = controller
rabbit_userid = openstack
rabbit_password = $DEFAULT_PASS

[paste_deploy]
config_file = /etc/keystone/keystone-paste.ini

[resource]
admin_project_name = admin
admin_project_domain_name = default
driver = sql

[role]
driver = sql

[token]
driver = sql
provider = fernet
expiration = 7200

[extra_headers]
Distribution = Ubuntu
EOF

echo "##### DB SYNC #####"
keystone-manage db_sync

keystone-manage fernet_setup --keystone-user keystone --keystone-group keystone

rm -f /var/lib/keystone/keystone.db

sed -i 's/Options Indexes FollowSymLinks/Options FollowSymLinks/g' /etc/apache2/apache2.conf

word_count=`grep -c "ServerName\ controller" /etc/apache2/apache2.conf`
if [ "$word_count" == "0" ]; then
	echo "ServerName controller" >> /etc/apache2/apache2.conf
fi

filename=/etc/apache2/sites-available/wsgi-keystone.conf
cat << EOF > $filename
Listen 5000
Listen 35357

<VirtualHost *:5000>
    WSGIDaemonProcess keystone-public processes=5 threads=1 user=keystone group=keystone display-name=%{GROUP}
    WSGIProcessGroup keystone-public
    WSGIScriptAlias / /usr/bin/keystone-wsgi-public
    WSGIApplicationGroup %{GLOBAL}
    WSGIPassAuthorization On
    <IfVersion >= 2.4>
      ErrorLogFormat "%{cu}t %M"
    </IfVersion>
    ErrorLog /var/log/apache2/keystone.log
    CustomLog /var/log/apache2/keystone_access.log combined

    <Directory /usr/bin>
        <IfVersion >= 2.4>
            Require all granted
        </IfVersion>
        <IfVersion < 2.4>
            Order allow,deny
            Allow from all
        </IfVersion>
    </Directory>
</VirtualHost>

<VirtualHost *:35357>
    WSGIDaemonProcess keystone-admin processes=5 threads=1 user=keystone group=keystone display-name=%{GROUP}
    WSGIProcessGroup keystone-admin
    WSGIScriptAlias / /usr/bin/keystone-wsgi-admin
    WSGIApplicationGroup %{GLOBAL}
    WSGIPassAuthorization On
    <IfVersion >= 2.4>
      ErrorLogFormat "%{cu}t %M"
    </IfVersion>
    ErrorLog /var/log/apache2/keystone.log
    CustomLog /var/log/apache2/keystone_access.log combined

    <Directory /usr/bin>
        <IfVersion >= 2.4>
            Require all granted
        </IfVersion>
        <IfVersion < 2.4>
            Order allow,deny
            Allow from all
        </IfVersion>
    </Directory>
</VirtualHost>
EOF

a2dissite 000-default
a2ensite wsgi-keystone

#a2enmod wsgi
service apache2 restart

exit 0