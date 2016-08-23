#!/bin/bash
source net-config.cfg

apt-get -y remove --purge mysql*
rm -rf /var/lib/mysql

echo "########## INSTALL MARIADB(CLONE MYSQL) ##########"
echo mysql-server mysql-server/root_password password $DEFAULT_PASS | debconf-set-selections
echo mysql-server mysql-server/root_password_again password $DEFAULT_PASS | debconf-set-selections

apt-get -y install mariadb-server python-pymysql

filename=/etc/mysql/conf.d/mysqld_openstack.cnf
touch $filename 

cat << EOF > $filename
[mysqld]
bind-address = 0.0.0.0
default-storage-engine = innodb
innodb_file_per_table
collation-server = utf8_general_ci
init-connect = 'SET NAMES utf8'
character-set-server = utf8
max_connections = 10000
EOF

service mysql restart

echo "########## INSTALL DATABASE ##########"
cat << EOF | mysql -uroot -p$DEFAULT_PASS
DROP DATABASE IF EXISTS keystone;
DROP DATABASE IF EXISTS glance;
DROP DATABASE IF EXISTS nova_api;
DROP DATABASE IF EXISTS nova;
DROP DATABASE IF EXISTS cinder;
DROP DATABASE IF EXISTS neutron;
DROP DATABASE IF EXISTS heat;
DROP DATABASE IF EXISTS aodh;
DROP DATABASE IF EXISTS tacker;
#
CREATE DATABASE keystone;
GRANT ALL PRIVILEGES ON keystone.* TO 'keystone'@'localhost' IDENTIFIED BY '$DEFAULT_PASS';
GRANT ALL PRIVILEGES ON keystone.* TO 'keystone'@'%' IDENTIFIED BY '$DEFAULT_PASS';
#
CREATE DATABASE nova_api;
GRANT ALL PRIVILEGES ON nova_api.* TO 'nova'@'localhost' IDENTIFIED BY '$DEFAULT_PASS';
GRANT ALL PRIVILEGES ON nova_api.* TO 'nova'@'%' IDENTIFIED BY '$DEFAULT_PASS';

CREATE DATABASE nova;
GRANT ALL PRIVILEGES ON nova.* TO 'nova'@'localhost' IDENTIFIED BY '$DEFAULT_PASS';
GRANT ALL PRIVILEGES ON nova.* TO 'nova'@'%' IDENTIFIED BY '$DEFAULT_PASS';
#
CREATE DATABASE glance;
GRANT ALL PRIVILEGES ON glance.* TO 'glance'@'localhost' IDENTIFIED BY '$DEFAULT_PASS';
GRANT ALL PRIVILEGES ON glance.* TO 'glance'@'%' IDENTIFIED BY '$DEFAULT_PASS';
#
CREATE DATABASE cinder;
GRANT ALL PRIVILEGES ON cinder.* TO 'cinder'@'%' IDENTIFIED BY '$DEFAULT_PASS';
GRANT ALL PRIVILEGES ON cinder.* TO 'cinder'@'localhost' IDENTIFIED BY '$DEFAULT_PASS';
#
CREATE DATABASE neutron;
GRANT ALL PRIVILEGES ON neutron.* TO 'neutron'@'localhost' IDENTIFIED BY '$DEFAULT_PASS';
GRANT ALL PRIVILEGES ON neutron.* TO 'neutron'@'%' IDENTIFIED BY '$DEFAULT_PASS';
#
CREATE DATABASE heat;
GRANT ALL PRIVILEGES ON heat.* TO 'heat'@'localhost' IDENTIFIED BY '$DEFAULT_PASS';
GRANT ALL PRIVILEGES ON heat.* TO 'heat'@'%' IDENTIFIED BY '$DEFAULT_PASS';
#
CREATE DATABASE aodh;
GRANT ALL PRIVILEGES ON aodh.* TO 'aodh'@'localhost' IDENTIFIED BY '$DEFAULT_PASS';
GRANT ALL PRIVILEGES ON aodh.* TO 'aodh'@'%' IDENTIFIED BY '$DEFAULT_PASS';
#
CREATE DATABASE tacker;
GRANT ALL PRIVILEGES ON tacker.* TO 'tacker'@'localhost' IDENTIFIED BY '$DEFAULT_PASS';
GRANT ALL PRIVILEGES ON tacker.* TO 'tacker'@'%' IDENTIFIED BY '$DEFAULT_PASS';
#
FLUSH PRIVILEGES;
EOF

exit 0