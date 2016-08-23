#!/bin/bash
source aio-config.cfg

apt-get -y purge mariadb* --auto-remove
rm -rf /var/mysql /var/lib/mysql

echo "########## INSTALL MARIADB(CLONE MYSQL) ##########"
CODENAME=`lsb_release --codename | cut -f2`

export DEBIAN_FRONTEND=noninteractive
echo mariadb-server mysql-server/root_password password $DEFAULT_PASS | debconf-set-selections
echo mariadb-server mysql-server/root_password_again password $DEFAULT_PASS | debconf-set-selections

apt-get -y install mariadb-server python-pymysql

if [ "$CODENAME" == "xenial" ]; then

apt-get -y install python-mysqldb expect

sed -i "s/bind-address\t\t= 127.0.0.1/bind-address\t\t= 0.0.0.0/g" /etc/mysql/mariadb.conf.d/50-server.cnf
sed -i "s/#max_connections        = 100/max_connections        = 10000/g" /etc/mysql/mariadb.conf.d/50-server.cnf

sed -i "s/character-set-server  = utf8mb4/character-set-server  = utf8/g" /etc/mysql/mariadb.conf.d/50-server.cnf
sed -i "s/collation-server      = utf8mb4_general_ci/collation-server      = utf8_general_ci/g" /etc/mysql/mariadb.conf.d/50-server.cnf

sed -i "s/default-character-set = utf8mb4/default-character-set = utf8/g" /etc/mysql/mariadb.conf.d/50*-client*.cnf

service mysql restart

SECURE_MYSQL=$(expect -c "
 
set timeout 10
spawn mysql_secure_installation
 
expect \"Enter current password for root (enter for none):\"
send \"$DEFAULT_PASS\r\"
 
expect \"Change the root password?\"
send \"n\r\"
 
expect \"Remove anonymous users?\"
send \"y\r\"
 
expect \"Disallow root login remotely?\"
send \"y\r\"
 
expect \"Remove test database and access to it?\"
send \"y\r\"
 
expect \"Reload privilege tables now?\"
send \"y\r\"
 
expect eof
")
echo "$SECURE_MYSQL"

#cat << EOF | mysql -uroot -p$DEFAULT_PASS mysql
#update user set password=password('$DEFAULT_PASS'), plugin='' where user='root';
#FLUSH PRIVILEGES;
#EOF

apt-get -y purge expect

else

filename=/etc/mysql/conf.d/mysql.cnf
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

fi

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
##DROP DATABASE IF EXISTS aodh;
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
##CREATE DATABASE aodh;
##GRANT ALL PRIVILEGES ON aodh.* TO 'aodh'@'localhost' IDENTIFIED BY '$DEFAULT_PASS';
##GRANT ALL PRIVILEGES ON aodh.* TO 'aodh'@'%' IDENTIFIED BY '$DEFAULT_PASS';
#
CREATE DATABASE tacker;
GRANT ALL PRIVILEGES ON tacker.* TO 'tacker'@'localhost' IDENTIFIED BY '$DEFAULT_PASS';
GRANT ALL PRIVILEGES ON tacker.* TO 'tacker'@'%' IDENTIFIED BY '$DEFAULT_PASS';
#
FLUSH PRIVILEGES;
EOF

exit 0
