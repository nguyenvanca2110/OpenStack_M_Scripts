#!/bin/bash
source aio-config.cfg

export OS_TOKEN="$DEFAULT_PASS"
export OS_URL=http://controller:35357/v3
export OS_IDENTITY_API_VERSION=3

# Domain
openstack domain create --description "Default Domain" default

# Project
openstack project create --domain default --description "Admin Project" admin
openstack project create --domain default --description "Service Project" service

# Users
openstack user create --domain default --password "$DEFAULT_PASS" --email yangun@dcn.ssu.ac.kr admin
openstack user create --domain default --password "$DEFAULT_PASS" --email yangun@dcn.ssu.ac.kr glance
openstack user create --domain default --password "$DEFAULT_PASS" --email yangun@dcn.ssu.ac.kr nova
openstack user create --domain default --password "$DEFAULT_PASS" --email yangun@dcn.ssu.ac.kr neutron
openstack user create --domain default --password "$DEFAULT_PASS" --email yangun@dcn.ssu.ac.kr cinder
openstack user create --domain default --password "$DEFAULT_PASS" --email yangun@dcn.ssu.ac.kr heat
##openstack user create --domain default --password "$DEFAULT_PASS" --email yangun@dcn.ssu.ac.kr swift

# Roles
openstack role create admin
openstack role create user
openstack role create advsvc
openstack role create _member_
openstack role create heat_stack_owner
openstack role create heat_stack_user
openstack role add --project admin --user admin admin
openstack role add --project service --user glance admin
openstack role add --project service --user nova admin
openstack role add --project service --user neutron admin
openstack role add --project service --user cinder admin
openstack role add --project service --user heat admin
##openstack role add --project service --user swift admin

#Service
openstack service create --name keystone --description "OpenStack Identity" identity
openstack service create --name glance --description "OpenStack Image service" image
openstack service create --name nova --description "OpenStack Compute" compute
openstack service create --name neutron --description "OpenStack Networking" network
openstack service create --name cinder --description "OpenStack Block Storage" volume
openstack service create --name cinderv2 --description "OpenStack Block Storage" volumev2
openstack service create --name heat --description "OpenStack Orchestration" orchestration
openstack service create --name heat-cfn --description "OpenStack Orchestration cloudformation" cloudformation
##openstack service create --name swift --description "OpenStack Object Storage" object-store

#Endpoint
openstack endpoint create --region RegionOne identity public http://controller:5000/v3
openstack endpoint create --region RegionOne identity internal http://controller:5000/v3
openstack endpoint create --region RegionOne identity admin http://controller:35357/v3

openstack endpoint create --region RegionOne image public http://controller:9292
openstack endpoint create --region RegionOne image internal http://controller:9292
openstack endpoint create --region RegionOne image admin http://controller:9292
  
openstack endpoint create --region RegionOne compute public http://controller:8774/v2.1/%\(tenant_id\)s
openstack endpoint create --region RegionOne compute internal http://controller:8774/v2.1/%\(tenant_id\)s
openstack endpoint create --region RegionOne compute admin http://controller:8774/v2.1/%\(tenant_id\)s

openstack endpoint create --region RegionOne network public http://controller:9696
openstack endpoint create --region RegionOne network internal http://controller:9696
openstack endpoint create --region RegionOne network admin http://controller:9696
  
openstack endpoint create --region RegionOne volume public http://controller:8776/v1/%\(tenant_id\)s
openstack endpoint create --region RegionOne volume internal http://controller:8776/v1/%\(tenant_id\)s
openstack endpoint create --region RegionOne volume admin http://controller:8776/v1/%\(tenant_id\)s
  

openstack endpoint create --region RegionOne volumev2 public http://controller:8776/v2/%\(tenant_id\)s
openstack endpoint create --region RegionOne volumev2 internal http://controller:8776/v2/%\(tenant_id\)s
openstack endpoint create --region RegionOne volumev2 admin http://controller:8776/v2/%\(tenant_id\)s
  
openstack endpoint create --region RegionOne orchestration public http://controller:8004/v1/%\(tenant_id\)s
openstack endpoint create --region RegionOne orchestration internal http://controller:8004/v1/%\(tenant_id\)s
openstack endpoint create --region RegionOne orchestration admin http://controller:8004/v1/%\(tenant_id\)s

openstack endpoint create --region RegionOne cloudformation public http://controller:8000/v1
openstack endpoint create --region RegionOne cloudformation internal http://controller:8000/v1
openstack endpoint create --region RegionOne cloudformation admin http://controller:8000/v1

##openstack endpoint create --region RegionOne object-store public http://controller:8080/v1/AUTH_%(tenant_id)s
##openstack endpoint create --region RegionOne object-store internal http://controller:8080/v1/AUTH_%(tenant_id)s
##openstack endpoint create --region RegionOne object-store admin http://controller:8080/v1

#Create the heat domain
openstack domain create heat --description "Stack projects and users"
openstack user create --domain heat --password "$DEFAULT_PASS" --email yangun@dcn.ssu.ac.kr heat_domain_admin
openstack role add --domain heat --user heat_domain_admin admin


if [ "$IS_TELEMETRY" == "1" ]; then
openstack user create --domain default --password "$DEFAULT_PASS" --email yangun@dcn.ssu.ac.kr ceilometer
openstack user create --domain default --password "$DEFAULT_PASS" --email yangun@dcn.ssu.ac.kr aodh
openstack role add --project service --user ceilometer admin
openstack role add --project service --user aodh admin
openstack service create --name ceilometer --description "Telemetry" metering
openstack service create --name aodh --description "Telemetry alarming" alarming

openstack endpoint create --region RegionOne metering public http://controller:8777/
openstack endpoint create --region RegionOne metering internal http://controller:8777/
openstack endpoint create --region RegionOne metering admin http://controller:8777/

openstack endpoint create --region RegionOne alarming public http://controller:8042
openstack endpoint create --region RegionOne alarming internal http://controller:8042
openstack endpoint create --region RegionOne alarming admin http://controller:8042
fi

if [ "$IS_TACKER" == "1" ]; then
openstack project create --domain default --description "NFV Project" nfv
openstack user create --domain default --password "$DEFAULT_PASS" --email yangun@dcn.ssu.ac.kr tacker
openstack user create --domain default --password "$DEFAULT_PASS" --email yangun@dcn.ssu.ac.kr nfv_user
openstack role add --project service --user tacker admin
openstack role add --project service --user tacker advsvc
openstack role add --project nfv --user nfv_user admin
openstack role add --project nfv --user nfv_user advsvc
openstack service create --name tacker --description "Tacker Project" nfv-orchestration
openstack endpoint create --region RegionOne nfv-orchestration public http://controller:8888/
openstack endpoint create --region RegionOne nfv-orchestration internal http://controller:8888/
openstack endpoint create --region RegionOne nfv-orchestration admin http://controller:8888/
fi

unset OS_TOKEN OS_URL OS_IDENTITY_API_VERSION

echo "export OS_PROJECT_DOMAIN_NAME=default" > ~/admin-openrc.sh
echo "export OS_USER_DOMAIN_NAME=default" >> ~/admin-openrc.sh
echo "export OS_PROJECT_NAME=admin" >> ~/admin-openrc.sh
echo 'if [ "$1" == "" ]; then' >> ~/admin-openrc.sh
echo "export OS_PROJECT_NAME=admin" >> ~/admin-openrc.sh
echo "else" >> ~/admin-openrc.sh 
echo 'export OS_PROJECT_NAME=$1' >> ~/admin-openrc.sh
echo "fi" >> ~/admin-openrc.sh 
#echo "export OS_TENANT_NAME=admin" >> ~/admin-openrc.sh
echo "export OS_USERNAME=admin" >> ~/admin-openrc.sh
echo "export OS_PASSWORD=$DEFAULT_PASS" >> ~/admin-openrc.sh
echo "export OS_AUTH_URL=http://controller:35357/v3" >> ~/admin-openrc.sh
echo "export OS_IMAGE_API_VERSION=2" >> ~/admin-openrc.sh
echo "export OS_IDENTITY_API_VERSION=3" >> ~/admin-openrc.sh

chmod +x ~/admin-openrc.sh

exit 0
