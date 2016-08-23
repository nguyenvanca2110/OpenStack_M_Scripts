#!/bin/bash
source net-config.cfg
source ~/admin-openrc.sh

## ceilometer
if [ "$IS_TELEMETRY" -eq 1 ]; then
NOTI_TELEMETRY="[oslo_messaging_notifications]
driver = messagingv2"
fi

install_path=`pwd`

echo "##### INSTALL GLANCE ##### "
apt-get -y install glance

filename=/etc/glance/glance-api.conf
test -f $filename.org || cp $filename $filename.org
rm -f $filename

cat << EOF > $filename
[DEFAULT]
debug = false

rpc_backend = rabbit

[database]
connection = mysql+pymysql://glance:$DEFAULT_PASS@controller/glance

[glance_store]
stores = file,http
default_store = file
filesystem_store_datadir = /var/lib/glance/images/

[keystone_authtoken]
auth_uri = http://controller:5000
auth_url = http://controller:35357
memcached_servers = controller:11211
auth_type = password
project_domain_name = default
user_domain_name = default
project_name = service
username = glance
password = $DEFAULT_PASS

[oslo_messaging_rabbit]
rabbit_host = controller
rabbit_userid = openstack
rabbit_password = $DEFAULT_PASS

[paste_deploy]
flavor = keystone

## ceilometer
$NOTI_TELEMETRY
EOF

chown glance:glance $filename

filename=/etc/glance/glance-registry.conf
test -f $filename.org || cp $filename $filename.org
rm -f $filename

cat << EOF > $filename
[DEFAULT]
debug = false

rpc_backend = rabbit

[database]
connection = mysql+pymysql://glance:$DEFAULT_PASS@controller/glance

[keystone_authtoken]
auth_uri = http://controller:5000
auth_url = http://controller:35357
memcached_servers = controller:11211
auth_type = password
project_domain_name = default
user_domain_name = default
project_name = service
username = glance
password = $DEFAULT_PASS

[oslo_messaging_rabbit]
rabbit_host = controller
rabbit_userid = openstack
rabbit_password = $DEFAULT_PASS

[paste_deploy]
flavor = keystone

## ceilometer
$NOTI_TELEMETRY
EOF

chown glance:glance $filename

echo "##### DB SYNC #####"
glance-manage db_sync

service glance-registry restart
service glance-api restart

##apt-get -y install qemu-utils

mkdir -p ~/images
cd ~/images

echo "############ CREATE CIRROS IMAGE ##############"
wget http://download.cirros-cloud.net/0.3.4/cirros-0.3.4-x86_64-disk.img
glance image-create --name "cirros-0.3.4-x86_64" --file cirros-0.3.4-x86_64-disk.img \
--disk-format qcow2 --container-format bare --visibility public --progress

##echo "############ CREATE UBUNTU (UBUNTU/UBUNTU) ##############"
##wget http://uec-images.ubuntu.com/trusty/current/trusty-server-cloudimg-amd64-disk1.img
##
##qemu-img convert -c -O qcow2 trusty-server-cloudimg-amd64-disk1.img trusty-server-cloudimg-amd64-disk1_8GB.qcow2
##qemu-img resize trusty-server-cloudimg-amd64-disk1_8GB.qcow2 +8G
##modprobe nbd
##qemu-nbd -c /dev/nbd0 `pwd`/trusty-server-cloudimg-amd64-disk1_8GB.qcow2
##ls image || mkdir image
##mount /dev/nbd0p1 image
##
##sed -ri 's|(/boot/vmlinuz-.*-generic\s*root=LABEL=cloudimg-rootfs.*)$|\1 ds=nocloud|' image/boot/grub/grub.cfg
##sed -ri 's|^(GRUB_CMDLINE_LINUX_DEFAULT=).*$|\1" ds=nocloud"|' image/etc/default/grub
##sed -ri 's|^#(GRUB_TERMINAL=console)$|\1|' image/etc/default/grub
##
##mkdir -p image/var/lib/cloud/seed/nocloud
##
##tee image/var/lib/cloud/seed/nocloud/meta-data <<EOF
##instance-id: ubuntu
##local-hostname: ubuntu
##EOF
##
##tee image/var/lib/cloud/seed/nocloud/user-data <<EOF
###cloud-config
##password: ubuntu
##chpasswd: { expire: False }
##ssh_pwauth: True
##EOF
##
##sed -ri "s|^(127.0.0.1\s*localhost)$|\1\n127.0.0.1 `cat image/etc/hostname`|" image/etc/hosts
##
##sync
##umount image
##qemu-nbd -d /dev/nbd0
##modprobe -r nbd > /dev/null 2>&1
##
##glance image-create --name "ubuntu-server-14.04" \
## --file trusty-server-cloudimg-amd64-disk1_8GB.qcow2 \
## --disk-format qcow2 --container-format bare --visibility public --progress
##

## android download
## http://sourceforge.net/projects/androidx86-openstack/?source=typ_redirect
#glance image-create --name "androidx86-4.4" \
# --file androidx86-4.4.qcow2 \
# --disk-format qcow2 --container-format bare --visibility public --progress

rm -rf ~/images

cd $install_path

exit 0

##################################################################################
##################################################################################

apt-get install qemu-kvm libvirt-bin
apt-get install virt-manager
#apt-get install virtinst


install android
1. download iso (Hardware Disk : only IDE)
#instructons on how to create the image yourself: http://thisismyeye.blogspot.co.uk/2014/04/enabling-virtio-drivers-on-kernel-for.html 
wget https://sourceforge.net/projects/android-x86/files/Release%204.4/android-x86-4.4-r5.iso/download
mv download android-x86-4.4-r5.iso

2. execut virt-manager
name : android-x86-4.4
memory : 1024
cpu : 1
disk : 8G (IDE) 
NIC : e1000
Vedio : Default
refer : http://www.upubuntu.com/2012/03/how-to-install-android-x86-40-using.html

cp /var/lib/libvirt/images/android-x86-4.4.img ~/


3. openstack side

nova flavor-list
nova flavor-create --is-public true m1.android_min auto 2048 10 1 --rxtx-factor 1
nova flavor-create --is-public true m1.android_max auto 4096 10 2 --rxtx-factor 1

cd ~/

qemu-img convert -c -O qcow2 android-x86-4.4.img android-x86-4.4.qcow2
#qemu-img resize android-x86-4.4.qcow2 +8G

glance image-create --name "android-x86-4.4" --file android-x86-4.4.qcow2 \
--disk-format qcow2 --container-format bare --visibility public --progress \
--property hw_disk_bus=ide --property hw_vif_model=e1000



####### compile android
1. First,  to compile the OS you have to initialise the build environment.  Follow instructions here.

sudo sed -i 's/\/archive.ubuntu.com/\/ftp.daum.net/g' /etc/apt/sources.list
sudo apt-get update

wget http://kr.archive.ubuntu.com/ubuntu/pool/universe/o/openjdk-8/openjdk-8-jdk_8u45-b14-1_amd64.deb

sudo dpkg -i openjdk-8-jdk_8u45-b14-1_amd64.deb
sudo apt-get -f install
sudo update-alternatives --config java
sudo update-alternatives --config javac

sudo apt-get install git-core gnupg flex bison gperf build-essential \
  zip curl zlib1g-dev gcc-multilib g++-multilib libc6-dev-i386 \
  lib32ncurses5-dev x11proto-core-dev libx11-dev lib32z-dev ccache \
  libgl1-mesa-dev libxml2-utils xsltproc unzip

2. Download and install the repo client using instructions here.

mkdir ~/bin
PATH=~/bin:$PATH

curl https://storage.googleapis.com/git-repo-downloads/repo > ~/bin/repo
chmod a+x ~/bin/repo

git config --global user.email "you@example.com"
git config --global user.name "Your Name"

3. Download Androidx86 source from here.

mkdir android-x86
cd android-x86

# source download
repo init -u git://gitscm.sf.net/gitroot/android-x86/manifest -b marshmallow-x86
repo sync

4. Alter the configuration

vi kernel/arch/x86/configs/android-x86_defconfig
vi kernel/arch/x86/configs/android-x86_64_defconfig
CONFIG_VIRT_DRIVERS=Y
CONFIG_VIRTIO=y
CONFIG_VIRTIO_PCI=y
CONFIG_VIRTIO_MMIO=m
CONFIG_VIRTIO_BALLOON=m
CONFIG_VIRTIO_BLK=y
CONFIG_VIRTIO_NET=m
CONFIG_VIRTIO_RING=m
CONFIG_VIRTIO_CONSOLE=m
CONFIG_HW_RANDOM_VIRTIO=m
