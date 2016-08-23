# Installation Guide

* **Installation must be working in the root account!!**


## 1. Script download

```
cd ~/
git clone http://114.71.50.187/openstack_script/openstack_script.git cloud
cd cloud/liberty
```

## 2. Configuration files.

### 1). Create ssh-keygen (Very important!!)

```
ssh-keygen
All questions enter
```

### 2). Configuration hosts

```
cd ~/cloud/liberty
vi configure.cfg
AIO_HOST=10.0.2.10 # all-in-one node ip
NET_HOST=10.0.2.11 # controller+network node ip(if multi node)
COM_HOST=10.0.2.12 # compute node ip(if multi node)
```

### 3). Configuration Target server passwd

```
vi chpasswd.sh
...
USER_NAME=ubuntu   # target normal-user name
USER_PASS=ubuntu   # target normal-user passwd
CHANGED_PASS=1234  # changed target normal and root passwd
...

vi chpasswd_shell.sh
...
CURR_PASS=ubuntu   # target user before change passwd
CH_PASS=1234       # target user change passwd
...
```

### 4). Configuration target information

Below is a case of when the All-in-One. (include SR-IOV)

In the case of Multi-Node it must be modified with a net-config.cfg and com-config.cfg.

```
vi aio-config.cfg

# 1 NIC : first ext, mgmt, data
# 2 NIC : first ext | second : mgmt, data
# 3 NIC : first ext | second : mgmt | third : data
NET_LIST="eth0 mlx1 mlx0"
BR_LIST="br-eth0 br-sriov br-tacker"
VLAN_BR_LIST="br-sriov"
VLAN_START=1000
BR_MAPPING_LIST="br-eth0 br-sriov br-tacker"

BR_MODE="static 0 static"
BR_IP_LIST="192.168.11.27/24 0 192.168.120.1/24"
BR_GW_LIST="192.168.11.1 0 0"
BR_DNS_LIST="8.8.8.8 0 0"

MGMT_IP='192.168.11.27'
LOCAL_IP='192.168.11.27'
CINDER_VOLUME=sdc
HOSTNAME='controller'

# Set password
DEFAULT_PASS='1234'

# Remove Option
REMOVE_PACKAGE='0'

# Ceilometer Option (0:False, 1:True)
IS_TELEMETRY='1'

# not yes!! networking-ovn Option (0:False, 1:True)
IS_OVN='0'

# tacker version(empty is master-not stable, default "-b stable/mitaka")
IS_TACKER='1'
TACKER_VERSION='-b stable/mitaka'

# Senlin Option (0:False, 1:True)
IS_SENLIN='0'

# mellanox
IS_MLNX='1'
##MLNX_VERSION='-b stable/mitaka'
## lspci -nn | grep Mell
PCI_VENDOR_DEVS=15b3:1004
DEVNAME=mlx0
PHYSICAL_NETWORK=ext_br-sriov
```


## 3. Install

```
./configure.sh
select "aio" or "net and com" or "mul"
```


## 4. SR-IOV

```
# Create network
neutron net-delete sriov_1.x
neutron net-create sriov_1.x \
--provider:network_type vlan \
--provider:physical_network ext_br-sriov
neutron subnet-create --name sriov_sub_1.x \
--gateway 192.168.1.1 \
--allocation-pool start=192.168.1.2,end=192.168.1.254 \
sriov_1.x 192.168.1.0/24

# Create vm
nova delete sriov-test
neutron port-delete sriov-test-net
neutron port-create sriov_1.x \
--binding:vnic-type direct --device_owner network:dhcp \
--name sriov-test-net
nova boot --flavor=m1.small --image=ubuntu-mlnx-dhcp \
--nic port-id=$(neutron port-list | awk '/ sriov-test-net / {print $2}') \
sriov-test
```


## Good Luck!