# Welcome!

OpenStack Installation script by DCN Lab

* **Current Version:** Mitaka
// Assume that your IPv4 address is 192.168.10.14

Case: All-in-One
1. Edit file "aio-configure.conf"
"
NET_LIST="eth0"
BR_LIST="br-ext br-tacker" # Tacker IP is any address
VLAN_BR_LIST="br-ext"
VLAN_START=1000
BR_MAPPING_LIST="br-ext br-tacker"

BR_MODE="static static"
BR_IP_LIST="192.168.10.14/24 192.168.120.1/24" # Tacker IP Tacker is any address
BR_GW_LIST="192.168.10.1 0"
BR_DNS_LIST="8.8.8.8 0"

MGMT_IP='192.168.10.14'
LOCAL_IP='192.168.10.14'
CINDER_VOLUME=sdc1
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
IS_MLNX='0'
##MLNX_VERSION='-b stable/mitaka'
## lspci -nn | grep Mell
PCI_VENDOR_DEVS=15b3:1004
DEVNAME=mlx0
PHYSICAL_NETWORK=ext_br-sriov
"


2. Edit file "chpass.sh"

USER_NAME=ubuntu ## target user name
USER_PASS=1 ## target user passwd
CHANGED_PASS=1234 ## changed target passwd

3. Edit file "chpass_shell.sh"

USER_PASS=1 ## target user passwd
CHANGED_PASS=1234 ## changed target passwd

4. Edit file "configure.conf"




