# Welcome!

OpenStack Installation script by DCN Lab

* **Version:** Mitaka

* **Install mode:** All-in-One(only one box), Multi mode(controller+networks and compute node)

Add *Tacker module* to All-in-One mode.

### default tenant network *"vxlan"* and  *"securitygroup"* remove

```
vi /etc/neutron/plugins/ml2/ml2_conf.ini
...
tenant_network_types = flat,vxlan,gre,vlan

...
#enable_security_group = True
#enable_ipset = True
...
```


## Installation:

Installation instructions:

http://114.71.50.187/openstack_script/openstack_script/blob/master/liberty/INSTALL.md


## Issues:

Please report issue at:

http://114.71.50.187/openstack_script/openstack_script/issues


## External Resources:

OpenStack document:

http://docs.openstack.org/

Tacker git:

https://github.com/openstack/tacker

Tacker test guide:

http://114.71.50.187/openstack_script/openstack_script/blob/master/liberty/TACKER_GUIDE.md

For help on usage, please send mail to

<mailto:chonti@dcn.ssu.ac.kr> chonti.
