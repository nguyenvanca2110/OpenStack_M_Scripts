#!/bin/bash

source "configure_openstack_utils.sh"

OpenStack_node=$1

get_distrib
if [ "$DISTRIB" == "CentOS" ]; then
	cfg_log "Target OS is CentOS"
elif [ "$DISTRIB" == "Ubuntu" ]; then
	cfg_log "Target OS is Ubuntu"
fi

case "$OpenStack_node" in

	"aio")
		for i in {00..15}
		do
			script_name=`ls aio-$i-*.sh`
			total_len=`expr "$script_name" : '.*'`
			cfg_log "#################################################"
			cfg_log "## Installing ${script_name:7:$(($total_len-10))}"
			cfg_log "#################################################"
			./aio-$i-*.sh
		done
		##./aio-00-network.sh
		##./aio-01-prepare.sh
		##./aio-02-mariadb.sh
		##./aio-03-keystone.sh
		##./aio-04-tenant.sh
		##./aio-05-glance.sh
		##./aio-06-nova.sh
		##./aio-07-cinder.sh
		##./aio-08-neutron-ovn.sh
		##./aio-09-neutron-ovn.sh
		##./aio-10-heat.sh
		##./aio-11-ceilometer.sh
		##./aio-12-alarming.sh
		##./aio-13-horizon.sh
		##./aio-14-tacker.sh
		reboot
		;;

	"net")
		for i in {00..14}
		do
			script_name=`ls net-$i-*.sh`
			total_len=`expr "$script_name" : '.*'`
			cfg_log "#################################################"
			cfg_log "## Installing ${script_name:7:$(($total_len-10))}"
			cfg_log "#################################################"
			./net-$i-*.sh
		done
		reboot
		;;

	"com")
		for i in 00 01 06 07 08 09 11
		do
			script_name=`ls com-$i-*.sh`
			total_len=`expr "$script_name" : '.*'`
			cfg_log "#################################################"
			cfg_log "## Installing ${script_name:7:$(($total_len-10))}"
			cfg_log "#################################################"
			./com-$i-*.sh
		done
		##./com-00-network.sh
		##./com-01-prepare.sh
		##./com-06-nova.sh
		##./com-07-cinder.sh
		##./com-08-neutron-ovn.sh
		##./com-09-neutron.sh
		##./com-11-ceilomiter.sh
		reboot
		;;
	*)
	cfg_log "Configure system not implemented for node $OpenStack_node !"

esac

exit 0
