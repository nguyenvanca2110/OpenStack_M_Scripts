#!/bin/bash

rm -f configure_openstack_vars.sh

source "configure.cfg"
source "configure_openstack_utils.sh"

filename=/etc/hosts
test -f $filename.org || cp $filename $filename.org
rm -f $filename

cfg_log "Set Hosts file"

cat << EOF > $filename
127.0.0.1 localhost
$AIO_HOST aio
$NET_HOST net controller
$COM_HOST com compute
EOF

#############################################################################
#############################################################################
function openstack_aio
{
	rm -f openstack_aio.tar.gz
	
	tar cvpf openstack_aio.tar \
	configure_openstack.sh \
	configure_openstack_utils.sh \
        event_definitions.yaml \
        event_pipeline.yaml \
	aio-*.sh \
	aio-config.cfg
}

function openstack_net
{
	rm -f openstack_net.tar.gz
	
	tar cvpf openstack_net.tar \
	configure_openstack.sh \
	configure_openstack_utils.sh \
        event_definitions.yaml \
        event_pipeline.yaml \
	net-*.sh \
	net-config.cfg
}

function openstack_com
{
	rm -f openstack_com.tar.gz
	
	tar cvpf openstack_com.tar \
	configure_openstack.sh \
	configure_openstack_utils.sh \
        event_definitions.yaml \
        event_pipeline.yaml \
	com-*.sh \
	com-config.cfg
}
#############################################################################
#############################################################################
echo -n "Which node are you remote configuring? (aio,mul,net,com): "
cfg_read_var OpenStack_node

openstack_install=
nodes=()

case "$OpenStack_node" in

	"aio")
		cfg_log "Create openstack_aio.tar.gz for $OpenStack_node"
		openstack_aio
		gzip openstack_aio.tar
		nodes=(aio)
		;;
	
	"mul")
		cfg_log "Create openstack_net.tar.gz openstack_com.tar.gz for $OpenStack_node"
		openstack_net
		openstack_com
		gzip openstack_net.tar
		gzip openstack_com.tar
		nodes=(net com)
		;;

	"net")
		cfg_log "Create openstack_net.tar.gz for $OpenStack_node"
		openstack_net
		gzip openstack_net.tar
		nodes=(net)
		;;

	"com")
		cfg_log "Create openstack_com.tar.gz for $OpenStack_node"
		openstack_com
		gzip openstack_com.tar
		nodes=(com)
		;;
	*)
	openstack_install=false
	cfg_log "Configure system not implemented for node $OpenStack_node !"
esac

#############################################################################

if [ -z $openstack_install ]; then

for x in "${nodes[@]}"
do
	./chpasswd.sh $x

	cfg_log "Remote Copy to $x-node"
	scp openstack_$x.tar.gz root@$x:~/
	rm -f openstack_$x.tar.gz

	cfg_log "Connection to install $x OpenStack"
ssh -ttq -o "BatchMode yes" root@$x bash -c "'

	mkdir -p install_script
	cd install_script
	mv ../openstack_$x.tar.gz .

	tar xvfz openstack_$x.tar.gz

	./configure_openstack.sh $x

	cd ../
	
	rm -rf install_script
'"
done

fi
