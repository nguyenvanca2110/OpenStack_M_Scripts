#!/bin/bash
OpenStack_vars_file="configure_openstack_vars.sh"

bold=$(tput bold)					# Bold
bold_white=${bold}$(tput setaf 7)	# white color
txtrst=$(tput sgr0)					# Reset

function cfg_log
{
	echo "$bold_white OpenStack >>> $@ $txtrst"
}
function cfg_write_vars
{
    echo -e "$1=\"${@:2}\"\n" >> $OpenStack_vars_file
}
function cfg_read_var
{
    var_name="$1"
    eval var_value=\$$1
    if [ -z "$var_value" ] ; then
      read $var_name
      eval var_value=\$$var_name
      cfg_write_vars $1 $var_value
    else
      echo "$var_value (auto-filled from $OpenStack_vars_file)"
    fi
}
get_distrib()
{
	DISTRIB=`cat /etc/*release | grep 'DISTRIB_ID=' | cut -d '=' -f 2`
	if [ -z "$DISTRIB" ]; then
		DISTRIB=`head -n 1 /etc/issue | cut -f 1`
	fi
}

if [ -e "$OpenStack_vars_file" ] ; then
  source $OpenStack_vars_file
else
  echo -e "#!/bin/bash \n# This files stores the variables learned through user interactions. Delete file to trigger a rebuild\n" > $OpenStack_vars_file
fi
