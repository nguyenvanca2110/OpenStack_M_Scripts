#!/bin/bash

## target host address
## target1 or "target1 target2 ..."
ADDRESSES=$1

USER_NAME=ubuntu ## target user name
USER_PASS=ubuntu ## target user passwd
CHANGED_PASS=ubuntu ## changed target passwd

echo change node [$ADDRESSES]

#PORT=$2
#if [ -z $PORT ]; then
	PORT=22
#fi

if [ -z $ADDRESSES ]; then
	echo "usage : ./chpasswd.sh [target_addresses]"
	exit 0
fi

if [ ! -f ~/.ssh/id_rsa ]; then
	echo "usage : ssh-keygen"
	exit 0
fi

targets=($ADDRESSES)

apt-get install expect -y
rm -f ~/.ssh/known_hosts

##################################
## copy .ssh/id_rsa.pub
for ADDRESS in "${targets[@]}"
do
expect -c "
set timeout 3
spawn ssh-copy-id $USER_NAME@$ADDRESS

expect \"Are you sure you want to continue connecting (yes/no)? \"
send \"yes\r\"

expect \"$USER_NAME@$ADDRESS's password:\"
send \"$USER_PASS\r\"

expect eof"
done


##################################
## change passwd
for ADDRESS in "${targets[@]}"
do
scp -P $PORT chpasswd_shell.sh $USER_NAME@$ADDRESS:~/

ssh -ttq -o "BatchMode yes" $USER_NAME@$ADDRESS bash -c "'
./chpasswd_shell.sh
rm -f chpasswd_shell.sh
'"
done

##################################
## copy .ssh/id_rsa.pub
for ADDRESS in "${targets[@]}"
do
expect -c "
set timeout 3
spawn ssh-copy-id root@$ADDRESS

expect \"root@$ADDRESS's password:\"
send \"$CHANGED_PASS\r\"

expect eof"
done
