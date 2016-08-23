#!/bin/bash

CURR_PASS=ubuntu # target user current passwd
CH_PASS=ubuntu # target user change passwd

sudo apt-get install expect -y

filename=/etc/pam.d/common-password
test -f $filename.org || sudo cp $filename $filename.org
sudo sed -i 's/obscure\ /minlen\=1\ /g' $filename

filename=/etc/apt/sources.list
test -f $filename.org || sudo cp $filename $filename.org
#sudo sed -i 's/\/archive.ubuntu.com/\/kr.archive.ubuntu.com/g' $filename
#sudo sed -i 's/\/us.archive.ubuntu.com/\/kr.archive.ubuntu.com/g' $filename

sudo sed -i 's/\/archive.ubuntu.com/\/ftp.daum.net/g' $filename
sudo sed -i 's/\/us.archive.ubuntu.com/\/ftp.daum.net/g' $filename
sudo sed -i 's/\/kr.archive.ubuntu.com/\/ftp.daum.net/g' $filename

sudo apt-get update

SECURE_PASSWD=$(expect -c "
set timeout 3
spawn passwd
 
expect \"(current) UNIX password:\"
send \"$CURR_PASS\r\"
 
expect \"Enter new UNIX password:\"
send \"$CH_PASS\r\"
 
expect \"Retype new UNIX password:\"
send \"$CH_PASS\r\"

expect eof
")
 
echo $SECURE_PASSWD

SECURE_PASSWD=$(expect -c "
set timeout 3
spawn sudo passwd

expect \"password for $USER:\"
send \"$CH_PASS\r\"
 
expect \"Enter new UNIX password:\"
send \"$CH_PASS\r\"
 
expect \"Retype new UNIX password:\"
send \"$CH_PASS\r\"

expect eof
")
 
echo $SECURE_PASSWD

sudo sed -i 's/PermitRootLogin without-password/PermitRootLogin yes/g' /etc/ssh/sshd_config
sudo service ssh restart
