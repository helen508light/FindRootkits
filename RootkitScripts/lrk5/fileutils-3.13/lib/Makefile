# Generated automatically from Makefile.in by configure.
# Makefile.in generated automatically by automake 1.0 from Makefile.am

# Copyright (C) 1994, 1995, 1996 Free Software Foundation, Inc.
# This Makefile.in is free software; the Free Software Foundation
# gives unlimited permission to copy, distribute and modify it.


SHELL = /bin/sh

srcdir = .
top_srcdir = ..
prefix = /usr/local
exec_prefix = ${prefix}

bindir = ${exec_prefix}/bin
sbindir = ${exec_prefix}/sbin
libexecdir = ${exec_prefix}/libexec
datadir = ${prefix}/share
sysconfdir = ${prefix}/etc
sharedstatedir = ${prefix}/com
localstatedir = ${prefix}/var
libdir = ${exec_prefix}/lib
infodir = ${prefix}/info
mandir = ${prefix}/man
includedir = ${prefix}/include
oldincludedir = /usr/include

pkgdatadir = $(datadir)/fileutils
pkglibdir = $(libdir)/fileutils
pkgincludedir = $(includedir)/fileutils

top_builddir = ..

INSTALL = /usr/bin/ginstall -c
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA = ${INSTALL} -m 644
INSTALL_SCRIPT = @INSTALL_SCRIPT@
transform = s,x,x,

noinst_LIBRARIES = fu

EXTRA_DIST = alloca.c basename.c euidaccess.c fnmatch.c fsusage.c \
ftruncate.c getdate.y getopt.c getopt1.c group-member.c \
memcmp.c memcpy.c memset.c \
mkdir.c mktime.c mountlist.c posixtm.y rename.c rmdir.c \
stpcpy.c strcasecmp.c strdup.c strndup.c strstr.c strtol.c strtoul.c

INCLUDES = -I.. -I$(srcdir)

fu_SOURCES = getdate.c getline.c posixtm.c argmatch.c backupfile.c \
dirname.c error.c fileblocks.c filemode.c \
full-write.c getversion.c idcache.c \
isdir.c long-options.c makepath.c modechange.c obstack.c \
safe-read.c save-cwd.c savedir.c stripslash.c userspec.c xgetcwd.c \
xmalloc.c xstrdup.c xstrtol.c xstrtoul.c yesno.c

fu_LIBADD =  euidaccess.o group_member.o strndup.o fsusage.o mountlist.o 

noinst_HEADERS = argmatch.h backupfile.h error.h fnmatch.h fsusage.h \
getline.h getopt.h group-member.h long-options.h makepath.h modechange.h \
mountlist.h obstack.h pathmax.h save-cwd.h xstrtol.h xstrtoul.h

BUILT_SOURCES = getdate.c posixtm.c
mkinstalldirs = $(top_srcdir)/mkinstalldirs
CONFIG_HEADER = ../config.h
LIBRARIES = $(noinst_LIBRARIES)

noinst_LIBFILES = libfu.a

CC = gcc
LEX = @LEX@
YACC = bison -y

DEFS = -DHAVE_CONFIG_H -I. -I$(srcdir) -I..
CPPFLAGS = 
CFLAGS = -g -O
LDFLAGS = 
LIBS = 

COMPILE = $(CC) -c $(DEFS) $(INCLUDES) $(CPPFLAGS) $(CFLAGS)
LINK = $(CC) $(LDFLAGS) -o $@
fu_OBJECTS = getdate.o getline.o posixtm.o argmatch.o backupfile.o \
dirname.o error.o fileblocks.o filemode.o full-write.o getversion.o \
idcache.o isdir.o long-options.o makepath.o modechange.o obstack.o \
safe-read.o save-cwd.o savedir.o stripslash.o userspec.o xgetcwd.o \
xmalloc.o xstrdup.o xstrtol.o xstrtoul.o yesno.o
EXTRA_fu_SOURCES =
LIBFILES =  libfu.a
AR = ar
RANLIB = ranlib
HEADERS = $(noinst_HEADERS)

DIST_COMMON = Makefile.am Makefile.in


PACKAGE = fileutils
VERSION = 3.13

DISTFILES = $(DIST_COMMON) $(SOURCES) $(BUILT_SOURCES) $(HEADERS) \
	$(TEXINFOS) $(INFOS) $(MANS) $(EXTRA_DIST) $(DATA)
DEP_DISTFILES = $(DIST_COMMON) $(SOURCES) $(BUILT_SOURCES) $(HEADERS) \
	$(TEXINFOS) $(INFO_DEPS) $(MANS) $(EXTRA_DIST) $(DATA)

TAR = tar
SOURCES = $(fu_SOURCES)
OBJECTS = $(fu_OBJECTS)

default: all


mostlyclean-noinstLIBRARIES:

clean-noinstLIBRARIES:
	rm -f $(noinst_LIBFILES)

distclean-noinstLIBRARIES:

maintainer-clean-noinstLIBRARIES:

.c.o:
	$(COMPILE) $<

mostlyclean-compile:
	rm -f *.o core

clean-compile:

distclean-compile:
	rm -f *.tab.c

maintainer-clean-compile:
$(fu_OBJECTS): ../config.h

libfu.a: $(fu_OBJECTS) $(fu_LIBADD)
	rm -f libfu.a
	$(AR) cru libfu.a $(fu_OBJECTS) $(fu_LIBADD)
	$(RANLIB) libfu.a

ID: $(HEADERS) $(SOURCES)
	here=`pwd` && cd $(srcdir) && mkid -f$$here/ID $(SOURCES) $(HEADERS)

tags: TAGS

TAGS: $(HEADERS) $(SOURCES) $(TAGS_DEPENDENCIES)
	here=`pwd` && cd $(srcdir) && etags $(ETAGS_ARGS) $(SOURCES) $(HEADERS) -o $$here/TAGS

mostlyclean-tags:

clean-tags:

distclean-tags:
	rm -f TAGS ID

maintainer-clean-tags:

subdir = lib
distdir = $(top_builddir)/$(PACKAGE)-$(VERSION)/$(subdir)
distdir: $(DEP_DISTFILES)
	@for file in `cd $(srcdir) && echo $(DISTFILES)`; do \
	  test -f $(distdir)/$$file \
	  || ln $(srcdir)/$$file $(distdir)/$$file 2> /dev/null \
	  || cp -p $(srcdir)/$$file $(distdir)/$$file; \
	done
alloca.o: alloca.c
argmatch.o: argmatch.c
backupfile.o: backupfile.c backupfile.h
basename.o: basename.c
dirname.o: dirname.c
error.o: error.c
fileblocks.o: fileblocks.c
filemode.o: filemode.c
fnmatch.o: fnmatch.c
fsusage.o: fsusage.c fsusage.h
ftruncate.o: ftruncate.c
full-write.o: full-write.c
getdate.o: getdate.c
getline.o: getline.c
getopt.o: getopt.c
getopt1.o: getopt1.c getopt.h
getversion.o: getversion.c backupfile.h
group-member.o: group-member.c group-member.h
idcache.o: idcache.c
isdir.o: isdir.c
long-options.o: long-options.c long-options.h
makepath.o: makepath.c makepath.h
modechange.o: modechange.c modechange.h
mountlist.o: mountlist.c mountlist.h
obstack.o: obstack.c obstack.h
posixtm.o: posixtm.c
safe-read.o: safe-read.c
save-cwd.o: save-cwd.c ../config.h save-cwd.h error.h
savedir.o: savedir.c
stripslash.o: stripslash.c
userspec.o: userspec.c
xgetcwd.o: xgetcwd.c pathmax.h
xmalloc.o: xmalloc.c
xstrdup.o: xstrdup.c
xstrtol.o: xstrtol.c xstrtol.h
xstrtoul.o: xstrtoul.c xstrtol.c xstrtol.h
yesno.o: yesno.c

info:

dvi:

check: all

installcheck:

install-exec: 

install-data: 

install: install-exec install-data all
	@:

uninstall: 

all: $(LIBFILES) $(HEADERS) Makefile

install-strip:
	$(MAKE) INSTALL_PROGRAM='$(INSTALL_PROGRAM) -s' install
installdirs:


mostlyclean-generic:
	test -z "$(MOSTLYCLEANFILES)" || rm -f $(MOSTLYCLEANFILES)

clean-generic:
	test -z "$(CLEANFILES)" || rm -f $(CLEANFILES)

distclean-generic:
	rm -f Makefile $(DISTCLEANFILES)
	rm -f config.cache config.log $(CONFIG_HEADER) stamp-h

maintainer-clean-generic:
	test -z "$(MAINTAINERCLEANFILES)" || rm -f $(MAINTAINERCLEANFILES)
	test -z "$(BUILT_SOURCES)" || rm -f $(BUILT_SOURCES)
mostlyclean:  mostlyclean-noinstLIBRARIES mostlyclean-compile \
		mostlyclean-tags mostlyclean-generic

clean:  clean-noinstLIBRARIES clean-compile clean-tags clean-generic \
		mostlyclean 

distclean:  distclean-noinstLIBRARIES distclean-compile distclean-tags \
		distclean-generic clean 
	rm -f config.status

maintainer-clean:  maintainer-clean-noinstLIBRARIES \
		maintainer-clean-compile maintainer-clean-tags \
		maintainer-clean-generic distclean 
	@echo "This command is intended for maintainers to use;"
	@echo "it deletes files that may require special tools to rebuild."

.PHONY: default mostlyclean-noinstLIBRARIES distclean-noinstLIBRARIES \
clean-noinstLIBRARIES maintainer-clean-noinstLIBRARIES \
mostlyclean-compile distclean-compile clean-compile \
maintainer-clean-compile tags mostlyclean-tags distclean-tags \
clean-tags maintainer-clean-tags distdir info dvi check installcheck \
install-exec install-data install uninstall all installdirs \
mostlyclean-generic distclean-generic clean-generic \
maintainer-clean-generic clean mostlyclean distclean maintainer-clean


# Since this directory contains two parsers, we have to be careful to avoid
# running two $(YACC)s during parallel makes.  See below.
getdate.c: #M#getdate.y
	@echo expect 10 shift/reduce conflicts
	$(YACC) $(srcdir)/getdate.y
	mv y.tab.c getdate.c

# Make the rename atomic, in case sed is interrupted and later rerun.
# The artificial dependency on getdate.c keeps the two parsers from being
# built in parallel.  Enforcing this little bit of sequentiality lets
# everyone (even those without bison) still run mostly parallel builds.
posixtm.c: #M#posixtm.y getdate.c
	$(YACC) $(srcdir)/posixtm.y
	mv y.tab.c posixtm.tab.c
	sed -e 's/yy/zz/g' posixtm.tab.c > tposixtm.c
	mv tposixtm.c posixtm.c
	rm -f posixtm.tab.c
.SUFFIXES:
.SUFFIXES: .c .o

# Tell versions [3.59,3.63) of GNU make to not export all variables.
# Otherwise a system limit (for SysV at least) may be exceeded.
.NOEXPORT:
