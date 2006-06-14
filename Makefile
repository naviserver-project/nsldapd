ifndef NAVISERVER
    NAVISERVER  = /usr/local/ns
endif

#
# Module name
#
MOD      =  nsldapd.so

#
# Objects to build.
#
OBJS     = nsldapd.o

PROCS   = ldapd_procs.tcl

INSTALL += install-procs

include  $(NAVISERVER)/include/Makefile.module

install-procs: $(PROCS)
	for f in $(PROCS); do $(INSTALL_SH) $$f $(INSTTCL)/; done


