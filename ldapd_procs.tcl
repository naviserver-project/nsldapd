# Author: Vlad Seryakov vlad@crystalballinc.com
# March 2006

namespace eval ldap {

}

ns_schedule_proc -once 0 ldap::init

# Global LDAP initialization
proc ldap::init {} {

    ns_log Notice ldap::init: loaded
}

# LDAP server handler
proc ldap::server { args } {

    switch -- [ns_ldap reqget opname] {
     bind {
       # Authentication request
       ns_log notice ldap::server: [ns_ldap reqget bind]
     }
     
     search {
       # Search request
       ns_log notice ldap::server: [ns_ldap reqget search]
       ns_log notice ldap:result: [ns_ldap reqresult vlad cn Vlad sn Seryakov email vlad@crystalballinc.com]
     }
     
     default {
       # Set protocolerror for allother requests
       ns_ldap reqset rcname protocolerror
       ns_log notice ldap::server: unknown request: [ns_ldap reqget op]
     }
    }
}

