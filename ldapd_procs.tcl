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
       array set req [ns_ldap reqget search]
       ns_log notice ldap::server: [array get req]
       ns_log notice ldap::server: tcl: [ldap::build_filter_tcl $req(filter) "\$%s"]
       ns_log notice ldap::server: sql: [ldap::build_filter_sql $req(filter) "attrname='%s' AND attrvalue"]
       #ns_ldap reqresult vlad cn "Vlad Seryakov" mail vlad@crystalballinc.com
     }
     
     default {
       # Set protocolerror for allother requests
       ns_ldap reqset rcname protocolerror
       ns_log notice ldap::server: unknown request: [ns_ldap reqget op]
     }
    }
}


# Build Tcl code from the filter, tmpl is how to substitute/convert
# attribute name which is specified by %s, i.e. "\$%s" or \[varname %s\]
proc ldap::build_filter_tcl { filter tmpl { op && } } {

    set code ""
    foreach { left oper right } $filter {
      if { $code != "" } { append code " " $op " " }
      set var [string map [list %s $left] $tmpl]
      switch -- $oper {
       | { append code "([ldap::build_filter_tcl $right $tmpl ||])" }
       
       & { append code "([ldap::build_filter_tcl $right $tmpl])" }
       
       ! { append code "!([ldap::build_filter_tcl $right $tmpl])" }
       
       == -
       <= -
       >= { append code "($var $oper {$right})" }
       
       prefix { append code "(\[string match -nocase {$right*} $var\])" }
       
       suffix { append code "(\[string match -nocase {*$right} $var\])" }
       
       exists -
       approx -
       substr { append code "(\[string match -nocase {*$right*} $var\])" }
      }
    }
    return $code
}

# Build SQL code from the filter, tmpl is how to substitute/convert
# attribute name which is specified by %s, i.e. "attrname='%s' AND attrvalue" or "attr_value('%s')"
proc ldap::build_filter_sql { filter tmpl { op AND } } {

    set code ""
    foreach { left oper right } $filter {
      if { $code != "" } { append code " " $op " " }
      set var [string map [list %s $left] $tmpl]
      switch -- $oper {
       | { append code "([ldap::build_filter_sql $right $tmpl OR])" }
       
       & { append code "([ldap::build_filter_sql $right $tmpl])" }
       
       ! { append code "NOT ([ldap::build_filter_sql $right $tmpl])" }
       
       == { append code "($var = '$right')" }

       <= -
       >= { append code "($var $oper '$right')" }
       
       prefix { append code "($var ILIKE '$right%')" }
       
       suffix { append code "($var ILIKE '%$right')" }
       
       exists -
       approx -
       substr { append code "($var ILIKE '%$right%')" }
      }
    }
    return $code
}
