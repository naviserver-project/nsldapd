/*
 * The contents of this file are subject to the Mozilla Public License
 * Version 1.1 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 * http://www.mozilla.org/.
 *
 * Software distributed under the License is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
 * the License for the specific language governing rights and limitations
 * under the License.
 *
 * Based on TinyLDAP from http://www.fefe.de/tinyldap/
 * Thanks to Felix von Leitner <web@fefe.de>
 *
 * Copyright (C) 2001-2006 Vlad Seryakov
 * All rights reserved.
 *
 * Alternatively, the contents of this file may be used under the terms
 * of the GNU General Public License (the "GPL"), in which case the
 * provisions of GPL are applicable instead of those above.  If you wish
 * to allow use of your version of this file only under the terms of the
 * GPL and not to allow others to use your version of this file under the
 * License, indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by the GPL.
 * If you do not delete the provisions above, a recipient may use your
 * version of this file under either the License or the GPL.
 *
 * LDAPv3 (RFC2251)
 *
 *
 *      LDAPMessage ::= SEQUENCE {
 *
 *              messageID       MessageID,
 *              protocolOp      CHOICE {
 *                      bindRequest     BindRequest,
 *                      bindResponse    BindResponse,
 *                      unbindRequest   UnbindRequest,
 *                      searchRequest   SearchRequest,
 *                      searchResEntry  SearchResultEntry,
 *                      searchResDone   SearchResultDone,
 *                      searchResRef    SearchResultReference,
 *                      modifyRequest   ModifyRequest,
 *                      modifyResponse  ModifyResponse,
 *                      addRequest      AddRequest,
 *                      addResponse     AddResponse,
 *                      delRequest      DelRequest,
 *                      delResponse     DelResponse,
 *                      modDNRequest    ModifyDNRequest,
 *                      modDNResponse   ModifyDNResponse,
 *                      compareRequest  CompareRequest,
 *                      compareResponse CompareResponse,
 *                      abandonRequest  AbandonRequest,
 *                      extendedReq     ExtendedRequest,
 *                      extendedResp    ExtendedResponse
 *               },
 *               controls       [0] Controls OPTIONAL
 *      }
 *
 *      MessageID ::= INTEGER (0 .. maxInt)
 *
 *      maxInt INTEGER ::= 2147483647 -- (2^^31 - 1) --
 *
 *      LDAPString ::= OCTET STRING
 *
 *      Referral ::= SEQUENCE OF LDAPURL        (one or more)
 *
 *      LDAPURL ::= LDAPString                  (limited to URL chars)
 *
 *      LDAPOID ::= OCTET STRING
 *
 *      AttributeType ::= LDAPString
 *
 *      LDAPDN ::= LDAPString
 *
 *      RelativeLDAPDN ::= LDAPString
 *
 *      AttributeDescription ::= <AttributeType> [ ";" <options> ]
 *
 *      AttributeValueAssertion ::= SEQUENCE {
 *               attributeDesc   AttributeDescription,
 *               assertionValue  AssertionValue
 *      }
 *
 *      AssertionValue ::= OCTET STRING
 *
 *      Attribute ::= SEQUENCE {
 *              type    AttributeDescription,
 *              vals    SET OF AttributeValue
 *      }
 *
 *      MatchingRuleId ::= LDAPString
 *
 *
 *      BindRequest ::= SEQUENCE {
 *              version         INTEGER,
 *              name            DistinguishedName,       -- who
 *              authentication  CHOICE {
 *                      simple          [0] OCTET STRING -- passwd
 *                      krbv42ldap      [1] OCTET STRING
 *                      krbv42dsa       [2] OCTET STRING
 *                      sasl            [3] SaslCredentials
 *              }
 *      }
 *
 *      BindResponse ::= SEQUENCE {
 *              COMPONENTS OF LDAPResult,
 *              serverSaslCreds         OCTET STRING OPTIONAL
 *      }
 *
 *      SearchRequest := [APPLICATION 3] SEQUENCE {
 *              baseObject      DistinguishedName,
 *              scope           ENUMERATED {
 *                      baseObject      (0),
 *                      singleLevel     (1),
 *                      wholeSubtree    (2)
 *              },
 *              derefAliases    ENUMERATED {
 *                      neverDerefaliases       (0),
 *                      derefInSearching        (1),
 *                      derefFindingBaseObj     (2),
 *                      alwaysDerefAliases      (3)
 *              },
 *              sizelimit       INTEGER (0 .. 65535),
 *              timelimit       INTEGER (0 .. 65535),
 *              attrsOnly       BOOLEAN,
 *              filter          Filter,
 *              attributes      SEQUENCE OF AttributeType
 *      }
 *
 *      SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
 *              objectName      LDAPDN,
 *
 *              attributes      PartialAttributeList
 *      }
 *
 *      PartialAttributeList ::= SEQUENCE OF SEQUENCE {
 *              type    AttributeDescription,
 *              vals    SET OF AttributeValue
 *      }
 *
 *      Filter ::= CHOICE {
 *              and             [0]     SET OF Filter,
 *              or              [1]     SET OF Filter,
 *              not             [2]     Filter,
 *              equalityMatch   [3]     AttributeValueAssertion,
 *              substrings      [4]     SubstringFilter,
 *              greaterOrEqual  [5]     AttributeValueAssertion,
 *              lessOrEqual     [6]     AttributeValueAssertion,
 *              present         [7]     AttributeType,
 *              approxMatch     [8]     AttributeValueAssertion,
 *              extensibleMatch [9]     MatchingRuleAssertion
 *      }
 *
 *      SubstringFilter ::= SEQUENCE {
 *              type               AttributeType,
 *              SEQUENCE OF CHOICE {
 *                      initial          [0] IA5String,
 *                      any              [1] IA5String,
 *                      final            [2] IA5String
 *              }
 *      }
 *
 *      MatchingRuleAssertion ::= SEQUENCE {
 *              matchingRule    [1] MatchingRuleId OPTIONAL,
 *              type            [2] AttributeDescription OPTIONAL,
 *              matchValue      [3] AssertionValue,
 *              dnAttributes    [4] BOOLEAN DEFAULT FALSE
 *      }
 *
 *      LDAPResult ::= SEQUENCE {
 *              resultCode              ENUMERATED { ... },
 *              matchedDN               LDAPDN,
 *              errorMessage            LDAPString,
 *              referral                Referral OPTIONAL
 *      }
 */

/*
 * nsldapd.c -- LDAP  server
 *
 * Authors
 *
 *     Vlad Seryakov vlad@crystalballinc.com
 */

#include "ns.h"
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <netdb.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <string.h>

typedef enum ASN1TagClass {
  CLASS_UNIVERSAL        = (0<<6),
  CLASS_APPLICATION      = (1<<6),
  CLASS_PRIVATE          = (2<<6),
  CLASS_CONTEXT_SPECIFIC = (3<<6)
} ASN1TagClass;

typedef enum ASN1TagType {
  TYPE_PRIMITIVE         = (0<<5),
  TYPE_CONSTRUCTED       = (1<<5)
} ASN1TagType;

typedef enum ASN1Tag {
  TAG_BOOLEAN            = 1,
  TAG_INTEGER            = 2,
  TAG_OCTET_STRING       = 4,
  TAG_ENUMERATED         = 10,
  TAG_SEQUENCE_OF        = 16,
  TAG_SET_OF             = 17,
} ASN1Tag;

typedef enum FilterType {
  AND                    = 0,
  OR                     = 1,
  NOT                    = 2,
  EQUAL                  = 3,
  SUBSTRING              = 4,
  GREATEQUAL             = 5,
  LESSEQUAL              = 6,
  PRESENT                = 7,
  APPROX                 = 8,
  EXTENSIBLE             = 9
} FilterType;

typedef enum FilterExtType {
  FILTER_EXT_OID         = 1,
  FILTER_EXT_TYPE        = 2,
  FILTER_EXT_DNATTRS     = 4
} FilterExtType;

typedef enum LDAPOp {
  OP_BINDREQUEST         = 0,
  OP_BINDRESPONSE        = 1,
  OP_UNBINDREQUEST       = 2,
  OP_SEARCHREQUEST       = 3,
  OP_SEARCHRESULTENTRY   = 4,
  OP_SEARCHRESULTDONE    = 5,
  OP_MODIFYREQUEST       = 6,
  OP_MODIFYRESPONSE      = 7,
  OP_ADDREQUEST          = 8,
  OP_ADDRESPONSE         = 9,
  OP_DELREQUEST          = 10,
  OP_DELRESPONSE         = 11,
  OP_MODIFYDNREQUEST     = 12,
  OP_MODIFYDNRESPONSE    = 13,
  OP_COMPAREREQUEST      = 14,
  OP_COMPARERESPONSE     = 15,
  OP_ABANDONREQUEST      = 16,
  OP_EXTENDEDREQUEST     = 23,
  OP_EXTENDEDRESPONSE    = 24
} LDAPOp;

typedef enum LDAPError {
  LDAP_SUCCESS                       = 0,
  LDAP_OPERATIONSERROR               = 1,
  LDAP_PROTOCOLERROR                 = 2,
  LDAP_TIMELIMITEXCEEDED             = 3,
  LDAP_SIZELIMITEXCEEDED             = 4,
  LDAP_COMPAREFALSE                  = 5,
  LDAP_COMPARETRUE                   = 6,
  LDAP_AUTHMETHODNOTSUPPORTED        = 7,
  LDAP_STRONGAUTHREQUIRED            = 8,
  LDAP_REFERRAL                      = 10,
  LDAP_ADMINLIMITEXCEEDED            = 11,
  LDAP_UNAVAILABLECRITICALEXTENSION  = 12,
  LDAP_CONFIDENTIALITYREQUIRED       = 13,
  LDAP_SASLBINDINPROGRESS            = 14,
  LDAP_NOSUCHATTRIBUTE               = 16,
  LDAP_UNDEFINEDATTRIBUTETYPE        = 17,
  LDAP_INAPPROPRIATEMATCHING         = 18,
  LDAP_CONSTRAINTVIOLATION           = 19,
  LDAP_ATTRIBUTEORVALUEEXISTS        = 20,
  LDAP_INVALIDATTRIBUTESYNTAX        = 21,
  LDAP_NOSUCHOBJECT                  = 32,
  LDAP_ALIASPROBLEM                  = 33,
  LDAP_INVALIDDNSYNTAX               = 34,
  LDAP_ALIASDEREFERENCINGPROBLEM     = 36,
  LDAP_INAPPROPRIATEAUTHENTICATION   = 48,
  LDAP_INVALIDCREDENTIALS            = 49,
  LDAP_INSUFFICIENTACCESSRIGHTS      = 50,
  LDAP_BUSY                          = 51,
  LDAP_UNAVAILABLE                   = 52,
  LDAP_UNWILLINGTOPERFORM            = 53,
  LDAP_LOOPDETECT                    = 54,
  LDAP_NAMINGVIOLATION               = 64,
  LDAP_OBJECTCLASSVIOLATION          = 65,
  LDAP_NOTALLOWEDONNONLEAF           = 66,
  LDAP_NOTALLOWEDONRDN               = 67,
  LDAP_ENTRYALREADYEXISTS            = 68,
  LDAP_OBJECTCLASSMODSPROHIBITED     = 69,
  LDAP_AFFECTSMULTIPLEDSAS           = 71,
} LDAPError;

#define MAX_OPS                      25
#define MAX_BINDS                    4
#define MAX_ERRORS                   72

typedef struct String {
   const char* s;
   uint32_t l;
} String;

typedef struct Substring {
   struct Substring* next;
   enum {
     prefix = 0,
     any = 1,
     suffix = 2
   } substrtype;
   String s;
} Substring;

typedef struct Attribute {
   struct Attribute *next;
   String name;
} Attribute;

typedef struct AttributeValues {
   struct AttributeValues* next;
   String type;
   Attribute *values;
} AttributeValues;

typedef struct Filter {
   struct Filter *next;
   struct Filter *subject;
   FilterType type;
   String name;
   String value;
   Substring *substrings;
   uint32_t flags;
} Filter;

typedef struct SearchResultEntry {
   String objectName;
   AttributeValues *attributes;
} SearchResultEntry;

typedef struct Modify {
   struct Modify* next;
   enum {
     Add = 0,
     Delete = 1,
     Replace = 2
   } operation;
   String attribute;
   Attribute *values;
} Modify;

typedef struct BindRequest {
   uint32_t version;
   uint32_t method;
   String name;
   String password;
   String mechanism;
} BindRequest;

typedef struct BindResponse {
   uint32_t result;
   String matcheddn;
   String errmsg;
   String referral;
} BindResponse;

typedef struct SearchRequest {
   enum {
     baseObject = 0,
     singleLevel = 1,
     wholeSubtree = 2
   } scope;
   enum {
     neverDerefAliases = 0,
     derefInSearching = 1,
     derefFindingBaseObj = 2,
     derefAlways = 3
   } derefAliases;
   String baseObject;
   uint32_t sizeLimit;
   uint32_t timeLimit;
   uint32_t typesOnly;
   Filter *filter;
   Attribute *attributes;
} SearchRequest;

typedef struct ModifyRequest {
   String object;
   Modify *m;
} ModifyRequest;

typedef struct LDAPServer {
   char *name;
   int drivermode;
   int threadmode;
   int sendwait;
   int recvwait;
   int debug;
   int sock;
   int port;
   char *address;
   char *proc;
} LDAPServer;

typedef struct LDAPRequest {
   LDAPServer *server;
   struct sockaddr_in sa;
   Ns_DString ds;
   int sock;
   uint32_t op;
   uint32_t msgid;
   uint32_t msglen;
   struct {
     uint32_t rc;
     char *dn;
     char *errmsg;
     char *referral;
   } reply;
   union {
     BindRequest bind;
     SearchRequest search;
     ModifyRequest modify;
   };
} LDAPRequest;

int ldap_process(LDAPRequest *req);


static Ns_SockProc LDAPSockProc;
static Ns_DriverProc LDAPDriverProc;
static LDAPRequest *LDAPRequestNew(LDAPServer *server);
static void LDAPRequestProcess(LDAPRequest *arg);
static void LDAPRequestFree(LDAPRequest *req);
static int LDAPRequestProc(void *arg, Ns_Conn *conn);
static int LDAPRequestReply(LDAPRequest *req, char *buf, int op);
static int LDAPRequestReplySRE(LDAPRequest *req, SearchResultEntry *sre);
static void LDAPRequestTcl(LDAPRequest *req);
static int LDAPInterpInit(Tcl_Interp *interp, void *arg);
static int LDAPCmd(ClientData arg, Tcl_Interp *interp,int objc,Tcl_Obj *CONST objv[]);

static uint32_t scan_ldapstring(const char* src, const char* max,String* s);
static uint32_t scan_ldapmessage(const char* src, const char* max, uint32_t* messageid,uint32_t* op, uint32_t* len);
static uint32_t scan_ldapbindrequest(const char* src, const char* max, BindRequest *bind);
static uint32_t scan_ldapbindresponse(const char* src, const char* max, BindResponse *bind);
static uint32_t scan_ldapsearchfilter(const char* src, const char* max, Filter** f);
static uint32_t scan_ldapsearchrequest(const char* src, const char* max, SearchRequest* s);
static uint32_t scan_ldapsearchresultentry(const char* src, const char* max, SearchResultEntry* sre);
static uint32_t scan_ldapresult(const char* src, const char* max, uint32_t* result, String *matcheddn, String *errmsg, String *referral);
static uint32_t scan_ldapmodifyrequest(const char* src,const char* max, ModifyRequest* m);
static uint32_t scan_ldapaddrequest(const char * src, const char * max, ModifyRequest * a);
static uint32_t scan_ldapsearchfilterstring(const char* src, Filter** f);

static uint32_t fmt_ldapstring(char* dest, String* s);
static uint32_t fmt_ldapmessage(char* dest, long messageid, long op, long len);
static uint32_t fmt_ldapbindrequest(char* dest, long version, char* name,char* simple);
static uint32_t fmt_ldapsearchfilter(char* dest, Filter* f);
static uint32_t fmt_ldapsearchrequest(char* dest, SearchRequest* s);
static uint32_t fmt_ldapsearchresultentry(char* dest, SearchResultEntry* sre);
static uint32_t fmt_ldapresult(char* dest, long result, char* matcheddn, char* errmsg, char* referral);
static uint32_t fmt_ldapattrval(char* dest, AttributeValues* pal);
static uint32_t fmt_ldapattr(char* dest, Attribute* adl);
static uint32_t fmt_ldapavl(char* dest, Attribute* adl);
static uint32_t fmt_ldapsearchfilterstring(char* dest, Filter* f);

#define fmt_str(s) (s ? s : "")
#define fmt_asn1OCTETSTRING(dest,c,l) fmt_asn1string(dest, CLASS_UNIVERSAL, TYPE_PRIMITIVE, TAG_OCTET_STRING, c, l)
#define fmt_asn1INTEGER(dest,l) fmt_asn1int(dest, CLASS_UNIVERSAL, TYPE_PRIMITIVE, TAG_INTEGER, l)
#define fmt_asn1BOOLEAN(dest,l) fmt_asn1int(dest, CLASS_UNIVERSAL, TYPE_PRIMITIVE, TAG_BOOLEAN, l)
#define fmt_asn1ENUMERATED(dest,l) fmt_asn1int(dest, CLASS_UNIVERSAL, TYPE_PRIMITIVE, TAG_ENUMERATED, l)
#define fmt_asn1SEQUENCE(dest,l) fmt_asn1transparent(dest, CLASS_UNIVERSAL, TYPE_CONSTRUCTED, TAG_SEQUENCE_OF, l)
#define fmt_asn1SET(dest,l) fmt_asn1transparent(dest, CLASS_UNIVERSAL, TYPE_CONSTRUCTED, TAG_SET_OF, l)

static void free_ldapattr(Attribute* a);
static void free_ldapattrval(AttributeValues* a);
static void free_ldapfilter(Filter* f);
static void free_ldapsearchrequest(SearchRequest* s);
static void free_ldapmodifyrequest(ModifyRequest* m);
static void free_ldapaddrequest(ModifyRequest * a);
static void free_ldapsearchresultentry(SearchResultEntry* e);

static uint32_t fmt_asn1tag(char* dest, ASN1TagClass tc, ASN1TagType tt, uint32_t tag);
static uint32_t fmt_asn1length(char* dest, uint32_t l);
static uint32_t fmt_asn1intpayload(char* dest, uint32_t l);
static uint32_t fmt_asn1sintpayload(char* dest, signed long l);
static uint32_t fmt_asn1int(char* dest, ASN1TagClass tc, ASN1TagType tt, ASN1Tag tag, uint32_t l);
static uint32_t fmt_asn1sint(char* dest, ASN1TagClass tc, ASN1TagType tt, ASN1Tag tag, signed long l);
static uint32_t fmt_asn1transparent(char* dest, ASN1TagClass tc, ASN1TagType tt, ASN1Tag tag, uint32_t l);
static uint32_t fmt_asn1string(char* dest, ASN1TagClass tc, ASN1TagType tt, ASN1Tag tag, const char* c, uint32_t l);

static uint32_t scan_asn1tag(const char* src,const char* max, ASN1TagClass* tc,ASN1TagType* tt, uint32_t* tag);
static uint32_t scan_asn1length(const char* src,const char* max,uint32_t* length);
static uint32_t scan_asn1int(const char* src,const char* max, ASN1TagClass* tc,ASN1TagType* tt, uint32_t* tag, long* l);
static uint32_t scan_asn1rawint(const char* src, const char* max, uint32_t len,long* i);
static uint32_t scan_asn1string(const char* src, const char* max, ASN1TagClass* tc,ASN1TagType* tt,uint32_t* tag, const char** s,uint32_t* l);
static uint32_t scan_asn1BOOLEAN(const char* src, const char* max, uint32_t* l);
static uint32_t scan_asn1INTEGER(const char* src, const char* max, signed long* l);
static uint32_t scan_asn1ENUMERATED(const char* src, const char* max, uint32_t* l);
static uint32_t scan_asn1STRING(const char* src, const char* max,const char** s, uint32_t* l);
static uint32_t scan_asn1SEQUENCE(const char* src, const char* max, uint32_t* len);
static uint32_t scan_asn1SET(const char* src, const char* max, uint32_t* len);

static void print_ldapfilter(Ns_DString *ds, Filter* f, int clear);
static void print_ldapsearch(Ns_DString *ds, SearchRequest* s, int clear);
static void print_ldapbind(Ns_DString *ds, BindRequest* b, int clear);
static void print_ldapmodify(Ns_DString *ds, ModifyRequest* m, int clear);

const char* ldapScopes[] = { "baseObject", "singleLevel", "wholeSubtree" };
const char* ldapAliases[] = { "neverDerefAliases", "derefInSearching", "derefFindingBaseObj", "derefAlways" };
const char *ldapBinds[] = { "simple", "1", "2", "sasl" };
const char *ldapOps[] = { "bind", "bind", "unbind", "search", "searchresultentry", "searchresultdone", "modify",
                          "modify","add", "add", "del", "del", "modifydn", "modifydn", "compare", "compare",
                          "abandon", "17", "18", "19", "20", "21", "22", "extended", "extended" };
const char *ldapErrors[] = { "success", "operationserror", "protocolerror", "timelimitexceeded", "sizelimitexceeded",
                             "comparefalse", "comparetrue", "authmethodnotsupported", "strongauthrequired", "referral",
                             "adminlimitexceeded", "unavailablecriticalextension", "confidentialityrequired",
                             "saslbindinprogress", "nosuchattribute", "undefinedattributetype",  "inappropriatematching",
                             "constraintviolation", "attributeorvalueexists", "invalidattributesyntax",
                             "22", "23", "24", "25", "26", "27", "28", "29", "30", "31", "nosuchobject", "aliasproblem",
                             "invaliddnsyntax", "35", "aliasdereferencingproblem", "37", "38", "39", "40", "41", "42",
                             "43", "44", "45", "46", "47", "inappropriateauthentication", "invalidcredentials", "insufficientaccessrights",
                             "busy", "unavailable", "unwillingtoperform", "loopdetect", "55","56","57","58","59","60","61","62","63",
                             "namingviolation", "objectclassviolation", "notallowedonnonleaf", "notallowedonrdn", "entryalreadyexists",
                             "objectclassmodsprohibited", "affectsmultipledsas" };

static Ns_Tls ldapTls;

NS_EXPORT int Ns_ModuleVersion = 1;

NS_EXPORT int Ns_ModuleInit(char *server, char *module)
{
    char *path;
    LDAPServer *srvPtr;
    Ns_DriverInitData init;
    static int initialized = 0;

    if (!initialized) {
        initialized = 1;
        Ns_TlsAlloc(&ldapTls, 0);
    }

    srvPtr = ns_calloc(1, sizeof(LDAPServer));
    path = Ns_ConfigGetPath(server, module, NULL);
    if (!Ns_ConfigGetBool(path, "threadmode", &srvPtr->threadmode)) {
        srvPtr->threadmode = 1;
    }
    if (!Ns_ConfigGetBool(path, "drivermode", &srvPtr->drivermode)) {
        srvPtr->drivermode = 1;
    }
    srvPtr->proc = Ns_ConfigGetValue(path, "proc");
    srvPtr->address = Ns_ConfigGetValue(path, "address");
    srvPtr->debug = Ns_ConfigIntRange(path, "debug", 0, 0, 10);
    srvPtr->port = Ns_ConfigIntRange(path, "port", 389, 1, 65535);
    srvPtr->sendwait = Ns_ConfigIntRange(path, "sendwait", 30, 1, INT_MAX);
    srvPtr->recvwait = Ns_ConfigIntRange(path, "recvwait", 30, 1, INT_MAX);

    if (srvPtr->drivermode) {
        init.version = NS_DRIVER_VERSION_1;
        init.name = "nsldapd";
        init.proc = LDAPDriverProc;
        init.opts = 0;
        init.arg = srvPtr;
        init.path = NULL;
        if (Ns_DriverInit(server, module, &init) != NS_OK) {
            Ns_Log(Error, "nsldapd: driver init failed.");
            ns_free(srvPtr);
            return NS_ERROR;
        }
        Ns_RegisterRequest(server, "LDAP",  "/", LDAPRequestProc, NULL, srvPtr, 0);
    } else {
        if ((srvPtr->sock = Ns_SockListen(srvPtr->address, srvPtr->port)) == -1) {
            Ns_Log(Error,"nstftp: %s:%d: couldn't create socket: %s", srvPtr->address, srvPtr->port, strerror(errno));
            ns_free(srvPtr);
            return NS_ERROR;
        }
        Ns_SockCallback(srvPtr->sock, LDAPSockProc, srvPtr, NS_SOCK_READ|NS_SOCK_EXIT|NS_SOCK_EXCEPTION);
    }
    srvPtr->name = ns_strdup(server);
    Ns_TclRegisterTrace(server, LDAPInterpInit, srvPtr, NS_TCL_TRACE_CREATE);
    return NS_OK;
}

static int LDAPInterpInit(Tcl_Interp *interp, void *arg)
{
    Tcl_CreateObjCommand(interp, "ns_ldap", LDAPCmd, arg, NULL);
    return NS_OK;
}

static int LDAPDriverProc(Ns_DriverCmd cmd, Ns_Sock *sock, struct iovec *bufs, int nbufs)
{
    Ns_Time timeout = {0,0};

    switch (cmd) {
     case DriverAccept:
         return Ns_DriverSockRequest(sock, "LDAP / LDAP/1.0");

     case DriverRecv:
        timeout.sec = sock->driver->recvwait;
        return Ns_SockRecvBufs(sock->sock, bufs, nbufs, &timeout);

     case DriverSend:
        timeout.sec = sock->driver->sendwait;
        return Ns_SockSendBufs(sock->sock, bufs, nbufs, &timeout);

     case DriverClose:
     case DriverKeep:
         break;
    }
    return NS_ERROR;
}

static int LDAPRequestProc(void *arg, Ns_Conn *conn)
{
    LDAPServer *server = (LDAPServer*)arg;
    Ns_Sock *sock = Ns_ConnSockPtr(conn);
    LDAPRequest *req = LDAPRequestNew(server);

    req->sa = sock->sa;
    req->sock = sock->sock;
    LDAPRequestProcess(req);
    LDAPRequestFree(req);
    return NS_OK;
}

static void LDAPThread(void *arg)
{
    LDAPRequest *req = (LDAPRequest*)arg;
    LDAPRequestProcess(req);
    LDAPRequestFree(req);
}

static int LDAPSockProc(SOCKET sock, void *arg, int when)
{
    LDAPServer *server = (LDAPServer*)arg;
    int slen = sizeof(struct sockaddr_in);
    LDAPRequest *req;

    switch(when) {
     case NS_SOCK_READ:
         req = LDAPRequestNew(server);
         req->sock = Ns_SockAccept(sock, (struct sockaddr *) &req->sa, &slen);
         if (server->threadmode) {
             Ns_ThreadCreate(LDAPThread, (void*)req, 0, 0);
         } else {
             LDAPRequestProcess(req);
             LDAPRequestFree(req);
         }
         return NS_TRUE;
    }
    close(sock);
    return NS_FALSE;
}

static LDAPRequest *LDAPRequestNew(LDAPServer *server)
{
    LDAPRequest *req = ns_calloc(1, sizeof(LDAPRequest));
    req->server = server;
    Ns_DStringInit(&req->ds);
    return req;
}

static void LDAPRequestFree(LDAPRequest *req)
{
    if (req != NULL) {
        Ns_DStringFree(&req->ds);
        ns_free(req->reply.dn);
        ns_free(req->reply.errmsg);
        ns_free(req->reply.referral);
        ns_free(req);
    }
}

static void LDAPRequestProcess(LDAPRequest* req)
{
    char buf[4096];
    Ns_Time timeout = { 0, 0 };
    int nread, len = 0;

    if (req->server->debug > 1) {
        Ns_Log(Notice, "LDAP: FD %d: %s: connected", req->sock, ns_inet_ntoa(req->sa.sin_addr));
    }

    Ns_TlsSet(&ldapTls, req);

    while (1) {
        timeout.sec = req->server->recvwait;
        nread = Ns_SockRecv(req->sock, buf + len, sizeof(buf) - len, &timeout);
        if (nread <= 0) {
            goto err;
        }
        if (req->server->debug > 3) {
            Ns_Log(Notice, "LDAP: FD %d: %s: read %d bytes", req->sock, ns_inet_ntoa(req->sa.sin_addr), nread);
        }
        len += nread;
        nread = scan_ldapmessage(buf, buf + len, &req->msgid, &req->op, &req->msglen);
        if (nread <= 0) {
            continue;
        }
        if (req->server->debug > 2) {
            Ns_Log(Notice, "LDAP: FD %d: %s: op %s(%u), msgid %u, len %u bytes", req->sock, ns_inet_ntoa(req->sa.sin_addr), req->op < MAX_OPS ? ldapOps[req->op] : "unknown", req->op, req->msgid, req->msglen);
        }
        switch (req->op) {
        case OP_BINDREQUEST: {
            if (scan_ldapbindrequest(buf + nread, buf + len, &req->bind) > 0) {
                LDAPRequestTcl(req);
            } else {
                req->reply.rc = LDAP_PROTOCOLERROR;
            }
            if (req->server->debug > 2) {
                print_ldapbind(&req->ds, &req->bind, 1);
                Ns_Log(Notice, "LDAP: FD %d: %s: %u bind: %s", req->sock, ns_inet_ntoa(req->sa.sin_addr), req->msgid, req->ds.string);
            }
            if (LDAPRequestReply(req, buf, OP_BINDRESPONSE) <= 0) {
                goto err;
            }
            break;
        }

        case OP_SEARCHREQUEST: {
            if (scan_ldapsearchrequest(buf + nread, buf + len, &req->search) > 0) {
                if (req->server->debug > 2) {
                    print_ldapsearch(&req->ds, &req->search, 1);
                    Ns_Log(Notice, "LDAP: FD %d: %s: %u search: %s", req->sock, ns_inet_ntoa(req->sa.sin_addr), req->msgid, req->ds.string);
                }
                LDAPRequestTcl(req);
                free_ldapsearchrequest(&req->search);
            } else {
                req->reply.rc = LDAP_PROTOCOLERROR;
            }
            if (LDAPRequestReply(req, buf, OP_SEARCHRESULTDONE) <= 0) {
                goto err;
            }
            break;
        }

        case OP_MODIFYREQUEST:
            if (scan_ldapmodifyrequest(buf + nread, buf + len, &req->modify) > 0) {
                LDAPRequestTcl(req);
                free_ldapmodifyrequest(&req->modify);
            }
            req->reply.rc = LDAP_PROTOCOLERROR;
            if (LDAPRequestReply(req, buf, OP_MODIFYRESPONSE) <= 0) {
                goto err;
            }
            break;

        case OP_ADDREQUEST:
            if (scan_ldapaddrequest(buf + nread, buf + len, &req->modify) > 0) {
                LDAPRequestTcl(req);
                free_ldapaddrequest(&req->modify);
            }
            req->reply.rc = LDAP_OPERATIONSERROR;
            if (LDAPRequestReply(req, buf, OP_ADDRESPONSE) <= 0) {
                goto err;
            }
            break;

        case OP_DELREQUEST:
            req->reply.rc = LDAP_OPERATIONSERROR;
            if (LDAPRequestReply(req, buf, OP_DELRESPONSE) <= 0) {
                goto err;
            }
            break;

        case OP_UNBINDREQUEST:
        case OP_ABANDONREQUEST:
        default:
            goto done;
        }
        req->msglen += nread;
        if (req->msglen < len) {
            memmove(buf, buf + req->msglen, len - req->msglen);
            len -= req->msglen;
        } else {
            len = 0;
        }
    }

done:
    Ns_TlsSet(&ldapTls, 0);

    if (req->server->debug > 1) {
        Ns_Log(Notice, "LDAP: FD %d: %s: %u disconnected", req->sock, ns_inet_ntoa(req->sa.sin_addr), req->msgid);
    }
    return;

err:
    Ns_Log(Error, "nsldapd: %d: error: %s", req->sock, strerror(errno));
    goto done;
}

static void LDAPRequestTcl(LDAPRequest *req)
{
    if (req->server->proc) {
        Tcl_Interp *interp = Ns_TclAllocateInterp(req->server->name);
        if (Tcl_VarEval(interp, req->server->proc, " ", ns_inet_ntoa(req->sa.sin_addr), NULL) != TCL_OK) {
            Ns_TclLogError(interp);
        }
        Ns_TclDeAllocateInterp(interp);
    }
}

static int LDAPRequestReply(LDAPRequest *req, char *buf, int op)
{
    int rlen, mlen;
    char *outptr = buf + 100;
    Ns_Time timeout = {req->server->sendwait, 0};

    rlen = fmt_ldapresult(outptr, req->reply.rc, fmt_str(req->reply.dn), fmt_str(req->reply.errmsg), fmt_str(req->reply.referral));
    mlen = fmt_ldapmessage(0, req->msgid, op, rlen);
    fmt_ldapmessage(outptr - mlen, req->msgid, op, rlen);
    return Ns_SockSend(req->sock, outptr - mlen, rlen + mlen, &timeout);
}

static int LDAPRequestReplySRE(LDAPRequest *req, SearchResultEntry *sre)
{
    char *buf;
    int rc, rlen, mlen;
    Ns_Time timeout = {req->server->sendwait, 0};

    rlen = fmt_ldapsearchresultentry(0, sre);
    buf = ns_malloc(rlen + 32);
    mlen = fmt_ldapmessage(buf, req->msgid, OP_SEARCHRESULTENTRY, rlen);
    fmt_ldapsearchresultentry(buf + mlen, sre);
    rc = Ns_SockSend(req->sock, buf, rlen + mlen, &timeout);
    ns_free(buf);
    return rc;
}

static int LDAPCmd(ClientData arg, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    LDAPServer *server = arg;
    char buf[4096];
    LDAPRequest *req;
    SearchResultEntry sre;
    AttributeValues *attr;
    int i, j, cmd;
    enum commands {
        cmdSearch, cmdReqGet, cmdReqSet, cmdReqResult
    };
    static const char *sCmd[] = {
        "search", "reqget", "regset", "reqresult",
        0
    };

    if (objc < 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "args");
        return TCL_ERROR;
    }
    if (Tcl_GetIndexFromObj(interp, objv[1], sCmd, "command", TCL_EXACT, &cmd) != TCL_OK) {
        return TCL_ERROR;
    }

    switch (cmd) {
     case cmdReqGet:
        req = (LDAPRequest*)Ns_TlsGet(&ldapTls);
        if (!req) {
            break;
        }
        if (objc < 3) {
            Tcl_WrongNumArgs(interp, 2, objv, "name");
            return TCL_ERROR;
        }
        Ns_DStringSetLength(&req->ds, 0);
        if (!strcmp(Tcl_GetString(objv[2]), "op")) {
            Ns_DStringPrintf(&req->ds, "%u", req->op);
        } else
        if (!strcmp(Tcl_GetString(objv[2]), "opname")) {
            Ns_DStringPrintf(&req->ds, "%s", req->op < MAX_OPS ? ldapOps[req->op] : "unknown");
        } else
        if (!strcmp(Tcl_GetString(objv[2]), "id")) {
            Ns_DStringPrintf(&req->ds, "%u", req->msgid);
        } else
        if (!strcmp(Tcl_GetString(objv[2]), "ipaddr")) {
            Ns_DStringAppend(&req->ds, ns_inet_ntoa(req->sa.sin_addr));
        } else
        if (!strcmp(Tcl_GetString(objv[2]), "bind")) {
            print_ldapbind(&req->ds, &req->bind, 0);
        } else
        if (!strcmp(Tcl_GetString(objv[2]), "search")) {
            print_ldapsearch(&req->ds, &req->search, 0);
        } else
        if (!strcmp(Tcl_GetString(objv[2]), "filter")) {
            print_ldapfilter(&req->ds, req->search.filter, 0);
        } else
        if (!strcmp(Tcl_GetString(objv[2]), "modify")) {
            print_ldapmodify(&req->ds, &req->modify, 0);
        }
        Tcl_AppendResult(interp, req->ds.string, 0);
        break;

     case cmdReqSet:
        req = (LDAPRequest*)Ns_TlsGet(&ldapTls);
        if (!req) {
            break;
        }
        for (i = 2; i < objc - 1; i += 2) {
            if (!strcasecmp(Tcl_GetString(objv[i]), "rc")) {
                req->reply.rc = atoi(Tcl_GetString(objv[i+1]));
            } else
            if (!strcasecmp(Tcl_GetString(objv[i]), "rcname")) {
                for (j = 0; j < MAX_ERRORS; j++) {
                    if (!strcasecmp(ldapErrors[j], Tcl_GetString(objv[i+1]))) {
                        req->reply.rc = j;
                        break;
                    }
                }
            } else
            if (!strcasecmp(Tcl_GetString(objv[i]), "dn")) {
                ns_free(req->reply.dn);
                req->reply.dn = ns_strdup(Tcl_GetString(objv[i+1]));
            } else
            if (!strcasecmp(Tcl_GetString(objv[i]), "errmsg")) {
                ns_free(req->reply.errmsg);
                req->reply.errmsg = ns_strdup(Tcl_GetString(objv[i+1]));
            } else
            if (!strcasecmp(Tcl_GetString(objv[i]), "referral")) {
                ns_free(req->reply.referral);
                req->reply.referral = ns_strdup(Tcl_GetString(objv[i+1]));
            }
        }
        break;

     case cmdReqResult:
        req = (LDAPRequest*)Ns_TlsGet(&ldapTls);
        if (!req) {
            break;
        }
        if (objc < 3) {
            Tcl_WrongNumArgs(interp, 2, objv, "objname ?type value? ...");
            return TCL_ERROR;
        }
        memset(&sre, 0, sizeof(sre));
        sre.objectName.s = Tcl_GetStringFromObj(objv[2], (int*)&sre.objectName.l);
        for (i = 3; i < objc - 1; i += 2) {
            attr = ns_calloc(1, sizeof(AttributeValues));
            attr->type.s = Tcl_GetStringFromObj(objv[i], (int*)&attr->type.l);
            attr->values = ns_calloc(1, sizeof(Attribute));
            attr->values->name.s = Tcl_GetStringFromObj(objv[i+1], (int*)&attr->values->name.l);
            attr->next = sre.attributes;
            sre.attributes = attr;
        }
        Tcl_SetObjResult(interp, Tcl_NewIntObj(LDAPRequestReplySRE(req, &sre)));
        free_ldapsearchresultentry(&sre);
        break;

     case cmdSearch: {
        Ns_DString ds;
        Filter *filter;
        BindRequest breq;
        BindResponse bres;
        SearchRequest sreq;
        int nread, sock, len, port = 389;
        uint32_t op, msgid = 1;
        uint32_t rlen, mlen, res;
        Ns_Time timeout = {0, 0};

        if (objc < 4) {
            Tcl_WrongNumArgs(interp, 2, objv, "host filter ?binddn str? ?-port n? ?-user str? ?-password str? ?-attrs attr,attr,...?");
            return TCL_ERROR;
        }
        memset(&sreq, 0, sizeof(sreq));
        memset(&breq, 0, sizeof(breq));
        memset(&bres, 0, sizeof(bres));

        // Prepare Bind Reauest
        rlen = fmt_ldapbindrequest(buf + 100, 3, (char*)breq.name.s, (char*)breq.password.s);
        mlen = fmt_ldapmessage(0, msgid, OP_BINDREQUEST, rlen);
        fmt_ldapmessage(buf + 100 - mlen, msgid, OP_BINDREQUEST, rlen);
        timeout.sec = server->sendwait;
        sock = Ns_SockTimedConnect(Tcl_GetString(objv[2]), port, &timeout);
        if (sock == -1) {
            Tcl_AppendResult(interp, "unable to connect to ", Tcl_GetString(objv[2]), 0);
            return TCL_ERROR;
        }
        // Send request
        if (Ns_SockSend(sock, buf + 100 - mlen, rlen + mlen, &timeout) <= 0) {
            Tcl_AppendResult(interp, "timeout sending bind request to ", Tcl_GetString(objv[2]), ": ", strerror(errno), 0);
            close(sock);
            return TCL_ERROR;
        }
        // Wait for the reply
        timeout.sec = server->recvwait;
        len = Ns_SockRecv(sock, buf, sizeof(buf), &timeout);
        if (len <= 0) {
            Tcl_AppendResult(interp, "timeout reading bind reply from ", Tcl_GetString(objv[2]), " ", strerror(errno), 0);
            close(sock);
            return TCL_ERROR;
        }
        // Parse reply
        res = scan_ldapmessage(buf, buf + len, &msgid, &op, &mlen);
        if (!res || op != OP_BINDRESPONSE) {
            Tcl_AppendResult(interp, "invalid bind response from ", Tcl_GetString(objv[2]), 0);
            close(sock);
            return TCL_ERROR;
        }
        res = scan_ldapbindresponse(buf + res, buf + res + mlen, &bres);
        if (!res || bres.result) {
            Tcl_AppendResult(interp, "unable to bind to ", Tcl_GetString(objv[2]), 0);
            close(sock);
            return TCL_ERROR;
        }
        // Parse search filter
        if (!scan_ldapsearchfilterstring(Tcl_GetString(objv[3]), &filter)) {
            Tcl_AppendResult(interp, "invalid filter ", Tcl_GetString(objv[3]), 0);
            close(sock);
            return TCL_ERROR;
        }
        // Prepare Search Request
        sreq.scope = wholeSubtree;
        sreq.derefAliases = neverDerefAliases;
        sreq.filter = filter;
        rlen = fmt_ldapsearchrequest(buf + 100, &sreq);
        mlen = fmt_ldapmessage(0, ++msgid, OP_SEARCHREQUEST, rlen);
        fmt_ldapmessage(buf + 100 - mlen, msgid, OP_SEARCHREQUEST, rlen);
        free_ldapfilter(filter);
        timeout.sec = server->sendwait;
        // Send request
        if (Ns_SockSend(sock, buf + 100 - mlen, rlen + mlen, &timeout) <= 0) {
            Tcl_AppendResult(interp, "timeout sending search request to ", Tcl_GetString(objv[2]), " ", strerror(errno), 0);
            close(sock);
            return TCL_ERROR;
        }
        timeout.sec = server->recvwait;
        Ns_DStringInit(&ds);
        len = 0;
        while (1) {
            // Wait for the reply
            nread = Ns_SockRecv(sock, buf + len, sizeof(buf) - len, &timeout);
            if (nread <= 0) {
                Tcl_AppendResult(interp, "timeout reading search reply from ", Tcl_GetString(objv[2]), " ", strerror(errno), 0);
                goto err;
            }
            len += nread;
            // Parse reply
            res = scan_ldapmessage(buf, buf + len, &msgid, &op, &mlen);
            if (res <= 0) {
                continue;
            }
            switch (op) {
            case OP_SEARCHRESULTENTRY:
                if (!(res = scan_ldapsearchresultentry(buf + res, buf + len, &sre))) {
                    continue;
                }
                Ns_DStringAppend(&ds, "dn {");
                Ns_DStringNAppend(&ds, sre.objectName.s, sre.objectName.l);
                Ns_DStringAppend(&ds, "}");
                for (attr = sre.attributes; attr; attr = attr->next) {
                     Ns_DStringAppend(&ds, " ");
                     Ns_DStringNAppend(&ds, attr->type.s, attr->type.l);
                     Ns_DStringAppend(&ds, " {");
                     Ns_DStringNAppend(&ds, attr->values->name.s, attr->values->name.l);
                     Ns_DStringAppend(&ds, "}");
                }
                free_ldapsearchresultentry(&sre);
                break;

            case OP_SEARCHRESULTDONE:
                goto done;

            default:
                Tcl_AppendResult(interp, "invalid search response from ", Tcl_GetString(objv[2]), 0);
                goto err;
            }
            mlen += nread;
            if (mlen < len) {
                memmove(buf, buf + mlen, len - mlen);
                len -= mlen;
            } else {
                len = 0;
            }
        }
done:
        mlen = fmt_ldapmessage(buf, ++msgid, OP_UNBINDREQUEST, 0);
        timeout.sec = 0;
        Ns_SockSend(sock, buf, mlen, &timeout);
        close(sock);
        Tcl_AppendResult(interp, ds.string, 0);
        Ns_DStringFree(&ds);
        return TCL_OK;
err:
        close(sock);
        Ns_DStringFree(&ds);
        return TCL_ERROR;
    }
    }
    return TCL_OK;
}

static uint32_t scan_strchr(const char *in, char needle)
{
  register const char *t = in, c = needle;
  for (;;) {
      if (!*t || *t==c) break; ++t;
      if (!*t || *t==c) break; ++t;
      if (!*t || *t==c) break; ++t;
      if (!*t || *t==c) break; ++t;
  }
  return t - in;
}


static uint32_t scan_asn1BOOLEAN(const char *src, const char *max, uint32_t *l)
{
    uint32_t tmp, tag;
    ASN1TagClass tc;
    ASN1TagType tt;
    long ltmp;

    if ((tmp = scan_asn1int(src, max, &tc, &tt, &tag, &ltmp)) && tag == TAG_BOOLEAN) {
        if (ltmp < 0 || src + tmp + ltmp > max) {
            return 0;
        }
        *l = (uint32_t) ltmp;
        return tmp;
    }
    return 0;
}

static uint32_t scan_asn1ENUMERATED(const char *src, const char *max, uint32_t *l)
{
    uint32_t tmp, tag;
    ASN1TagClass tc;
    ASN1TagType tt;
    long ltmp;

    if ((tmp = scan_asn1int(src, max, &tc, &tt, &tag, &ltmp)) && tag == TAG_ENUMERATED) {
        if (ltmp < 0 || src + tmp + ltmp > max) {
            return 0;
        }
        *l = (uint32_t) ltmp;
        return tmp;
    }
    return 0;
}

static uint32_t scan_asn1INTEGER(const char *src, const char *max, signed long *l)
{
    uint32_t tmp, tag;
    ASN1TagClass tc;
    ASN1TagType tt;

    if ((tmp = scan_asn1int(src, max, &tc, &tt, &tag, l)) && tag == TAG_INTEGER) {
        return tmp;
    }
    return 0;
}

static uint32_t scan_asn1SEQUENCE(const char *src, const char *max, uint32_t *len)
{
    uint32_t res, tmp, tag;
    ASN1TagClass tc;
    ASN1TagType tt;

    if (!(res = scan_asn1tag(src, max, &tc, &tt, &tag)) || tag != TAG_SEQUENCE_OF) {
        return 0;
    }
    if (!(tmp = scan_asn1length(src + res, max, len))) {
        return 0;
    }
    res += tmp;
    return res;
}

static uint32_t scan_asn1SET(const char *src, const char *max, uint32_t *len)
{
    uint32_t res, tmp, tag;
    ASN1TagClass tc;
    ASN1TagType tt;

    if (!(res = scan_asn1tag(src, max, &tc, &tt, &tag)) || tag != TAG_SET_OF) {
        return 0;
    }
    if (!(tmp = scan_asn1length(src + res, max, len))) {
        return 0;
    }
    res += tmp;
    return res;
}

static uint32_t scan_asn1STRING(const char *src, const char *max, const char **s, uint32_t *l)
{
    uint32_t tag;
    ASN1TagClass tc;
    ASN1TagType tt;

    return scan_asn1string(src, max, &tc, &tt, &tag, s, l);
}

static uint32_t scan_asn1int(const char *src, const char *max, ASN1TagClass *tc, ASN1TagType *tt, uint32_t *tag, signed long *l)
{
    uint32_t len, tmp, tlen;

    if (!(len = scan_asn1tag(src, max, tc, tt, tag))) {
        return 0;
    }
    if (!(tmp = scan_asn1length(src + len, max, &tlen))) {
        return 0;
    }
    len += tmp;
    if (!(scan_asn1rawint(src + len, max, tlen, l))) {
        return 0;
    }
    return len + tlen;
}

static uint32_t scan_asn1length(const char *src, const char *max, uint32_t *length)
{
    const char *orig = src;

    if (src > max) {
        return 0;
    }

    /* If the highest bit of the first byte is clear, the byte is the length.
     * Otherwise the next n bytes are the length (n being the lower 7 bits)
     */

    if (*src & 0x80) {
        int chars = *src & 0x7f;
        uint32_t l = 0;
        while (chars > 0) {
            if (++src >= max) {
                return 0;
            }
            if (l > (((uint32_t) -1) >> 8)) {
                return 0;       /* catch integer overflow */
            }
            l = l * 256 + (unsigned char) *src;
            --chars;
        }
        *length = l;
    } else {
        *length = *src & 0x7f;
    }
    src++;
    if (src + *length > max) {
        return 0;               /* catch integer overflow */
    }
    if (src + *length < src) {
        return 0;
    }
    return src - orig;
}

static uint32_t scan_asn1oid(const char *src, const char *max)
{
    uint32_t res, tmp, tag, tlen;
    ASN1TagClass tc;
    ASN1TagType tt;

    if (!(res = scan_asn1tag(src, max, &tc, &tt, &tag))) {
        goto error;
    }
    if (!(tmp = scan_asn1length(src + res, max, &tlen))) {
        goto error;
    }
    res += tmp;
    {
        uint32_t i, x, y;
        tmp = 0;
        for (i = 0; src[res + i] & 128; ++i) {
            tmp = (tmp << 7) + ((unsigned char) src[res + i] & (~128));
        }
        tmp = (tmp << 7) + (unsigned char) src[res + i];
        ++i;
        x = tmp / 40;
        y = tmp - x * 40;
        while (x > 2) {
            --x;
            y += 40;
        }
        for (; i < tlen; ++i) {
            tmp = 0;
            for (; src[res + i] & 128; ++i) {
                tmp = (tmp << 7) + ((unsigned char) src[res + i] & (~128));
            }
            tmp = (tmp << 7) + (unsigned char) src[res + i];
        }
    }
    return res + tlen;
error:
    return 0;
}


static uint32_t scan_asn1rawint(const char *src, const char *max, uint32_t len, long *l)
{
    uint32_t i, j;
    long m;

    if (*src < 0) {
        m = -1;
    } else {
        m = 0;
    }
    for (i = j = 0; i < len; ++i, ++j) {
        if ((m == 0 && *src == 0) || (m == -1 && *src == -1)) {
            --j;
        }
        m = (m << 8) | (unsigned char) *src;
        ++src;
        if (src > max) {
            return 0;
        }
    }
    if (j > sizeof(long)) {
        return 0;
    }
    *l = m;
    return len;
}

static uint32_t scan_asn1string(const char *src, const char *max, ASN1TagClass *tc, ASN1TagType *tt, uint32_t *tag, const char **s, uint32_t *l)
{
    uint32_t len, tmp;

    if (!(len = scan_asn1tag(src, max, tc, tt, tag))) {
        return 0;
    }
    if (!(tmp = scan_asn1length(src + len, max, l))) {
        return 0;
    }
    len += tmp;
    *s = src + len;
    return len + *l;
}

static uint32_t scan_asn1tag(const char *src, const char *max, ASN1TagClass *tc, ASN1TagType *tt, uint32_t *tag)
{
    const char *orig = src;
    *tc = (*src & 0xC0);
    *tt = (*src & 0x20);

    if (max < src) {
        return 0;
    }
    /* The lower 5 bits are the tag, unless it's 0x1f, in which case the
     * next bytes are the tag: always take the lower 7 bits; the last byte
     * in the sequence is marked by a cleared high bit
     */
    if ((*src & 0x1f) == 0x1f) {
        uint32_t l = 0;
        for (;;) {
            ++src;
            if (src > max) {
                return 0;
            }
            if (l > (((uint32_t) -1) >> 7)) {
                return 0;       /* catch integer overflow */
            }
            l = l * 128 + (*src & 0x7F);
            if (!(*src & 0x80)) {
                break;
            }
        }
        *tag = l;
        return (src - orig + 1);
    } else {
        *tag = *src & 0x1f;
        return 1;
    }
}

static uint32_t scan_ldapstring(const char *src, const char *max, String *s)
{
    return scan_asn1STRING(src, max, &s->s, &s->l);
}

static uint32_t scan_ldapmessage(const char *src, const char *max, uint32_t *messageid, uint32_t *op, uint32_t *len)
{
    uint32_t res, tmp;
    ASN1TagClass tc;
    ASN1TagType tt;

    if (!(res = scan_asn1SEQUENCE(src, max, len))) {
        return 0;
    }
    if (!(tmp = scan_asn1INTEGER(src + res, max, (long *) messageid))) {
        return 0;
    }
    res += tmp;
    if (!(tmp = scan_asn1tag(src + res, max, &tc, &tt, op))) {
        return 0;
    }
    if (tc != CLASS_APPLICATION) {
        return 0;
    }
    res += tmp;
    if (!(tmp = scan_asn1length(src + res, max, len))) {
        return 0;
    }
    res += tmp;
    return res;
}

static uint32_t scan_ldapbindrequest(const char *src, const char *max, BindRequest *bind)
{
    signed long version;
    uint32_t res, tmp;
    ASN1TagClass tc;
    ASN1TagType tt;

    memset(bind, 0, sizeof(BindRequest));
    if (!(res = scan_asn1INTEGER(src, max, &version))) {
        return 0;
    }
    bind->version = version;
    if (!(tmp = scan_ldapstring(src + res, max, &bind->name))) {
        return 0;
    }
    res += tmp;
    if (!(tmp = scan_asn1tag(src + res, max, &tc, &tt, &bind->method))) {
        return 0;
    }
    if (tc != CLASS_PRIVATE || tt != TYPE_PRIMITIVE) {
        return 0;
    }
    switch (bind->method) {
     case 0:
         if (!(tmp = scan_ldapstring(src + res, max, &bind->password))) {
             return 0;
         }
         res += tmp;
         break;

     case 3:
         if (!(tmp = scan_ldapstring(src + res, max, &bind->mechanism))) {
             return 0;
         }
         res += tmp;
         if (!(tmp = scan_ldapstring(src + res, max, &bind->password))) {
             return 0;
         }
         res += tmp;
         break;
     default:
         return 0;
    }
    return res;
}

static uint32_t scan_ldapbindresponse(const char *src, const char *max, BindResponse *bind)
{
    uint32_t res, tmp;

    if (!(res = scan_asn1ENUMERATED(src, max, &bind->result))) {
        return 0;
    }
    if (!(tmp = scan_ldapstring(src + res, max, &bind->matcheddn))) {
        return 0;
    }
    res += tmp;
    if (src + res < max) {
        if (!(tmp = scan_ldapstring(src + res, max, &bind->errmsg))) {
            return 0;
        }
        res += tmp;
    } else {
        bind->errmsg.s = 0;
        bind->errmsg.l = 0;
    }
    if (src + res < max) {
        if (!(tmp = scan_ldapstring(src + res, max, &bind->referral))) {
            return res;
        }
        res += tmp;
    } else {
        bind->referral.s = 0;
        bind->referral.l = 0;
    }
    return res;
}

static uint32_t scan_ldapaddrequest(const char *src, const char *max, ModifyRequest *a)
{
    uint32_t res, tmp;
    uint32_t oslen;        /* outer sequence length */
    Modify *last = 0;

    memset(a, 0, sizeof(ModifyRequest));
    a->m = ns_calloc(1, sizeof(Modify));
    if (!(res = scan_ldapstring(src, max, &a->object))) {
        goto error;
    }
    if (!(tmp = scan_asn1SEQUENCE(src + res, max, &oslen))) {
        goto error;
    }
    res += tmp;
    if (src + res + oslen > max) {
        goto error;
    }
    max = src + res + oslen;
    if (src + res >= max) {
        goto error;             /* need at least one record */
    }
    do {
        uint32_t islen;
        if (last) {
            Modify *cur;
            if (!(cur = ns_malloc(sizeof(Modify)))) {
                goto error;
            }
            last->next = cur;
            last = cur;
        } else {
            last = a->m;
        }
        last->next = 0;
        if (!(tmp = scan_asn1SEQUENCE(src + res, max, &islen))) {
            goto error;
        }
        res += tmp;
        /* scan Attribute: */
        if (!(tmp = scan_ldapstring(src + res, max, &last->attribute))) {
            goto error;
        }
        res += tmp;

        /* scan set of AttributeValue: */
        {
            uint32_t set_len;
            const char *set_max;
            Attribute *ilast = 0;
            if (!(tmp = scan_asn1SET(src + res, max, &set_len))) {
                goto error;
            }
            res += tmp;
            set_max = src + res + set_len;
            if (src + res + set_len != set_max) {
                goto error;
            }
            while (src + res < set_max) {
                if (ilast) {
                    Attribute *x;
                    if (!(x = ns_malloc(sizeof(Attribute)))) {
                        goto error;
                    }
                    ilast->next = x;
                    ilast = ilast->next;
                } else {
                    ilast = last->values = ns_calloc(1, sizeof(Attribute));
                }
                ilast->next = 0;
                if (!(tmp = scan_ldapstring(src + res, max, &ilast->name))) {
                    goto error;
                }
                res += tmp;
            }
        }
    } while (src + res < max);
    return res;
error:
    free_ldapaddrequest(a);
    return 0;
}

static uint32_t scan_ldapmodifyrequest(const char *src, const char *max, ModifyRequest *m)
{
    uint32_t res, tmp;
    uint32_t oslen;        /* outer sequence length */
    Modify *last = 0;

    memset(m, 0, sizeof(ModifyRequest));
    m->m = ns_calloc(1, sizeof(Modify));
    if (!(res = scan_ldapstring(src, max, &m->object))) {
        goto error;
    }
    if (!(tmp = scan_asn1SEQUENCE(src + res, max, &oslen))) {
        goto error;
    }
    res += tmp;
    if (src + res + oslen > max) {
        goto error;
    }
    max = src + res + oslen;
    if (src + res >= max) {
        goto error;             /* need at least one record */
    }
    do {
        uint32_t islen, etmp;
        if (last) {
            Modify *cur;
            if (!(cur = ns_malloc(sizeof(Modify)))) {
                goto error;
            }
            last->next = cur;
            last = cur;
        } else {
            last = m->m;
        }
        last->next = 0;
        if (!(tmp = scan_asn1SEQUENCE(src + res, max, &islen))) {
            goto error;
        }
        res += tmp;
        if (!(tmp = scan_asn1ENUMERATED(src + res, max, &etmp))) {
            goto error;
        }
        if (etmp > 2) {
            goto error;
        }
        last->operation = etmp;
        res += tmp;
        {
            uint32_t iislen;       /* urgh, _three_ levels of indirection */
            const char *imax;
            if (!(tmp = scan_asn1SEQUENCE(src + res, max, &iislen))) {
                goto error;
            }
            res += tmp;
            imax = src + res + iislen;
            if (imax > max) {
                goto error;
            }
            if (!(tmp = scan_ldapstring(src + res, imax, &last->attribute))) {
                goto error;
            }
            res += tmp;
            {
                uint32_t iiislen;  /* waah, _four_ levels of indirection!  It doesn't get more inefficient than this */
                const char *iimax;
                Attribute *ilast = 0;
                if (!(tmp = scan_asn1SET(src + res, max, &iiislen))) {
                    goto error;
                }
                res += tmp;
                iimax = src + res + iiislen;
                if (src + res + iiislen != imax) {
                    goto error;
                }
                while (src + res < iimax) {
                    if (ilast) {
                        Attribute *x;
                        if (!(x = ns_malloc(sizeof(Attribute)))) {
                            goto error;
                        }
                        x->next = ilast;
                        ilast = x;
                    } else {
                        ilast = last->values = ns_calloc(1, sizeof(Attribute));
                    }
                    if (!(tmp = scan_ldapstring(src + res, imax, &ilast->name))) {
                        goto error;
                    }
                    res += tmp;
                }
            }
        }
        break;
    } while (src + res < max);
    return res;
error:
    free_ldapmodifyrequest(m);
    return 0;
}

static uint32_t scan_ldapresult(const char *src, const char *max, uint32_t *result, String *matcheddn, String *errmsg, String *referral)
{
    uint32_t res, tmp;

    if (!(res = scan_asn1ENUMERATED(src, max, result))) {
        return 0;
    }
    if (!(tmp = scan_ldapstring(src + res, max, matcheddn))) {
        return 0;
    }
    res += tmp;
    if (!(tmp = scan_ldapstring(src + res, max, errmsg))) {
        return 0;
    }
    res += tmp;
    if (src + res == max) {
        referral->l = 0;
        referral->s = 0;
        return res;
    }
    if (!(tmp = scan_ldapstring(src + res, max, referral))) {
        return 0;
    }
    return res + tmp;
}

static uint32_t scan_ldapsearchfilter(const char *src, const char *max, Filter **f)
{
    ASN1TagType tt;
    ASN1TagClass tc;
    const char *nmax;
    uint32_t tag, len, len2, res, tmp;

    *f = 0;
    if (!(res = scan_asn1tag(src, max, &tc, &tt, &tag))) {
        goto error;
    }
    if (tc != CLASS_PRIVATE || (tt != TYPE_CONSTRUCTED && tag != 7) || tag > 9) {
        goto error;
    }
    if (!(tmp = scan_asn1length(src + res, max, &len))) {
        goto error;
    }
    res += tmp;
    if (src + res + len > max) {
        goto error;
    }
    if (!(*f = ns_calloc(1, sizeof(Filter)))) {
        goto error;
    }
    nmax = src + res + len;
    switch ((*f)->type = tag) {
    case 0: /* and [0] SET OF Filter */
    case 1: /* or  [1] SET OF Filter */
        (*f)->subject = 0;
        while (src + res < max) {
            Filter *F = (*f)->subject;
            if (!(tmp = scan_ldapsearchfilter(src + res, nmax, &(*f)->subject))) {
                if (F) {        /* OK, end of sequence */
                    (*f)->subject = F;
                    break;
                }
                (*f)->subject = F;
                goto error;
            }
            (*f)->subject->next = F;
            res += tmp;
        }
        break;

    case 2: /* not [2] Filter */
        if (!(tmp = scan_ldapsearchfilter(src + res, nmax, &(*f)->subject))) {
            goto error;
        }
        if (tmp != len) {
            goto error;
        }
        res += tmp;
        break;

    case 3: /* equalityMatch   [3] AttributeValue */
    case 5: /* greaterOrEqual  [5] AttributeValue */
    case 6: /* lessOrEqual     [6] AttributeValue */
    case 8: /* approxMatch     [8] AttributeValue */
        if (!(tmp = scan_ldapstring(src + res, nmax, &(*f)->name))) {
            goto error;
        }
        res += tmp;
        if (!(tmp = scan_ldapstring(src + res, nmax, &(*f)->value))) {
            goto error;
        }
        res += tmp;
        break;

    case 4: /* substrings [4] SubstringFilter */
        if (!(tmp = scan_ldapstring(src + res, nmax, &(*f)->name))) {
            goto error;
        }
        res += tmp;
        if (!(tmp = scan_asn1SEQUENCE(src + res, nmax, &len2))) {
            goto error;
        }
        res += tmp;
        if (src + res + len2 != nmax) {
            goto error;
        }
        while (src + res < nmax) {
            Substring *s = ns_malloc(sizeof(Substring));
            uint32_t x;
            ASN1TagType tt;
            ASN1TagClass tc;
            if (!s) {
                goto error;
            }
            if (!(tmp = scan_asn1string(src + res, nmax, &tc, &tt, &x, &s->s.s, &s->s.l))) {
                free(s);
                goto error;
            }
            if (x > 2) {
                goto error;
            }
            s->substrtype = x;
            res += tmp;
            s->next = (*f)->substrings;
            (*f)->substrings = s;
        }
        break;

    case 7: /* present [7] Attribute, */
        (*f)->name.s = src + res;
        (*f)->name.l = len;
        res += len;
        break;

    case 9: /* extensibleMatch [9] MatchingRuleAssertion */
        if (!(res = scan_asn1tag(src + res, nmax, &tc, &tt, &tag))) {
            goto error;
        }
        if (!(tmp = scan_asn1length(src + res, nmax, &len))) {
            goto error;
        }
        res += tmp;
        switch (tag) {
         case 1:
             if (!(tmp = scan_ldapstring(src + res, nmax, &(*f)->name))) {
                 goto error;
             }
             (*f)->flags |= FILTER_EXT_OID;
             res += tmp;
             break;
         case 2:
             if (!(tmp = scan_ldapstring(src + res, nmax, &(*f)->name))) {
                 goto error;
             }
             (*f)->flags |= FILTER_EXT_TYPE;
             res += tmp;
             break;
        }
        if (!(tmp = scan_ldapstring(src + res, nmax, &(*f)->value))) {
            Ns_Log(Error, "EXT3 val");
            goto error;
        }
        res += tmp;
        if (!(tmp = scan_asn1tag(src + res, nmax, &tc, &tt, &tag))) {
            Ns_Log(Error, "EXT tag");
            goto error;
        }
        if (tag == TAG_BOOLEAN) {
            if (!(tmp = scan_asn1BOOLEAN(src + res, nmax, &len2))) {
                goto error;
            }
            if (len2) {
                (*f)->flags |= FILTER_EXT_DNATTRS;
            }
            res += tmp;
        }
        break;
    }
    return res;
error:
    free_ldapfilter(*f);
    *f = 0;
    return 0;
}

static uint32_t scan_ldapsearchrequest(const char *src, const char *max, SearchRequest *s)
{
    uint32_t res, tmp;
    uint32_t etmp;
    signed long ltmp;

    s->attributes = 0;
    s->filter = 0;
    if (!(res = scan_ldapstring(src, max, &s->baseObject))) {
        goto error;
    }
    if (!(tmp = scan_asn1ENUMERATED(src + res, max, &etmp))) {
        goto error;
    }
    if (etmp > 2) {
        goto error;
    }
    s->scope = etmp;
    res += tmp;
    if (!(tmp = scan_asn1ENUMERATED(src + res, max, &etmp))) {
        goto error;
    }
    if (etmp > 3) {
        goto error;
    }
    s->derefAliases = etmp;
    res += tmp;
    if (!(tmp = scan_asn1INTEGER(src + res, max, &ltmp)) || ltmp < 0) {
        goto error;
    }
    s->sizeLimit = (uint32_t) ltmp;
    res += tmp;
    if (!(tmp = scan_asn1INTEGER(src + res, max, &ltmp)) || ltmp < 0) {
        goto error;
    }
    s->timeLimit = (uint32_t) ltmp;
    res += tmp;
    if (!(tmp = scan_asn1BOOLEAN(src + res, max, &s->typesOnly))) {
        goto error;
    }
    res += tmp;
    if (!(tmp = scan_ldapsearchfilter(src + res, max, &s->filter))) {
        goto error;
    }
    res += tmp;
    /* now for the attributelist */
    if (!(tmp = scan_asn1SEQUENCE(src + res, max, &etmp))) {
        goto error;
    }
    res += tmp;
    {
        const char *nmax = src + res + etmp;
        Attribute **a = &s->attributes;
        if (nmax > max) {
            goto error;
        }
        for (;;) {
            if (src + res > nmax) {
                goto error;
            }
            if (src + res == nmax) {
                break;
            }
            if (!*a) {
                *a = ns_calloc(1, sizeof(Attribute));
            }
            if (!*a) {
                goto error;
            }
            if (!(tmp = scan_ldapstring(src + res, nmax, &(*a)->name))) {
                goto error;
            }
            res += tmp;
            a = &(*a)->next;
        }
        return res;
    }
error:
    free_ldapsearchrequest(s);
    return 0;
}

static uint32_t scan_ldapsearchresultentry(const char *src, const char *max, SearchResultEntry *sre)
{
    uint32_t res, tmp;
    uint32_t oslen;        /* outer sequence length */
    AttributeValues **a = &sre->attributes;

    *a = 0;
    if (!(res = scan_ldapstring(src, max, &sre->objectName))) {
        goto error;
    }
    if (!(tmp = scan_asn1SEQUENCE(src + res, max, &oslen))) {
        goto error;
    }
    res += tmp;
    if (src + res + oslen > max) {
        goto error;
    }
    max = src + res + oslen;    /* we now may have a stronger limit */
    while (src + res < max) {
        String s;
        Attribute *x;
        uint32_t islen;
        const char *nmax;
        if (!(tmp = scan_asn1SEQUENCE(src + res, max, &islen))) {
            goto error;
        }
        res += tmp;
        nmax = src + res + islen;
        if (nmax > max) {
            goto error;
        }
        if (!(tmp = scan_ldapstring(src + res, nmax, &s))) {
            goto error;
        }
        if (!(*a = ns_malloc(sizeof(AttributeValues)))) {
            goto error;
        }
        (*a)->next = 0;
        (*a)->values = 0;
        (*a)->type = s;
        res += tmp;
        if (!(tmp = scan_asn1SET(src + res, max, &islen))) {
            goto error;
        }
        res += tmp;
        if (src + res + islen != nmax) {
            goto error;
        }
        while (src + res < nmax) {
            if (!(tmp = scan_ldapstring(src + res, max, &s))) {
                goto error;
            }
            if (!(x = ns_malloc(sizeof(Attribute)))) {
                goto error;
            }
            x->name = s;
            x->next = (*a)->values;
            (*a)->values = x;
            res += tmp;
        }
        a = &(*a)->next;
    }
    *a = 0;
    return res;
error:
    free_ldapattrval(sre->attributes);
    return 0;
}

static uint32_t scan_ldapsearchfilterstring(const char *src, Filter **f)
{
    char *s = (char *) src;

    if (!(*f = ns_calloc(sizeof(Filter), 1))) {
        goto error;
    }
    if (s[0] == '*' && (s[1] == 0 || s[1] == '(')) {
        int i = scan_ldapsearchfilterstring("(objectClass=*)", f);
        if (i) {
            return 1;
        }
    }
    if (*s != '(') {
        goto error;
    }
    switch (*(++s)) {
    case '&':
        ++s;
        (*f)->type = AND;
scan_filterlist:
        {
            Filter **n;
            s += scan_ldapsearchfilterstring(s, &(*f)->subject);
            n = &(*f)->subject->next;
            while (*s != ')') {
                uint32_t l = scan_ldapsearchfilterstring(s, n);
                if (!l) {
                    return 0;
                }
                s += l;
                n = &(*n)->next;
            }
        }
        break;

    case '|':
        ++s;
        (*f)->type = OR;
        goto scan_filterlist;
        break;

    case '!':
        (*f)->type = NOT;
        ++s;
        s += scan_ldapsearchfilterstring(s, &(*f)->subject);
        break;

    default:
        (*f)->name.s = s;
        (*f)->name.l = scan_strchr(s, '=') - 1;
        s += (*f)->name.l + 1;
        switch (*(s - 1)) {
        case '~':
            (*f)->type = APPROX;
            break;

        case '>':
            (*f)->type = GREATEQUAL;
            break;

        case '<':
            (*f)->type = LESSEQUAL;
            break;

        default:
            ++(*f)->name.l;
            if (*(++s) == '*') {
                if (*(++s) == ')') {
                    (*f)->type = PRESENT;
                    return s - src;
                }
                (*f)->type = SUBSTRING;
substring:
                while (*s != ')') {
                    int i, j;
                    Substring *substring = ns_malloc(sizeof(Substring));
                    if (!substring) {
                        goto error;
                    }
                    substring->s.s = s;
                    i = scan_strchr(s, ')');
                    j = scan_strchr(s, '*');
                    if (i > j) {
                        substring->substrtype = any;
                        s += substring->s.l = j;
                        ++s;
                    } else {
                        substring->substrtype = suffix;
                        s += substring->s.l = i;
                    }
                    substring->next = (*f)->substrings;
                    (*f)->substrings = substring;
                    if (*s == 0) {
                        goto error;
                    }
                }
            } else {
                int i, j;
                i = scan_strchr(s, ')');
                j = scan_strchr(s, '*');
                if (i > j) {
                    Substring *substring = ns_malloc(sizeof(Substring));
                    if (!substring) {
                        goto error;
                    }
                    (*f)->type = SUBSTRING;
                    substring->substrtype = prefix;
                    substring->s.s = s;
                    s += substring->s.l = j;
                    ++s;
                    substring->next = (*f)->substrings;
                    (*f)->substrings = substring;
                    goto substring;
                } else {
                    (*f)->type = EQUAL;
                }
            }
        }
        if (*s == '=') {
            ++s;
        }
        (*f)->value.s = s;
        s += (*f)->value.l = scan_strchr(s, ')');
        if (*s != ')') {
            goto error;
        }
    }
    return s - src + 1;
error:
    free_ldapfilter(*f);
    *f = 0;
    return 0;
}

static uint32_t fmt_asn1int(char *dest, ASN1TagClass tc, ASN1TagType tt, ASN1Tag tag, uint32_t l)
{
    uint32_t len, tmp;

    /* first the tag */
    if (!dest) {
        return fmt_asn1tag(0, tc, tt, tag) + 1 + fmt_asn1intpayload(0, l);
    }
    len = fmt_asn1tag(dest, tc, tt, tag);
    tmp = fmt_asn1intpayload(dest + len + 1, l);
    if (fmt_asn1length(dest + len, tmp) != 1) {
        return 0;
    }
    return len + tmp + 1;
}

static uint32_t fmt_asn1intpayload(char *dest, uint32_t l)
{
    uint32_t i, fixup, needed = sizeof l;

    for (i = 1; i < needed; ++i) {
        if (!(l >> (i * 8))) {
            break;
        }
    }
    fixup = (l >> ((i - 1) * 8)) & 0x80 ? 1 : 0;
    if (dest) {
        uint32_t j = i;
        if (fixup) {
            *dest++ = 0;
        }
        while (j) {
            --j;
            *dest = (l >> (j * 8)) & 0xff;
            ++dest;
        }
    }
    return i + fixup;
}

/* write int in least amount of bytes, return number of bytes */
/* as used in ASN.1 length */
static uint32_t fmt_asn1length(char *dest, uint32_t l)
{
    /* encoding is either l%128 or (0x80+number of bytes,bytes) */
    int i, needed = (sizeof l);

    if (l < 128) {
        if (dest) {
            *dest = l & 0x7f;
        }
        return 1;
    }
    for (i = 1; i < needed; ++i) {
        if (!(l >> (i * 8))) {
            break;
        }
    }
    if (dest) {
        int j = i;
        *dest = 0x80 + i;
        ++dest;
        while (j) {
            --j;
            *dest = ((l >> (j * 8)) & 0xff);
            ++dest;
        }
    }
    return i + 1;
}

static uint32_t fmt_asn1sint(char *dest, ASN1TagClass tc, ASN1TagType tt, ASN1Tag tag, signed long l)
{
    uint32_t len, tmp;

    /* first the tag */
    if (!dest) {
        return fmt_asn1tag(0, tc, tt, tag) + 1 + fmt_asn1intpayload(0, l);
    }
    len = fmt_asn1tag(dest, tc, tt, tag);
    tmp = fmt_asn1sintpayload(dest + len + 1, l);
    if (fmt_asn1length(dest + len, tmp) != 1) {
        return 0;
    }
    return len + tmp + 1;
}

static uint32_t fmt_asn1sintpayload(char *dest, signed long l)
{
    uint32_t i, needed = sizeof l;
    signed long tmp = 0x7f;

    if (l >= 0) {
        return fmt_asn1intpayload(dest, l);
    }
    for (i = 1; i < needed; ++i) {
        /* assumes two's complement */
        if ((l | tmp) == -1) {
            break;
        }
        tmp = (tmp << 8) | 0xff;
    }
    if (dest) {
        int j = i;
        while (j) {
            --j;
            *dest = (l >> (j * 8)) & 0xff;
            ++dest;
        }
    }
    return i;
}

static uint32_t fmt_asn1string(char *dest, ASN1TagClass tc, ASN1TagType tt, ASN1Tag tag, const char *c, uint32_t l)
{
    int len = fmt_asn1transparent(dest, tc, tt, tag, l);
    if (dest) {
        memcpy(dest + len, c, l);
    }
    return len + l;
}

/* write int in least amount of bytes, return number of bytes */
/* as used in ASN.1 tags */
static uint32_t fmt_asn1tag(char *dest, ASN1TagClass tc, ASN1TagType tt, uint32_t l)
{
    /* encoding is either l%128 or (0x1f,...) */
    int i, needed = (sizeof l) * 7 / 8;

    if (l < 0x1f) {
        if (dest) {
            *dest = (int) tc + (int) tt + (l & 0x1f);
        }
        return 1;
    }
    for (i = 1; i < needed; ++i)
        if (!(l >> (i * 7))) {
            break;
        }
    if (dest) {
        int j = i;
        *dest = (int) tc + (int) tt + 0x1f;
        ++dest;
        while (j) {
            --j;
            *dest = ((l >> (j * 7)) & 0x7f) + (j ? 0x80 : 0);
            ++dest;
        }
    }
    return i + 1;
}

static uint32_t fmt_asn1transparent(char *dest, ASN1TagClass tc, ASN1TagType tt, ASN1Tag tag, uint32_t l)
{
    uint32_t len, tmp;

    /* first the tag */
    len = fmt_asn1tag(dest, tc, tt, tag);
    tmp = fmt_asn1length(dest ? dest + len : dest, l);
    return tmp + len;
}

static uint32_t fmt_adl(char *dest, Attribute *adl, int seq)
{
    Attribute *x = adl;
    long sum = 0;
    int tmp;

    while (x) {
        sum += fmt_asn1OCTETSTRING(0, 0, x->name.l);
        x = x->next;
    }
    if (seq) {
        tmp = fmt_asn1SEQUENCE(dest, sum);
    } else {
        tmp = fmt_asn1SET(dest, sum);
    }
    sum += tmp;
    if (dest) {
        dest += tmp;
        x = adl;
        while (x) {
            dest += fmt_ldapstring(dest, &x->name);
            x = x->next;
        }
    }
    return sum;
}

static uint32_t fmt_ldapattr(char *dest, Attribute *adl)
{
    return fmt_adl(dest, adl, 1);
}

static uint32_t fmt_ldapavl(char *dest, Attribute *adl)
{
    return fmt_adl(dest, adl, 0);
}

static uint32_t fmt_ldapbindrequest(char *dest, long version, char *name, char *simple)
{
    uint32_t l, sum, nlen;

    name = name != NULL ? name : "";
    simple = simple != NULL ? simple : "";
    nlen = strlen(name);
    sum = l = fmt_asn1INTEGER(dest, version);
    if (dest) {
        dest += l;
    }
    l = fmt_asn1OCTETSTRING(dest, name, nlen);
    sum += l;
    if (dest) {
        dest += l;
    }
    nlen = strlen(simple);
    l = fmt_asn1string(dest, CLASS_PRIVATE, TYPE_PRIMITIVE, 0, simple, nlen);
    if (dest) {
        dest += l;
    }
    return sum + l;
}

static uint32_t fmt_ldapmessage(char *dest, long messageid, long op, long len)
{
    uint32_t l, l2, l3;

    l2 = fmt_asn1INTEGER(0, messageid);
    l3 = fmt_asn1transparent(0, CLASS_APPLICATION, TYPE_CONSTRUCTED, op, len);
    l = fmt_asn1SEQUENCE(dest, len + l2 + l3);
    if (!dest) {
        return l + l2 + l3;
    }
    l += fmt_asn1INTEGER(dest + l, messageid);
    l += fmt_asn1transparent(dest + l, CLASS_APPLICATION, TYPE_CONSTRUCTED, op, len);
    return l;
}

static uint32_t fmt_ldapattrval(char *dest, AttributeValues *pal)
{
    long sum, l, l2;

    if (!pal) {
        return 0;
    }
    sum = fmt_ldapstring(0, &pal->type);
    /* look how much space the adl needs */
    l = fmt_ldapavl(0, pal->values);
    /* write sequence header */
    l2 = fmt_asn1SEQUENCE(dest, l + sum);
    if (dest) {
        fmt_ldapstring(dest + l2, &pal->type);
        dest += sum + l2;
    }
    sum += l + l2;
    if (dest) {
        fmt_ldapavl(dest, pal->values);
        dest += l;
    }
    return sum + fmt_ldapattrval(dest, pal->next);
}


static uint32_t fmt_ldapresult(char *dest, long result, char *matcheddn, char *errmsg, char *referral)
{
    uint32_t l, sum = 0, nlen;

    matcheddn = matcheddn != NULL ? matcheddn : "";
    errmsg = errmsg != NULL ? errmsg : "";
    referral = referral != NULL ? referral : "";
    sum = l = fmt_asn1ENUMERATED(dest, result);
    if (dest) {
        dest += l;
    }
    nlen = strlen(matcheddn);
    l = fmt_asn1OCTETSTRING(dest, matcheddn, nlen);
    sum += l;
    if (dest) {
        dest += l;
    }
    nlen = strlen(errmsg);
    l = fmt_asn1OCTETSTRING(dest, errmsg, nlen);
    sum += l;
    if (dest) {
        dest += l;
    }
    if (referral && *referral) {
        nlen = strlen(referral);
        l = fmt_asn1OCTETSTRING(dest, referral, nlen);
        sum += l;
        if (dest) {
            dest += l;
        }
    }
    return sum;
}

static uint32_t fmt_ldapsubstring(char *dest, Substring *s)
{
    long sum = 0, tmp = 0;

    while (s) {
        tmp = fmt_asn1string(dest, CLASS_PRIVATE, TYPE_PRIMITIVE, s->substrtype, s->s.s, s->s.l);
        if (dest) {
            dest += tmp;
        }
        sum += tmp;
        s = s->next;
    }
    return sum;
}

static uint32_t fmt_ldapsearchfilter(char *dest, Filter *f)
{
    char *nd = dest;
    long sum = 0, savesum, l = 0, tmp = 0;

    if (!f) {
        return 0;
    }
    switch (f->type) {
    case AND:
    case OR:
    case NOT:
        sum = fmt_ldapsearchfilter(dest, f->subject);
        break;

    case EQUAL:
    case GREATEQUAL:
    case LESSEQUAL:
    case APPROX:
        l = fmt_ldapstring(nd, &f->name);
        sum += l;
        if (nd) {
            nd += l;
        }
        l = fmt_ldapstring(nd, &f->value);
        sum += l;
        if (nd) {
            nd += l;
        }
        break;

    case SUBSTRING:
        tmp = fmt_ldapsubstring(0, f->substrings);
        l = fmt_ldapstring(nd, &f->name);
        sum += l;
        if (nd) {
            nd += l;
        }
        l = fmt_asn1SEQUENCE(nd, tmp);
        sum += l;
        if (nd) {
            nd += l;
        }
        l = fmt_ldapsubstring(nd, f->substrings);
        sum += l;
        break;

    case PRESENT:
        return fmt_asn1string(dest, CLASS_PRIVATE, TYPE_PRIMITIVE, f->type, f->name.s, f->name.l);
        break;

    case EXTENSIBLE:

    default:
        return 0;
    }
    savesum = sum;
    if (f->next) {
        if (dest) {
            sum += fmt_ldapsearchfilter(dest + sum, f->next);
        } else {
            sum += fmt_ldapsearchfilter(dest, f->next);
        }
    }
    tmp = fmt_asn1length(0, savesum);
    if (!dest) {
        return sum + tmp + 1;
    }
    if (dest) {
        memmove(dest + tmp + 1, dest, sum);
    }
    fmt_asn1tag(dest, CLASS_PRIVATE, TYPE_CONSTRUCTED, f->type);
    fmt_asn1length(dest + 1, savesum);
    return sum + tmp + 1;
}

static uint32_t fmt_ldapsearchfilterstring(char *dest, Filter *f)
{
    uint32_t len = 0;

    if (dest) {
        dest[len] = '(';
    }
    len++;
    switch (f->type) {
    case AND:
    case OR:
    case NOT:
        if (dest) {
            dest[len] = "&|!"[f->type];
        }
        ++len;
        len += fmt_ldapsearchfilterstring(dest ? dest + len : 0, f->subject);
        break;

    case EQUAL:
    case GREATEQUAL:
    case LESSEQUAL:
    case APPROX:
        if (dest) {
            memmove(dest + len, f->name.s, f->name.l);
            len += f->name.l;
            if (f->type != EQUAL) {
                dest[len] = "><~"[f->type - GREATEQUAL];
                ++len;
            }
            dest[len] = '=';
            ++len;
            memmove(dest + len, f->value.s, f->value.l);
            len += f->value.l;
        } else {
            len += f->name.l + f->value.l + 1 + (f->type > EQUAL);
        }
        break;

    case SUBSTRING:
        {
            Substring *x = f->substrings;
            while (x) {
                if (dest) {
                    memmove(dest + len, f->name.s, f->name.l);
                    len += f->name.l;
                    dest[len] = '=';
                    ++len;
                    if (x->substrtype != prefix) {
                        dest[len] = '*';
                        ++len;
                    }
                    memmove(dest + len, x->s.s, x->s.l);
                    len += x->s.l;
                    if (x->substrtype != suffix) {
                        dest[len] = '*';
                        ++len;
                    }
                    if (x->next) {
                        dest[len] = ')';
                        dest[len + 1] = '(';
                        len += 2;
                    }
                } else {
                    len += f->name.l + 1 + x->s.l + 1 + (x->substrtype == any) + (x->next ? 2 : 0);
                }
                x = x->next;
            }
        }
        break;

    case PRESENT:
        if (dest) {
            memmove(dest + len, f->name.s, f->name.l);
            dest[len + f->name.l] = '=';
            dest[len + f->name.l + 1] = '*';
        }
        len += f->name.l + 2;
        break;

    case EXTENSIBLE:

    default:
        return -1;
    }
    if (dest) {
        dest[len] = ')';
    }
    return len + 1;
}

static uint32_t fmt_ldapsearchrequest(char *dest, SearchRequest *sr)
{
    int l, sum = fmt_ldapstring(dest, &sr->baseObject);
    if (dest) {
        dest += sum;
    }
    l = fmt_asn1ENUMERATED(dest, sr->scope);
    sum += l;
    if (dest) {
        dest += l;
    }
    l = fmt_asn1ENUMERATED(dest, sr->derefAliases);
    sum += l;
    if (dest) {
        dest += l;
    }
    l = fmt_asn1INTEGER(dest, sr->sizeLimit);
    sum += l;
    if (dest) {
        dest += l;
    }
    l = fmt_asn1INTEGER(dest, sr->timeLimit);
    sum += l;
    if (dest) {
        dest += l;
    }
    l = fmt_asn1BOOLEAN(dest, sr->typesOnly);
    sum += l;
    if (dest) {
        dest += l;
    }
    l = fmt_ldapsearchfilter(dest, sr->filter);
    sum += l;
    if (dest) {
        dest += l;
    }
    l = fmt_ldapattr(dest, sr->attributes);
    return sum + l;
}

static uint32_t fmt_ldapsearchresultentry(char *dest, SearchResultEntry *sre)
{
    uint32_t l, sum = fmt_ldapstring(dest, &sre->objectName);
    if (dest) {
        dest += sum;
    }
    l = fmt_asn1SEQUENCE(dest, fmt_ldapattrval(0, sre->attributes));
    sum += l;
    if (dest) {
        dest += l;
    }
    l = fmt_ldapattrval(dest, sre->attributes);
    return sum + l;
}

static uint32_t fmt_ldapstring(char *dest, String *s)
{
    return fmt_asn1OCTETSTRING(dest, s->s, s->l);
}

static void free_ldapsearchrequest(SearchRequest *s)
{
    free_ldapattr(s->attributes);
    free_ldapfilter(s->filter);
    s->filter = NULL;
    s->attributes = NULL;
}

static void free_ldapaddrequest(ModifyRequest *a)
{
    while (a->m) {
        Modify *tmp = a->m->next;
        free_ldapattr(a->m->values);
        ns_free(a);
        a->m = tmp;
    }
}

static void free_ldapmodifyrequest(ModifyRequest *m)
{
    while (m->m) {
        Modify *tmp = m->m->next;
        free_ldapattr(m->m->values);
        ns_free(m);
        m->m = tmp;
    }
}

static void free_ldapattr(Attribute *a)
{
    while (a) {
        Attribute *tmp = a->next;
        ns_free(a);
        a = tmp;
    }
}

static void free_ldapattrval(AttributeValues *a)
{
    while (a) {
        AttributeValues *tmp = a->next;
        free_ldapattr(a->values);
        ns_free(a);
        a = tmp;
    }
}

static void free_ldapfilter(Filter *f)
{
    while (f) {
        Filter *tmp = f->next;
        free_ldapfilter(f->subject);
        while (f->substrings) {
            Substring *s = f->substrings->next;
            ns_free(f->substrings);
            f->substrings = s;
        }
        ns_free(f);
        f = tmp;
    }
}

static void free_ldapsearchresultentry(SearchResultEntry *e)
{
    free_ldapattrval(e->attributes);
    e->attributes = NULL;
}

static void print_ldapfilter(Ns_DString *ds, Filter* f, int clear)
{
    if (clear) {
        Ns_DStringSetLength(ds, 0);
    }
    switch (f->type) {
     case AND:
         Ns_DStringAppend(ds, "& & {");
         print_ldapfilter(ds, f->subject, 0);
         Ns_DStringAppend(ds, "} ");
         break;

     case OR:
         Ns_DStringAppend(ds, "| | {");
         print_ldapfilter(ds, f->subject, 0);
         Ns_DStringAppend(ds, "} ");
         break;

     case NOT:
         Ns_DStringAppend(ds, "! ! {");
         print_ldapfilter(ds, f->subject, 0);
         Ns_DStringAppend(ds, "} ");
         break;

     case SUBSTRING: {
         Substring *s = f->substrings;
         Ns_DStringNAppend(ds, f->name.s, f->name.l);
         while (s) {
             switch(s->substrtype) {
              case prefix:
                  Ns_DStringAppend(ds, " prefix {");
                  break;
              case any:
                  Ns_DStringAppend(ds, " substr {");
                  break;
              case suffix:
                  Ns_DStringAppend(ds, " suffix {");
                  break;
             }
             Ns_DStringNAppend(ds, s->s.s, s->s.l);
             Ns_DStringAppend(ds, "}");
             s = s->next;
         }
         break;
     }

     case EQUAL:
         Ns_DStringNAppend(ds, f->name.s, f->name.l);
         Ns_DStringAppend(ds, " == {");
         Ns_DStringNAppend(ds, f->value.s, f->value.l);
         Ns_DStringAppend(ds, "}");
         break;


     case GREATEQUAL:
         Ns_DStringNAppend(ds, f->name.s, f->name.l);
         Ns_DStringAppend(ds, " >= {");
         Ns_DStringNAppend(ds, f->value.s, f->value.l);
         Ns_DStringAppend(ds, "}");
         break;

     case LESSEQUAL:
         Ns_DStringNAppend(ds, f->name.s, f->name.l);
         Ns_DStringAppend(ds, " <= {");
         Ns_DStringNAppend(ds, f->value.s, f->value.l);
         Ns_DStringAppend(ds, "}");
         break;

     case APPROX:
         Ns_DStringNAppend(ds, f->value.s, f->value.l);
         Ns_DStringAppend(ds, " approx {");
         Ns_DStringNAppend(ds, f->name.s, f->name.l);
         Ns_DStringAppend(ds, "}");
         break;

     case PRESENT:
         Ns_DStringNAppend(ds, f->value.s, f->value.l);
         Ns_DStringAppend(ds, " exists {");
         Ns_DStringNAppend(ds, f->name.s, f->name.l);
         Ns_DStringAppend(ds, "}");
         break;

     case EXTENSIBLE:
         Ns_DStringNAppend(ds, f->name.s, f->name.l);
         Ns_DStringPrintf(ds, " :%d {", f->flags);
         Ns_DStringNAppend(ds, f->value.s, f->value.l);
         Ns_DStringAppend(ds, "}");
         break;
    }
    if (f->next) {
        Ns_DStringAppend(ds, " ");
        print_ldapfilter(ds, f->next, 0);
    }
}

static void print_ldapsearch(Ns_DString *ds, SearchRequest* s, int clear)
{
    Attribute *attr = s->attributes;

    if (clear) {
        Ns_DStringSetLength(ds, 0);
    }
    Ns_DStringAppend(ds, "base {");
    Ns_DStringNAppend(ds, s->baseObject.s, s->baseObject.l);
    Ns_DStringPrintf(ds, "} scope %s alias %s sizelimit %u timelimit %u filter {", ldapScopes[s->scope], ldapAliases[s->derefAliases], s->sizeLimit, s->timeLimit);
    print_ldapfilter(ds, s->filter, 0);
    Ns_DStringAppend(ds, "} attributes {");
    while (attr) {
        Ns_DStringNAppend(ds, attr->name.s, attr->name.l);
        if ((attr = attr->next)) {
            Ns_DStringAppend(ds, " ");
        }
    }

    Ns_DStringAppend(ds, "}");
}

static void print_ldapbind(Ns_DString *ds, BindRequest* b, int clear)
{
    if (clear) {
        Ns_DStringSetLength(ds, 0);
    }
    Ns_DStringPrintf(ds, "version %u method %u ", b->version, b->method);
    Ns_DStringPrintf(ds, "methodname %s bindname {",  (b->method < MAX_BINDS ? ldapBinds[b->method] : "unknown"));
    Ns_DStringNAppend(ds, b->name.s, b->name.l);
    Ns_DStringAppend(ds, "} password {");
    Ns_DStringNAppend(ds, b->password.s, b->password.l);
    Ns_DStringAppend(ds, "} mechanism {");
    Ns_DStringNAppend(ds, b->mechanism.s, b->mechanism.l);
    Ns_DStringAppend(ds, "}");
}

static void print_ldapmodify(Ns_DString *ds, ModifyRequest* m, int clear)
{
    Attribute *val = m->m->values;

    if (clear) {
        Ns_DStringSetLength(ds, 0);
    }
    Ns_DStringPrintf(ds, "op %s object {",m->m->operation == Add ? "add" : m->m->operation == Delete ? "delete" : "relpace");
    Ns_DStringNAppend(ds, m->object.s, m->object.l);
    Ns_DStringAppend(ds, "} attribute {");
    Ns_DStringNAppend(ds, m->m->attribute.s, m->m->attribute.l);
    Ns_DStringAppend(ds, "} values {");
    while (val) {
        Ns_DStringNAppend(ds, val->name.s, val->name.l);
        if ((val = val->next)) {
            Ns_DStringAppend(ds, " ");
        }
    }
    Ns_DStringAppend(ds, "}");
}
