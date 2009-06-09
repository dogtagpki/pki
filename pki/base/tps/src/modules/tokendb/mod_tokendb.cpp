// --- BEGIN COPYRIGHT BLOCK ---
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation;
// version 2.1 of the License.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor,
// Boston, MA  02110-1301  USA 
// 
// Copyright (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

#ifdef __cplusplus
extern "C"
{
#endif

#ifdef XP_WIN32
#define TOKENDB_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TOKENDB_PUBLIC
#endif /* !XP_WIN32 */



/*  _________________________________________________________________
**
**  Tokendb Module Headers
**  _________________________________________________________________
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef XP_WIN32
#include <unistd.h>  /* sleep */
#else /* XP_WIN32 */
#include <windows.h>
#endif /* XP_WIN32 */

#include "nspr.h"
#include "prio.h"
#include "plstr.h"
#include "prmem.h"
#include "prtime.h"

#include "httpd/httpd.h"
#include "httpd/http_config.h"
#include "httpd/http_log.h"
#include "httpd/http_protocol.h"
#include "httpd/http_main.h"
#include "httpd/http_request.h"

#include "apr_strings.h"

#include "cms/CertEnroll.h"
#include "engine/RA.h"
#include "tus/tus_db.h"
#include "processor/RA_Processor.h"

extern TOKENDB_PUBLIC char *nss_var_lookup( apr_pool_t *p, server_rec *s,
                                            conn_rec *c, request_rec *r,
                                            char *var );


/*  _________________________________________________________________
**
**  Tokendb Module Definitions
**  _________________________________________________________________
*/

#define JS_START "<SCRIPT LANGUAGE=\"JavaScript\">\n<!--\n"
#define JS_STOP  "//-->\n</SCRIPT>\n"
#define CMS_TEMPLATE_TAG "<CMS_TEMPLATE>"

#define MAX_INJECTION_SIZE 5120
#define MAX_OVERLOAD       20
#define SHORT_LEN          256

#define BASE64_HEADER "-----BEGIN CERTIFICATE-----\n"
#define BASE64_FOOTER "-----END CERTIFICATE-----\n"

#define TOKENDB_OPERATORS_IDENTIFIER       "TUS Officers"
#define TOKENDB_AGENTS_IDENTIFIER         "TUS Agents"
#define TOKENDB_ADMINISTRATORS_IDENTIFIER "TUS Administrators"

#define OP_PREFIX "op.format"

#define NUM_PROFILES_TO_DISPLAY 15
#define NUM_ENTRIES_PER_PAGE 25
#define MAX_LEN_PROFILES_TO_DISPLAY 1000

#define error_out(msg1,msg2) \
    PR_snprintf(injection, MAX_INJECTION_SIZE, \
        "%s%s%s%s%s", JS_START, "var error = \"Error: ", \
        msg1,"\";\n", JS_STOP ); \
    buf = getData( errorTemplate, injection ); \
    ap_log_error( ( const char * ) "tus", __LINE__, \
        APLOG_ERR, 0, rq->server, \
        ( const char * ) msg2 ); \
    ( void ) ap_rwrite( ( const void * ) buf, PL_strlen( buf ), rq );

#define ldap_error_out(msg1,msg2) \
    PR_snprintf( injection, MAX_INJECTION_SIZE, \
        "%s%s%s%s%s%s", JS_START, \
        "var error = \"", msg1, \
        ldap_err2string( status ), \
        "\";\n", JS_STOP ); \
    buf = getData( errorTemplate, injection ); \
    ap_log_error( ( const char * ) "tus", __LINE__, \
        APLOG_ERR, 0, rq->server, \
        ( const char * ) msg2, \
        ldap_err2string( status ) ); \
    ( void ) ap_rwrite( ( const void * ) buf, PL_strlen( buf ), rq );

#define post_ldap_error(msg) \
    ap_log_error( ( const char * ) "tus", __LINE__, \
        APLOG_ERR, 0, rq->server, \
        (const char *) msg,  ldap_err2string( status ) );

#define get_cfg_string(cname, vname) \
    if( ( s = PL_strstr( buf, cname ) ) != NULL ) { \
        s += PL_strlen( cname ); \
        v = s; \
        while( *s != '\x0D' && *s != '\x0A' && *s != '\0' && \
               ( PRUint32 ) ( s - buf ) < size ) { \
            s++; \
        } \
        n = s - v; \
        s = PL_strndup( v, n ); \
        if( s != NULL ) { \
            if( vname != NULL ) { \
                PL_strfree( vname ); \
                vname = NULL; \
            } \
            vname = s; \
        } else { \
            do_free(buf); \
            return 0; \
        } \
    }

/**
 * Provide reasonable defaults for some defines.
 */
enum MOD_TOKENDB_BOOL {
    MOD_TOKENDB_FALSE = 0,
    MOD_TOKENDB_TRUE = 1
}; 



/*  _________________________________________________________________
**
**  Tokendb Module Request Data
**  _________________________________________________________________
*/

static PRFileDesc *debug_fd                  = NULL;
static char *templateDir                     = NULL;
static char *errorTemplate                   = NULL;
static char *indexTemplate                   = NULL;
static char *indexAdminTemplate              = NULL;
static char *indexOperatorTemplate           = NULL;
static char *newTemplate                     = NULL;
static char *searchTemplate                  = NULL;
static char *searchResultTemplate            = NULL;
static char *searchAdminTemplate             = NULL;
static char *searchAdminResultTemplate       = NULL;
static char *searchActivityTemplate          = NULL;
static char *searchCertificateTemplate       = NULL;
static char *searchCertificateResultTemplate = NULL;
static char *searchActivityResultTemplate    = NULL;
static char *searchActivityAdminTemplate     = NULL;
static char *searchActivityAdminResultTemplate = NULL;
static char *editTemplate                    = NULL;
static char *editResultTemplate              = NULL;
static char *showTemplate                    = NULL;
static char *showCertTemplate                = NULL;
static char *showAdminTemplate               = NULL;
static char *deleteTemplate                  = NULL;
static char *doTokenTemplate                 = NULL;
static char *doTokenConfirmTemplate          = NULL;
static char *revokeTemplate                  = NULL;
static char *addResultTemplate               = NULL;
static char *deleteResultTemplate            = NULL;
static char *editUserTemplate                = NULL;
static char *searchUserResultTemplate        = NULL;
static char *searchUserTemplate              = NULL;
static char *newUserTemplate                 = NULL;
static char *userDeleteTemplate              = NULL;
static char *auditAdminTemplate              = NULL;

static char *profileList                     = NULL;

static int sendInPieces = 0;
static RA_Processor m_processor;



/*  _________________________________________________________________
**
**  Tokendb Module Command Data
**  _________________________________________________________________
*/

static const char MOD_TOKENDB_CONFIGURATION_FILE_PARAMETER[] =
"TokendbConfigPathFile";

static const char MOD_TOKENDB_CONFIGURATION_FILE_USAGE[] =
"Tokendb Configuration Filename prefixed by a complete path, or\n"
"a path that is relative to the Apache server root.";



/*  _________________________________________________________________
**
**  Tokendb Module Server Configuration Creation Data
**  _________________________________________________________________
*/

typedef struct {
    char *Tokendb_Configuration_File;
    MOD_TOKENDB_BOOL enabled;
} mod_tokendb_server_configuration;



/*  _________________________________________________________________
**
**  Tokendb Module Registration Data
**  _________________________________________________________________
*/

#define MOD_TOKENDB_CONFIG_KEY tokendb_module

static const char MOD_TOKENDB_CONFIG_KEY_NAME[] = "tokendb_module";

extern module TOKENDB_PUBLIC MOD_TOKENDB_CONFIG_KEY;



/*  _________________________________________________________________
**
**  Tokendb Module Helper Functions
**  _________________________________________________________________
*/

/**
 * Terminate Apache
 */
void tokendb_die( void )
{
    /*
     * This is used for fatal errors and here
     * it is common module practice to really
     * exit from the complete program.
     */
    exit( 1 );
}


void tokendbDebug( const char* msg )
{
    RA::Debug( "mod_tokendb::mod_tokendb_handler",
               msg);
#if 0
    if( debug_fd ) {
        PR_fprintf( debug_fd, msg );
    }
#endif
}

inline void do_free(char * buf)
{
    if (buf != NULL) {
        PR_Free(buf);
        buf = NULL;
    }
}

/**
 * unencode
 * summary: takes a URL encoded string and returns an unencoded string 
 *        : must be freed by caller
 */
char *unencode(const char *src)
{
    char *dest = NULL;
    char *dp = NULL;
    dest = (char *) PR_Malloc(PL_strlen(src)* sizeof(char) + 1);
    dp = dest;
    for(; PL_strlen(src) > 0 ; src++, dp++)
        if(*src == '+')
            *dp = ' ';
        else if(*src == '%') {
            int code;
            if (sscanf(src+1, "%2x", &code) != 1) code = '?';
            *dp = code;
            src +=2; 
        }     
        else
         *dp = *src;
    *dp = '\0';
    return dest;
}

/**
 * get_field
 * summary: used to parse query strings in get and post requests
 *        : returns the value of the parameter following fname, in query string s.
 *         must be freed by caller.
 * example: get_field("op=hello&name=foo&title=bar", "name=") returns foo
 */
char *get_field( char *s, char* fname, int len)
{
    char *end = NULL;
    char *tmp = NULL;
    char *ret = NULL;
    int  n;

    if( ( s = PL_strstr( s, fname ) ) == NULL ) {
        return NULL;
    }

    s += strlen(fname);
    end = PL_strchr( s, '&' );

    if( end != NULL ) {
        n = end - s;
    } else {
        n = PL_strlen( s );
    }
    
    if (n == 0) {
        return NULL;
    } else if (n > len) {
        /* string too long */
        return NULL; 
    } else {
        tmp = (char *) PL_strndup(s,n);
        ret = unencode(tmp);
        do_free(tmp);
        return ret;
    }
}

/**
 * get_post_field
 * summary: get value from apr_table containing HTTP-Post values
 * params: post - apr_table with post data
 *       : fname = name of post-field
 */
char *get_post_field( apr_table_t *post, const char *fname, int len) 
{
   char *ret = NULL;
   if (post) {
      ret = unencode(apr_table_get(post, fname));
      if ((ret != NULL) && (PL_strlen(ret) > len)) {
        PR_Free(ret);
        return NULL;
      } else {
        return ret;
      }
   } else {
      return NULL;
  }
}

/**
 * similar to get_post_field - but returns the original post data
 * without unencoding - used for userCert 
 */
char *get_encoded_post_field(apr_table_t *post, const char *fname, int len)              
{
   char *ret = NULL;
   if (post) {
      ret = PL_strdup(apr_table_get(post, fname));
      if ((ret != NULL) && (PL_strlen(ret) > len)) {
        PL_strfree(ret);
        return NULL;
      } else {
        return ret;
      }
   } else {
      return NULL;
  }
}

/**
 * match_profile
 * summary: returns true if the profile passed in matches an existing profile
 *          in the profileList read from CS.cfg. Called when confirming that 
 *          a user entered "other profile" is a real profile
 */
bool match_profile(const char *profile)
{
   return RA::match_comma_list(profile, profileList);
}

char *getTemplateFile( char *fileName, int *injectionTagOffset )
{
    char *buf = NULL;
    char *s   = NULL;
    PRFileDesc *fd = NULL;
    char fullFileName[4096];
    PRFileInfo info;
    PRUint32   fileSize;
    PRUint32   size;
    PRInt32    k, n;

    *injectionTagOffset = -1;

    PR_snprintf( fullFileName, 4096, "%s/%s", templateDir, fileName );

    if( PR_GetFileInfo( fullFileName, &info ) != PR_SUCCESS ) {
        return buf;
    }

    fileSize = info.size;
    size = fileSize + 1;

    buf = ( char * ) PR_Malloc( size );
    if( buf == NULL ) {
        return buf;
    }

    fd = PR_Open( fullFileName, PR_RDONLY, 00400 );
    if( fd == NULL ) {
        if( buf != NULL ) {
            PR_Free( buf );
            buf = NULL;
        }
        return NULL;
    }

    k = 0;
    while( ( n = PR_Read( fd, &buf[k], fileSize-k ) ) > 0 ) {
        k += n;
        if( ( PRUint32 ) k >= fileSize ) {
            break;
        }
    }

    if( fd != NULL ) {
        PR_Close( fd );
        fd = NULL;
    }

    if( n < 0 || ( ( PRUint32 ) k > fileSize ) ) {
        if( buf != NULL ) {
            PR_Free( buf );
            buf = NULL;
        }
        return NULL;
    }

    buf[k] = '\0';

    if( ( s = PL_strstr( buf, CMS_TEMPLATE_TAG ) ) != NULL ) {
        *injectionTagOffset = PL_strlen( buf ) - PL_strlen( s );
    }

    return buf;
}


char *getData( char *fileName, char *injection )
{
    char *buf = NULL;
    char *s   = NULL;
    PRFileDesc *fd = NULL;
    char fullFileName[4096];
    PRFileInfo info;
    PRUint32   fileSize;
    PRUint32   size, len;
    PRUint32   injectionSize;
    PRInt32    k, n;

    PR_snprintf( fullFileName, 4096, "%s/%s", templateDir, fileName );

    if( PR_GetFileInfo( fullFileName, &info ) != PR_SUCCESS ) {
        return buf;
    }

    fileSize = info.size;
    size = fileSize;
    injectionSize = 0;

    if( injection != NULL && PL_strlen( injection ) > 0 ) {
        injectionSize = PL_strlen( injection );
        size += injectionSize;
    }

    size++;

    buf = ( char * ) PR_Malloc( size );
    if( buf == NULL ) {
        return buf;
    }

    fd = PR_Open( fullFileName, PR_RDONLY, 00400 );
    if( fd == NULL ) {
        if( buf != NULL ) {
            PR_Free( buf );
            buf = NULL;
        }
        return NULL;
    }

    k = 0;
    while( ( n = PR_Read( fd, &buf[k], fileSize-k ) ) > 0 ) {
        k += n;
        if( ( PRUint32 ) k >= fileSize ) {
            break;
        }
    }

    if( fd != NULL ) {
        PR_Close( fd );
        fd = NULL;
    }

    if( n < 0 || ( ( PRUint32 ) k > fileSize ) ) {
        if( buf != NULL ) {
            PR_Free( buf );
            buf = NULL;
        }
        return NULL;
    }

    buf[k] = '\0';
    if( injectionSize > 0 ) {
        if( ( s = PL_strstr( buf, CMS_TEMPLATE_TAG ) ) != NULL ) {
            len = PL_strlen( s ) - PL_strlen( CMS_TEMPLATE_TAG );
            memmove( s + injectionSize, 
                     s + PL_strlen( CMS_TEMPLATE_TAG ),
                     len + 1 );
            memcpy( s, injection, injectionSize );
        }
    }

    return buf;
}

/**
 * returns string with special characters escaped.  Caller must free the contents 
 */
char *escapeSpecialChars(char* src)
{
    char *ret;
    int i =0;

    if (PL_strlen(src) == 0) {
        return PL_strdup(src);
    }
    ret = (char *)PR_Malloc(PL_strlen(src) * 2 + 1);

    while (*src != '\0') {
        if (*src == '"') {
            ret[i++] = '\\';
            ret[i++] = '"';
        } else {
            ret[i++] = *src;
        }
        src++; 
    }
    ret[i]='\0';  
    return ret;   
}


void getCertificateFilter( char *filter, char *query )
{
    char *uid  = NULL;
    char *tid  = NULL;
    char *end  = NULL;
    char *cn  = NULL;
    char *view = NULL;
    int  len   = 0;
    int  i     = 0;

    tid  = PL_strstr( query, "tid=" );
    uid  = PL_strstr( query, "uid=" );
    cn  = PL_strstr( query, "cn=" );
    view = PL_strstr( query, "op=view" );

    if( view == NULL ) {
      view = PL_strstr( query, "op=show" );
    }

    filter[0] = '\0';

    if( tid == NULL && uid == NULL && cn == NULL ) {
      PL_strcat( filter, "(tokenID=*)" );
      return;
    }

    if( tid != NULL && uid != NULL &&  view != NULL ) {
        PL_strcat( filter, "(&" );
    }

    if( tid != NULL ) {
        PL_strcat( filter, "(tokenID=" );
        end = PL_strchr( tid, '&' );
        len = PL_strlen( filter );
        if( end != NULL ) {
            i = end - tid - 4;

            if( i > 0 ) {
                memcpy( filter+len, tid+4, i );
            }
            filter[len+i] = '\0';
        } else {
            PL_strcat( filter, tid+4 );
        }
        if( view != NULL ) {
            PL_strcat( filter, "*)" );
        } else {
            PL_strcat( filter, ")" );
        }
    }

    if( uid != NULL && view != NULL ) {
        PL_strcat( filter, "(tokenUserID=" );
        end = PL_strchr( uid, '&' );
        len = PL_strlen( filter );
        if( end != NULL ) {
            i = end - uid - 4;
            if( i > 0 ) {
                memcpy( filter+len, uid+4, i );
            }

            filter[len+i] = '\0';
        } else {
            PL_strcat( filter, uid+4 );
        }

        PL_strcat( filter, "*)" );
        /* PL_strcat( filter, ")" ); */
    }

    if( cn != NULL ) {
        PL_strcat( filter, "(cn=" );
        end = PL_strchr( cn, '&' );
        len = PL_strlen( filter );
        if( end != NULL ) {
            i = end - cn - 3;
            if( i > 0 ) {
                memcpy( filter+len, cn+3, i );
            }

            filter[len+i] = '\0';
        } else {
            PL_strcat( filter, cn+3 );
        }

        PL_strcat( filter, "*)" );
        /* PL_strcat( filter, ")" ); */
    }

    if(tid != NULL && uid != NULL && view != NULL) {
        PL_strcat( filter, ")" );
    }
}


void getActivityFilter( char *filter, char *query )
{
    char *uid  = NULL;
    char *tid  = NULL;
    char *end  = NULL;
    char *view = NULL;
    int  len   = 0;
    int  i     = 0;

    tid  = PL_strstr( query, "tid=" );
    uid  = PL_strstr( query, "uid=" );
    view = PL_strstr( query, "op=view" );
    filter[0] = '\0';

    if( tid == NULL && uid == NULL ) {
      PL_strcat( filter, "(tokenID=*)" );
    }

    if( tid != NULL && uid != NULL && view != NULL ) {
        PL_strcat( filter, "(&" );
    }

    if( tid != NULL ) {
        PL_strcat( filter, "(tokenID=" );
        end = PL_strchr( tid, '&' );
        len = PL_strlen( filter );

        if( end != NULL ) {
            i = end - tid - 4;
            if( i > 0 ) {
                memcpy( filter+len, tid+4, i );
            }
            filter[len+i] = '\0';
        } else {
            PL_strcat( filter, tid+4 );
        }

        if( view != NULL ) {
            PL_strcat( filter, "*)" );
        } else {
            PL_strcat( filter, ")" );
        }
    }

    if( uid != NULL && view != NULL ) {
        PL_strcat( filter, "(tokenUserID=" );
        end = PL_strchr( uid, '&' );
        len = PL_strlen( filter );
        if( end != NULL ) {
            i = end - uid - 4;
            if( i > 0 ) {
                memcpy( filter+len, uid+4, i );
            }

            filter[len+i] = '\0';
        } else {
            PL_strcat( filter, uid+4 );
        }

        PL_strcat( filter, "*)" );
        /* PL_strcat( filter, ")" ); */
    }

    if( tid != NULL && uid != NULL && view != NULL) {
        PL_strcat( filter, ")" );
    }
}

/**
 * get_user_filter
 * summary: returns an ldap search filter used for displaying 
 *          user data when searching users based on uid, firstName and lastName
 * params: filter - ldap search filter.  Resu;t returned here.
 *         query  - query string passed in
 */
void getUserFilter (char *filter, char *query) {
    char *uid        = NULL;
    char *firstName  = NULL;
    char *lastName   = NULL;

    uid  = get_field(query, "uid=", SHORT_LEN);
    firstName = get_field(query, "firstName=", SHORT_LEN);
    lastName = get_field(query, "lastName=", SHORT_LEN);
  
    filter[0] = '\0';

    if ((uid == NULL) && (firstName == NULL) && (lastName ==NULL)) {
        PL_strcat(filter, "(objectClass=Person");
    } else {
        PL_strcat(filter, "(&(objectClass=Person)");
    }

    if (uid != NULL) {
        PL_strcat(filter, "(uid=");
        PL_strcat(filter, uid);
        PL_strcat(filter,")");
    }

    if (lastName != NULL) {
        PL_strcat(filter, "(sn=");
        PL_strcat(filter, lastName);
        PL_strcat(filter,")");
    }

    if (firstName != NULL) {
        PL_strcat(filter, "(givenName=");
        PL_strcat(filter, firstName);
        PL_strcat(filter,")");
    }

    PL_strcat(filter, ")");

    do_free(uid);
    do_free(firstName);
    do_free(lastName);
}

/**
 * add_profile_filter
 * summary: returns an ldap search filter which is a concatenation 
 *          of the authorized profile search filter and the regular search
 *          filter.  To be freed by caller.
 * params: filter - search filter
 *         auth_filter: authorized profiles filter
 */
char *add_profile_filter( char *filter, char *auth_filter)
{
    char *ret;
    int size;
    char no_auth_filter[] = "(tokenType=\"\")";
    if (filter == NULL) return NULL;
    if ((auth_filter == NULL) || (PL_strstr( auth_filter, ALL_PROFILES))) {
        ret = PL_strdup(filter);
    } else if (PL_strstr( auth_filter, NO_PROFILES)) {
        size = (PL_strlen(filter) + PL_strlen(no_auth_filter) + 4) * sizeof(char);
        ret = (char *) PR_Malloc(size);
        PR_snprintf(ret, size, "%s%s%s%s",
            "(&", filter,no_auth_filter, ")");
    } else {
        size = (PL_strlen(filter) + PL_strlen(auth_filter) + 4) * sizeof(char);
        ret = (char *) PR_Malloc(size);
        PR_snprintf(ret, size, "%s%s%s%s", 
            "(&", filter, auth_filter, ")");
    }
    return ret;
}
           

void getFilter( char *filter, char *query )
{
    char *uid  = NULL;
    char *tid  = NULL;
    char *end  = NULL;
    char *view = NULL;
    int  len   = 0;
    int  i     = 0;

    tid  = PL_strstr( query, "tid=" );
    uid  = PL_strstr( query, "uid=" );
    view = PL_strstr( query, "op=view" );
    filter[0] = '\0';

    if( tid == NULL && uid == NULL ) {
      PL_strcat( filter, "(cn=*)" );
    }

    if( tid != NULL && uid != NULL && view != NULL ) {
        PL_strcat( filter, "(&" );
    }

    if( tid != NULL ) {
        PL_strcat( filter, "(cn=" );
        end = PL_strchr( tid, '&' );
        len = PL_strlen( filter );

        if( end != NULL ) {
            i = end - tid - 4;
            if( i > 0 ) {
                memcpy( filter+len, tid+4, i );
            }

            filter[len+i] = '\0';
        } else {
            PL_strcat( filter, tid+4 );
        }

        if (view != NULL) {
            PL_strcat( filter, "*)" );
        } else {
            PL_strcat( filter, ")" );
        }
    }

    if( uid != NULL && view != NULL ) {
        PL_strcat( filter, "(tokenUserID=" );
        end = PL_strchr( uid, '&' );
        len = PL_strlen( filter );
        if( end != NULL ) {
            i = end - uid - 4;
            if( i > 0 ) {
                memcpy( filter+len, uid+4, i );
            }

            filter[len+i] = '\0';
        } else {
            PL_strcat( filter, uid+4 );
        }

        PL_strcat( filter, "*)" );
        /* PL_strcat( filter, ")" ); */
    }

    if( tid != NULL && uid != NULL && view != NULL ) {
        PL_strcat( filter, ")" );
    }
}


void getCN( char *cn, char *query )
{
    char *tid = NULL;
    char *end = NULL;
    int  i    = 0;

    cn[0] = '\0';
    tid  = PL_strstr( query, "tid=" );
    if( tid != NULL ) {
        end = PL_strchr( tid, '&' );

        if( end != NULL ) {
            i = end - tid - 4;

            if( i > 0 ) {
                memcpy( cn, tid+4, i );
            }

            cn[i] = '\0';
        } else {
            PL_strcat( cn, tid+4 );
        }
    }
}


void getTemplateName( char *cn, char *query )
{
    char *tid = NULL;
    char *end = NULL;
    int  i    = 0;

    cn[0] = '\0';
    tid  = PL_strstr( query, "template=" );

    if( tid != NULL ) {
        end = PL_strchr( tid, '&' );

        if( end != NULL ) {
            i = end - tid - 4;

            if( i > 0 ) {
                memcpy( cn, tid+4, i );
            }

            cn[i] = '\0';
        } else {
            PL_strcat( cn, tid+4 );
        }
    }
}


char *parse_modification_number( char *s )
{
    char *end = NULL;
    int  n;

    if( ( s = PL_strstr( s, "m=" ) ) == NULL ) {
        return NULL;
    }

    s += 2;
    end = PL_strchr( s, '&' );

    if( end != NULL ) {
        n = end - s;
    } else {
        n = PL_strlen( s );
    }
    
    return PL_strndup( s, n );
}


char **parse_modification_number_change( char *s )
{
    char *end = NULL;
    char **v  = NULL;
    char tmp[32];
    int  n, m;

    end = PL_strchr( s, '&' );

    if( end != NULL ) {
        n = end - s;
        if( n > 0 ) {
            memcpy( tmp, s, n );
        }
        tmp[n] = '\0';
    } else {
        n = PL_strlen( s );
        PL_strcpy( tmp, s );
    }

    m = atoi( tmp );
    m++;
    PR_snprintf( tmp, 32, "%d", m );
    n = PL_strlen( tmp );

    if( ( v = allocate_values( 1, n+1 ) ) == NULL ) {
        return NULL;
    }

    PL_strcpy( v[0], tmp );

    return v;
}


char **parse_status_change( char *s )
{
    char *end = NULL;
    char **v  = NULL;
    int  n;

    end = PL_strchr( s, '&' );
    if( end != NULL ) {
        n = end - s;
    } else {
        n = PL_strlen( s );
    }

    if( ( v = allocate_values( 1, n+1 ) ) == NULL ) {
        return NULL;
    }
    PL_strncpy( v[0], s, n );

    return v;
}


char **parse_uid_change( char *s )
{
    char *end = NULL;
    char *p   = NULL;
    char *q   = NULL;
    char **v  = NULL;
    int   i, k, n, m;

    end = PL_strchr( s, '&' );
    if( end != NULL ) {
        n = end - s;
    } else {
        n = PL_strlen( s );
    }

    k = n;
    p = s;
    m = 1;

    while( k > 0 ) {
        if( ( p = PL_strnchr( p, ',', k ) ) == NULL ) {
            break;
        }

        p++;
        k = n - ( p - s );
        m++;
    }
        
    if( ( v = allocate_values( m, n+1 ) ) == NULL ) {
        return NULL;
    }

    if( m > 1 ) {
        k = n;
        p = s;
        i = 0;

        while( k > 0 ) {
            if( ( q = PL_strnchr( p, ',', k ) ) != NULL ) {
                PL_strncpy( v[i], p, q-p );
                q++;
                p = q;
                k = n - ( p - s );
                i++;
                v[i] = v[i-1] + PL_strlen( v[i-1] ) + 1;
            } else {
                PL_strncpy( v[i], p, k );
                break;
            }
        }
    } else {
        PL_strncpy( v[0], s, n );
    }
    
    return v;
}


char **parse_reason_change( char *s )
{
    char *end = NULL;
    char **v  = NULL;
    int  n;

    end = PL_strchr( s, '&' );
    if( end != NULL ) {
        n = end - s;
    } else {
        n = PL_strlen( s );
    }

    if( ( v = allocate_values( 1, n+1 ) ) == NULL ) {
        return NULL;
    }
    PL_strncpy( v[0], s, n );

    return v;
}


char **parse_policy_change( char *s )
{
    char *end = NULL;
    char **v  = NULL;
    int  n;

    end = PL_strchr( s, '&' );

    if( end != NULL ) {
        n = end - s;
    } else {
        n = PL_strlen( s );
    }

    if( ( v = allocate_values( 1, n+1 ) ) == NULL ) {
        return NULL;
    }

    PL_strncpy( v[0], s, n );

    return v;
}


LDAPMod **getModifications( char *query )
{
    LDAPMod **mods = NULL;
    char **v = NULL;
    int  n   = 0;
    int  k   = 0;
    char *s;

    s  = query;

    while( ( s = PL_strchr( s, '&' ) ) != NULL ) {
        s++;
        n++;
    }

    if( n > 0 && PL_strstr( query, "&tid=" ) != NULL ) {
        n--;
    }

    if( n > 0 ) {
        n++;
    } else {
        return NULL;
    }


    mods = allocate_modifications( n );

    if( mods == NULL ) {
        return NULL;
    }

    if( ( v = create_modification_date_change() ) == NULL ) {
        if( mods != NULL ) {
            free_modifications( mods, 0 );
            mods = NULL;
        }
        return NULL;
    }

    mods[0]->mod_op = LDAP_MOD_REPLACE;
    mods[0]->mod_type = get_modification_date_name();
    mods[0]->mod_values = v;
    k = 1;

    if( k < n && ( ( s = PL_strstr( query, "m=" ) ) != NULL ) ) {
        s += 2;
        if( ( v = parse_modification_number_change( s ) ) == NULL ) {
            if( mods != NULL ) {
                free_modifications( mods, 0 );
                mods = NULL;
            }
            return NULL;
        }

        mods[k]->mod_op = LDAP_MOD_REPLACE;
        mods[k]->mod_type = get_number_of_modifications_name();
        mods[k]->mod_values = v;
        k++;
    }

    if( k < n && ( ( s = PL_strstr( query, "s=" ) ) != NULL ) ) {
        s += 2;

        if( ( v = parse_status_change( s ) ) == NULL ) {
            if( mods != NULL ) {
                free_modifications( mods, 0 );
                mods = NULL;
            }
            return NULL;
        }

        mods[k]->mod_op = LDAP_MOD_REPLACE;
        mods[k]->mod_type = get_token_status_name();
        mods[k]->mod_values = v;
        k++;
    }

    if( k < n && ( ( s = PL_strstr( query, "uid=" ) ) != NULL ) ) {
        s += 4;
        if( ( v = parse_uid_change( s ) ) == NULL ) {
            if( mods != NULL ) {
                free_modifications( mods, 0 );
                mods = NULL;
            }
            return NULL;
        }

        mods[k]->mod_op = LDAP_MOD_REPLACE;
        mods[k]->mod_type = get_token_users_name();
        mods[k]->mod_values = v;
        k++;
    }

    if( k < n && ( ( s = PL_strstr( query, "tokenPolicy=" ) ) != NULL ) ) {
        s += 12;

        if( ( v = parse_policy_change( s ) ) == NULL ) {
            if( mods != NULL ) {
                free_modifications( mods, 0 );
                mods = NULL;
            }
            return NULL;
        }

        mods[k]->mod_op = LDAP_MOD_REPLACE;
        mods[k]->mod_type = get_policy_name();
        mods[k]->mod_values = v;
        k++;
    }

    if( k < n && ( ( s = PL_strstr( query, "tokenReason=" ) ) != NULL ) ) {
        s += 12;

        if( ( v = parse_reason_change( s ) ) == NULL ) {
            if( mods != NULL ) {
                free_modifications( mods, 0 );
                mods = NULL;
            }
            return NULL;
        }

        mods[k]->mod_op = LDAP_MOD_REPLACE;
        mods[k]->mod_type = get_reason_name();
        mods[k]->mod_values = v;
        k++;
    }

    return mods;
}

int get_tus_config( char *name )
{
    PRFileDesc *fd = NULL;
    char *buf = NULL;
    char *s   = NULL;
    char *v   = NULL;
    PRFileInfo info;
    PRUint32   size;
    int  k, n;

    if( PR_GetFileInfo( name, &info ) != PR_SUCCESS ) {
        return 0;
    }

    size = info.size;
    size++;
    buf = (char *)PR_Malloc( size );

    if( buf == NULL ) {
        return 0;
    }

    fd = PR_Open( name, PR_RDONLY, 00400 );
    if( fd == NULL ) {
        if( buf != NULL ) {
            PR_Free( buf );
            buf = NULL;
        }
        return 0;
    }

    k = 0;
    while( ( n = PR_Read( fd, &buf[k], size-k-1 ) ) > 0 ) {
        k += n;
        if( ( PRUint32 ) ( k+1 ) >= size ) {
            break;
        }
    }

    if( fd != NULL ) {
        PR_Close( fd );
        fd = NULL;
    }

    if( n < 0 || ( ( PRUint32 ) ( k+1 ) > size ) ) {
        if( buf != NULL ) {
            PR_Free( buf );
            buf = NULL;
        }
        return 0;
    }

    buf[k] = '\0';

    if( ( s = PL_strstr( buf, "tokendb.templateDir=" ) ) != NULL ) {
        s += PL_strlen( "tokendb.templateDir=" );
        v = s;

        while( *s != '\x0D' && *s != '\x0A' && *s != '\0' && 
               ( PRUint32 ) ( s - buf ) < size ) {
            s++;
        }

        n = s - v;

        s = PL_strndup( v, n );
        if( s != NULL ) {
            if( templateDir != NULL ) {
                PL_strfree( templateDir );
                templateDir = NULL;
            }
            templateDir = s;
        } else {
            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }
            return 0;
        }
    }

    if( ( s = PL_strstr( buf, "tokendb.errorTemplate=" ) ) != NULL ) {
        s += PL_strlen( "tokendb.errorTemplate=" );
        v = s;

        while( *s != '\x0D' && *s != '\x0A' && *s != '\0' && 
               ( PRUint32 ) ( s - buf ) < size ) {
            s++;
        }

        n = s - v;

        s = PL_strndup( v, n );
        if( s != NULL ) {
            if( errorTemplate != NULL ) {
                PL_strfree( errorTemplate );
                errorTemplate = NULL;
            }
            errorTemplate = s;
        } else {
            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }
            return 0;
        }
    }

    if( ( s = PL_strstr( buf, "tokendb.indexTemplate=" ) ) != NULL ) {
        s += PL_strlen( "tokendb.indexTemplate=" );
        v = s;

        while( *s != '\x0D' && *s != '\x0A' && *s != '\0' && 
               ( PRUint32 ) ( s - buf ) < size ) {
            s++;
        }

        n = s - v;

        s = PL_strndup( v, n );
        if( s != NULL ) {
            if( indexTemplate != NULL ) {
                PL_strfree( indexTemplate );
                indexTemplate = NULL;
            }
            indexTemplate = s;
        } else {
            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }
            return 0;
        }
    }

    if( ( s = PL_strstr( buf, "tokendb.indexAdminTemplate=" ) ) != NULL ) {
        s += PL_strlen( "tokendb.indexAdminTemplate=" );
        v = s;

        while( *s != '\x0D' && *s != '\x0A' && *s != '\0' && 
               ( PRUint32 ) ( s - buf ) < size ) {
            s++;
        }

        n = s - v;

        s = PL_strndup( v, n );
        if( s != NULL ) {
            if( indexAdminTemplate != NULL ) {
                PL_strfree( indexAdminTemplate );
                indexAdminTemplate = NULL;
            }
            indexAdminTemplate = s;
        } else {
            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }
            return 0;
        }
    }

    if( ( s = PL_strstr( buf, "tokendb.indexOperatorTemplate=" ) ) != NULL ) {
        s += PL_strlen( "tokendb.indexOperatorTemplate=" );
        v = s;

        while( *s != '\x0D' && *s != '\x0A' && *s != '\0' && 
               ( PRUint32 ) ( s - buf ) < size ) {
            s++;
        }

        n = s - v;

        s = PL_strndup( v, n );
        if( s != NULL ) {
            if( indexOperatorTemplate != NULL ) {
                PL_strfree( indexOperatorTemplate );
                indexOperatorTemplate = NULL;
            }
            indexOperatorTemplate = s;
        } else {
            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }
            return 0;
        }
    }

    if( ( s = PL_strstr( buf, "tokendb.newTemplate=" ) ) != NULL ) {
        s += PL_strlen( "tokendb.newTemplate=" );
        v = s;

        while( *s != '\x0D' && *s != '\x0A' && *s != '\0' && 
               ( PRUint32 )( s - buf ) < size ) {
            s++;
        }

        n = s - v;

        s = PL_strndup( v, n );
        if( s != NULL ) {
            if( newTemplate != NULL ) {
                PL_strfree( newTemplate );
                newTemplate = NULL;
            }
            newTemplate = s;
        } else {
            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }
            return 0;
        }
    }
    
     if( ( s = PL_strstr( buf, "tokendb.searchUserResultTemplate=" ) ) != NULL ) {
        s += PL_strlen( "tokendb.searchUserResultTemplate=" );
        v = s;

        while( *s != '\x0D' && *s != '\x0A' && *s != '\0' &&
               ( PRUint32 )( s - buf ) < size ) {
            s++;
        }

        n = s - v;

        s = PL_strndup( v, n );
        if( s != NULL ) {
            do_free(searchUserResultTemplate);
            searchUserResultTemplate = s;
        } else {
            do_free(buf);
            return 0;
        }
    }

    if( ( s = PL_strstr( buf, "tokendb.newUserTemplate=" ) ) != NULL ) {
        s += PL_strlen( "tokendb.newUserTemplate=" );
        v = s;

        while( *s != '\x0D' && *s != '\x0A' && *s != '\0' &&
               ( PRUint32 )( s - buf ) < size ) {
            s++;
        }

        n = s - v;

        s = PL_strndup( v, n );
        if( s != NULL ) {
            do_free(newUserTemplate);
            newUserTemplate = s;
        } else {
            do_free(buf);
            return 0;
        }
    }

    if( ( s = PL_strstr( buf, "tokendb.searchTemplate=" ) ) != NULL ) {
        s += PL_strlen( "tokendb.searchTemplate=" );
        v = s;

        while( *s != '\x0D' && *s != '\x0A' && *s != '\0' && 
               ( PRUint32 ) ( s - buf ) < size ) {
            s++;
        }

        n = s - v;

        s = PL_strndup( v, n );
        if( s != NULL ) {
            if( searchTemplate != NULL ) {
                PL_strfree( searchTemplate );
                searchTemplate = NULL;
            }
            searchTemplate = s;
        } else {
            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }
            return 0;
        }
    }

    if( ( s = PL_strstr( buf, "tokendb.searchCertificateTemplate=" ) ) != NULL ) {
        s += PL_strlen( "tokendb.searchCertificateTemplate=" );
        v = s;

        while( *s != '\x0D' && *s != '\x0A' && *s != '\0' && 
               ( PRUint32 ) ( s - buf ) < size ) {
            s++;
        }

        n = s - v;

        s = PL_strndup( v, n );
        if( s != NULL ) {
            if( searchCertificateTemplate != NULL ) {
                PL_strfree( searchCertificateTemplate );
                searchCertificateTemplate = NULL;
            }
            searchCertificateTemplate = s;
        } else {
            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }
            return 0;
        }
    }

    if( ( s = PL_strstr( buf, "tokendb.searchAdminTemplate=" ) ) != NULL ) {
        s += PL_strlen( "tokendb.searchAdminTemplate=" );
        v = s;

        while( *s != '\x0D' && *s != '\x0A' && *s != '\0' && 
               ( PRUint32 ) ( s - buf ) < size ) {
            s++;
        }

        n = s - v;

        s = PL_strndup( v, n );
        if( s != NULL ) {
            if( searchAdminTemplate != NULL ) {
                PL_strfree( searchAdminTemplate );
                searchAdminTemplate = NULL;
            }
            searchAdminTemplate = s;
        } else {
            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }
            return 0;
        }
    }
  
     if( ( s = PL_strstr( buf, "tokendb.searchUserTemplate=" ) ) != NULL ) {
        s += PL_strlen( "tokendb.searchUserTemplate=" );
        v = s;

        while( *s != '\x0D' && *s != '\x0A' && *s != '\0' &&
               ( PRUint32 ) ( s - buf ) < size ) {
            s++;
        }

        n = s - v;

        s = PL_strndup( v, n );
        if( s != NULL ) {
            if( searchUserTemplate != NULL ) {
                PL_strfree( searchUserTemplate );
                searchUserTemplate = NULL;
            }
            searchUserTemplate = s;
        } else {
            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }
            return 0;
        }
    }

    if( ( s = PL_strstr( buf, "tokendb.searchActivityTemplate=" ) ) != NULL) {
        s += PL_strlen( "tokendb.searchActivityTemplate=" );
        v = s;

        while( *s != '\x0D' && *s != '\x0A' && *s != '\0' && 
               ( PRUint32 ) ( s - buf ) < size ) {
            s++;
        }

        n = s - v;

        s = PL_strndup( v, n );
        if( s != NULL ) {
            if( searchActivityTemplate != NULL ) {
                PL_strfree( searchActivityTemplate );
                searchActivityTemplate = NULL;
            }
            searchActivityTemplate = s;
        } else {
            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }
            return 0;
        }
    }

    if( ( s = PL_strstr( buf, "tokendb.searchActivityAdminTemplate=" ) ) != NULL) {
        s += PL_strlen( "tokendb.searchActivityAdminTemplate=" );
        v = s;

        while( *s != '\x0D' && *s != '\x0A' && *s != '\0' && 
               ( PRUint32 ) ( s - buf ) < size ) {
            s++;
        }

        n = s - v;

        s = PL_strndup( v, n );
        if( s != NULL ) {
            if( searchActivityAdminTemplate != NULL ) {
                PL_strfree( searchActivityAdminTemplate );
                searchActivityAdminTemplate = NULL;
            }
            searchActivityAdminTemplate = s;
        } else {
            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }
            return 0;
        }
    }

    if( ( s = PL_strstr( buf, "tokendb.searchCertificateResultTemplate=" ) ) !=
        NULL ) {
        s += PL_strlen( "tokendb.searchCertificateResultTemplate=" );
        v = s;

        while( *s != '\x0D' && *s != '\x0A' && *s != '\0' && 
               ( PRUint32 ) ( s - buf ) < size ) {
            s++;
        }

        n = s - v;

        s = PL_strndup( v, n );
        if( s != NULL ) {
            if( searchCertificateResultTemplate != NULL ) {
                PL_strfree( searchCertificateResultTemplate );
                searchCertificateResultTemplate = NULL;
            }
            searchCertificateResultTemplate = s;
        } else {
            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }
            return 0;
        }
    }

    if( ( s = PL_strstr( buf, "tokendb.searchActivityResultTemplate=" ) ) !=
        NULL ) {
        s += PL_strlen( "tokendb.searchActivityResultTemplate=" );
        v = s;

        while( *s != '\x0D' && *s != '\x0A' && *s != '\0' && 
               ( PRUint32 ) ( s - buf ) < size ) {
            s++;
        }

        n = s - v;

        s = PL_strndup( v, n );
        if( s != NULL ) {
            if( searchActivityResultTemplate != NULL ) {
                PL_strfree( searchActivityResultTemplate );
                searchActivityResultTemplate = NULL;
            }
            searchActivityResultTemplate = s;
        } else {
            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }
            return 0;
        }
    }

    if( ( s = PL_strstr( buf, "tokendb.searchAdminResultTemplate=" ) ) !=
        NULL ) {
        s += PL_strlen( "tokendb.searchAdminResultTemplate=" );
        v = s;
        while( *s != '\x0D' && *s != '\x0A' && *s != '\0' && 
               ( PRUint32 ) ( s - buf ) < size ) {
            s++;
        }

        n = s - v;

        s = PL_strndup( v, n );
        if( s != NULL ) {
            if( searchAdminResultTemplate != NULL ) {
                PL_strfree( searchAdminResultTemplate );
                searchAdminResultTemplate = NULL;
            }
            searchAdminResultTemplate = s;
        } else {
            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }
            return 0;
        }
    }

    if( ( s = PL_strstr( buf, "tokendb.searchResultTemplate=" ) ) != NULL ) {
        s += PL_strlen( "tokendb.searchResultTemplate=" );
        v = s;

        while( *s != '\x0D' && *s != '\x0A' && *s != '\0' && 
               ( PRUint32 ) ( s - buf ) < size ) {
            s++;
        }

        n = s - v;

        s = PL_strndup( v, n );
        if( s != NULL ) {
            if( searchResultTemplate != NULL ) {
                PL_strfree( searchResultTemplate );
                searchResultTemplate = NULL;
            }
            searchResultTemplate = s;
        } else {
            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }
            return 0;
        }
    }

    if( ( s = PL_strstr( buf, "tokendb.deleteTemplate=" ) ) != NULL ) {
        s += PL_strlen( "tokendb.deleteTemplate=" );
        v = s;

        while( *s != '\x0D' && *s != '\x0A' && *s != '\0' && 
               ( PRUint32 ) ( s - buf ) < size ) {
            s++;
        }

        n = s - v;

        s = PL_strndup( v, n );
        if( s != NULL ) {
            if( deleteTemplate != NULL ) {
                PL_strfree( deleteTemplate );
                deleteTemplate = NULL;
            }
            deleteTemplate = s;
        } else {
            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }
            return 0;
        }
    }

    if( ( s = PL_strstr( buf, "tokendb.userDeleteTemplate=" ) ) != NULL ) {
        s += PL_strlen( "tokendb.userDeleteTemplate=" );
        v = s;

        while( *s != '\x0D' && *s != '\x0A' && *s != '\0' &&
               ( PRUint32 ) ( s - buf ) < size ) {
            s++;
        }

        n = s - v;

        s = PL_strndup( v, n );
        if( s != NULL ) {
            if( userDeleteTemplate != NULL ) {
                PL_strfree( userDeleteTemplate );
                userDeleteTemplate = NULL;
            }
            userDeleteTemplate = s;
        } else {
            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }
            return 0;
        }
    }

    if( ( s = PL_strstr( buf, "tokendb.doTokenConfirmTemplate=" ) ) != NULL ) {
        s += PL_strlen( "tokendb.doTokenConfirmTemplate=" );
        v = s;

        while( *s != '\x0D' && *s != '\x0A' && *s != '\0' &&
               ( PRUint32 ) ( s - buf ) < size ) {
            s++;
        }

        n = s - v;

        s = PL_strndup( v, n );
        if( s != NULL ) {
            if( doTokenConfirmTemplate != NULL ) {
                PL_strfree( doTokenConfirmTemplate );
                revokeTemplate = NULL;
            }
            doTokenConfirmTemplate = s;
        } else {
            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }
            return 0;
        }
    }

    if( ( s = PL_strstr( buf, "tokendb.doTokenTemplate=" ) ) != NULL ) {
        s += PL_strlen( "tokendb.doTokenTemplate=" );
        v = s;

        while( *s != '\x0D' && *s != '\x0A' && *s != '\0' && 
               ( PRUint32 ) ( s - buf ) < size ) {
            s++;
        }

        n = s - v;

        s = PL_strndup( v, n );
        if( s != NULL ) {
            if( doTokenTemplate != NULL ) {
                PL_strfree( doTokenTemplate );
                revokeTemplate = NULL;
            }
            doTokenTemplate = s;
        } else {
            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }
            return 0;
        }
    }

    if( ( s = PL_strstr( buf, "tokendb.revokeTemplate=" ) ) != NULL ) {
        s += PL_strlen( "tokendb.revokeTemplate=" );
        v = s;

        while( *s != '\x0D' && *s != '\x0A' && *s != '\0' && 
               ( PRUint32 ) ( s - buf ) < size ) {
            s++;
        }

        n = s - v;

        s = PL_strndup( v, n );
        if( s != NULL ) {
            if( revokeTemplate != NULL ) {
                PL_strfree( revokeTemplate );
                revokeTemplate = NULL;
            }
            revokeTemplate = s;
        } else {
            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }
            return 0;
        }
    }

    if( ( s = PL_strstr( buf, "tokendb.showAdminTemplate=" ) ) != NULL ) {
        s += PL_strlen( "tokendb.showAdminTemplate=" );
        v = s;

        while( *s != '\x0D' && *s != '\x0A' && *s != '\0' && 
               ( PRUint32 ) ( s - buf ) < size ) {
            s++;
        }

        n = s - v;

        s = PL_strndup( v, n );
        if( s != NULL ) {
            if( showAdminTemplate != NULL ) {
                PL_strfree( showAdminTemplate );
                showAdminTemplate = NULL;
            }
            showAdminTemplate = s;
        } else {
            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }
            return 0;
        }
    }

    if( ( s = PL_strstr( buf, "tokendb.showCertTemplate=" ) ) != NULL ) {
        s += PL_strlen( "tokendb.showCertTemplate=" );
        v = s;

        while( *s != '\x0D' && *s != '\x0A' && *s != '\0' && 
               ( PRUint32 ) ( s - buf ) < size ) {
            s++;
        }

        n = s - v;

        s = PL_strndup( v, n );
        if (s != NULL) {
            if( showCertTemplate != NULL ) {
                PL_strfree( showCertTemplate );
                showCertTemplate = NULL;
            }
            showCertTemplate = s;
        } else {
            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }
            return 0;
        }
    }

    if( ( s = PL_strstr( buf, "tokendb.showTemplate=" ) ) != NULL ) {
        s += PL_strlen( "tokendb.showTemplate=" );
        v = s;

        while( *s != '\x0D' && *s != '\x0A' && *s != '\0' && 
               ( PRUint32 ) ( s - buf ) < size ) {
            s++;
        }

        n = s - v;

        s = PL_strndup( v, n );
        if( s != NULL ) {
            if( showTemplate != NULL ) {
                PL_strfree( showTemplate );
                showTemplate = NULL;
            }
            showTemplate = s;
        } else {
            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }
            return 0;
        }
    }

    if( ( s = PL_strstr( buf, "tokendb.searchActivityAdminResultTemplate=" ) ) != NULL ) {
        s += PL_strlen( "tokendb.searchActivityAdminResultTemplate=" );
        v = s;

        while( *s != '\x0D' && *s != '\x0A' && *s != '\0' && 
               ( PRUint32 ) ( s - buf ) < size ) {
            s++;
        }

        n = s - v;

        s = PL_strndup( v, n );
        if( s != NULL ) {
            if( searchActivityAdminResultTemplate != NULL ) {
                PL_strfree( searchActivityAdminResultTemplate );
                searchActivityAdminResultTemplate = NULL;
            }
            searchActivityAdminResultTemplate = s;
        } else {
            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }
            return 0;
        }
    }

    if( ( s = PL_strstr( buf, "tokendb.editUserTemplate=" ) ) != NULL ) {
        s += PL_strlen( "tokendb.editUserTemplate=" );
        v = s;

        while( *s != '\x0D' && *s != '\x0A' && *s != '\0' && 
               ( PRUint32 ) ( s - buf ) < size ) {
            s++;
        }

        n = s - v;

        s = PL_strndup( v, n );
        if( s != NULL ) {
            if( editUserTemplate != NULL ) {
                PL_strfree( editUserTemplate );
                editUserTemplate = NULL;
            }
            editUserTemplate = s;
        } else {
            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }
            return 0;
        }
    }

    if( ( s = PL_strstr( buf, "tokendb.editTemplate=" ) ) != NULL ) {
        s += PL_strlen( "tokendb.editTemplate=" );
        v = s;

        while( *s != '\x0D' && *s != '\x0A' && *s != '\0' && 
               ( PRUint32 ) ( s - buf ) < size ) {
            s++;
        }

        n = s - v;

        s = PL_strndup( v, n );
        if( s != NULL ) {
            if( editTemplate != NULL ) {
                PL_strfree( editTemplate );
                editTemplate = NULL;
            }
            editTemplate = s;
        } else {
            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }
            return 0;
        }
    }

    if( ( s = PL_strstr( buf, "tokendb.editResultTemplate=" ) ) != NULL ) {
        s += PL_strlen( "tokendb.editResultTemplate=" );
        v = s;

        while( *s != '\x0D' && *s != '\x0A' && *s != '\0' && 
               ( PRUint32 ) ( s - buf ) < size ) {
            s++;
        }

        n = s - v;

        s = PL_strndup( v, n );
        if( s != NULL ) {
            if( editResultTemplate != NULL ) {
                PL_strfree( editResultTemplate );
                editResultTemplate = NULL;
            }
            editResultTemplate = s;
        } else {
            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }
            return 0;
        }
    }

    if( ( s = PL_strstr( buf, "tokendb.addResultTemplate=" ) ) != NULL ) {
        s += PL_strlen( "tokendb.addResultTemplate=" );
        v = s;

        while( *s != '\x0D' && *s != '\x0A' && *s != '\0' && 
               ( PRUint32 ) ( s - buf ) < size ) {
            s++;
        }

        n = s - v;

        s = PL_strndup( v, n );
        if( s != NULL ) {
            if( addResultTemplate != NULL ) {
                PL_strfree( addResultTemplate );
                addResultTemplate = NULL;
            }
            addResultTemplate = s;
        } else {
            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }
            return 0;
        }
    }

    if( ( s = PL_strstr( buf, "tokendb.deleteResultTemplate=" ) ) != NULL ) {
        s += PL_strlen( "tokendb.deleteResultTemplate=" );
        v = s;

        while( *s != '\x0D' && *s != '\x0A' && *s != '\0' && 
               ( PRUint32 ) ( s - buf ) < size ) {
            s++;
        }

        n = s - v;

        s = PL_strndup( v, n );
        if( s != NULL ) {
            if( deleteResultTemplate != NULL ) {
                PL_strfree( deleteResultTemplate );
                deleteResultTemplate = NULL;
            }
            deleteResultTemplate = s;
        } else {
            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }
            return 0;
        }
    }

    if( ( s = PL_strstr( buf, "tokendb.tokendb.sendInPieces=" ) ) != NULL ) {
        s += 13;
        v = s;

        while( *s != '\x0D' && *s != '\x0A' && *s != '\0' && 
               ( PRUint32 ) ( s - buf ) < size ) {
            s++;
        }

        n = s - v;

        s = PL_strndup( v, n );
        if( s != NULL ) {
            sendInPieces = atoi( s );
            PL_strfree( s );
            s = NULL;
        } else {
            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }
            return 0;
        }
    }

    if( ( s = PL_strstr( buf, "target.tokenType.list=" ) ) != NULL ) {
        s += PL_strlen( "target.tokenType.list=" );
        v = s;

        while( *s != '\x0D' && *s != '\x0A' && *s != '\0' &&
               ( PRUint32 ) ( s - buf ) < size ) {
            s++;
        }

        n = s - v;

        s = PL_strndup( v, n );
        if( s != NULL ) {
            if( profileList != NULL ) {
                PL_strfree( profileList );
                profileList = NULL;
            }
            profileList = s;
        } else {
            do_free(buf);
            return 0;
        }
    }

    get_cfg_string("tokendb.auditAdminTemplate=", auditAdminTemplate);

    if( buf != NULL ) {
        PR_Free( buf );
        buf = NULL;
    }

    tus_db_end();

    return 1;
}


/*  _________________________________________________________________
**
**  Tokendb Module Request Phase
**  _________________________________________________________________
*/

/**
 * Terminate the Tokendb module
 */
static apr_status_t
mod_tokendb_terminate( void *data )
{
    /* This routine is ONLY called when this server's */
    /* pool has been cleared or destroyed.            */

    /* Log Tokendb module debug information. */
    RA::Debug( "mod_tokendb::mod_tokendb_terminate",
               "The Tokendb module has been terminated!" );

    tus_db_end();
    tus_db_cleanup();

    /* Since all members of mod_tokendb_server_configuration are allocated */
    /* from a pool, there is no need to unset any of these members.        */

    /* Shutdown all APR library routines.                     */
    /* NOTE:  This automatically destroys all memory pools.   */
    /*        Allow the TPS/NSS Modules to perform this task. */
    /* apr_terminate(); */

    /* Terminate the entire Apache server                     */
    /* NOTE:  Allow the TPS/NSS Modules to perform this task. */

    return OK;
}


/**
 * Initialize the Tokendb module
 */
static int
mod_tokendb_initialize( apr_pool_t *p,
                        apr_pool_t *plog,
                        apr_pool_t *ptemp,
                        server_rec *sv )
{
    mod_tokendb_server_configuration *sc = NULL;
    char *cfg_path_file = NULL;
    char *error = NULL;
    int status;

    /* Retrieve the Tokendb module. */
    sc = ( ( mod_tokendb_server_configuration * )
           ap_get_module_config( sv->module_config,
                                 &MOD_TOKENDB_CONFIG_KEY ) );

    /* Check to see if the Tokendb module has been loaded. */
    if( sc->enabled == MOD_TOKENDB_TRUE ) {
        return OK;
    }

    /* Load the Tokendb module. */

#ifdef DEBUG_Tokendb
    debug_fd = PR_Open( "/tmp/tus-debug.log",
                        PR_RDWR | PR_CREATE_FILE | PR_APPEND,
                        00400 | 00200 );
#endif

    /* Retrieve the path to where the configuration files are located, and */
    /* insure that the Tokendb module configuration file is located here.  */
    if( sc->Tokendb_Configuration_File != NULL ) {
        /* provide Tokendb Config File from     */
        /* <apache_server_root>/conf/httpd.conf */
        if( sc->Tokendb_Configuration_File[0] == '/' ) {
            /* Complete path to Tokendb Config File is denoted */
            cfg_path_file = apr_psprintf( p,
                                          "%s",
                                          ( char * )
                                          sc->Tokendb_Configuration_File );
        } else {
            /* Tokendb Config File is located relative */
            /* to the Apache server root               */
            cfg_path_file = apr_psprintf( p,
                                          "%s/%s",
                                          ( char * ) ap_server_root,
                                          ( char * )
                                          sc->Tokendb_Configuration_File );
        }
   } else {
        /* Log information regarding this failure. */
        ap_log_error( "mod_tokendb_initialize",
                      __LINE__, APLOG_ERR, 0, sv,
                      "The tokendb module was installed incorrectly since the "
                      "parameter named '%s' is missing from the Apache "
                      "Configuration file!",
                      ( char * ) MOD_TOKENDB_CONFIGURATION_FILE_PARAMETER );

        /* Display information on the screen regarding this failure. */
        printf( "\nUnable to start Apache:\n"
                "    The tokendb module is missing the required parameter named"
                "    \n'%s' in the Apache Configuration file!\n",
                ( char * ) MOD_TOKENDB_CONFIGURATION_FILE_PARAMETER );

        goto loser;
   }

    /* Initialize the Token DB. */
    if( get_tus_config( cfg_path_file ) &&
        get_tus_db_config( cfg_path_file ) ) {
        RA::Debug( "mod_tokendb::mod_tokendb_initialize",
                           "Initializing TUS database");
        if( ( status = tus_db_init( &error ) ) != LDAP_SUCCESS ) {
            if( error != NULL ) {
                RA::Debug( "mod_tokendb::mod_tokendb_initialize",
                           "Token DB initialization failed: '%s'",
                           error );
                PR_smprintf_free( error );
                error = NULL;
            } else {
                RA::Debug( "mod_tokendb::mod_tokendb_initialize",
                           "Token DB initialization failed" );
            }

#if 0
            goto loser;
#endif
        } else {
                RA::Debug( "mod_tokendb::mod_tokendb_initialize",
                           "Token DB initialization succeeded" );
        }
    } else {
        RA::Debug( "mod_tokendb::mod_tokendb_initialize",
                   "Error reading tokendb config file: '%s'",
                   cfg_path_file );
    }

    /* Initialize the "server" member of mod_tokendb_server_configuration. */
    sc->enabled = MOD_TOKENDB_TRUE;

    /* Register a server termination routine. */
    apr_pool_cleanup_register( p,
                               sv,
                               mod_tokendb_terminate,
                               apr_pool_cleanup_null );

    /* Log Tokendb module debug information. */
    RA::Debug( "mod_tokendb::mod_tokendb_initialize",
               "The Tokendb module has been successfully loaded!" );

    return OK;

loser:
    /* Log Tokendb module debug information. */
    RA::Debug( "mod_tokendb::mod_tokendb_initialize",
               "Failed loading the Tokendb module!" );

    /* Since all members of mod_tokendb_server_configuration are allocated */
    /* from a pool, there is no need to unset any of these members.        */

    /* Shutdown all APR library routines.                   */
    /* NOTE:  This automatically destroys all memory pools. */
    apr_terminate();

    /* Terminate the entire Apache server */
    tokendb_die();

    return DECLINED;
}


char *stripBase64HeaderAndFooter( char *cert )
{
    char *base64_data = NULL;
    char *data = NULL;
    char *footer = NULL;

    if( ( cert != NULL ) &&
        ( strlen( cert ) > strlen( BASE64_HEADER ) ) ) {
        /* Strip off the base64 header. */
        data = ( char * ) ( cert + strlen( BASE64_HEADER ) );

        /* Find base64 footer. */
        footer = ( char * ) strstr( ( const char * ) data,
                                    ( const char * ) BASE64_FOOTER );
        if( footer != NULL ) {
            /* Strip off the base64 footer. */
            footer[0] = '\0';
        }

        /* Finally, store data in the base64_data storage area. */
        base64_data = strdup( data );
    }

    return base64_data;
}

/**
 * util_read
 * summary: called from read_post. reads posted data
 */
static int util_read(request_rec *r, const char **rbuf)
{
    int rc = OK;

    if ((rc = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR))) {
        return rc;
    }

    if (ap_should_client_block(r)) {
        char argsbuffer[HUGE_STRING_LEN];
        int rsize, len_read, rpos=0;
        long length = r->remaining;
        *rbuf = (const char*) apr_pcalloc(r->pool, length + 1);


        while ((len_read =
                ap_get_client_block(r, argsbuffer, sizeof(argsbuffer))) > 0) {
            if ((rpos + len_read) > length) {
                rsize = length - rpos;
            }
            else {
                rsize = len_read;
            }
            memcpy((char*)*rbuf + rpos, argsbuffer, rsize);
            rpos += rsize;
        }

    }

    return rc;
}

/**
 * read_post
 * read data in a post request and store it in an apr_table
 */
static int read_post(request_rec *r, apr_table_t **tab)
{
    const char *data;
    const char *key, *val, *type;
    int rc = OK;

    if((rc = util_read(r, &data)) != OK) {
        return rc;
    }

    if(*tab) {
        apr_table_clear(*tab);
    }
    else {
        *tab = apr_table_make(r->pool, 8);
    }

    while(*data && (val = ap_getword(r->pool, &data, '&'))) {
        key = ap_getword(r->pool, &val, '=');

        ap_unescape_url((char*)key);
        ap_unescape_url((char*)val);

        apr_table_merge(*tab, key, val);
    }

    return OK;
}

/**
 * add_authorization_data
 * writes variable that describe whether the user is an admin, agent or operator to the 
 * injection data.  Used by templates to determine which tabs to display
 */
void add_authorization_data(const char *userid, int is_admin, int is_operator, int is_agent, char *injection)
{
    if (is_agent) {
        PL_strcat(injection, "var agentAuth = \"true\";\n");
    }
    if (is_operator) {
        PL_strcat(injection, "var operatorAuth = \"true\";\n");
    }
    if (is_admin) {
        PL_strcat(injection, "var adminAuth = \"true\";\n");
    }
}
    

/**
 * mod_tokendb_handler handles the protocol between the tokendb and the RA
 */
static int
mod_tokendb_handler( request_rec *rq )
{
    int sendPieces = 0;
    int rc = 0;
    LDAPMessage *result = NULL;
    LDAPMessage *e      = NULL;
    LDAPMod     **mods  = NULL;
    char *injection     = NULL;
    char *mNum          = NULL;
    char *buf           = NULL;
    char *uri           = NULL;
    char *query         = NULL;
    char *cert          = NULL;
    char *base64_cert   = NULL;
    char *userid        = NULL;
    char *error         = NULL;
    char *tid           = NULL;
    char *question      = NULL;
    const char *tokentype = NULL;


    /* user fields */
    char *uid           = NULL;
    char *firstName     = NULL;
    char *lastName      = NULL;
    char *opOperator    = NULL;
    char *opAdmin       = NULL;
    char *opAgent       = NULL;
    char *userCert      = NULL;

    /* keep track of which menu we are in - operator or agent */
    char *topLevel      = NULL; 

    char **attrs        = NULL;
    char **vals         = NULL;
    int maxReturns;
    int q;
    int i, n, len, maxEntries, nEntries, entryNum;
    int status = LDAP_SUCCESS;
    int size, tagOffset, statusNum;
    char fixed_injection[MAX_INJECTION_SIZE];
    char configname[512];
    char filter[512];
    char msg[512];
    char template1[512];
    char question_no[100];
    char cuid[256];
    char cuidUserId[100];
    char serial[100];
    char userCN[256];
    char tokenType[512];
    apr_table_t *post = NULL; /* used for POST data */
  
    char *statusString = NULL;
    char *s1, *s2;
    char *end;
    char **attr_values;
    char *auth_filter = NULL;

    /* authorization */
    int is_admin = 0;
    int is_agent = 0;
    int is_operator = 0;

    int end_val =0;
    int start_val = 0;

    RA::Debug( "mod_tokendb_handler::mod_tokendb_handler",
               "mod_tokendb_handler::mod_tokendb_handler" );

    RA::Debug( "mod_tokendb::mod_tokendb_handler",
               "uri '%s'", rq->uri);
                                                                                
    /* XXX: We need to change "tus" to "tokendb" */
    if (strcmp(rq->handler, "tus") != 0) {
      RA::Debug( "mod_tokendb::mod_tokendb_handler", "DECLINED uri '%s'", rq->uri);
         return DECLINED;
    }

    RA::Debug( "mod_tokendb::mod_tokendb_handler",
               "uri '%s' DONE", rq->uri);

    tokendbDebug( "tokendb request arrived...serving tokendb\n" );

    injection = fixed_injection;

    ap_set_content_type( rq, "text/html" );

    if( !is_tus_db_initialized() ) {
      tokendbDebug( "token DB was not initialized \n" );

        if( ( status = tus_db_init( &error ) ) != LDAP_SUCCESS ) {
            if( error != NULL ) {
                PR_snprintf( injection, MAX_INJECTION_SIZE,
                             "%s%s%s%s%s", JS_START,
                             "var error = \"", error,
                             "\";\n", JS_STOP );

                buf = getData( errorTemplate, injection );

                ( void ) ap_rwrite( ( const void * ) buf,
                                    PL_strlen( buf ), rq );

                PR_smprintf_free( error );
                error = NULL;
            } else {
                PR_snprintf( injection, MAX_INJECTION_SIZE,
                             "%s%s%s%s%s", JS_START,
                             "var error = \"", "NULL",
                             "\";\n", JS_STOP );

                buf = getData( errorTemplate, injection );

                ( void ) ap_rwrite( ( const void * ) buf,
                                    PL_strlen( buf ), rq );
            }

            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }

            return DONE;
        }
    } else {
        tokendbDebug( "token DB was initialized\n" );
    }

    tokendbDebug( "authentication\n" );

    cert = nss_var_lookup( rq->pool,
                           rq->server,
                           rq->connection,
                           rq,
                           ( char * ) "SSL_CLIENT_CERT" );
    if( cert == NULL ) {
          error_out("Authentication Failure", "Failed to authenticate request");
          do_free(buf);
          return DONE;
    }

    tokendbDebug( cert );
    tokendbDebug( "\n" );

    base64_cert = stripBase64HeaderAndFooter( cert );

    tokendbDebug( base64_cert );
    tokendbDebug( "\n" );

    userid = tus_authenticate( base64_cert );
    do_free(base64_cert);
    if( userid == NULL ) {
          error_out("Authentication Failure", "Failed to authenticate request");
          do_free(buf);

          return DONE;
    }

    /* authorization */
    is_admin = tus_authorize(TOKENDB_ADMINISTRATORS_IDENTIFIER, userid);
    is_agent = tus_authorize(TOKENDB_AGENTS_IDENTIFIER, userid);
    is_operator = tus_authorize(TOKENDB_OPERATORS_IDENTIFIER, userid);

    if( rq->uri != NULL ) {
        uri = PL_strdup( rq->uri );
    }
 
    if (rq->method_number == M_POST) {
        status = read_post(rq, &post);
        if(post && !apr_is_empty_table(post)) {
            query = PL_strdup( apr_table_get(post, "query"));
        }
    } else {
    /* GET request */
        if( rq->args != NULL ) {
            query = PL_strdup( rq->args );
        }
    }

    RA::Debug( "mod_tokendb_handler::mod_tokendb_handler",
               "uri='%s' params='%s'",
               uri, ( query==NULL?"":query ) );

    if( query == NULL ) {
        char *itemplate = NULL;
        tokendbDebug( "authorization for index case\n" );
        if (is_agent) {
//   RA::Audit(EventName, format, va_list...);
//   just an example... not really the right place
            RA::Audit(EV_ROLE_ASSUME, AUDIT_MSG_FORMAT, userid, "Success", "Tokendb agent user authorization");
            itemplate = indexTemplate;
        } else if (is_operator) {
            itemplate = indexOperatorTemplate;
        } else if (is_admin) {
            itemplate = indexAdminTemplate;
        } else {
            RA::Audit(EV_AUTHZ_FAIL, AUDIT_MSG_FORMAT, userid, "Failure", "Tokendb user authorization");
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_free(uri);
            do_free(query);

            return DONE;
        }

        PR_snprintf( injection, MAX_INJECTION_SIZE,
                     "%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n", 
                     "var userid = \"", userid,
                     "\";\n" );
        add_authorization_data(userid, is_admin, is_operator, is_agent, injection);
        PL_strcat(injection, JS_STOP);

        buf = getData( itemplate, injection );
        itemplate = NULL;
    } else if( ( PL_strstr( query, "op=index_operator" ) ) ) {
        tokendbDebug( "authorization for op=index_operator\n" );
        if (!is_operator) {
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_free(uri);
            do_free(query);
            return DONE;
        }

        PR_snprintf( injection, MAX_INJECTION_SIZE,
                     "%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n", 
                     "var userid = \"", userid,
                     "\";\n" );
        add_authorization_data(userid, is_admin, is_operator, is_agent, injection);
        PL_strcat(injection, JS_STOP);

        buf = getData( indexOperatorTemplate, injection );
    } else if( ( PL_strstr( query, "op=index_admin" ) ) ) {
        tokendbDebug( "authorization\n" );
        if (!is_admin) {
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_free(uri);
            do_free(query);
            return DONE;
        }

        PR_snprintf( injection, MAX_INJECTION_SIZE,
                     "%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n", 
                     "var userid = \"", userid,
                     "\";\n" );
        add_authorization_data(userid, is_admin, is_operator, is_agent, injection);
        PL_strcat(injection, JS_STOP);

        buf = getData( indexAdminTemplate, injection );
    } else if( ( PL_strstr( query, "op=do_token" ) ) ) {
        tokendbDebug( "authorization for do_token\n" );

        if( !is_agent ) {
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_free(uri);
            do_free(query);
            return DONE;
        }

        /* XXX - chrisho */
        /* op=do_token */
        /* question=1|2|... */
        /* tid=cuid */

        tokendbDebug( "print query\n" );
        tokendbDebug( query );
        tokendbDebug( "\n" );

        tid = PL_strstr( query, "tid=" );
        if( tid != NULL ) {
            end = PL_strchr( tid, '&' );
            if( end != NULL ) { 
                i = end - tid - 4;
                if( i > 0 ) {
                    memcpy( cuid, tid+4, i );
                }                
                cuid[i] = '\0';
            } else {
                PL_strcpy( cuid, tid+4 );
            }
        }

        tokendbDebug( cuid );
        tokendbDebug( "\n" );
        question = PL_strstr( query, "question=" );
        q = question[9] - '0';

        PR_snprintf( question_no, 256, "%d", q );

        tokendbDebug( question_no );

        rc = find_tus_db_entry( cuid, 1, &result );
        if( rc == 0 ) {
            e = get_first_entry( result );    
            if( e != NULL ) {
                attr_values = get_attribute_values( e, "tokenUserID" );
                PL_strcpy( cuidUserId, attr_values[0] );
                tokendbDebug( cuidUserId );
                if (attr_values != NULL) {
                    free_values(attr_values, 1);
                    attr_values = NULL;
                }
                 
                attr_values = get_attribute_values( e, "tokenType" );
                PL_strcpy( tokenType, attr_values[0] );
                tokendbDebug( tokenType );
                if (attr_values != NULL) {
                    free_values(attr_values, 1);
                    attr_values = NULL;
                }

            }
        }

        if( result != NULL ) {
            ldap_msgfree( result );
        }


        /* Is this token physically damaged */
        if( q == 1 ) {

            PR_snprintf((char *)msg, 256,
              "'%s' marked token physically damaged", userid);
            RA::tdb_activity(rq->connection->remote_ip, cuid, "do_token", "initiated",
                     msg, cuidUserId, tokenType);

            /* get the certificates on this lost token */
            PR_snprintf( ( char * ) filter, 256,
                         "(&(tokenID=%s)(tokenUserID=%s))",
                         cuid, cuidUserId );
            rc = find_tus_certificate_entries_by_order_no_vlv( filter,
                                                               &result, 1 );
            if( rc == 0 ) {
                CertEnroll *certEnroll = new CertEnroll();
                for( e = get_first_entry( result );
                     e != NULL;
                     e = get_next_entry( e ) ) {
                    char *attr_status = get_cert_status( e );

                    if( strcmp( attr_status, "revoked" ) == 0 ) {
                        if( attr_status != NULL ) {
                            PL_strfree( attr_status );
                            attr_status = NULL;
                        }

                        continue;
                    }

                    char *attr_serial= get_cert_serial( e );
                    char *attr_tokenType = get_cert_tokenType( e );
                    char *attr_keyType = get_cert_type( e );

                    PR_snprintf( ( char * ) configname, 256,
                                 "op.enroll.%s.keyGen.%s.recovery."
                                 "destroyed.revokeCert",
                                 attr_tokenType, attr_keyType );

                    bool revokeCert = RA::GetConfigStore()->
                                      GetConfigAsBool( configname, true );

                    PR_snprintf( ( char * ) configname, 256,
                                 "op.enroll.%s.keyGen.%s.recovery."
                                 "destroyed.revokeCert.reason",
                                 attr_tokenType, attr_keyType );

                    char *revokeReason = ( char * )
                                         ( RA::GetConfigStore()->
                                         GetConfigAsString( configname,
                                                            "0" ) );

                    if( revokeCert ) {
                        char *attr_cn = get_cert_cn( e );

                        PR_snprintf( ( char * ) configname, 256,
                                     "op.enroll.%s.keyGen.%s.ca.conn",
                                     attr_tokenType, attr_keyType ); 

                        char *connid = ( char * )
                                       ( RA::GetConfigStore()->
                                         GetConfigAsString( configname ) );

                        PR_snprintf( serial, 100, "0x%s", attr_serial );

                        statusNum = certEnroll->RevokeCertificate(revokeReason,
                                    serial, connid, statusString );

                        // update certificate status
                        if( strcmp( revokeReason, "6" ) == 0 ) {
                            PR_snprintf((char *)msg, 256, "Certificate '%s' is marked as revoked_on_hold", attr_cn);
                            RA::tdb_activity(rq->connection->remote_ip, cuid, "do_token", "initiated", msg, cuidUserId, attr_tokenType);
                            update_cert_status( attr_cn, "revoked_on_hold" );
                        } else {
                            PR_snprintf((char *)msg, 256, "Certificate '%s' is marked as revoked", attr_cn);
                            RA::tdb_activity(rq->connection->remote_ip, cuid, "do_token", "initiated", msg, cuidUserId, attr_tokenType);
                            update_cert_status( attr_cn, "revoked" );
                        }

                        if( attr_cn != NULL ) {
                            PL_strfree( attr_cn );
                            attr_cn = NULL;
                        }
                        do_free(statusString);
                    }

                    if( attr_status != NULL ) {
                        PL_strfree( attr_status );
                        attr_status = NULL;
                    }

                    if( attr_serial != NULL ) {
                        PL_strfree( attr_serial );
                        attr_serial = NULL;
                    }

                    if( attr_tokenType != NULL ) {
                        PL_strfree( attr_tokenType );
                        attr_tokenType = NULL;
                    }

                    if( attr_keyType != NULL ) {
                        PL_strfree( attr_keyType );
                        attr_keyType = NULL;
                    }
                }

                if( result != NULL ) {
                    ldap_msgfree( result );
                }

                if( certEnroll != NULL ) {
                    delete certEnroll;
                    certEnroll = NULL;
                }

            }

            /* change the tokenStatus to lost (reason: destroyed). */
            rc = update_token_status_reason( cuidUserId, cuid,
                                             "lost", "destroyed" );
            if( rc == -1 ) {
                tokendbDebug( "token is physically damaged. rc = -1\n" );

                PR_snprintf( injection, MAX_INJECTION_SIZE,
                             "%s%s%s%s", JS_START,
                             "var error = \"Failed to create LDAPMod: ",
                             "\";\n", JS_STOP );

                buf = getData( errorTemplate, injection );

                ap_log_error( ( const char * ) "tus", __LINE__,
                              APLOG_ERR, 0, rq->server,
                              ( const char * ) "Failed to create LDAPMod" );

                ( void ) ap_rwrite( ( const void * ) buf,
                                    PL_strlen( buf ), rq );

                do_free(buf);
                do_free(uri);
                do_free(query);

                return DONE;
            } else if( rc > 0 ) {
                tokendbDebug( "token is physically damaged. rc > 0\n" );

                PR_snprintf( injection, MAX_INJECTION_SIZE,
                             "%s%s%s%s%s", JS_START,
                             "var error = \"LDAP mod error: ",
                             ldap_err2string( rc ),
                             "\";\n", JS_STOP );

                buf = getData( errorTemplate, injection );

                ap_log_error( ( const char * ) "tus", __LINE__,
                              APLOG_ERR, 0, rq->server,
                              ( const char * ) "LDAP error: %s", 
                              ldap_err2string( rc ) );

                ( void ) ap_rwrite( ( const void * ) buf,
                                    PL_strlen( buf ), rq );

                do_free(buf);
                do_free(uri);
                do_free(query);

                return DONE;
            }

        /* Is this token permanently lost? */
        } else if( q == 2 || q == 6) {
            if (q == 2) {
              PR_snprintf((char *)msg, 256,
                "'%s' marked token permanently lost", userid);             
            } else {
              PR_snprintf((char *)msg, 256,
                "'%s' marked token terminated", userid);             
            }
            RA::tdb_activity(rq->connection->remote_ip, cuid, "do_token", "initiated",
                     msg, cuidUserId, tokenType);

            /* get the certificates on this lost token */
            PR_snprintf( ( char * ) filter, 256,
                         "(&(tokenID=%s)(tokenUserID=%s))",
                         cuid, cuidUserId );

            rc = find_tus_certificate_entries_by_order_no_vlv( filter,
                                                               &result, 1 );
            if( rc == 0 ) {
                CertEnroll *certEnroll = new CertEnroll();
                for( e = get_first_entry( result );
                     e != NULL;
                     e = get_next_entry( e ) ) { 
                    char *attr_status = get_cert_status( e );

                    if( strcmp( attr_status, "revoked" ) == 0 ) {
                        if( attr_status != NULL ) {
                            PL_strfree( attr_status );
                            attr_status = NULL;
                        }

                        continue;
                    }

                    char *attr_serial= get_cert_serial( e );
                    char *attr_tokenType = get_cert_tokenType( e );
                    char *attr_keyType = get_cert_type( e );

                    PR_snprintf( ( char * ) configname, 256,
                                 "op.enroll.%s.keyGen.%s.recovery."
                                 "keyCompromise.revokeCert",
                                 attr_tokenType, attr_keyType );

                    bool revokeCert = RA::GetConfigStore()->
                                      GetConfigAsBool( configname, true );

                    PR_snprintf( ( char * ) configname, 256,
                                 "op.enroll.%s.keyGen.%s.recovery."
                                 "keyCompromise.revokeCert.reason",
                                 attr_tokenType, attr_keyType );

                    char *revokeReason = ( char * )
                                         ( RA::GetConfigStore()->
                                           GetConfigAsString( configname,
                                                              "1" ) );

                    if( revokeCert ) {
                        char *attr_cn = get_cert_cn( e );

                        PR_snprintf( ( char * ) configname, 256,
                                     "op.enroll.%s.keyGen.%s.ca.conn",
                                     attr_tokenType, attr_keyType ); 

                        char *connid = ( char * )
                                       ( RA::GetConfigStore()->
                                         GetConfigAsString( configname ) );

                        PR_snprintf( serial, 100, "0x%s", attr_serial );

                        statusNum = certEnroll->
                                    RevokeCertificate( revokeReason,
                                                       serial,
                                                       connid,
                                                       statusString );

                        // update certificate status
                        if( strcmp(revokeReason, "6" ) == 0 ) {
                            PR_snprintf((char *)msg, 256, "Certificate '%s' is marked as revoked_on_hold", attr_cn);
                            RA::tdb_activity(rq->connection->remote_ip, cuid, "do_token", "initiated", msg, cuidUserId, attr_tokenType);
                            update_cert_status( attr_cn, "revoked_on_hold" );
                        } else {
                            PR_snprintf((char *)msg, 256, "Certificate '%s' is marked as revoked", attr_cn);
                            RA::tdb_activity(rq->connection->remote_ip, cuid, "do_token", "initiated", msg, cuidUserId, attr_tokenType);
                            update_cert_status( attr_cn, "revoked" );
                        }

                        if( attr_cn != NULL ) {
                            PL_strfree( attr_cn );
                            attr_cn = NULL;
                        }
                        do_free(statusString);
                    }

                    if( attr_status != NULL ) {
                        PL_strfree( attr_status );
                        attr_status = NULL;
                    }

                    if( attr_serial != NULL ) {
                        PL_strfree( attr_serial );
                        attr_serial = NULL;
                    }

                    if( attr_tokenType != NULL ) {
                        PL_strfree( attr_tokenType );
                        attr_tokenType = NULL;
                    }

                    if( attr_keyType != NULL ) {
                        PL_strfree( attr_keyType );
                        attr_keyType = NULL;
                    }
                }

                if( result != NULL ) {
                    ldap_msgfree( result );
                }

                if( certEnroll != NULL ) {
                    delete certEnroll;
                    certEnroll = NULL;
                }
            }

            /* revoke all the certs on the token. make http connection to CA */
         
            /* change the tokenStatus to lost (reason: keyCompromise) */
            tokendbDebug( "Revoke all the certs on this token "
                          "(reason: keyCompromise)\n" );

            if (q == 6) { /* terminated */
              rc = update_token_status_reason( cuidUserId, cuid,
                                             "terminated", "keyCompromise" );
            } else {
              rc = update_token_status_reason( cuidUserId, cuid,
                                             "lost", "keyCompromise" );
            }
            if( rc == -1 ) {
                PR_snprintf( injection, MAX_INJECTION_SIZE,
                             "%s%s%s%s", JS_START,
                             "var error = \"Failed to create LDAPMod: ",
                             "\";\n", JS_STOP );

                buf = getData( errorTemplate, injection );

                ap_log_error( ( const char * ) "tus", __LINE__,
                              APLOG_ERR, 0, rq->server,
                              ( const char * ) "Failed to create LDAPMod" );

                ( void ) ap_rwrite( ( const void * ) buf,
                                    PL_strlen( buf ), rq );

                do_free(buf);
                do_free(uri);
                do_free(query);

                return DONE;
            } else if( rc > 0 ) {
                PR_snprintf( injection, MAX_INJECTION_SIZE,
                             "%s%s%s%s%s", JS_START,
                             "var error = \"LDAP mod error: ",
                             ldap_err2string( rc ),
                             "\";\n", JS_STOP );

                buf = getData( errorTemplate, injection );

                ap_log_error( ( const char * ) "tus", __LINE__,
                              APLOG_ERR, 0, rq->server,
                              ( const char * ) "LDAP error: %s",
                              ldap_err2string( rc ) );

                ( void ) ap_rwrite( ( const void * ) buf,
                                    PL_strlen( buf ), rq );

                do_free(buf);
                do_free(uri);
                do_free(query);

                return DONE;
            }

        /* Is this token temporarily lost? */
        } else if( q == 3 ) {

            PR_snprintf((char *)msg, 256,
              "'%s' marked token temporarily lost", userid);
            RA::tdb_activity(rq->connection->remote_ip, cuid, "do_token", "initiated",
                     msg, cuidUserId, tokenType);

            /* all certs on the token are revoked (onHold) */
            tokendbDebug( "Revoke all the certs on this token "
                          "(reason: onHold)\n" );

            /* get the certificates on this lost token */
            PR_snprintf( ( char * ) filter, 256,
                         "(&(tokenID=%s)(tokenUserID=%s))",
                         cuid, cuidUserId );

            rc = find_tus_certificate_entries_by_order_no_vlv( filter,
                                                               &result, 1 );
            if( rc == 0 ) {
                CertEnroll *certEnroll = new CertEnroll();
                for( e = get_first_entry( result );
                     e != NULL;
                     e = get_next_entry( e ) ) { 
                    char *attr_status = get_cert_status( e );
                    if( strcmp( attr_status, "revoked" ) == 0 || 
                        strcmp( attr_status, "revoked_on_hold" ) == 0 ) {
                        if( attr_status != NULL ) {
                            PL_strfree( attr_status );
                            attr_status = NULL; 
                        }

                        continue;
                    }

                    char *attr_serial= get_cert_serial( e );
                    char *attr_tokenType = get_cert_tokenType( e );
                    char *attr_keyType = get_cert_type( e );

                    PR_snprintf( ( char * ) configname, 256,
                                 "op.enroll.%s.keyGen.%s.recovery."
                                 "onHold.revokeCert",
                                 attr_tokenType, attr_keyType );

                    bool revokeCert = RA::GetConfigStore()->
                                      GetConfigAsBool( configname, true );

                    PR_snprintf( ( char * ) configname, 256,
                                 "op.enroll.%s.keyGen.%s.recovery.onHold."
                                 "revokeCert.reason",
                                 attr_tokenType, attr_keyType );

                    char *revokeReason = ( char * )
                                         ( RA::GetConfigStore()->
                                           GetConfigAsString( configname,
                                                              "0" ) );

                    if( revokeCert ) {
                        char *attr_cn = get_cert_cn( e );

                        PR_snprintf( ( char * ) configname, 256,
                                     "op.enroll.%s.keyGen.%s.ca.conn",
                                     attr_tokenType, attr_keyType );

                        char *connid = ( char * )
                                       ( RA::GetConfigStore()->
                                         GetConfigAsString( configname ) );

                        PR_snprintf( serial, 100, "0x%s", attr_serial );

                        statusNum = certEnroll->
                                    RevokeCertificate( revokeReason,
                                                       serial,
                                                       connid,
                                                       statusString );

                        if( strcmp( revokeReason, "6" ) == 0 ) {
                            PR_snprintf((char *)msg, 256, "Certificate '%s' is marked as revoked_on_hold", attr_cn);
                            RA::tdb_activity(rq->connection->remote_ip, cuid, "do_token", "initiated", msg, cuidUserId, attr_tokenType);
                            update_cert_status( attr_cn, "revoked_on_hold" );
                        } else {
                            PR_snprintf((char *)msg, 256, "Certificate '%s' is marked as revoked", attr_cn);
                            RA::tdb_activity(rq->connection->remote_ip, cuid, "do_token", "initiated", msg, cuidUserId, attr_tokenType);
                            update_cert_status( attr_cn, "revoked" );
                        }

                        do_free(statusString);
                    }

                    if( attr_status != NULL ) {
                        PL_strfree( attr_status );
                        attr_status = NULL;
                    }

                    if( attr_serial != NULL ) {
                        PL_strfree( attr_serial );
                        attr_serial = NULL;
                    }

                    if( attr_tokenType != NULL ) {
                        PL_strfree( attr_tokenType );
                        attr_tokenType = NULL;
                    }

                    if( attr_keyType != NULL ) {
                        PL_strfree( attr_keyType );
                        attr_keyType = NULL;
                    }
                }

                if (result != NULL) {
                    ldap_msgfree( result );
                }

                if( certEnroll != NULL ) {
                    delete certEnroll;
                    certEnroll = NULL;
                }

            }

            rc = update_token_status_reason( cuidUserId, cuid,
                                             "lost", "onHold" );
            if( rc == -1 ) {
                PR_snprintf( injection, MAX_INJECTION_SIZE,
                             "%s%s%s%s", JS_START,
                             "var error = \"Failed to create LDAPMod: ",
                             "\";\n", JS_STOP );

                buf = getData( errorTemplate, injection );

                ap_log_error( ( const char * ) "tus", __LINE__,
                              APLOG_ERR, 0, rq->server,
                              ( const char * ) "Failed to create LDAPMod" );

                ( void ) ap_rwrite( ( const void * ) buf,
                                    PL_strlen( buf ), rq );
                do_free(buf);
                do_free(uri);
                do_free(query);

                return DONE;
            } else if( rc > 0 ) {
                PR_snprintf( injection, MAX_INJECTION_SIZE,
                             "%s%s%s%s%s", JS_START,
                             "var error = \"LDAP mod error: ",
                             ldap_err2string( rc ),
                             "\";\n", JS_STOP );

                buf = getData( errorTemplate, injection );

                ap_log_error( ( const char * ) "tus", __LINE__,
                              APLOG_ERR, 0, rq->server,
                              ( const char * ) "LDAP error: %s",
                              ldap_err2string( rc ) );

                ( void ) ap_rwrite( ( const void * ) buf,
                                    PL_strlen( buf ), rq );

                do_free(buf);
                do_free(uri);
                do_free(query);

                return DONE;
            }

        /* Is this temporarily lost token found? */
        } else if( q == 4 ) {

            PR_snprintf((char *)msg, 256,
              "'%s' marked lost token found", userid);
            RA::tdb_activity(rq->connection->remote_ip, cuid, "do_token", "initiated",
                     msg, cuidUserId, tokenType);

            tokendbDebug( "The temporarily lost token is found.\n" );
            
            // to find out the tokenType on this lost token
            PR_snprintf( ( char * ) filter, 256,
                         "(&(tokenID=%s)(tokenUserID=%s))",
                         cuid, cuidUserId );

            /* all certs on the token are unrevoked (offHold) */
            /* get the certificates on this lost token        */
            tokendbDebug( "Offhold all the certificates on "
                          "the temp lost token." );

            rc = find_tus_certificate_entries_by_order_no_vlv( filter,
                                                               &result, 1 );
            if( rc == 0 ) {
                CertEnroll *certEnroll = new CertEnroll();
                for( e = get_first_entry( result );
                     e != NULL;
                     e = get_next_entry( e ) ) { 
                    char *attr_status = get_cert_status( e );
                    if( strcmp( attr_status, "active" ) == 0 || 
                        strcmp( attr_status, "revoked" ) == 0 ) {
                        if( attr_status != NULL ) {
                            PL_strfree( attr_status );
                            attr_status = NULL;
                        }

                        continue;
                    }

                    char *attr_serial= get_cert_serial( e );
                    char *attr_tokenType = get_cert_tokenType( e );
                    char *attr_keyType = get_cert_type( e );

                    PR_snprintf( ( char * ) configname, 256,
                                 "op.enroll.%s.keyGen.%s.recovery."
                                 "onHold.revokeCert",
                                 attr_tokenType, attr_keyType );

                    bool revokeCert = RA::GetConfigStore()->
                                      GetConfigAsBool( configname, true );
                    if( revokeCert ) {
                        char *attr_cn = get_cert_cn( e );

                        PR_snprintf( ( char * ) configname, 256,
                                     "op.enroll.%s.keyGen.%s.ca.conn",
                                     attr_tokenType, attr_keyType );

                         char *connid = ( char * )
                                         ( RA::GetConfigStore()->
                                           GetConfigAsString( configname ) );
                         

                        PR_snprintf( serial, 100, "0x%s", attr_serial );

                         int statusNum = certEnroll->
                                          UnrevokeCertificate( serial,
                                                               connid,
                                                               statusString );
                         

                          PR_snprintf((char *)msg, 256, "Certificate '%s' is marked as active", attr_cn);
                          RA::tdb_activity(rq->connection->remote_ip, cuid, "do_token", "initiated", msg, cuidUserId, attr_tokenType);
                        update_cert_status( attr_cn, "active" );
                        
                        if( attr_cn != NULL ) {
                            PL_strfree( attr_cn );
                            attr_cn = NULL;
                        }

                        do_free(statusString);
                    }

                    if( attr_serial != NULL ) {
                        PL_strfree( attr_serial );
                        attr_serial = NULL;
                    }

                    if( attr_tokenType != NULL ) {
                        PL_strfree( attr_tokenType );
                        attr_tokenType = NULL;
                    }

                    if( attr_keyType != NULL ) {
                        PL_strfree( attr_keyType );
                        attr_keyType = NULL;
                    }
                } // end of for loop
             
                if( result != NULL ) {
                    ldap_msgfree( result );
                }

                if( certEnroll != NULL ) {
                    delete certEnroll;
                    certEnroll = NULL;
                }
            }

            update_token_status_reason( cuidUserId, cuid, "active", NULL );

            if( rc == -1 ) {
                error_out("Failed to create LDAPMod: ", "Failed to create LDAPMod");

                do_free(buf);
                do_free(uri);
                do_free(query);

                return DONE;
            } else if( rc > 0 ) {
                ldap_error_out("LDAP mod error: ", "LDAP error: %s");

                do_free(buf);
                do_free(uri);
                do_free(query);

                return DONE;
            }

        /* Does this temporarily lost token become permanently lost? */
        } else if (q == 5) {

            PR_snprintf((char *)msg, 256,
              "'%s' marked lost token permanently lost", userid);
            RA::tdb_activity(rq->connection->remote_ip, cuid, "do_token", "initiated",
                     msg, cuidUserId, tokenType);

            tokendbDebug( "Change the revocation reason from onHold "
                          "to keyCompromise\n" );

            // to find out the tokenType on this lost token
            PR_snprintf( ( char * ) filter, 256,
                         "(&(tokenID=%s)(tokenUserID=%s))",
                         cuid, cuidUserId );

            /* revoke all the certs on this token (reason: keyCompromise) */
            tokendbDebug( "Revoke all the certs on this token "
                          "(reason: keyCompromise)\n" );

            /* get the certificates on this lost token */
            PR_snprintf( ( char * ) filter, 256,
                         "(&(tokenID=%s)(tokenUserID=%s))",
                         cuid, cuidUserId );

            rc = find_tus_certificate_entries_by_order_no_vlv( filter,
                                                               &result, 1 );
            if( rc == 0 ) {
                CertEnroll *certEnroll = new CertEnroll();
                for( e = get_first_entry(result);
                     e != NULL;
                     e = get_next_entry( e ) ) { 
                    char *attr_status = get_cert_status( e );
                    if( strcmp( attr_status, "revoked" ) == 0 ) {
                        if( attr_status != NULL ) {
                            PL_strfree( attr_status );
                            attr_status = NULL;
                        }
                        continue;
                    }

                    char *attr_serial= get_cert_serial( e );
                    char *attr_tokenType = get_cert_tokenType( e );
                    char *attr_keyType = get_cert_type( e );

                    PR_snprintf( ( char * ) configname, 256,
                                 "op.enroll.%s.keyGen.%s.recovery."
                                 "keyCompromise.revokeCert",
                                 attr_tokenType, attr_keyType );

                    bool revokeCert = RA::GetConfigStore()->
                                      GetConfigAsBool( configname, true );

                    PR_snprintf( ( char * ) configname, 256,
                                 "op.enroll.%s.keyGen.%s.recovery."
                                 "keyCompromise.revokeCert.reason",
                                 attr_tokenType, attr_keyType );

                    char *revokeReason = ( char * )
                                         ( RA::GetConfigStore()->
                                           GetConfigAsString( configname,
                                                              "1" ) );

                    if( revokeCert ) {
                        char *attr_cn = get_cert_cn( e );

                        PR_snprintf( ( char * ) configname, 256,
                                     "op.enroll.%s.keyGen.%s.ca.conn",
                                     attr_tokenType, attr_keyType );

                        char *connid = ( char * )
                                       ( RA::GetConfigStore()->
                                         GetConfigAsString( configname ) );

                        PR_snprintf( serial, 100, "0x%s", attr_serial );

                        int statusNum = 0;
                        if( strcmp( attr_status, "revoked_on_hold" ) == 0 ) {
                            statusNum = certEnroll->
                                        UnrevokeCertificate( serial,
                                                             connid,
                                                             statusString );
                            do_free(statusString);
                        }

                        if( statusNum == 0 ) {
                            statusNum = certEnroll->
                                        RevokeCertificate( revokeReason,
                                                           serial,
                                                           connid, 
                                                           statusString );
                            do_free(statusString);
                        }

                        if( strcmp( revokeReason, "6" ) == 0 ) {
                          PR_snprintf((char *)msg, 256, "Certificate '%s' is marked as revoked_on_hold", attr_cn);
                          RA::tdb_activity(rq->connection->remote_ip, cuid, "do_token", "initiated", msg, cuidUserId, attr_tokenType);
                            update_cert_status( attr_cn, "revoked_on_hold" );
                        } else {
                          PR_snprintf((char *)msg, 256, "Certificate '%s' is marked as revoked", attr_cn);
                          RA::tdb_activity(rq->connection->remote_ip, cuid, "do_token", "initiated", msg, cuidUserId, attr_tokenType);
                            update_cert_status( attr_cn, "revoked" );
                        }

                        if( attr_cn != NULL ) {
                            PL_strfree( attr_cn );
                            attr_cn = NULL;
                        }
                    }

                    if( attr_serial != NULL ) {
                        PL_strfree( attr_serial );
                        attr_serial = NULL;
                    }

                    if( attr_tokenType != NULL ) {
                        PL_strfree( attr_tokenType );
                        attr_tokenType = NULL;
                    }

                    if( attr_keyType != NULL ) {
                        PL_strfree( attr_keyType );
                        attr_keyType = NULL;
                    }
                } // end of the for loop

                if( result != NULL ) {
                    ldap_msgfree( result );
                }

                if( certEnroll != NULL ) {
                    delete certEnroll;
                    certEnroll = NULL;
                }
            }

            rc = update_token_status_reason( cuidUserId, cuid,
                                             "lost", "keyCompromise" );
        }
        
        tokendbDebug( "do_token: rc = 0\n" );

        PR_snprintf( injection, MAX_INJECTION_SIZE,
                     "%s%s%d%s%s%s%s%s%s%s", JS_START,
                     "var rc = \"", rc, "\";\n",
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid,
                     "\";\n" );

        add_authorization_data(userid, is_admin, is_operator, is_agent, injection);
        PL_strcat(injection, JS_STOP);

        buf = getData( doTokenTemplate, injection );
    } else if( ( PL_strstr( query, "op=revoke" ) ) ) {
        tokendbDebug("authorization\n");

        if( ! is_agent ) {
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_free(uri);
            do_free(query);
            return DONE;
        }

        /* XXX - chrisho */
        /* op=revoke */
        /* tid=cuid */

        PR_snprintf( injection, MAX_INJECTION_SIZE,
                     "%s%s%s%s%s%s%s", JS_START,
                    "var uriBase = \"", uri, "\";\n",
                    "var userid = \"", userid,
                    "\";\n" );
        add_authorization_data(userid, is_admin, is_operator, is_agent, injection);
        PL_strcat(injection, JS_STOP);

        buf = getData( revokeTemplate, injection );
    } else if( ( PL_strstr( query, "op=search_activity_admin" ) ) ) {
        tokendbDebug( "authorization\n" );

        if (! is_admin) {
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_free(uri);
            do_free(query);
            return DONE;
        } 

        PR_snprintf( injection, MAX_INJECTION_SIZE,
                     "%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid,
                     "\";\n" );

        add_authorization_data(userid, is_admin, is_operator, is_agent, injection);
        PL_strcat(injection, JS_STOP);

        buf = getData( searchActivityAdminTemplate, injection );
    } else if( ( PL_strstr( query, "op=search_activity" ) ) ) {
        tokendbDebug( "authorization\n" );

        if ((! is_agent) && (! is_operator)) {
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_free(uri);
            do_free(query);
            return DONE;
        } 

        PR_snprintf( injection, MAX_INJECTION_SIZE,
                     "%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid,
                     "\";\n" );

        topLevel = get_field(query, "top=", SHORT_LEN);
        if ((topLevel != NULL) && (PL_strstr(topLevel, "operator"))) {
            PL_strcat(injection, "var topLevel = \"operator\";\n");
        }
        do_free(topLevel);
        add_authorization_data(userid, is_admin, is_operator, is_agent, injection);
        PL_strcat(injection, JS_STOP);

        buf = getData( searchActivityTemplate, injection );
    } else if( ( PL_strstr( query, "op=search_admin" ) ) || 
               ( PL_strstr( query, "op=search_users"  ) )) { 
        tokendbDebug( "authorization\n" );

        if( ! is_admin ) {
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_free(uri);
            do_free(query);

            return DONE;
        }

        PR_snprintf( injection, MAX_INJECTION_SIZE,
                     "%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid,
                     "\";\n" );
        add_authorization_data(userid, is_admin, is_operator, is_agent, injection);
        PL_strcat(injection, JS_STOP);

        if ( PL_strstr( query, "op=search_admin" ) ) {
            buf = getData( searchAdminTemplate, injection );
        } else if ( PL_strstr( query, "op=search_users" ) ) {
            buf = getData( searchUserTemplate, injection );
        }
    } else if ( PL_strstr( query, "op=search_certificate" ) )  {
        tokendbDebug( "authorization\n" );
        if ((! is_agent) && (! is_operator)) { 
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_free(uri);
            do_free(query);
            return DONE;
        }

        PR_snprintf( injection, MAX_INJECTION_SIZE,
                     "%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid,
                     "\";\n");

        topLevel = get_field(query, "top=", SHORT_LEN);
        if ((topLevel != NULL) && (PL_strstr(topLevel, "operator"))) {
            PL_strcat(injection, "var topLevel = \"operator\";\n");
        }
        do_free(topLevel);
        add_authorization_data(userid, is_admin, is_operator, is_agent, injection);
        PL_strcat(injection, JS_STOP);

        buf = getData( searchCertificateTemplate, injection );
    } else if( ( PL_strstr( query, "op=search" ) ) ) {
        tokendbDebug( "authorization for op=search\n" );
        if ((! is_agent) && (! is_operator)) {
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_free(uri);
            do_free(query);
            return DONE;
        }

        PR_snprintf( injection, MAX_INJECTION_SIZE,
                     "%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid,
                     "\";\n");
        
        topLevel = get_field(query, "top=", SHORT_LEN);
        if ((topLevel != NULL) && (PL_strstr(topLevel, "operator"))) {
            PL_strcat(injection, "var topLevel = \"operator\";\n");
        }
        do_free(topLevel);
        add_authorization_data(userid, is_admin, is_operator, is_agent, injection);
        PL_strcat(injection, JS_STOP);

        buf = getData( searchTemplate, injection );
    } else if( ( PL_strstr( query, "op=new" ) ) ) {
        tokendbDebug( "authorization\n" );
        if( ! is_admin ) {
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_free(uri);
            do_free(query);
            return DONE;

        }

        PR_snprintf( injection, MAX_INJECTION_SIZE,
                     "%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n", 
                     "var userid = \"", userid,
                     "\";\n" );
        add_authorization_data(userid, is_admin, is_operator, is_agent, injection);
        PL_strcat(injection, JS_STOP);

        buf = getData( newTemplate,injection );
    } else if ( ( PL_strstr( query, "op=add_user" ) ) ) {
        tokendbDebug( "authorization for add_user\n" );
        if( ! is_admin ) {
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_free(uri);
            do_free(query);

            return DONE;
        }

        PR_snprintf( injection, MAX_INJECTION_SIZE,
                     "%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid,
                     "\";\n");
        add_authorization_data(userid, is_admin, is_operator, is_agent, injection);
        PL_strcat(injection, JS_STOP);

        buf = getData( newUserTemplate,injection );
    } else if( ( PL_strstr( query, "op=view_admin" ) )       ||
               ( PL_strstr( query, "op=view_certificate" ) ) ||
               ( PL_strstr( query, "op=view_activity_admin" ) ) ||
               ( PL_strstr( query, "op=view_activity" ) )    ||
               ( PL_strstr( query, "op=view_users" ) )       ||
               ( PL_strstr( query, "op=view" ) )             ||
               ( PL_strstr( query, "op=edit_admin" ) )       ||
               ( PL_strstr( query, "op=edit_user" ) )        ||
               ( PL_strstr( query, "op=edit" ) )             ||
               ( PL_strstr( query, "op=show_certificate" ) ) ||
               ( PL_strstr( query, "op=show" ) )             ||
               ( PL_strstr( query, "op=do_confirm_token" ) ) ||
               ( PL_strstr( query, "op=user_delete_confirm"))||
               ( PL_strstr( query, "op=confirm" ) ) ) {
        if( ( PL_strstr( query, "op=confirm" ) )    ||
            ( PL_strstr( query, "op=view_admin" ) ) ||
            ( PL_strstr( query, "op=view_activity_admin" ) ) ||
            ( PL_strstr( query, "op=show_admin" ) ) ||
            ( PL_strstr( query, "op=view_users") )  ||
            ( PL_strstr( query, "op=edit_user") )   ||
            ( PL_strstr( query, "op=user_delete_confirm") ) ||
            ( PL_strstr( query, "op=edit_admin" ) ) ) {
            tokendbDebug( "authorization for admin ops\n" );

            if( ! is_admin ) {
                error_out("Authorization Failure", "Failed to authorize request");
                do_free(buf);
                do_free(uri);
                do_free(query);

                return DONE;
            }
        } else if ((PL_strstr(query, "op=edit")) || 
                   (PL_strstr(query, "do_confirm_token"))) {
            tokendbDebug( "authorization for op=edit and op=do_confirm_token\n" );

            if (! is_agent ) {
                error_out("Authorization Failure", "Failed to authorize request");
                do_free(buf);
                do_free(uri);
                do_free(query);

                return DONE;
            }
        } else if (PL_strstr(query, "op=view_activity")) {
            tokendbDebug( "authorization for view_activity\n" );

            /* check removed -- all roles permitted 
            if ( (! is_agent) && (! is_operator) && (! is_admin)) {
                error_out("Authorization Failure", "Failed to authorize request");
                do_free(buf);
                do_free(uri);
                do_free(query);

                return DECLINED;
            } */
        } else {
            tokendbDebug( "authorization\n" );

            if ((! is_agent) && (!is_operator)) { 
                error_out("Authorization Failure", "Failed to authorize request");
                do_free(buf);
                do_free(uri);
                do_free(query);

                return DONE;
            }
        }

        if ((PL_strstr( query, "op=view_activity_admin")) || 
            (PL_strstr( query, "op=view_activity" ) )) {
            getActivityFilter( filter, query );
        } else if( PL_strstr( query, "op=view_certificate" ) ) {
            getCertificateFilter( filter, query );
        } else if( PL_strstr( query, "op=show_certificate" ) ) {
            getCertificateFilter( filter, query );
        } else if ((PL_strstr( query, "op=view_users" ) ) ||
                   (PL_strstr( query, "op=user_delete_confirm")) ||
                   (PL_strstr( query, "op=edit_user" ) )) {
            getUserFilter( filter, query );
        } else {
            getFilter( filter, query );
        }

        auth_filter = get_authorized_profiles(userid, is_admin);

        tokendbDebug("auth_filter");
        tokendbDebug(auth_filter);

        char *complete_filter = add_profile_filter(filter, auth_filter);
        do_free(auth_filter);

        tokendbDebug( "looking for filter:" );
        tokendbDebug( complete_filter );
        tokendbDebug( filter );
        tokendbDebug( "\n" );

        /*  retrieve maxCount */
        s1 = PL_strstr( query, "maxCount=" );
        if( s1 == NULL ) {
            maxReturns = 100;
        } else {
            s2 = PL_strchr( ( const char * ) s1, '&' );
            if( s2 == NULL ) {
                maxReturns = atoi( s1+9 );
            } else {
                *s2 = '\0'; 
                maxReturns = atoi( s1+9 );
                *s2 = '&'; 
            }
        }

        if (( PL_strstr( query, "op=view_activity_admin" )) ||
            ( PL_strstr( query, "op=view_activity" ) )) {
            status = find_tus_activity_entries_no_vlv( complete_filter, &result, 1 );
        } else if( PL_strstr( query, "op=view_certificate" ) ) {

            ap_log_error( ( const char * ) "tus", __LINE__,
                          APLOG_ERR, 0, rq->server,
                          ( const char * ) "LDAP filter: %s", complete_filter);

            status = find_tus_certificate_entries_by_order_no_vlv( complete_filter,
                                                                   &result,
                                                                   0 );
        } else if( PL_strstr( query, "op=show_certificate" ) ||
                   PL_strstr( query, "op=view_certificate" ) ) {
            /* status = find_tus_certificate_entries( filter,
                                                      maxReturns,
                                                      &result ); */

            ap_log_error( ( const char * ) "tus", __LINE__,
                          APLOG_ERR, 0, rq->server,
                          ( const char * ) "LDAP filter: %s", complete_filter);

            status = find_tus_certificate_entries_by_order_no_vlv( complete_filter,
                                                                   &result,
                                                                   0 );
        } else if( PL_strstr( query, "op=show_admin" ) ||
                   PL_strstr( query, "op=show" )       ||
                   PL_strstr( query, "op=edit_admin" ) ||
                   PL_strstr( query, "op=confirm" )    ||
                   PL_strstr( query, "op=do_confirm_token" ) ) {
            status = find_tus_token_entries_no_vlv( complete_filter, &result, 0 );
        } else if ((PL_strstr (query, "op=view_users" ))  ||
                   (PL_strstr (query, "op=user_delete_confirm")) ||
                   (PL_strstr (query, "op=edit_user" )))  {
            status = find_tus_user_entries_no_vlv( filter, &result, 0); 
        } else {
            status = find_tus_db_entries( complete_filter, maxReturns, &result );
        }

        if( status != LDAP_SUCCESS ) {
            ldap_error_out("LDAP search error: ", "LDAP search error: %s");
            do_free(complete_filter);
            do_free(buf);
            do_free(uri);
            do_free(query);

            return DONE;
        }

        do_free(complete_filter);
        nEntries = get_number_of_entries( result );
        entryNum = 0;
        maxEntries = 0;
        size = 0;

        PL_strcpy( injection, JS_START );
        PL_strcat( injection, "var userid = \"" );
        PL_strcat( injection, userid );
        PL_strcat( injection, "\";\n" );
        PL_strcat( injection, "var uriBase = \"" );
        PL_strcat( injection, uri );
        PL_strcat( injection, "\";\n" );

        if( nEntries > 1 ) {
            if( sendInPieces && PL_strstr( query, "op=view_activity_admin" ) ) {
                buf = getTemplateFile( searchActivityAdminResultTemplate,
                                       &tagOffset );
                if( buf != NULL && tagOffset >= 0 ) {
                    ( void ) ap_rwrite( ( const void * ) buf, tagOffset, rq );
                    sendPieces = 1;
                }
            } else if( sendInPieces && PL_strstr( query, "op=view_activity" ) ) {
                buf = getTemplateFile( searchActivityResultTemplate,
                                       &tagOffset );
                if( buf != NULL && tagOffset >= 0 ) {
                    ( void ) ap_rwrite( ( const void * ) buf, tagOffset, rq );
                    sendPieces = 1;
                }
            } else if( sendInPieces &&
                       PL_strstr( query, "op=view_certificate" ) ) {
                buf = getTemplateFile( searchCertificateResultTemplate,
                                       &tagOffset );
                if( buf != NULL && tagOffset >= 0 ) {
                    ( void ) ap_rwrite( ( const void * ) buf, tagOffset, rq );
                    sendPieces = 1;
                }
            } else if (sendInPieces && PL_strstr( query, "op=view_users" )) {
                buf = getTemplateFile( searchUserResultTemplate, &tagOffset );
                if( buf != NULL && tagOffset >= 0 ) {
                    ( void ) ap_rwrite( ( const void * ) buf, tagOffset, rq );
                    sendPieces = 1;
                }
            } else if( sendInPieces && PL_strstr( query, "op=view" ) ) {
                buf = getTemplateFile( searchResultTemplate, &tagOffset );
                if( buf != NULL && tagOffset >= 0 ) {
                    ( void ) ap_rwrite( ( const void * ) buf, tagOffset, rq );
                    sendPieces = 1;
                }
            }

            PL_strcat( injection, "var total = \"" );

            len = PL_strlen( injection );

            PR_snprintf( &injection[len], ( MAX_INJECTION_SIZE-len ),
                         "%d", nEntries );

            PL_strcat( injection, "\";\n" );
        } else {
            if( ( vals = get_token_states() ) != NULL ) {
                PL_strcat( injection, "var tokenStates = \"" );
                for( i = 0; vals[i] != NULL; i++ ) {
                    if( i > 0 ) {
                        PL_strcat( injection, "," );
                    }

                    PL_strcat( injection, vals[i] );
                }

                if( i > 0 ) {
                    PL_strcat( injection, "\";\n" );
                } else {
                    PL_strcat( injection, "null;\n" );
                }
            }
        }

        PL_strcat( injection, "var results = new Array();\n" );
        PL_strcat( injection, "var item = 0;\n" );

        if( PL_strstr( query, "op=do_confirm_token" ) ) {
                question = PL_strstr( query, "question=" );

                q = question[9] - '0';

                PR_snprintf( question_no, 256, "%d", q );

                PL_strcat( injection, "var question = \"" );
                PL_strcat( injection, question_no );
                PL_strcat( injection, "\";\n" );
        }

        /* get attributes to be displayed to the user */
        if (( PL_strstr( query, "op=view_activity_admin" ) ) ||
            ( PL_strstr( query, "op=view_activity" ) )) {
            attrs = get_activity_attributes();
        } else if( PL_strstr( query, "op=view_certificate" ) ) {
            attrs = get_certificate_attributes();
        } else if( PL_strstr( query, "op=show_certificate" ) ) {
            attrs = get_certificate_attributes();
        } else if ((PL_strstr( query, "op=user_delete_confirm")) ||
                   (PL_strstr( query, "op=edit_user") ) )   {
            attrs = get_user_attributes();
        } else if (PL_strstr( query, "op=view_users") ) {
            attrs = get_view_user_attributes();
        } else {
            attrs = get_token_attributes();
        }

        /* start_val used in paging of profiles on the edit_user page */
        if (PL_strstr( query, "op=edit_user") ) {
            char *start_val_str = get_field(query, "start_val=", SHORT_LEN);
            if (start_val_str != NULL) { 
                start_val = atoi(start_val_str);
                do_free(start_val_str);
            } else {
                start_val = 0;
            }
            end_val = start_val + NUM_PROFILES_TO_DISPLAY;
        }

        /* flash used to display edit result upon redirection back to the edit_user page */
        if (PL_strstr(query, "op=edit_user") ) {
           char *flash = get_field(query, "flash=", SHORT_LEN);
           if (flash != NULL) {
              PL_strcat(injection, "var flash = \"");
              PL_strcat(injection, flash);
              PL_strcat(injection, "\";\n");
              do_free(flash);
           }
           PR_snprintf(msg, 256, "var num_profiles_to_display = %d ;\n", NUM_PROFILES_TO_DISPLAY);
           PL_strcat(injection, msg);
        }

        /* start_entry_val is used for pagination of entries on all other pages */
        int start_entry_val;
        int end_entry_val;
        int first_pass = 1;
        int one_time = 1;
        char *start_entry_val_str = get_field(query, "start_entry_val=", SHORT_LEN);
        if (start_entry_val_str != NULL) {
            start_entry_val = atoi(start_entry_val_str);
            do_free(start_entry_val_str);
        } else {
            start_entry_val = 1;
        }
        end_entry_val = start_entry_val + NUM_ENTRIES_PER_PAGE;

        for( e = get_first_entry( result );
             ( maxReturns > 0 ) && ( e != NULL );
             e = get_next_entry( e ) ) {
            maxReturns--;
            entryNum++;

            if ((entryNum < start_entry_val) || (entryNum >= end_entry_val)) {
                if (one_time == 1) {
                    PL_strcat(injection, "var my_query = \"");
                    PL_strcat(injection, query);
                    PL_strcat(injection, "\";\n");
                    one_time =0;
                }
                // skip values not within the page range
                if (entryNum == end_entry_val) {
                    PL_strcat( injection, "var has_more_entries = 1;\n"); 
                } 
                continue;
            }

            PL_strcat( injection, "var o = new Object();\n" );

            for( n = 0; attrs[n] != NULL; n++ ) {
                /* Get the values of the attribute. */
                if( ( vals = get_attribute_values( e, attrs[n] ) ) != NULL ) {
                    int v_start =0;
                    int v_end = MAX_INJECTION_SIZE;
                    PL_strcat( injection, "o." );
                    PL_strcat( injection, attrs[n] );
                    PL_strcat( injection, " = " );

                    if (PL_strstr(attrs[n], PROFILE_ID)) {
                        v_start = start_val;
                        v_end = end_val;
                    } 

                    for( i = v_start; (vals[i] != NULL) && (i < v_end); i++ ) {
                        if( i > start_val ) {
                            PL_strcat( injection, "#" );
                        } else {
                            PL_strcat( injection, "\"" );
                        }

                        // make sure to escape any special characters
                        char *escaped = escapeSpecialChars(vals[i]);
                        PL_strcat( injection, escaped );
                        if (escaped != NULL) {
                            PL_strfree(escaped);
                        }
                    }

                    if( i > v_start ) {
                        PL_strcat( injection, "\";\n" );
                    } else {
                        PL_strcat( injection, "null;\n" );
                    }

                    if (PL_strstr(attrs[n], PROFILE_ID))  {
                        if (vals[i] != NULL) { 
                            PL_strcat( injection, "var has_more_profile_vals = \"true\";\n");
                        } else {
                            PL_strcat( injection, "var has_more_profile_vals = \"false\";\n");
                        }
                        PR_snprintf(msg, 256, "var start_val = %d ;\n var end_val = %d ;\n", 
                            start_val, i);
                        PL_strcat( injection, msg);
                    }

                    /* Free the attribute values from memory when done. */
                    if( vals != NULL ) {
                        free_values( vals, 1 );
                        vals = NULL;
                    }
                }
            }

            PL_strcat( injection, "results[item++] = o;\n" );

            len = PL_strlen( injection );

            if( first_pass == 1 && nEntries > 1 && sendPieces == 0 ) {
                if( ( nEntries * len ) > MAX_INJECTION_SIZE ) {
                    size = nEntries;
                    if( ( nEntries * len ) >
                        ( MAX_OVERLOAD * MAX_INJECTION_SIZE ) ) {
                        maxEntries = ( MAX_OVERLOAD * MAX_INJECTION_SIZE ) /
                                     len;
                        size = maxEntries;
                    }

                    size *= len;

                    injection = ( char* ) PR_Malloc( size );

                    if( injection != NULL ) {
                        PL_strcpy( injection, fixed_injection );
                    } else {
                        injection = fixed_injection;
                        maxEntries = MAX_INJECTION_SIZE / len;
                        size = MAX_INJECTION_SIZE;
                    }
                }
                first_pass=0;

		PR_snprintf(msg, 256, "var start_entry_val = %d ; \nvar num_entries_per_page= %d ; \n", 
                            start_entry_val, NUM_ENTRIES_PER_PAGE);
                PL_strcat( injection, msg);
            }

            if( sendPieces ) {
                ( void ) ap_rwrite( ( const void * ) injection,
                                    PL_strlen( injection ), rq );
                injection[0] = '\0';
            }

            if( maxEntries > 0 && entryNum >= maxEntries ) {
                break;
            }
        }

        if( result != NULL ) {
            free_results( result );
            result = NULL;
        }

        if( maxEntries > 0 && nEntries > 1 ) {
            PL_strcat( injection, "var limited = \"" );

            len = PL_strlen( injection );

            PR_snprintf( &injection[len], ( size-len ), "%d", entryNum );

            PL_strcat( injection, "\";\n" );
        }

        /* populate the user roles */
        if ((PL_strstr( query, "op=edit_user")) ||
            (PL_strstr( query, "op=user_delete_confirm"))) {

            uid  = get_field(query, "uid=", SHORT_LEN);
            bool officer = false;
            bool agent = false;
            bool admin = false;
            status = find_tus_user_role_entries( uid, &result );
            for (e = get_first_entry( result );
                 e != NULL;
                 e = get_next_entry( e ) ) {
                char *dn = NULL;
                dn = get_dn(e);
                if (PL_strstr(dn, "Officers"))
                    officer=true; 
                if (PL_strstr(dn, "Agents"))
                    agent = true; 
                if (PL_strstr(dn, "Administrators")) 
                    admin = true;
                if (dn != NULL) {
                    PL_strfree(dn);
                    dn=NULL;
                } 
            }
            if (officer) {
                 PL_strcat( injection, "var operator = \"CHECKED\"\n");
            } else {
                 PL_strcat( injection, "var operator = \"\"\n");
            }
            if (agent) {
                 PL_strcat( injection, "var agent = \"CHECKED\"\n");
            } else {
                 PL_strcat( injection, "var agent = \"\"\n");
            }
            if (admin) {
                 PL_strcat( injection, "var admin = \"CHECKED\"\n");
            } else {
                 PL_strcat( injection, "var admin = \"\"\n");
            }

            if( result != NULL ) {
                free_results( result );
                result = NULL;
            }
            do_free(uid);
        }

        /* populate the profile checkbox */
        /* for sanity, we limit the number of entries displayed as well as the max number of characters transferred */
        if (PL_strstr( query, "op=edit_user")) {
            if (profileList != NULL) {
                int n_profiles = 0;
                int l_profiles = 0;
                bool more_profiles = false;

                char *pList = PL_strdup(profileList);
                char *sresult = NULL;
                
                PL_strcat( injection, "var profile_list = new Array(");
                sresult = strtok(pList, ",");
                n_profiles++;
                while (sresult != NULL) {
                    n_profiles++;
                    l_profiles  += PL_strlen(sresult);
                    if ((n_profiles > NUM_PROFILES_TO_DISPLAY) || (l_profiles > MAX_LEN_PROFILES_TO_DISPLAY)) {
                        PL_strcat(injection, "\"Other Profiles\",");
                        more_profiles = true;
                        break;
                    }

                    PL_strcat(injection, "\"");
                    PL_strcat(injection, sresult);
                    PL_strcat(injection, "\",");
                    sresult = strtok(NULL, ",");
                }
                do_free(pList);
                PL_strcat(injection, "\"All Profiles\")\n");
                if (more_profiles) {
                    PL_strcat(injection, "var more_profiles=\"true\";\n");
                } else {
                    PL_strcat(injection, "var more_profiles=\"false\";\n");
                }
            }
        }
        topLevel = get_field(query, "top=", SHORT_LEN);
        if ((topLevel != NULL) && (PL_strstr(topLevel, "operator"))) {
            PL_strcat(injection, "var topLevel = \"operator\";\n");
        }
        do_free(topLevel);


        add_authorization_data(userid, is_admin, is_operator, is_agent, injection);
        PL_strcat( injection, JS_STOP );

        if( sendPieces ) {
            ( void ) ap_rwrite( ( const void * ) injection,
                                PL_strlen( injection ), rq );

            mNum = buf + tagOffset + PL_strlen( CMS_TEMPLATE_TAG );

            ( void ) ap_rwrite( ( const void * ) mNum,
                                PL_strlen( mNum ), rq );

            mNum = NULL;

            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }
        } else {
            if( PL_strstr( query, "op=view_activity_admin" ) ) {
                buf = getData( searchActivityAdminResultTemplate, injection ); 
            } else if( PL_strstr( query, "op=view_activity" ) ) {
                buf = getData( searchActivityResultTemplate, injection );
            } else if( PL_strstr( query, "op=view_certificate" ) ) {
                buf = getData( searchCertificateResultTemplate, injection );
            } else if( PL_strstr( query, "op=show_admin" ) ) {
                buf = getData( showAdminTemplate, injection );
            } else if( PL_strstr( query, "op=view_admin" ) ) {
                buf = getData( searchAdminResultTemplate, injection );
            } else if (PL_strstr( query, "op=view_users") ) {
                buf = getData( searchUserResultTemplate, injection);
            } else if( PL_strstr( query, "op=view" ) ) {
                buf = getData( searchResultTemplate, injection );
            } else if (PL_strstr( query, "op=edit_user") ) {
                buf = getData( editUserTemplate, injection);
            } else if( PL_strstr( query, "op=edit" ) ) {
                buf = getData( editTemplate, injection );
            } else if( PL_strstr( query, "op=show_certificate" ) ) {
                buf = getData( showCertTemplate, injection );
            } else if( PL_strstr( query, "op=do_confirm_token" ) ) {
                buf = getData( doTokenConfirmTemplate, injection );
            } else if( PL_strstr( query, "op=show" ) ) {
                buf = getData( showTemplate, injection );
            } else if( PL_strstr( query, "op=confirm" ) ) {
                buf = getData( deleteTemplate, injection );
            } else if ( PL_strstr( query, "op=user_delete_confirm" ) ) {
                buf = getData( userDeleteTemplate, injection );
            }

        }

        if( injection != fixed_injection ) {
            if( injection != NULL ) {
                PR_Free( injection );
                injection = NULL;
            }

            injection = fixed_injection;
        }
    } else if ( PL_strstr( query, "op=add_profile_user" )) {
        tokendbDebug("authorization for op=add_profile_user");
        if( ! is_admin ) {
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_free(uri);
            do_free(query);

            return DONE;
        }
        uid = get_post_field(post, "uid", SHORT_LEN);
        char *profile = get_post_field(post, "profile_0", SHORT_LEN);
        char *other_profile = get_post_field(post, "other_profile", SHORT_LEN);
        if ((profile != NULL) && (uid != NULL)) {
            if (PL_strstr(profile, "Other Profiles")) {
                if ((other_profile != NULL) && (match_profile(other_profile))) {
                    do_free(profile);
                    profile = PL_strdup(other_profile);
                } else {
                    error_out("Invalid Profile to be added", "Invalid Profile to be added");
                    do_free(profile);
                    do_free(other_profile);
                    do_free(uid);
                    do_free(buf);
                    do_free(uri);
                    do_free(query);

                    return OK;
               }
            }
            if (PL_strstr(profile, ALL_PROFILES)) {
                status = delete_all_profiles_from_user(userid, uid);
            }

            status = add_profile_to_user(userid, uid, profile);
            if ((status != LDAP_SUCCESS) && (status != LDAP_TYPE_OR_VALUE_EXISTS)) {
                    PR_snprintf(msg, 512, "LDAP Error in adding profile %s to user %s",
                        profile, uid);
                    post_ldap_error(msg);
            }
        }
        do_free(other_profile);
        do_free(buf);
        do_free(uri);
        do_free(query);

        PR_snprintf((char *)msg, 512,
            "'%s' has added profile %s to user %s", userid, profile, uid);
        RA::tdb_activity(rq->connection->remote_ip, "", "add_profile", "success", msg, uid, NO_TOKEN_TYPE);


        PR_snprintf(injection, MAX_INJECTION_SIZE,
                    "/tus/tus?op=edit_user&uid=%s&flash=Profile+%s+has+been+added+to+the+user+record",
                    uid, profile);
        do_free(profile);
        do_free(uid);
        rq->method = apr_pstrdup(rq->pool, "GET");
        rq->method_number = M_GET;

        ap_internal_redirect_handler(injection, rq);
        return OK;
    } else if ( PL_strstr( query, "op=save_user" )) {
        tokendbDebug( "authorization for op=save_user\n" );

        if( ! is_admin ) {
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_free(uri);
            do_free(query);

            return DONE;
        }
        // first save user details
        uid = get_post_field(post, "uid", SHORT_LEN);
        firstName = get_post_field(post, "firstName", SHORT_LEN);
        lastName = get_post_field(post, "lastName", SHORT_LEN);
        userCert = get_encoded_post_field(post, "userCert", HUGE_STRING_LEN);
        opOperator = get_post_field(post, "opOperator", SHORT_LEN);
        opAgent = get_post_field(post, "opAgent", SHORT_LEN);
        opAdmin = get_post_field(post, "opAdmin", SHORT_LEN);

        PR_snprintf((char *)userCN, 256,
            "%s %s", firstName, lastName);

        status = update_user_db_entry(userid, uid, lastName, firstName, userCN, userCert);

        do_free(firstName);
        do_free(lastName);
        do_free(userCert);

        if( status != LDAP_SUCCESS ) {
            ldap_error_out("LDAP modify error: ", "LDAP error: %s");
            do_free(buf);
            do_free(uri);
            do_free(query);
            do_free(uid);
            do_free(opOperator);
            do_free(opAgent);
            do_free(opAdmin);

            return DONE;
        }
 
        if ((opOperator != NULL) && (PL_strstr(opOperator, OPERATOR))) {
            status = add_user_to_role_db_entry(userid, uid, OPERATOR);
            if ((status!= LDAP_SUCCESS) && (status != LDAP_TYPE_OR_VALUE_EXISTS)) {
                PR_snprintf(msg, 512, "Error adding user %s to role %s", uid, OPERATOR);
                post_ldap_error(msg);
            }
        } else {
            status = delete_user_from_role_db_entry(userid, uid, OPERATOR);
            if ((status!= LDAP_SUCCESS) && (status != LDAP_NO_SUCH_ATTRIBUTE)) {
                PR_snprintf(msg, 512, "Error deleting user %s from role %s", uid, OPERATOR);
                post_ldap_error(msg);
            }
        }

        if ((opAgent != NULL) && (PL_strstr(opAgent, AGENT))) {
            status = add_user_to_role_db_entry(userid, uid, AGENT);
            if ((status!= LDAP_SUCCESS) && (status != LDAP_TYPE_OR_VALUE_EXISTS)) {
                PR_snprintf(msg, 512, "Error adding user %s to role %s", uid, AGENT);
                post_ldap_error(msg);
            }
        } else {
            status = delete_user_from_role_db_entry(userid, uid, AGENT);
            if ((status!= LDAP_SUCCESS) && (status != LDAP_NO_SUCH_ATTRIBUTE)) {
                PR_snprintf(msg, 512, "Error deleting user %s from role %s", uid, AGENT);
                post_ldap_error(msg);
            }

        }

        if ((opAdmin != NULL) && (PL_strstr(opAdmin, ADMINISTRATOR))) {
            status = add_user_to_role_db_entry(userid, uid, ADMINISTRATOR);
            if ((status!= LDAP_SUCCESS) && (status != LDAP_TYPE_OR_VALUE_EXISTS)) {
                PR_snprintf(msg, 512, "Error adding user %s to role %s", uid, ADMINISTRATOR);
                post_ldap_error(msg);
            }
        } else {
            status = delete_user_from_role_db_entry(userid, uid, ADMINISTRATOR);
            if ((status!= LDAP_SUCCESS) && (status != LDAP_NO_SUCH_ATTRIBUTE)) {
                PR_snprintf(msg, 512, "Error deleting user %s from role %s", uid, ADMINISTRATOR);
                post_ldap_error(msg);
            }
        }
  
        do_free(opOperator);
        do_free(opAgent);
        do_free(opAdmin);

        // save profile details
        char *nProfileStr = get_post_field(post, "nProfiles", SHORT_LEN);
        int nProfiles = atoi (nProfileStr);
        do_free(nProfileStr);

        for (int i=0; i< nProfiles; i++) {
            char p_name[256];
            char p_delete[256];
            PR_snprintf(p_name, 256, "profile_%d", i);
            PR_snprintf(p_delete, 256, "delete_%d", i);
            char *profile = get_post_field(post, p_name, SHORT_LEN);
            char *p_del = get_post_field(post, p_delete, SHORT_LEN);

            if ((profile != NULL) && (p_del != NULL) && (PL_strstr(p_del, "delete"))) {
                status = delete_profile_from_user(userid, uid, profile);
                if ((status != LDAP_SUCCESS) && (status != LDAP_NO_SUCH_ATTRIBUTE)) {
                    PR_snprintf(msg, 512, "LDAP Error in deleting profile %s from user %s",
                        profile, uid);
                    post_ldap_error(msg);
                }
            }
            do_free(profile);
            do_free(p_del);
        }

        do_free(buf);
        do_free(uri);
        do_free(query);

        PR_snprintf((char *)msg, 512,
            "'%s' has modified user %s", userid, uid);
        RA::tdb_activity(rq->connection->remote_ip, "", "modify_user", "success", msg, uid, NO_TOKEN_TYPE);

        PR_snprintf(injection, MAX_INJECTION_SIZE,
                    "/tus/tus?op=edit_user&uid=%s&flash=User+record+%s+has+been+updated", 
                    uid, uid);
        do_free(uid);
        rq->method = apr_pstrdup(rq->pool, "GET");
        rq->method_number = M_GET;

        ap_internal_redirect_handler(injection, rq);
        return OK;
    } else if( PL_strstr( query, "op=save" ) ) {
        tokendbDebug( "authorization\n" );

        if( ! is_agent ) {
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_free(uri);
            do_free(query);
            return DONE;
        }

        getCN( filter, query );
        mNum = parse_modification_number( query );
        mods = getModifications( query );

        if( mNum != NULL ) {
            status = check_and_modify_tus_db_entry( userid, filter,
                                                    mNum, mods );

            PL_strfree( mNum );

            mNum = NULL;
        } else {
            status = modify_tus_db_entry( userid, filter, mods );
        }

        if( mods != NULL ) {
            free_modifications( mods, 0 );
            mods = NULL;
        }

        if( status != LDAP_SUCCESS ) {
             ldap_error_out("LDAP modify error: ", "LDAP error: %s");
            do_free(buf);
            do_free(uri);
            do_free(query);
            return DONE;
        }

        PR_snprintf( injection, MAX_INJECTION_SIZE,
                     "%s%s%s%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid, "\";\n",
                     "var tid = \"", filter, "\";\n");
        add_authorization_data(userid, is_admin, is_operator, is_agent, injection);
        PL_strcat(injection, JS_STOP);

        buf = getData( editResultTemplate, injection );

    } else if ( PL_strstr( query, "op=do_delete_user" ) ) {
        tokendbDebug( "authorization for do_delete_user\n" );

        if( ! is_admin ) {
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_free(uri);
            do_free(query);

            return DONE;
        }

        uid = get_post_field(post, "uid", SHORT_LEN);
        opOperator = get_post_field(post, "opOperator", SHORT_LEN);
        opAdmin = get_post_field(post, "opAdmin", SHORT_LEN);
        opAgent = get_post_field(post, "opAgent", SHORT_LEN);

        if (uid == NULL) {
            error_out("Error in delete user. userid is null", "Error in delete user. userid is null");
            do_free(buf);
            do_free(uri);
            do_free(query);
            do_free(opOperator);
            do_free(opAdmin);
            do_free(opAgent);
            
            return DONE;
        }

        if (opOperator != NULL) {
            status = delete_user_from_role_db_entry(userid, uid, OPERATOR);
            if ((status!= LDAP_SUCCESS) && (status != LDAP_NO_SUCH_ATTRIBUTE)) {
                PR_snprintf(msg, 512, "Error deleting user %s from role %s", uid, OPERATOR);
                post_ldap_error(msg);
            }
        }

        if (opAgent != NULL) {
            status = delete_user_from_role_db_entry(userid, uid, AGENT);
            if ((status!= LDAP_SUCCESS) && (status != LDAP_NO_SUCH_ATTRIBUTE)) {
                PR_snprintf(msg, 512, "Error deleting user %s from role %s", uid, AGENT);
                post_ldap_error(msg);
            }
        }

        if (opAdmin != NULL) {
            status = delete_user_from_role_db_entry(userid, uid, ADMINISTRATOR);
            if ((status!= LDAP_SUCCESS) && (status != LDAP_NO_SUCH_ATTRIBUTE)) {
                PR_snprintf(msg, 512, "Error deleting user %s from role %s", uid, ADMINISTRATOR);
                post_ldap_error(msg);
            }
        }

        do_free(opOperator);
        do_free(opAdmin);
        do_free(opAgent);
            
        status = delete_user_db_entry(userid, uid);

        if ((status != LDAP_SUCCESS) && (status != LDAP_NO_SUCH_OBJECT)) {
            PR_snprintf(msg, 512, "Error deleting user %s", uid);
            ldap_error_out(msg, msg);
            do_free(buf);
            do_free(uri);
            do_free(query);
            do_free(uid);
           
            return DONE;
        }

        PR_snprintf((char *)msg, 256,
            "'%s' has deleted user %s", userid, uid);
        RA::tdb_activity(rq->connection->remote_ip, "", "delete_user", "success", msg, uid, NO_TOKEN_TYPE);

        PR_snprintf( injection, MAX_INJECTION_SIZE,
                     "%s%s%s%s%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid, "\";\n",
                     "var tid = \"",     uid, "\";\n",
                     "var deleteType = \"user\";\n");
        add_authorization_data(userid, is_admin, is_operator, is_agent, injection);
        PL_strcat(injection, JS_STOP);

        do_free(uid);
        
        buf = getData( deleteResultTemplate, injection );
    } else if ( PL_strstr( query, "op=addUser" ) ) {
        tokendbDebug( "authorization for addUser\n" );

        if( ! is_admin ) {
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_free(uri);
            do_free(query);

            return DONE;
        }

        uid = get_post_field(post, "userid", SHORT_LEN);
        firstName = get_post_field(post, "firstName", SHORT_LEN);
        lastName = get_post_field(post, "lastName", SHORT_LEN);
        opOperator = get_post_field(post, "opOperator", SHORT_LEN);
        opAdmin = get_post_field(post, "opAdmin", SHORT_LEN);
        opAgent = get_post_field(post, "opAgent", SHORT_LEN);
        userCert = get_encoded_post_field(post, "cert", HUGE_STRING_LEN); 

        if ((PL_strlen(uid) == 0) || (PL_strlen(firstName) == 0) || (PL_strlen(lastName) == 0)) {
            error_out("Bad input to op=addUser", "Bad input to op=addUser");
            do_free(uid);
            do_free(firstName);
            do_free(lastName);
            do_free(opOperator);
            do_free(opAdmin);
            do_free(opAgent);
            do_free(userCert);
            do_free(buf);
            do_free(uri);
            do_free(query);

            return OK;
        }
        PR_snprintf((char *)userCN, 256, 
            "%s %s", firstName, lastName);

        status = add_user_db_entry(userid, uid, "", lastName, firstName, userCN, userCert);
        if (status != LDAP_SUCCESS) {
            PR_snprintf((char *)msg, 512, "LDAP Error in adding new user %s", uid);   
            ldap_error_out(msg, msg);
            do_free(uid);
            do_free(firstName);
            do_free(lastName);
            do_free(opOperator);
            do_free(opAdmin);
            do_free(opAgent);
            do_free(userCert);
            do_free(buf);
            do_free(uri);
            do_free(query);

            return OK;
        }

        PR_snprintf((char *)msg, 512,
            "'%s' has created new user %s", userid, uid);
        RA::tdb_activity(rq->connection->remote_ip, "", "add_user", "success", msg, uid, NO_TOKEN_TYPE);

        if ((opOperator != NULL) && (PL_strstr(opOperator, OPERATOR))) {
            status = add_user_to_role_db_entry(userid, uid, OPERATOR);
            if ((status!= LDAP_SUCCESS) && (status != LDAP_TYPE_OR_VALUE_EXISTS)) {
                PR_snprintf(msg, 512, "Error adding user %s to role %s", uid, OPERATOR);
                post_ldap_error(msg);
            }
        } else {
            status = delete_user_from_role_db_entry(userid, uid, OPERATOR);
            if ((status!= LDAP_SUCCESS) && (status != LDAP_NO_SUCH_ATTRIBUTE)) {
                PR_snprintf(msg, 512, "Error deleting user %s from role %s", uid, OPERATOR);
                post_ldap_error(msg);
            }
        }

        if ((opAgent != NULL) && (PL_strstr(opAgent, AGENT))) {
            status = add_user_to_role_db_entry(userid, uid, AGENT);
            if ((status!= LDAP_SUCCESS) && (status != LDAP_TYPE_OR_VALUE_EXISTS)) {
                PR_snprintf(msg, 512, "Error adding user %s to role %s", uid, AGENT);
                post_ldap_error(msg);
            }
        } else {
            status = delete_user_from_role_db_entry(userid, uid, AGENT);
            if ((status!= LDAP_SUCCESS) && (status != LDAP_NO_SUCH_ATTRIBUTE)) {
                PR_snprintf(msg, 512, "Error deleting user %s from role %s", uid, AGENT);
                post_ldap_error(msg);
            }
        }
        if ((opAdmin != NULL) && (PL_strstr(opAdmin, ADMINISTRATOR))) {
            status = add_user_to_role_db_entry(userid, uid, ADMINISTRATOR);
            if ((status!= LDAP_SUCCESS) && (status != LDAP_TYPE_OR_VALUE_EXISTS)) {
                PR_snprintf(msg, 512, "Error adding user %s to role %s", uid, ADMINISTRATOR);
                post_ldap_error(msg);
            }
        } else {
            status = delete_user_from_role_db_entry(userid, uid, ADMINISTRATOR);
            if ((status!= LDAP_SUCCESS) && (status != LDAP_NO_SUCH_ATTRIBUTE)) {
                PR_snprintf(msg, 512, "Error deleting user %s from role %s", uid, ADMINISTRATOR);
                post_ldap_error(msg);
            }

        }

        do_free(firstName);
        do_free(lastName);
        do_free(opOperator);
        do_free(opAdmin);
        do_free(opAgent);
        do_free(userCert);
       
        PR_snprintf( injection, MAX_INJECTION_SIZE,
                     "%s%s%s%s%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid, "\";\n",
                     "var tid = \"",     uid, "\";\n", 
                     "var addType = \"user\";\n");
        add_authorization_data(userid, is_admin, is_operator, is_agent, injection);
        PL_strcat(injection, JS_STOP);

        do_free(uid);
        
        buf = getData( addResultTemplate, injection );

    } else if( PL_strstr( query, "op=add" ) ) {
        tokendbDebug( "authorization for op=add\n" );
        RA_Status token_type_status;
        if( ! is_agent ) {
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_free(uri);
            do_free(query);
            return DONE;
        }

        getCN( filter, query );

        if (m_processor.GetTokenType(OP_PREFIX, 0, 0, filter, (const char*) NULL, (NameValueSet*) NULL,
                token_type_status, tokentype)) {
            PL_strcpy(tokenType, tokentype); 
        } else {
            PL_strcpy(tokenType, NO_TOKEN_TYPE);
        }
            
        PR_snprintf((char *)msg, 256,
            "'%s' has created new token", userid);
        RA::tdb_activity(rq->connection->remote_ip, filter, "add", "token", msg, "", tokenType);

        if( strcmp( filter, "" ) == 0 ) {
            error_out("No Token ID Found", "Failed to authorize request");
            do_free(buf);
            do_free(uri);
            do_free(query);
            return DONE;
        }

        status = add_default_tus_db_entry( NULL, userid,
                                           filter, "uninitialized",
                                           NULL, NULL, tokenType );

        if( status != LDAP_SUCCESS ) {
            ldap_error_out("LDAP add error: ", "LDAP error: %s");
            do_free(buf);
            do_free(uri);
            do_free(query);
            return DONE;
        }

        PR_snprintf( injection, MAX_INJECTION_SIZE,
                     "%s%s%s%s%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid, "\";\n",
                     "var tid = \"",    filter, "\";\n", 
                     "var addType = \"token\";\n");
        add_authorization_data(userid, is_admin, is_operator, is_agent, injection);
        PL_strcat(injection, JS_STOP);


        buf = getData( addResultTemplate, injection );
    } else if( PL_strstr( query, "op=delete" ) ) {
        RA_Status token_type_status;
        tokendbDebug( "authorization for op=delete\n" );

        if( ! is_admin ) {
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_free(uri);
            do_free(query);

            return DONE;
        }

        getCN( filter, query );

        if (m_processor.GetTokenType(OP_PREFIX, 0, 0, filter, (const char*) NULL, (NameValueSet*) NULL,
                token_type_status, tokentype)) {
            PL_strcpy(tokenType, tokentype);
        } else {
            PL_strcpy(tokenType, NO_TOKEN_TYPE);
        }


        PR_snprintf((char *)msg, 256,
            "'%s' has deleted token", userid);
        RA::tdb_activity(rq->connection->remote_ip, filter, "delete", "token", msg, "", tokenType);

        status = delete_tus_db_entry( userid, filter );

        if( status != LDAP_SUCCESS ) {
            ldap_error_out("LDAP delete error: ", "LDAP error: %s");
            do_free(buf);
            do_free(uri);
            do_free(query);

            return DONE;
        }

        PR_snprintf( injection, MAX_INJECTION_SIZE,
                     "%s%s%s%s%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid, "\";\n",
                     "var tid = \"", filter, "\";\n", 
                     "var deleteType = \"token\";\n");
        add_authorization_data(userid, is_admin, is_operator, is_agent, injection);
        PL_strcat(injection, JS_STOP);

        buf = getData( deleteResultTemplate, injection );
    } else if( PL_strstr( query, "op=load" ) ) {
        tokendbDebug( "authorization for op=load\n" );

        if( (! is_agent ) && (! is_operator) ) {
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_free(uri);
            do_free(query);

            return DONE;
        }

        getTemplateName( template1, query );

        buf = getData( template1, injection );
    } else if ( PL_strstr( query, "op=audit_admin") ) {
        tokendbDebug( "authorization for op=audit_admin\n" );

        if (!is_admin )  {
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_free(uri);
            do_free(query);

            return DONE;
        }

        PR_snprintf (injection, MAX_INJECTION_SIZE,
             "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s", JS_START,
             "var uriBase = \"", uri, "\";\n",
             "var userid = \"", userid, "\";\n",
             "var signedAuditEnable = \"", RA::m_audit_enabled ? "true": "false", "\";\n",
             "var logSigningEnable = \"", RA::m_audit_signed ? "true" : "false", "\";\n",
             "var signedAuditSelectedEvents = \"", RA::m_signedAuditSelectedEvents, "\";\n",
             "var signedAuditSelectableEvents = \"", RA::m_signedAuditSelectableEvents, "\";\n",
             "var signedAuditNonSelectableEvents = \"", RA::m_signedAuditNonSelectableEvents, "\";\n");

         RA::Debug( "mod_tokendb::mod_tokendb_handler",
               "signedAudit: %s %s %s %s %s", 
               RA::m_audit_enabled ? "true": "false",
               RA::m_audit_signed ? "true": "false",
               RA::m_signedAuditSelectedEvents,
               RA::m_signedAuditSelectableEvents, 
               RA::m_signedAuditNonSelectableEvents);
         
        char *flash = get_field(query, "flash=", SHORT_LEN);
        if (flash != NULL) {
            PL_strcat(injection, "var flash = \"");
            PL_strcat(injection, flash);
            PL_strcat(injection, "\";\n");
            do_free(flash);
        }

        add_authorization_data(userid, is_admin, is_operator, is_agent, injection);
        PL_strcat(injection, JS_STOP);
        buf = getData(auditAdminTemplate, injection);
    } else if (PL_strstr( query, "op=update_audit_admin") ) {
        tokendbDebug( "authorization for op=audit_admin\n" );

        if (!is_admin )  {
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_free(uri);
            do_free(query);

            return DONE;
        }
 
        int need_update=0;

        char *auditEnable = get_post_field(post, "auditEnable", SHORT_LEN);
        if (PL_strcmp(auditEnable, "true") == 0) {
           if (! RA::m_audit_enabled) {
               need_update = 1;
               RA::m_audit_enabled = true;
               RA::update_signed_audit_enable("true");
            
               PR_snprintf((char *)msg, 512, "'%s' has enabled audit logging", userid);
               RA::tdb_activity(rq->connection->remote_ip, "", "enable_audit_logging", "success", msg, userid, NO_TOKEN_TYPE);

               // we need to sleep or not all our actvity logs will be written
               PR_Sleep(PR_SecondsToInterval(1));
           }
        }

        if (PL_strcmp(auditEnable, "false") == 0) {
           if (RA::m_audit_enabled) {
               need_update = 1;
               RA::m_audit_enabled = false;
               RA::update_signed_audit_enable("false");

               PR_snprintf((char *)msg, 512, "'%s' has disabled audit logging", userid);
               RA::tdb_activity(rq->connection->remote_ip, "", "disable_audit_logging", "success", msg, userid, NO_TOKEN_TYPE);
               PR_Sleep(PR_SecondsToInterval(1));
           }
        }
        do_free(auditEnable);

        char *logSigning = get_post_field(post, "logSigningEnable", SHORT_LEN);
        if (PL_strcmp(logSigning, "true") == 0) {
           if (! RA::m_audit_signed) {
               need_update = 1;
               RA::m_audit_signed = true;
               RA::update_signed_audit_logging_enable("true");

               PR_snprintf((char *)msg, 512, "'%s' has enabled audit log signing", userid);
               RA::tdb_activity(rq->connection->remote_ip, "", "enable_audit_log_signing", "success", msg, userid, NO_TOKEN_TYPE);
               PR_Sleep(PR_SecondsToInterval(1));
           }
        }

        if (PL_strcmp(logSigning, "false") == 0) {
           if (RA::m_audit_signed) {
               need_update = 1;
               RA::m_audit_signed = false;
               RA::update_signed_audit_logging_enable("false");

               PR_snprintf((char *)msg, 512, "'%s' has disabled audit log signing", userid);
               RA::tdb_activity(rq->connection->remote_ip, "", "disable_audit_log_signing", "success", msg, userid, NO_TOKEN_TYPE);
               PR_Sleep(PR_SecondsToInterval(1));
           }
        }
        do_free(logSigning);

        int nEvents = atoi (get_post_field(post, "nEvents", SHORT_LEN));

        char new_selected[MAX_INJECTION_SIZE];

        int first_match = 1;
        for (int i=0; i< nEvents; i++) {
            char e_name[256];
            PR_snprintf(e_name, 256, "event_%d", i);
            char *event = get_post_field(post, e_name, SHORT_LEN);
            if ((event != NULL) && RA::IsValidEvent(event)) {
                if (first_match != 1) {
                    PL_strcat(new_selected, ",");
                }
                first_match = 0;
                PL_strcat(new_selected, event);
            }
            do_free(event);
        }

        if (PL_strcmp(new_selected, RA::m_signedAuditSelectedEvents) != 0) {
            need_update = 1;
            RA::update_signed_audit_selected_events(new_selected);

            PR_snprintf((char *)msg, 512,
            "'%s' has modified audit signing configuration", userid);
            RA::tdb_activity(rq->connection->remote_ip, "", "modify_audit_signing", "success", msg, userid, NO_TOKEN_TYPE);

        }

        if (need_update == 1) {
           tokendbDebug("Updating signed audit events in CS.cfg");
           RA::GetConfigStore()->Commit(true);
        } 

        PR_snprintf(injection, MAX_INJECTION_SIZE,
                    "/tus/tus?op=audit_admin&flash=Signed+Audit+configuration+has+been+updated");
        do_free(buf);
        do_free(uri);
        do_free(query);

        rq->method = apr_pstrdup(rq->pool, "GET");
        rq->method_number = M_GET;

        ap_internal_redirect_handler(injection, rq);
        return OK;
    }

    if( buf != NULL ) {
        len = PL_strlen( buf );

        ( void ) ap_rwrite( ( const void * ) buf, len, rq );

        do_free(buf);
    }
    do_free(userid);
    do_free(uri);
    do_free(query);

    return OK;
}



/*  _________________________________________________________________
**
**  Tokendb Module Command Phase
**  _________________________________________________________________
*/

static const char *mod_tokendb_get_config_path_file( cmd_parms *cmd,
                                                     void *mconfig,
                                                     const char *tokendbconf )
{
    if( cmd->path ) {
        ap_log_error( APLOG_MARK, APLOG_ERR, 0, NULL,
                      "The %s config param cannot be specified "
                      "in a Directory section.",
                      cmd->directive->directive );
    } else {
        mod_tokendb_server_configuration *sc = NULL;

        /* Retrieve the Tokendb module. */
        sc = ( ( mod_tokendb_server_configuration * )
               ap_get_module_config( cmd->server->module_config,
                                     &MOD_TOKENDB_CONFIG_KEY ) );

        /* Initialize the "Tokendb Configuration File" */
        /* member of mod_tokendb_server_configuration. */
        sc->Tokendb_Configuration_File = apr_pstrdup( cmd->pool, tokendbconf );
    }

    return NULL;
}


static const command_rec mod_tokendb_config_cmds[] = {
    AP_INIT_TAKE1( MOD_TOKENDB_CONFIGURATION_FILE_PARAMETER,
                   ( const char*(*)() ) mod_tokendb_get_config_path_file,
                   NULL,
                   RSRC_CONF,
                   MOD_TOKENDB_CONFIGURATION_FILE_USAGE ),
   { NULL }
};



/*  _________________________________________________________________
**
**  Tokendb Module Server Configuration Creation Phase
**  _________________________________________________________________
*/

/**
 * Create Tokendb module server configuration
 */
static void *
mod_tokendb_config_server_create( apr_pool_t *p, server_rec *sv )
{
    /* Initialize all APR library routines. */
    apr_initialize();

    /* Create a memory pool for this server. */
    mod_tokendb_server_configuration *sc = ( mod_tokendb_server_configuration * )
                                           apr_pcalloc( p,
                                                        ( apr_size_t )
                                                        sizeof( *sc ) );
    
    /* Initialize all members of mod_tokendb_server_configuration. */
    sc->Tokendb_Configuration_File = NULL;
    sc->enabled = MOD_TOKENDB_FALSE;

    return sc;
}



/*  _________________________________________________________________
**
**  Tokendb Module Registration Phase
**  _________________________________________________________________
*/
                                                                                
static void
mod_tokendb_register_hooks( apr_pool_t *p )
{
    static const char *const mod_tokendb_preloaded_modules[]  = { "mod_nss.c",
                                                                  "mod_tps.cpp",
                                                                  NULL };
    static const char *const mod_tokendb_postloaded_modules[] = { NULL };
                                                                                
    ap_hook_post_config( mod_tokendb_initialize,
                         mod_tokendb_preloaded_modules,
                         mod_tokendb_postloaded_modules,
                         APR_HOOK_MIDDLE );

    ap_hook_handler( mod_tokendb_handler,
                     mod_tokendb_preloaded_modules,
                     mod_tokendb_postloaded_modules,
                     APR_HOOK_MIDDLE );
}


module TOKENDB_PUBLIC MOD_TOKENDB_CONFIG_KEY = {
    STANDARD20_MODULE_STUFF,
    NULL,                             /* create per-dir    config structures */
    NULL,                             /* merge  per-dir    config structures */
    mod_tokendb_config_server_create, /* create per-server config structures */
    NULL,                             /* merge  per-server config structures */
    mod_tokendb_config_cmds,          /* table of configuration directives   */
    mod_tokendb_register_hooks        /* register hooks */
};



#ifdef __cplusplus
}
#endif

