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
#include "prthread.h"
#include "cert.h"
#include "regex.h"
#include "nss3/base64.h"
#include "prprf.h"

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
#include "selftests/SelfTest.h"

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

#define MAX_INJECTION_SIZE 10240 

#define MAX_OVERLOAD       20
#define LOW_INJECTION_SIZE 4096 
#define SHORT_LEN          256

#define BASE64_HEADER "-----BEGIN CERTIFICATE-----\n"
#define BASE64_FOOTER "-----END CERTIFICATE-----\n"

#define TOKENDB_OPERATORS_IDENTIFIER       "TUS Operators"
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
        APLOG_MODULE_INDEX, APLOG_ERR, 0, rq->server, \
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
        APLOG_MODULE_INDEX, APLOG_ERR, 0, rq->server, \
        ( const char * ) msg2, \
        ldap_err2string( status ) ); \
    ( void ) ap_rwrite( ( const void * ) buf, PL_strlen( buf ), rq );

#define post_ldap_error(msg) \
    ap_log_error( ( const char * ) "tus", __LINE__, \
        APLOG_MODULE_INDEX, APLOG_ERR, 0, rq->server, \
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

#define get_cfg_int(cname, vname) \
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
            char *endptr = NULL; \
            errno = 0; \
            vname = strtol(s, &endptr, 10);\
            if ((errno == ERANGE && (vname == LONG_MAX || vname == LONG_MIN)) \
              || (endptr == s)) { \
                vname=0; \
            } \
            do_free(s); \
        } else { \
            do_free(buf); \
            do_free(s); \
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

#define MAX_TOKEN_UI_STATE  6

enum token_ui_states  {
    TOKEN_UNINITIALIZED = 0,
    TOKEN_DAMAGED =1,
    TOKEN_PERM_LOST=2,
    TOKEN_TEMP_LOST=3,
    TOKEN_FOUND =4,
    TOKEN_TEMP_LOST_PERM_LOST =5,
    TOKEN_TERMINATED = 6
};

/*  _________________________________________________________________
**
**  Tokendb Module Request Data
**  _________________________________________________________________
*/

#ifdef DEBUG_Tokendb
static PRFileDesc *debug_fd                  = NULL;
#endif

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
static char *selfTestTemplate                = NULL;
static char *selfTestResultsTemplate         = NULL;
static char *agentSelectConfigTemplate       = NULL;
static char *selectConfigTemplate            = NULL;
static char *agentViewConfigTemplate         = NULL;
static char *editConfigTemplate              = NULL;
static char *confirmConfigChangesTemplate    = NULL;
static char *addConfigTemplate               = NULL;
static char *confirmDeleteConfigTemplate     = NULL;
static int maxSizeLimit                      = 0;
static int defaultSizeLimit                  = 0;
static int maxTimeLimit                      = 0;
static int defaultTimeLimit                  = 0;
static int pwLength                          = 0;

static char *profileList                     = NULL;
static char *transitionList                  = NULL;

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
APLOG_USE_MODULE(tokendb);

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
               "%s", msg);
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

inline void do_strfree(char *buf)
{
    if (buf != NULL) {
        PL_strfree(buf);
        buf = NULL;
    }
}

inline bool valid_berval(struct berval** b)
{
    return (b != NULL) && (b[0] != NULL) && (b[0]->bv_val != NULL);
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
char *get_field( char *s, const char* fname, int len)
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
      if ((ret != NULL) && ((int) PL_strlen(ret) > len)) {
        PR_Free(ret);
        return NULL;
      } else {
        return ret;
      }
   } else {
      return NULL;
  }
}

char *get_post_field_s( apr_table_t *post, const char *fname)
{
   char *ret = NULL;
   if (post) {
      ret = unencode(apr_table_get(post, fname));
      return ret;
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
      if ((ret != NULL) && ((int) PL_strlen(ret) > len)) {
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

int get_token_ui_state(char *state, char *reason)
{
    int ret = 0;
    if (strcmp(state, STATE_UNINITIALIZED) == 0) {
        ret = TOKEN_UNINITIALIZED;
    } else if (strcasecmp(state, STATE_ACTIVE) == 0) {
        ret = TOKEN_FOUND;
    } else if (strcasecmp(state, STATE_LOST) == 0) {
        if (strcasecmp(reason, "keyCompromise") == 0) {
            /* perm lost or temp -> perm lost */
            ret =  TOKEN_PERM_LOST;
        } else if (strcasecmp(reason, "destroyed") == 0) {
            ret = TOKEN_DAMAGED;
        } else if (strcasecmp(reason, "onHold") == 0) {
            ret = TOKEN_TEMP_LOST;
        }  
    } else if (strcasecmp(state, "terminated") == 0) {
        ret = TOKEN_TERMINATED;
    } else {
        /* state is disabled or otherwise : what to do here? */
        ret = TOKEN_PERM_LOST;
    }
    return ret;
}

bool transition_allowed(int oldState, int newState) 
{
    /* parse the allowed transitions string and look for old:new */
    char search[128];

    if (transitionList == NULL) return true;

    PR_snprintf(search, 128, "%d:%d", oldState, newState);
    return RA::match_comma_list(search, transitionList);
}

void add_allowed_token_transitions(int token_ui_state, char *injection, int injection_size) 
{
    bool first = true;
    int i=1;
    char state[128];

    sprintf(state, "var allowed_transitions=\"");
    PR_snprintf( injection, injection_size , "%s%s", injection,   state );
    for (i=1; i<=MAX_TOKEN_UI_STATE; i++) {
        if (transition_allowed(token_ui_state, i)) {
            if (first) {
               sprintf(state, "%d", i);
               first = false;
            } else {
               sprintf(state, ",%d", i);
            }
            PR_snprintf( injection, injection_size , "%s%s", injection,   state );
        }
    }

    PR_snprintf( injection, injection_size , "%s%s", injection,   "\";\n" );
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

void getCertificateFilter( char *filter, int filterSize,  char *query )
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
      PR_snprintf( filter, filterSize, "%s%s", filter, "(tokenID=*)");
      return;
    }

    if( tid != NULL && uid != NULL &&  view != NULL ) {
        PR_snprintf( filter, filterSize, "%s%s", filter, "(&");
    }

    if( tid != NULL ) {
        PR_snprintf( filter, filterSize, "%s%s", filter, "(tokenID=");
        end = PL_strchr( tid, '&' );
        len = PL_strlen( filter );
        if( end != NULL ) {
            i = end - tid - 4;

            if( i > 0 ) {
                memcpy( filter+len, tid+4, i );
            }
            filter[len+i] = '\0';
        } else {
            PR_snprintf( filter, filterSize, "%s%s", filter, tid+4);
        }
        if( view != NULL ) {
            PR_snprintf( filter, filterSize, "%s%s", filter, "*)");
        } else {
            PR_snprintf( filter, filterSize, "%s%s", filter, ")");
        }
    }

    if( uid != NULL && view != NULL ) {
        PR_snprintf( filter, filterSize, "%s%s", filter, "(tokenUserID=");
        end = PL_strchr( uid, '&' );
        len = PL_strlen( filter );
        if( end != NULL ) {
            i = end - uid - 4;
            if( i > 0 ) {
                memcpy( filter+len, uid+4, i );
            }

            filter[len+i] = '\0';
        } else {
            PR_snprintf( filter, filterSize, "%s%s", filter, uid+4);
        }

        PR_snprintf( filter, filterSize, "%s%s", filter, "*)");
    }

    if( cn != NULL ) {
        PR_snprintf( filter, filterSize, "%s%s", filter, "(cn=" );
        end = PL_strchr( cn, '&' );
        len = PL_strlen( filter );
        if( end != NULL ) {
            i = end - cn - 3;
            if( i > 0 ) {
                memcpy( filter+len, cn+3, i );
            }

            filter[len+i] = '\0';
        } else {
            PR_snprintf( filter, filterSize, "%s%s", filter, cn+3);
        }

        PR_snprintf( filter, filterSize, "%s%s", filter, "*)");
    }

    if(tid != NULL && uid != NULL && view != NULL) {
        PR_snprintf( filter, filterSize, "%s%s", filter, ")");
    }
}


void getActivityFilter( char *filter, int filterSize, char *query )
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
      PR_snprintf( filter, filterSize, "%s%s", filter, "(tokenID=*)");
    }

    if( tid != NULL && uid != NULL && view != NULL ) {
         PR_snprintf( filter, filterSize, "%s%s", filter, "(&");
    }

    if( tid != NULL ) {
         PR_snprintf( filter, filterSize, "%s%s", filter, "(tokenID=");
        end = PL_strchr( tid, '&' );
        len = PL_strlen( filter );

        if( end != NULL ) {
            i = end - tid - 4;
            if( i > 0 ) {
                memcpy( filter+len, tid+4, i );
            }
            filter[len+i] = '\0';
        } else {
             PR_snprintf( filter, filterSize, "%s%s", filter, tid+4);
        }

        if( view != NULL ) {
             PR_snprintf( filter, filterSize, "%s%s", filter, "*)" );
        } else {
             PR_snprintf( filter, filterSize, "%s%s", filter, ")");
        }
    }

    if( uid != NULL && view != NULL ) {
         PR_snprintf( filter, filterSize, "%s%s", filter, "(tokenUserID=" );
        end = PL_strchr( uid, '&' );
        len = PL_strlen( filter );
        if( end != NULL ) {
            i = end - uid - 4;
            if( i > 0 ) {
                memcpy( filter+len, uid+4, i );
            }

            filter[len+i] = '\0';
        } else {
             PR_snprintf( filter, filterSize, "%s%s", filter, uid+4);
        }

         PR_snprintf( filter, filterSize, "%s%s", filter, "*)");
    }

    if( tid != NULL && uid != NULL && view != NULL) {
         PR_snprintf( filter, filterSize, "%s%s", filter, ")");
    }
}

/**
 * get_user_filter
 * summary: returns an ldap search filter used for displaying 
 *          user data when searching users based on uid, firstName and lastName
 * params: filter - ldap search filter.  Resu;t returned here.
 *         query  - query string passed in
 */
void getUserFilter (char *filter, int filterSize,  char *query) {
    char *uid        = NULL;
    char *firstName  = NULL;
    char *lastName   = NULL;

    uid  = get_field(query, "uid=", SHORT_LEN);
    firstName = get_field(query, "firstName=", SHORT_LEN);
    lastName = get_field(query, "lastName=", SHORT_LEN);
  
    filter[0] = '\0';

    if ((uid == NULL) && (firstName == NULL) && (lastName ==NULL)) {
         PR_snprintf( filter, filterSize, "%s%s", filter, "(objectClass=Person");
    } else {
         PR_snprintf( filter, filterSize, "%s%s", filter,  "(&(objectClass=Person)");
    }

    if (uid != NULL) {
         PR_snprintf( filter, filterSize, "%s%s", filter, "(uid=" );

         PR_snprintf( filter, filterSize, "%s%s", filter,uid);

         PR_snprintf( filter, filterSize, "%s%s", filter, ")" );
    }

    if (lastName != NULL) {

         PR_snprintf( filter, filterSize, "%s%s", filter, "(sn=" );

         PR_snprintf( filter, filterSize, "%s%s", filter, lastName);

         PR_snprintf( filter, filterSize, "%s%s", filter, ")");
    }

    if (firstName != NULL) {

         PR_snprintf( filter, filterSize, "%s%s", filter, "(givenName=" );

         PR_snprintf( filter, filterSize, "%s%s", filter, firstName);

         PR_snprintf( filter, filterSize, "%s%s", filter, ")");
    }

     PR_snprintf( filter, filterSize, "%s%s", filter, ")");

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
           

void getFilter( char *filter, int filterSize,  char *query )
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
      PR_snprintf( filter, filterSize, "%s%s", filter, "(cn=*)" );
    }

    if( tid != NULL && uid != NULL && view != NULL ) {
        PR_snprintf( filter, filterSize, "%s%s", filter, "(&" );
    }

    if( tid != NULL ) {
        PR_snprintf( filter, filterSize, "%s%s", filter, "(cn=" );
        end = PL_strchr( tid, '&' );
        len = PL_strlen( filter );

        if( end != NULL ) {
            i = end - tid - 4;
            if( i > 0 ) {
                memcpy( filter+len, tid+4, i );
            }

            filter[len+i] = '\0';
        } else {
            PR_snprintf( filter, filterSize, "%s%s", filter, tid+4);
        }

        if (view != NULL) {
            PR_snprintf( filter, filterSize, "%s%s", filter, "*)");
        } else {
            PR_snprintf( filter, filterSize, "%s%s", filter, ")" );
        }
    }

    if( uid != NULL && view != NULL ) {
        PR_snprintf( filter, filterSize, "%s%s", filter, "(tokenUserID=" );
        end = PL_strchr( uid, '&' );
        len = PL_strlen( filter );
        if( end != NULL ) {
            i = end - uid - 4;
            if( i > 0 ) {
                memcpy( filter+len, uid+4, i );
            }

            filter[len+i] = '\0';
        } else {
            PR_snprintf( filter, filterSize, "%s%s", filter, uid+4);
        }

        PR_snprintf( filter, filterSize, "%s%s", filter, "*)" );
    }

    if( tid != NULL && uid != NULL && view != NULL ) {
        PR_snprintf( filter, filterSize, "%s%s", filter, ")" );
    }
}


void getCN( char *cn, int cnSize,  char *query )
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
            PR_snprintf( cn, cnSize, "%s%s", cn, tid+4);
        }
    }
}


void getTemplateName( char *cn, int cnSize,  char *query )
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
            PR_snprintf( cn, cnSize, "%s%s", cn, tid+4);
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

    /* keep this assignment to profileList for backwards compatibility.
       It has been superseded by target.Profiles.list.
       This should be removed in a future release */
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

    get_cfg_string("tokendb.allowedTransitions=", transitionList);
    get_cfg_string("tokendb.auditAdminTemplate=", auditAdminTemplate);
    get_cfg_string("tokendb.selfTestTemplate=", selfTestTemplate);
    get_cfg_string("tokendb.selfTestResultsTemplate=", selfTestResultsTemplate);
    get_cfg_string("tokendb.selectConfigTemplate=", selectConfigTemplate);
    get_cfg_string("tokendb.agentSelectConfigTemplate=", agentSelectConfigTemplate);
    get_cfg_string("tokendb.editConfigTemplate=", editConfigTemplate);
    get_cfg_string("tokendb.agentViewConfigTemplate=", agentViewConfigTemplate);
    get_cfg_string("tokendb.confirmConfigChangesTemplate=", confirmConfigChangesTemplate);
    get_cfg_string("tokendb.addConfigTemplate=", addConfigTemplate);
    get_cfg_string("tokendb.confirmDeleteConfigTemplate=", confirmDeleteConfigTemplate);
    get_cfg_string("target.Profiles.list=", profileList);
    get_cfg_int("general.search.sizelimit.max=", maxSizeLimit);
    get_cfg_int("general.search.sizelimit.default=", defaultSizeLimit);
    get_cfg_int("general.search.timelimit.max=", maxTimeLimit);
    get_cfg_int("general.search.timelimit.min=", defaultTimeLimit);
    get_cfg_int("general.pwlength.min=", pwLength);

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
                      __LINE__, APLOG_MODULE_INDEX, APLOG_ERR, 0, sv,
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
    const char *key, *val;
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
 * check_injection_size
 * Used when the injection size can become large - as in the case where lists of tokens, certs or activities are being returned.
 * If the free space in injection drops below a threshold, more space is allocated.  Fails if injection exceeds a certain size.
 * This should not happen because the number of entries to return per page is limited.
 *
 * returns 0 on success,1 on failure
 */
int check_injection_size(char **injection, int *psize, char *fixed_injection)
{

   tokendbDebug("In check_injection_size");
   char *new_ptr = NULL;
   if (((*psize) - PL_strlen(*injection)) <= LOW_INJECTION_SIZE) {
       if ((*psize) > MAX_OVERLOAD * MAX_INJECTION_SIZE) {
           tokendbDebug("Error: Injection exceeds maximum size.  Output will be truncated");
           return 1;
       }
       if (*injection == fixed_injection) {
            *injection = (char *) PR_Malloc(MAX_INJECTION_SIZE + (*psize));
            if (*injection != NULL) {
                PL_strcpy(*injection, fixed_injection);
                (*psize) += MAX_INJECTION_SIZE;
            } else {
                tokendbDebug("Error: Unable to allocate memory for injection. Output will be truncated");
                *injection = fixed_injection;
                return 1;
            }
       } else {
            tokendbDebug("check_injection_size about to realloc the injection buffer");
            new_ptr = (char *) PR_Realloc(*injection, (*psize) + MAX_INJECTION_SIZE);
            if (new_ptr != NULL) {
                //allocation successful
                *injection = new_ptr;
                (*psize) += MAX_INJECTION_SIZE;
            } else {
                tokendbDebug("Error: Failed to reallocate memory for injection.  Output will be truncated");
                return 1;
            }
       }
   }
   return 0;
}

/**
 * safe_injection_strcat
 * try not to over write our buffer any more
 * this routine will try to detect if we are going over the limit
 * if so, attempt to alter the buffer.
*/
int  safe_injection_strcat(char ** injection, int *injection_size , char *catData, char * fixed_injection )
{
    int result = 0;

    int current_len = strlen(*injection);
    if (catData == NULL) {
        return result;
    }
    int cat_data_len = strlen(catData);

    if ( cat_data_len == 0) {
        return result;
    }
    int expected_len = current_len + cat_data_len;

    if ( expected_len >= *injection_size ) {

        RA::Debug( "safe_injection_strcat, about to truncate, resize injection buffer:  ", "current len: %d expected_len %d data_len: %d cur_injection_size %d",current_len, expected_len, cat_data_len, *injection_size );

        /* We are going to get truncated!
           Let's try to update the size of the buffer.
        */

        /* This will always return a bigger buffer, because we are passing in the full
           current size of the buffer, not the current length of the string in the buffer.
        */

        int check_res = check_injection_size(injection, injection_size, fixed_injection);

        RA::Debug( "safe_injection_strcat, done  resizing injection buffer:  ", " new injection size: %d ",*injection_size );

        if (check_res == 1) {
            return result;
        }
        /* let's check it one more time for truncation*/

        if ( expected_len >= *injection_size ) {
             RA::Debug( "safe_injection_strcat, about to truncate, second attempt after first try. resize injection buffer:  ", "current len: %d expected_len %d data_len: %d cur_injection_size %d",current_len, expected_len, cat_data_len, *injection_size );

            check_res = check_injection_size(injection, injection_size, fixed_injection);
        }

        if ( check_res == 1 || (expected_len >= *injection_size)) {
            return result;
        }
    }

    PRUint32 sLen = PR_snprintf( *injection, *injection_size , "%s%s", *injection,   catData );

    if (sLen == expected_len)
       result = 0;
    else
       result = 1;

    return result;
}

/**
 * add_authorization_data
 * writes variable that describe whether the user is an admin, agent or operator to the
 * injection data.  Used by templates to determine which tabs to display
 */
void add_authorization_data(const char *userid, int is_admin, int is_operator, int is_agent, char **injection, int *injectionSize, char * fixed_injection)
{
    if (is_agent) {
        safe_injection_strcat(injection, injectionSize ,"var agentAuth = \"true\";\n", fixed_injection );
    }
    if (is_operator) {
        safe_injection_strcat(injection, injectionSize ,"var operatorAuth = \"true\";\n", fixed_injection );
    }
    if (is_admin) {
        safe_injection_strcat(injection, injectionSize ,"var adminAuth = \"true\";\n", fixed_injection );
    }
}

/*
 * We need to compare current values in the database entry e with new values.
 * If they are different, then we need to provide the audit message
 */
int audit_attribute_change(LDAPMessage *e, const char *fname, char *fvalue, char *msg)
{ 
    struct berval **attr_values = NULL;
    char pString[512]="";

    attr_values = get_attribute_values( e, fname );
    if (attr_values != NULL) {
        if (fvalue == NULL) {
            // value has been deleted
            PR_snprintf(pString, 512, "%s;;no_value", fname);
        } else if (valid_berval(attr_values) && 
                   (strcmp(fvalue, attr_values[0]->bv_val) != 0)) {
            // value has been changed 
            PR_snprintf(pString, 512, "%s;;%s", fname, fvalue);
        }
        free_values(attr_values, 1);
        attr_values = NULL;
    } else if (fvalue != NULL) {
        // value has been added
        PR_snprintf(pString, 512, "%s;;%s", fname, fvalue);
    }

    if (strlen(pString) > 0) {
        if (strlen(msg) != 0) PL_strncat(msg, "+", 4096 - strlen(msg));
        PL_strncat(msg, pString, 4096 - strlen(msg));
    }
    return 0;
}

/**
 * replaces all instances of a substring oldstr with newstr
 * must be freed by caller
 **/
char *replace(const char *s, const char *oldstr, const char *newstr)
{
    char *ret = NULL;
    int i, count = 0;
    size_t newlen = PL_strlen(newstr);
    size_t oldlen = PL_strlen(oldstr);

    if (s == NULL) {
        return ret;
    }
    for (i = 0; s[i] != '\0'; i++) {
        if (PL_strstr(&s[i], oldstr) == &s[i]) {
            count++;
            i += oldlen - 1;
        }
    }

    ret = (char *) PR_Malloc(PL_strlen(s)  + count * (newlen - oldlen) + 1);
    if (ret == NULL) {
        return ret;
    }

    i = 0;
    while (*s) {
        if (PL_strstr(s, oldstr) == s) {
            PL_strncpy(&ret[i], newstr, newlen);
            i += newlen;
            s += oldlen;
    } else
        ret[i++] = *s++;
    }
    ret[i] = '\0';

    return ret;
}

char *escapeString(const char *s)
{
    char *ret, *ret1, *ret2, *ret3;

    ret1 = replace(s,    "\"", "&dbquote");
    ret2 = replace(ret1, "\'", "&singlequote");
    ret3 = replace(ret2, "<", "&lessthan");
    ret = replace(ret3, ">", "&greaterthan");
    do_free(ret1);
    do_free(ret2);
    do_free(ret3);
    return ret;
}

char *unescapeString(const char *s)
{
    char *ret, *ret1, *ret2, *ret3;

    ret1 = replace(s,   "&dbquote", "\"");
    ret2 = replace(ret1,"&singlequote", "\'");
    ret3 = replace(ret2, "&lessthan", "<");
    ret = replace(ret3, "&greaterthan", ">");
    do_free(ret1);
    do_free(ret2);
    do_free(ret3);
    return ret;
}

char *escapeJavaScriptString(char* src)
{
    char *ret, *ret1, *ret2, *ret3, *ret4;
    int i, j;

    for (i = 0, j = 0; src != NULL && i < PL_strlen(src); i++) {
        if (src[i] > 31) {
            src[j++] = src[i];
        }
    }
    src[j++] = '\0';
    ret1 = replace(src,  "&",  "&#38;");
    ret2 = replace(ret1, "\"", "&#34;");
    ret3 = replace(ret2, "\'", "&#39;");
    ret4 = replace(ret3, "<",  "&#60;");
    ret  = replace(ret4, ">",  "&#62;");
    do_free(ret1);
    do_free(ret2);
    do_free(ret3);
    do_free(ret4);

    return ret;
}


/**
 * determines if the parameter set named pname of type ptype 
 * has been defined.  
 **/
bool config_param_exists(char *ptype, char* pname)
{
    char configname[256]="";
    PR_snprintf( ( char * ) configname, 256, "target.%s.list", ptype );
    const char* conf_list = RA::GetConfigStore()->GetConfigAsString( configname );
    return RA::match_comma_list((const char*) pname, (char *) conf_list);
}

/** 
 * takes in the type and name of the parameter set.
 * returns the current state and timestamp of this parameter set.
 *
 * If a parameter set is being viewed in the UI for the first time, the state is returned
 * as "Enabled" and the timestamp is set to the current timestamp.
 **/
void get_config_state_timestamp(char *type, char *name, char **pstate, char **ptimestamp)
{
    char configname[256] = "";
    bool commit_needed = false;
    const char *tmp_state = NULL;
    const char *tmp_timestamp = NULL;
    int status;
    PRLock *config_lock = RA::GetConfigLock();

    PR_Lock(config_lock);
    PR_snprintf(configname, 256, "config.%s.%s.state", type, name);
    
    tmp_state = RA::GetConfigStore()->GetConfigAsString(configname);
    if ((tmp_state == NULL) && (config_param_exists(type, name))) {
        RA::GetConfigStore()->Add(configname, "Enabled");
        commit_needed = true;
        *pstate = (char *) PL_strdup("Enabled");
    } else {
       *pstate = (char *) PL_strdup(tmp_state);
    }
 
    PR_snprintf(configname, 256, "config.%s.%s.timestamp", type, name);
    tmp_timestamp = RA::GetConfigStore()->GetConfigAsString(configname);
    if ((tmp_timestamp == NULL) &&  (config_param_exists(type, name))) {
        char new_ts[256];
        PR_snprintf(new_ts, 256, "%lld", PR_Now());
        RA::GetConfigStore()->Add(configname, new_ts);
        commit_needed = true;
        *ptimestamp = (char *) PL_strdup(new_ts);
    } else {
        *ptimestamp = (char *) PL_strdup(tmp_timestamp);
    }
    
    PR_Unlock(config_lock);
    if (commit_needed) {
        char error_msg[512];
        status = RA::GetConfigStore()->Commit(false, error_msg, 512);
        if (status != 0) {        
            tokendbDebug(error_msg);
        }
    }
}

/**
 * takes in a parameter set type and name
 * removes any variables defining the state and timestamp.  
 * Called when a parameter set is deleted.
 **/
void remove_config_state_timestamp(char *type, char *name)
{
    char configname[256] = "";
    PRLock *config_lock = RA::GetConfigLock();

    PR_Lock(config_lock);
    PR_snprintf(configname, 256, "config.%s.%s.state", type, name);
    RA::GetConfigStore()->Remove(configname);

    PR_snprintf(configname, 256, "config.%s.%s.timestamp", type, name);
    RA::GetConfigStore()->Remove(configname);
    PR_Unlock(config_lock);

}

/**
 * takes in a parameter set type
 * returns true if this parameter set type must be approved/ disabled by an agent
 **/
bool agent_must_approve(char *conf_type)
{
    const char* agent_list = RA::GetConfigStore()->GetConfigAsString("target.agent_approve.list");
    return RA::match_comma_list((const char*) conf_type, (char *) agent_list);
}

/**
 * This is the main function used to set the state and timestamp for parameter sets 
 * managed by the UI.  The function includes checks to enforce only allowed transitions.
 * 
 * Arguments are as follows:
 *     type: parameter set type
 *     name: parameter set name
 *     old_ts: old timestamp of parameter set.  Used to check for concurrency conflicts.
 *     new_state: state to transition to: one of "Enabled", "Disabled", "Pending_Approval" or "Writing"
 *     who: role requesting the transition, one of "Agent" or "Admin"
 *     new_config: true if this is a new parameter set, false otherwise
 *     userid: userid of user requesting the transition, used for audit log message 
 * 
 * function will return 0 on success, non-zero otherwise
 **/
int set_config_state_timestamp(char *type, char* name, char *old_ts, const char *new_state, const char *who, bool new_config, char *userid)
{
    char ts_name[256] = "";
    char state_name[256] = "";
    char writer_name[256] = "";
    char new_ts[256] ="";
    char final_state[256] = "";
    char me[256]="";
    int ret =0;
    PRTime now;
    PRThread *ct = NULL;
    PRLock *config_lock = RA::GetConfigLock();

    PR_snprintf(ts_name, 256, "config.%s.%s.timestamp", type, name);
    PR_snprintf(state_name, 256, "config.%s.%s.state", type, name);
    PR_snprintf(writer_name, 256, "config.%s.%s.writer", type, name); 

    ct = PR_GetCurrentThread();
    PR_snprintf(me, 256, "%x", ct);

    PR_Lock(config_lock); 
    if (new_config) {
        if (agent_must_approve(type)) {
             RA::GetConfigStore()->Add(state_name, "Disabled");
        } else {
             RA::GetConfigStore()->Add(state_name, "Enabled");
        }
        now = PR_Now();
        PR_snprintf(new_ts, 256, "%lld", now);
        RA::GetConfigStore()->Add(ts_name, new_ts);
    }

    // used to make sure auditing is correct
    PR_snprintf(final_state, 256, "%s", new_state);

    const char *cur_state = RA::GetConfigStore()->GetConfigAsString(state_name);
    const char *cur_writer = RA::GetConfigStore()->GetConfigAsString(writer_name, "");
    const char *cur_ts = RA::GetConfigStore()->GetConfigAsString(ts_name);

    if ((cur_state == NULL) || (cur_ts == NULL)) {
        // this item has likely been deleted
        ret=20;
        goto release_and_exit;
    }

    if ((PL_strcmp(cur_ts, old_ts) != 0) && (!new_config)) {
        // version out of date
        ret=1;
        goto release_and_exit;
    } 

    if (PL_strcmp(cur_state, new_state) == 0) {
        ret=0; 
        goto release_and_exit;
    }

    if (PL_strcmp(who, "Admin")==0) {
        if (PL_strcmp(new_state, "Disabled")==0) {
            if ((PL_strcmp(cur_state, "Writing") == 0) && (PL_strcmp(me, cur_writer) == 0)) {
                // "Writing" to "Disabled", with me as writer, admin finishes writes after "Save"
                now = PR_Now();
                PR_snprintf(new_ts, 256, "%lld", now); 
                RA::GetConfigStore()->Add(ts_name, new_ts);
                if (agent_must_approve(type)) {
                    RA::GetConfigStore()->Add(state_name, new_state);
                } else {
                    PR_snprintf(final_state, 256, "Enabled");
                    RA::GetConfigStore()->Add(state_name, "Enabled");
                }
                ret=0;
                goto release_and_exit;
            } else {
                ret=2;
                goto release_and_exit;
            }
        } else if (PL_strcmp(new_state, "Enabled")==0) {
            if ((!agent_must_approve(type)) && (PL_strcmp(cur_state, "Writing") == 0) 
              && (PL_strcmp(me, cur_writer) == 0)) {
                now = PR_Now();
                PR_snprintf(new_ts, 256, "%lld", now);
                RA::GetConfigStore()->Add(ts_name, new_ts);
                ret = 0;
                goto release_and_exit;
            }

            //  no valid transitions for admin (if agent approval required)
            ret=3;
            goto release_and_exit;
        } else if (PL_strcmp(new_state, "Pending_Approval")==0) {
            if (PL_strcmp(cur_state, "Disabled") == 0) {
                // Disabled -> Pending (admin submits for approval with no changes) 
                RA::GetConfigStore()->Add(state_name, new_state);
                ret=0;
                goto release_and_exit;
            } else if ((PL_strcmp(cur_state, "Writing") == 0) && (PL_strcmp(me, cur_writer) == 0)) {
                // Writing -> Pending. (admin finishes writes after "Submit for Approval")
                now = PR_Now();
                PR_snprintf(new_ts, 256, "%lld", now);    
                RA::GetConfigStore()->Add(ts_name, new_ts);
                RA::GetConfigStore()->Add(state_name, new_state);
                ret=0;
                goto release_and_exit;
            } else {
                ret=4;
                goto release_and_exit;
            }
        } else if (PL_strcmp(new_state, "Writing")==0) {
            if (PL_strcmp(cur_state, "Disabled") == 0) {
                // Disabled -> Writing (admin start to write changes - need to save writer)
                RA::GetConfigStore()->Add(writer_name, me);
                RA::GetConfigStore()->Add(state_name, new_state);
                ret=0;
                goto release_and_exit;
            } if ((!agent_must_approve(type)) && (PL_strcmp(cur_state, "Enabled") == 0)) {
                // Enabled -> Writing (admin start to write changes for case where agent need not approve - need to save writer)
                RA::GetConfigStore()->Add(writer_name, me);
                RA::GetConfigStore()->Add(state_name, new_state);
                ret=0;
                goto release_and_exit;
            } else {
                ret=5;
                goto release_and_exit;
            }
        }
    }

    if (PL_strcmp(who, "Agent")==0) {
        if (PL_strcmp(new_state, "Disabled")==0) {
            if ((PL_strcmp(cur_state, "Enabled") == 0) || (PL_strcmp(cur_state, "Pending_Approval") == 0)) {
                // "Enabled or Pending" to "Disabled", agent disables or rejects
                RA::GetConfigStore()->Add(state_name, new_state);
                ret=0;
                goto release_and_exit;
            } else {
                ret=6;
                goto release_and_exit;
            }
        } else if (PL_strcmp(new_state, "Enabled")==0) {
            if ((PL_strcmp(cur_state, "Disabled") == 0) || (PL_strcmp(cur_state, "Pending_Approval") == 0)) {
                // "Disabled or Pending" to "Enabled", agent approves
                RA::GetConfigStore()->Add(state_name, new_state);
                ret=0;
                goto release_and_exit;
            } else {
                ret=7;
                goto release_and_exit;
            }
        } else if (PL_strcmp(new_state, "Pending_Approval")==0) {
            //  no valid transitions for agent
            ret=8;
            goto release_and_exit;
        } else if (PL_strcmp(new_state, "Writing")==0) {
            //  no valid transitions for agent
            ret=9;
            goto release_and_exit;
        }
    }

release_and_exit:
    PR_Unlock(config_lock);

    //audit changes
    char pString[256]="";
    char msg[256] = "";

    if (PL_strcmp(new_ts, "") != 0) {
        PR_snprintf(pString, 256, "%s;;%s+%s;;%s", state_name, final_state, ts_name, new_ts);
        PR_snprintf(msg, 256, "config item state and timestamp changed");
    } else {
        PR_snprintf(pString, 256, "%s;;%s", state_name, final_state);
        PR_snprintf(msg, 256, "config item state changed");
    }
    if (ret == 0) { 
        RA::Audit(EV_CONFIG_AUDIT, AUDIT_MSG_CONFIG, userid, who, "Success", type, pString, msg);
    } else {
        PR_snprintf(msg, 256, "config item state or timestamp change failed, return value is %d", ret);
        RA::Audit(EV_CONFIG, AUDIT_MSG_CONFIG, userid, who, "Failure", type, pString, msg);
    }
    return ret;
}

/** 
 * takes in the type and name of the parameter set
 * looks up the regular expression pattern for this parameter set in CS.cfg and substitutes
 * $name with the name of the parameter set.
 * returns this "fixed" pattern as a string (that must be freed by caller)
 **/
char *get_fixed_pattern(char *ptype, char *pname)
{
    char configname[256]="";
    char tmpc[256]="";
    char *p = NULL;
    char *fixed_pattern = NULL;

     PR_snprintf( ( char * ) configname, 256, "target.%s.pattern", ptype );
    const char* pattern = RA::GetConfigStore()->GetConfigAsString( configname );

    if (pattern == NULL) {
        tokendbDebug("get_pattern_substore: pattern is NULL");
        return NULL;
    }

    if ((p = PL_strstr(pattern, "$name"))) {
        PL_strncpy(tmpc, pattern, p-pattern);
        tmpc[p-pattern] = '\0';
        sprintf(tmpc+(p-pattern), "%s%s", pname, p+PL_strlen("$name"));
        fixed_pattern = (char *) PL_strdup(tmpc);
        p = NULL;
    } else {
        fixed_pattern=PL_strdup(pattern);
    }

    tokendbDebug(fixed_pattern);

    return fixed_pattern;
} 

/**
 * get ConfigStore with entries that match the relevant pattern
 * must be freed by caller 
 **/
ConfigStore *get_pattern_substore(char *ptype, char *pname)
{ 
    char *fixed_pattern = NULL;
    ConfigStore *store = NULL;

    fixed_pattern=get_fixed_pattern(ptype, pname);
    if (fixed_pattern == NULL) {
        return NULL;
    }
    store = RA::GetConfigStore()->GetPatternSubStore(fixed_pattern);

    do_strfree(fixed_pattern); 
    return store;
}

/***
 * parse the parameter string of form foo=bar&&foo2=baz&& ...
 * and perform (and audit) the changes
 **/
void parse_and_apply_changes(char* userid, char* ptype, char* pname, const char *operation, char *params) {
    char *pair;
    char *line = NULL;
    int i;
    int len;
    char *lasts = NULL;
    int op=0;
    char audit_str[4096] = "";
    char *fixed_pattern = NULL;
    regex_t *regex=NULL;
    int err_no;

    if (PL_strstr(operation, "ADD")) {
        op=1;
    } else if (PL_strstr(operation, "DELETE")) {
        op=2;
    } else if (PL_strstr(operation, "MODIFY")) {
        op=3;
    }

    tokendbDebug(operation);

    // get the correct pattern and regex
    fixed_pattern = get_fixed_pattern(ptype, pname);
    if (fixed_pattern == NULL) {
       tokendbDebug("parse_and_apply_changes: pattern is NULL. Aborting changes ..");
       return;
    }

    regex = (regex_t *) malloc(sizeof(regex_t));
    memset(regex, 0, sizeof(regex_t));

    if((err_no=regcomp(regex, fixed_pattern, 0))!=0) /* Comple the regex */
    {
      // Error in computing the regex
      size_t length;
      char *buffer;
      length = regerror (err_no, regex, NULL, 0);
      buffer = (char *) PR_Malloc(length);
      regerror (err_no, regex, buffer, length);
      tokendbDebug("parse_and_apply_changes: error computing the regex, aborting changes");
      tokendbDebug(buffer);
      PR_Free(buffer);
      regfree(regex);
      return;
    }
    size_t no_sub = regex->re_nsub+1;
    regmatch_t *result = NULL;
    
    line = PL_strdup(params);
    pair = PL_strtok_r(line, "&&", &lasts);
    while (pair != NULL) {
        len = strlen(pair);
        i = 0;
        while (1) {
            if (i >= len) {
                goto skip1;
            }
            if (pair[i] == '\0') {
                goto skip1;
            }
            if (pair[i] == '=') {
                pair[i] = '\0';
                break;
            }
            i++;
        }

        result = NULL;
        result = (regmatch_t *) PR_Malloc(sizeof(regmatch_t) * no_sub);
        if (regexec(regex, (char *) &pair[0], no_sub, result, 0)!=0) {
            tokendbDebug("parse_and_apply_changes: parameter does not match pattern. Dropping edit ..");
            tokendbDebug(&pair[0]);
            if (result != NULL) { 
                PR_Free(result);
                result=NULL;
            }
            goto skip1;
        }
        if (result != NULL) {
            PR_Free(result);
            result=NULL;
        }

        if (op == 1) { //ADD 
            RA::GetConfigStore()->Add(&pair[0], &pair[i+1]);
            PR_snprintf(audit_str, 4096, "%s;;%s", &pair[0], &pair[i+1]);
            RA::Audit(EV_CONFIG, AUDIT_MSG_CONFIG, userid, "Admin", "Success", "", audit_str, "config parameter added");
        } else if (op == 2) { //DELETE
            RA::GetConfigStore()->Remove(&pair[0]);
            PR_snprintf(audit_str, 4096, "%s;;%s", &pair[0], &pair[i+1]);
            RA::Audit(EV_CONFIG, AUDIT_MSG_CONFIG, userid, "Admin", "Success", "", audit_str, "config parameter deleted");
        } else if (op == 3) { //MODIFY
            RA::GetConfigStore()->Add(&pair[0], &pair[i+1]);
            PR_snprintf(audit_str, 4096, "%s;;%s", &pair[0], &pair[i+1]);
            RA::Audit(EV_CONFIG, AUDIT_MSG_CONFIG, userid, "Admin", "Success", "", audit_str, "config parameter modified");
        }
    skip1:
        pair = PL_strtok_r(NULL, "&&", &lasts);
    }
    do_strfree(line);
    do_strfree(fixed_pattern);
}

static int get_time_limit(char *query)
{
  char *val = NULL;
  int ret;

  val  = get_field(query, "timeLimit=", SHORT_LEN);
  if (val == NULL) {
      return maxTimeLimit;
  } 

  ret = atoi(val);
  if ((ret == 0) || (ret > maxTimeLimit)) {
      return maxTimeLimit;
  } 
  return ret;
}

static int get_size_limit(char *query)
{
  char *val = NULL;
  int ret;

  val  = get_field(query, "sizeLimit=", SHORT_LEN);
  if (val == NULL) {
      return maxSizeLimit;
  }

  ret = atoi(val);
  if ((ret == 0) || (ret > maxSizeLimit)) {
      return maxSizeLimit;
  }
  return ret;
}

/**
 * generate a simple password of at least specified length
 * containing upper case, lower case and special characters
 */
#define PW_MAX_LEN 1024

static char *generatePassword(int length) 
{
  char choices[80] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*_-+=':;.,";
  bool pw_ok = false;
  int i=0;
  int upper=0, lower=0, number=0, special=0;
  char pw[PW_MAX_LEN] = "";

  srand(time(0));

  while (!pw_ok) {
      int x; 
      x = 0 + int(79.0 * rand()/(RAND_MAX+1.0));
      pw[i] = choices[x];
      if (isupper(choices[x])) upper ++;
      if (islower(choices[x])) lower ++;
      if (isdigit(choices[x])) number ++;
      if (! isalpha(choices[x])) special ++;

      if ((i >= length) && (upper >=2) && (lower >=2) && (special >=2) && (number >=2)) 
          pw_ok = true;
      i++;
      if (i == PW_MAX_LEN) {
          i=0;
          upper = 0; 
          lower = 0;
          special =0;
          number =0;
          PR_snprintf(pw, PW_MAX_LEN, ""); 
      }
  }

  return PL_strdup(pw);
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
    struct berval **bvals = NULL;
    int maxReturns;
    int q;
    int i, n, len, nEntries, entryNum;
    int status = LDAP_SUCCESS;
    int size, tagOffset, statusNum;
    char fixed_injection[MAX_INJECTION_SIZE];
    int injection_size = MAX_INJECTION_SIZE;
    char pString[512] = "";
    char oString[512] = "";
    char pLongString[4096] = "";
    char configname[512] ="";
    char filter[2048] = "";
    char msg[512] = "";
    char question_no[100] ="";
    char cuid[256] = "";
    char cuidUserId[100]="";
    char tokenStatus[100]="";
    char tokenReason[100]="";
    int token_ui_state= 0;
    bool show_token_ui_state = false;
    char serial[100]="";
    char userCN[256]="";
    char tokenType[512]="";
    apr_table_t *post = NULL; /* used for POST data */
  
    char *statusString = NULL;
    char *s1, *s2;
    char *end;
    struct berval **attr_values = NULL;
    char *auth_filter = NULL;

    /* authorization */
    int is_admin = 0;
    int is_agent = 0;
    int is_operator = 0;

    int end_val =0;
    int start_val = 0;

    /* current operation for audit */
    char *op = NULL;

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

                buf = getData( errorTemplate, injection);

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
          RA::Audit(EV_AUTH_FAIL, AUDIT_MSG_AUTH, "null", "null", "Failure", "authentication failure, no cert");
          do_free(buf);
          return DONE;
    }
    
    tokendbDebug( cert );
    tokendbDebug( "\n" );

    base64_cert = stripBase64HeaderAndFooter( cert );

    tokendbDebug( base64_cert );
    tokendbDebug( "\n" );

    userid = tus_authenticate( base64_cert );

    if( userid == NULL ) {
          error_out("Authentication Failure", "Failed to authenticate request");

          SECStatus rv;
          SECItem certDER;
          CERTCertificate *c = NULL;

          rv = ATOB_ConvertAsciiToItem(&certDER, base64_cert);
          if (rv) {
              RA::Debug("mod_tokendb_handler::mod_tokendb_handler", "Error converting certificate data to binary");
          } else {
              c = CERT_DecodeCertFromPackage((char *)certDER.data, certDER.len);
          }

          RA::Audit(EV_AUTH_FAIL, AUDIT_MSG_AUTH, 
            (c!= NULL) && (c->subjectName != NULL) ? c->subjectName : "null", 
            "null", "Failure", "authentication failure");
          do_free(buf);

          if (c != NULL) {
              CERT_DestroyCertificate(c);
          }

          return DONE;
    }
    do_free(base64_cert);

    // useful to indicate cn of user cert
    RA::Audit(EV_AUTH_SUCCESS, AUDIT_MSG_AUTH, userid, userid, "Success", "authentication success");

    /* authorization */
    is_admin = tus_authorize(TOKENDB_ADMINISTRATORS_IDENTIFIER, userid);
    if (is_admin) { 
        RA::Audit(EV_ROLE_ASSUME, AUDIT_MSG_ROLE, userid, "Tokendb Admin", "Success", "assume privileged role");
    }

    is_agent = tus_authorize(TOKENDB_AGENTS_IDENTIFIER, userid);
    if (is_agent) { 
        RA::Audit(EV_ROLE_ASSUME, AUDIT_MSG_ROLE, userid, "Tokendb Agent", "Success", "assume privileged role");
    }
 
    is_operator = tus_authorize(TOKENDB_OPERATORS_IDENTIFIER, userid);
    if (is_operator) { 
        RA::Audit(EV_ROLE_ASSUME, AUDIT_MSG_ROLE, userid, "Tokendb Operator", "Success", "assume privileged role");
    } 

    if( rq->uri != NULL ) {
        uri = escapeJavaScriptString(rq->uri);
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

    if (uri == NULL || query == NULL) {
        char *itemplate = NULL;
        tokendbDebug( "authorization for index case\n" );
        if (uri != NULL && is_agent) {
            itemplate = indexTemplate;
        } else if (uri != NULL && is_operator) {
            itemplate = indexOperatorTemplate;
        } else if (uri != NULL && is_admin) {
            itemplate = indexAdminTemplate;
        } else {
            RA::Audit(EV_AUTHZ_FAIL, AUDIT_MSG_AUTHZ, userid, "index", "Failure", "Tokendb user authorization");
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);

            return DONE;
        }

        RA::Audit(EV_AUTHZ_SUCCESS, AUDIT_MSG_AUTHZ, userid, "index", "Success", "Tokendb user authorization");

        PR_snprintf( injection, injection_size,
                     "%s%s%s%s%s%s%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n", 
                     "var userid = \"", userid, "\";\n",
                     "var agent_target_list = \"", 
                     RA::GetConfigStore()->GetConfigAsString("target.agent_approve.list", ""), "\";\n",
                     "var target_list = \"", 
                      RA::GetConfigStore()->GetConfigAsString("target.configure.list", ""), "\";\n" );

        add_authorization_data(userid, is_admin, is_operator, is_agent, &injection, &injection_size, fixed_injection);
        safe_injection_strcat(&injection, &injection_size , JS_STOP, fixed_injection );

        buf = getData( itemplate, injection );
        itemplate = NULL;
    } else if( ( PL_strstr( query, "op=index_operator" ) ) ) {
        tokendbDebug( "authorization for op=index_operator\n" );
        if (!is_operator) {
            RA::Audit(EV_AUTHZ_FAIL, AUDIT_MSG_AUTHZ, userid, "index_operator", "Failure", "Tokendb user authorization");
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);
            return DONE;
        }
        RA::Audit(EV_AUTHZ_SUCCESS, AUDIT_MSG_AUTHZ, userid, "index_operator", "Success", "Tokendb user authorization");
        PR_snprintf( injection, injection_size,
                     "%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n", 
                     "var userid = \"", userid,
                     "\";\n" );
        add_authorization_data(userid, is_admin, is_operator, is_agent, &injection, &injection_size, fixed_injection);
        safe_injection_strcat(&injection, &injection_size , JS_STOP, fixed_injection );

        buf = getData( indexOperatorTemplate, injection );
    } else if( ( PL_strstr( query, "op=index_admin" ) ) ) {
        tokendbDebug( "authorization\n" );
        if (!is_admin) {
            RA::Audit(EV_AUTHZ_FAIL, AUDIT_MSG_AUTHZ, userid, "index_admin", "Failure", "Tokendb user authorization");
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);
            return DONE;
        }
        RA::Audit(EV_AUTHZ_SUCCESS, AUDIT_MSG_AUTHZ, userid, "index_admin", "Success", "Tokendb user authorization");

        PR_snprintf( injection, injection_size,
                     "%s%s%s%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n", 
                     "var userid = \"", userid, "\";\n", 
                     "var target_list = \"", RA::GetConfigStore()->GetConfigAsString("target.configure.list", ""), "\";\n" );

        add_authorization_data(userid, is_admin, is_operator, is_agent, &injection, &injection_size, fixed_injection);

        safe_injection_strcat(&injection, &injection_size , JS_STOP, fixed_injection );

        buf = getData( indexAdminTemplate, injection );
    } else if( ( PL_strstr( query, "op=do_token" ) ) ) {
        tokendbDebug( "authorization for do_token\n" );

        if( !is_agent ) {
            RA::Audit(EV_AUTHZ_FAIL, AUDIT_MSG_AUTHZ, userid, "do_token", "Failure", "Tokendb user authorization");
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);
            return DONE;
        }
        RA::Audit(EV_AUTHZ_SUCCESS, AUDIT_MSG_AUTHZ, userid, "do_token", "Success", "Tokendb user authorization");

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

        tokendbDebug( "cuid:" );
        tokendbDebug( cuid );
        tokendbDebug( "\n" );
        question = PL_strstr( query, "question=" );
        q = question[9] - '0';

        PR_snprintf( question_no, 256, "%d", q );

        tokendbDebug( "question_no:" );
        tokendbDebug( question_no );

        rc = find_tus_db_entry( cuid, 1, &result );
        if( rc == 0 ) {
            e = get_first_entry( result );    
            if( e != NULL ) {
                attr_values = get_attribute_values( e, "tokenUserID" );
                tokendbDebug( "cuidUserId:" );
                if (valid_berval(attr_values)) {
                    PL_strcpy( cuidUserId, attr_values[0]->bv_val );
                    tokendbDebug( cuidUserId );
                    free_values(attr_values, 1);
                    attr_values = NULL;
                } else
                    tokendbDebug("null");
                 
                attr_values = get_attribute_values( e, "tokenType" );
                tokendbDebug( "tokenType:" );
                if (valid_berval(attr_values)) {
                    PL_strcpy( tokenType, attr_values[0]->bv_val );
                    tokendbDebug( tokenType );
                    free_values(attr_values, 1);
                    attr_values = NULL;
                } else
                    tokendbDebug("null");
 
                attr_values = get_attribute_values( e, "tokenStatus" );
                tokendbDebug( "tokenStatus:" );
                if (valid_berval(attr_values)) {
                    PL_strcpy( tokenStatus, attr_values[0]->bv_val );
                    tokendbDebug( tokenStatus );
                    free_values(attr_values, 1);
                    attr_values = NULL;
                } else
                    tokendbDebug("null");

                attr_values = get_attribute_values( e, "tokenReason" );
                tokendbDebug( "tokenReason:" );
                if (valid_berval(attr_values)) {
                    PL_strcpy( tokenReason, attr_values[0]->bv_val );
                    tokendbDebug( tokenReason );
                    free_values(attr_values, 1);
                    attr_values = NULL;
                } else
                    tokendbDebug("null");
            }
        }

        if( result != NULL ) {
            ldap_msgfree( result );
        }

        token_ui_state = get_token_ui_state(tokenStatus, tokenReason);

        /* Is this token physically damaged */
        if(( q == 1 ) && (transition_allowed(token_ui_state, 1))) {

            PR_snprintf((char *)msg, 256,
              "'%s' marked token physically damaged", userid);
            RA::tdb_activity(rq->connection->client_ip, cuid, "do_token", "initiated",
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

                        CERTCertificate **attr_certificate= get_certificates( e );
                        statusNum = certEnroll->RevokeCertificate(
                                    true,
                                    attr_certificate[0],
                                    revokeReason,
                                    serial, connid, statusString );
                        if (attr_certificate[0] != NULL)
                            CERT_DestroyCertificate(attr_certificate[0]);

                        if (statusNum != 0) { // revocation errors
                            if( strcmp( revokeReason, "6" ) == 0 ) {
                                PR_snprintf((char *)msg, 256, "Errors in marking certificate on_hold '%s' : %s", attr_cn, statusString);
                                RA::tdb_activity(rq->connection->client_ip, cuid, "do_token", "failure", msg, cuidUserId, attr_tokenType);

                                RA::Audit(EV_CONFIG_TOKEN, AUDIT_MSG_CERT_STATUS_CHANGE, userid, 
                                  "Failure", "revoked_on_hold", serial, connid, statusString); 
                            } else {
                                PR_snprintf((char *)msg, 256, "Errors in revoking certificate '%s' : %s", attr_cn, statusString);
                                RA::tdb_activity(rq->connection->client_ip, cuid, "do_token", "failure", msg, cuidUserId, attr_tokenType);

                                RA::Audit(EV_CONFIG_TOKEN, AUDIT_MSG_CERT_STATUS_CHANGE, userid, 
                                  "Failure", "revoke", serial, connid, statusString); 
                            }
                        } else {
                            // update certificate status
                            if( strcmp( revokeReason, "6" ) == 0 ) {
                                PR_snprintf((char *)msg, 256, "Certificate '%s' is marked as revoked_on_hold", attr_cn);
                                RA::tdb_activity(rq->connection->client_ip, cuid, "do_token", "success", msg, cuidUserId, attr_tokenType);
                                update_cert_status( attr_cn, "revoked_on_hold" );

                                RA::Audit(EV_CONFIG_TOKEN, AUDIT_MSG_CERT_STATUS_CHANGE, userid, 
                                  "Success", "revoked_on_hold", serial, connid, ""); 
                            } else {
                                PR_snprintf((char *)msg, 256, "Certificate '%s' is marked as revoked", attr_cn);
                                RA::tdb_activity(rq->connection->client_ip, cuid, "do_token", "success", msg, cuidUserId, attr_tokenType);
                                update_cert_status( attr_cn, "revoked" );

                                RA::Audit(EV_CONFIG_TOKEN, AUDIT_MSG_CERT_STATUS_CHANGE, userid, 
                                  "Success", "revoke", serial, connid, ""); 
                            }
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

                PR_snprintf(oString, 512, "token_id;;%s", cuid);
                PR_snprintf(pString, 512, "tokenStatus;;lost+tokenReason;;destroyed");
                RA::Audit(EV_CONFIG_TOKEN, AUDIT_MSG_CONFIG, userid, "Agent", "Failure", oString, pString, "token marked physically damaged, rc=-1");

                PR_snprintf((char *)msg, 256, "Failed to update token status as physically damaged");
                RA::tdb_activity(rq->connection->client_ip, cuid, "do_token", "failure",
                     msg, cuidUserId, tokenType);

                PR_snprintf( injection, MAX_INJECTION_SIZE,
                             "%s%s%s%s", JS_START,
                             "var error = \"Failed to create LDAPMod: ",
                             "\";\n", JS_STOP );

                buf = getData( errorTemplate, injection );

                ap_log_error( ( const char * ) "tus", __LINE__,
                              APLOG_MODULE_INDEX, APLOG_ERR, 0, rq->server,
                              ( const char * ) "Failed to create LDAPMod" );

                ( void ) ap_rwrite( ( const void * ) buf,
                                    PL_strlen( buf ), rq );

                do_free(buf);
                do_strfree(uri);
                do_strfree(query);

                return DONE;
            } else if( rc > 0 ) {
                tokendbDebug( "token is physically damaged. rc > 0\n" );

                PR_snprintf(oString, 512, "token_id;;%s", cuid);
                PR_snprintf(pString, 512, "tokenStatus;;lost+tokenReason;;destroyed");
                RA::Audit(EV_CONFIG_TOKEN, AUDIT_MSG_CONFIG, userid, "Agent", "Failure", oString, pString, "token marked physically damaged, rc>0");

                PR_snprintf((char *)msg, 256, "Failed to update token status as physically damaged");
                RA::tdb_activity(rq->connection->client_ip, cuid, "do_token", "failure",
                     msg, cuidUserId, tokenType);

                PR_snprintf( injection, MAX_INJECTION_SIZE,
                             "%s%s%s%s%s", JS_START,
                             "var error = \"LDAP mod error: ",
                             ldap_err2string( rc ),
                             "\";\n", JS_STOP );

                buf = getData( errorTemplate, injection );

                ap_log_error( ( const char * ) "tus", __LINE__,
                              APLOG_MODULE_INDEX, APLOG_ERR, 0, rq->server,
                              ( const char * ) "LDAP error: %s", 
                              ldap_err2string( rc ) );

                ( void ) ap_rwrite( ( const void * ) buf,
                                    PL_strlen( buf ), rq );

                do_free(buf);
                do_strfree(uri);
                do_strfree(query);

                return DONE;
            }

            PR_snprintf(oString, 512, "token_id;;%s", cuid);
            PR_snprintf(pString, 512, "tokenStatus;;lost+tokenReason;;destroyed");
            RA::Audit(EV_CONFIG_TOKEN, AUDIT_MSG_CONFIG, userid, "Agent", "Success", oString, pString, "token marked physically damaged");

            PR_snprintf((char *)msg, 256, "Token marked as physically damaged");
            RA::tdb_activity(rq->connection->client_ip, cuid, "do_token", "success",
                     msg, cuidUserId, tokenType);

        /* Is this token permanently lost? */
        } else if(((q == 2) && (transition_allowed(token_ui_state, 2))) || 
                  ((q == 6) && (transition_allowed(token_ui_state, 6)))) {
            if (q == 2) {
              PR_snprintf((char *)msg, 256,
                "'%s' marked token permanently lost", userid);             
            } else {
              PR_snprintf((char *)msg, 256,
                "'%s' marked token terminated", userid);             
            }
            RA::tdb_activity(rq->connection->client_ip, cuid, "do_token", "initiated",
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

                        CERTCertificate **attr_certificate= get_certificates( e );
                        statusNum = certEnroll->
                                    RevokeCertificate(
                                                       true,
                                                       attr_certificate[0],
                                                       revokeReason,
                                                       serial,
                                                       connid,
                                                       statusString );
                        if (attr_certificate[0] != NULL)
                            CERT_DestroyCertificate(attr_certificate[0]);

                        if (statusNum != 0) { // revocation errors
                            if( strcmp( revokeReason, "6" ) == 0 ) {
                                PR_snprintf((char *)msg, 256, "Errors in marking certificate on_hold '%s' : %s", attr_cn, statusString);
                                RA::tdb_activity(rq->connection->client_ip, cuid, "do_token", "failure", msg, cuidUserId, attr_tokenType);

                                RA::Audit(EV_CONFIG_TOKEN, AUDIT_MSG_CERT_STATUS_CHANGE, userid,
                                  "Failure", "revoked_on_hold", serial, connid, statusString);
                            } else {
                                PR_snprintf((char *)msg, 256, "Errors in revoking certificate '%s' : %s", attr_cn, statusString);
                                RA::tdb_activity(rq->connection->client_ip, cuid, "do_token", "failure", msg, cuidUserId, attr_tokenType);

                                RA::Audit(EV_CONFIG_TOKEN, AUDIT_MSG_CERT_STATUS_CHANGE, userid,
                                  "Failure", "revoke", serial, connid, statusString);
                            }
                        } else {
                            // update certificate status
                            if( strcmp( revokeReason, "6" ) == 0 ) {
                                PR_snprintf((char *)msg, 256, "Certificate '%s' is marked as revoked_on_hold", attr_cn);
                                RA::tdb_activity(rq->connection->client_ip, cuid, "do_token", "success", msg, cuidUserId, attr_tokenType);
                                update_cert_status( attr_cn, "revoked_on_hold" );

                                RA::Audit(EV_CONFIG_TOKEN, AUDIT_MSG_CERT_STATUS_CHANGE, userid,
                                  "Success", "revoked_on_hold", serial, connid, "");                 
                            } else {
                                PR_snprintf((char *)msg, 256, "Certificate '%s' is marked as revoked", attr_cn);
                                RA::tdb_activity(rq->connection->client_ip, cuid, "do_token", "success", msg, cuidUserId, attr_tokenType);
                                update_cert_status( attr_cn, "revoked" );

                                RA::Audit(EV_CONFIG_TOKEN, AUDIT_MSG_CERT_STATUS_CHANGE, userid,
                                  "Success", "revoke", serial, connid, "");        
                            }
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

            PR_snprintf(oString, 512, "token_id;;%s", cuid);

            if (q == 6) { /* terminated */
              PR_snprintf(pString, 512, "tokenStatus;;terminated+tokenReason;;keyCompromise");
              rc = update_token_status_reason( cuidUserId, cuid,
                                             "terminated", "keyCompromise" );
            } else {
              PR_snprintf(pString, 512, "tokenStatus;;lost+tokenReason;;keyCompromise");
              rc = update_token_status_reason( cuidUserId, cuid,
                                             "lost", "keyCompromise" );
            }
            if( rc == -1 ) {
                if (q == 6) { /* terminated*/
                    RA::Audit(EV_CONFIG_TOKEN, AUDIT_MSG_CONFIG, userid, "Agent", "Failure", oString, pString, "token marked terminated, rc=-1");
                    PR_snprintf((char *)msg, 256, "Failure in updating token status to terminated");
                } else {
                    RA::Audit(EV_CONFIG_TOKEN, AUDIT_MSG_CONFIG, userid, "Agent", "Failure", oString, pString, "token marked permanently lost, rc=-1");
                    PR_snprintf((char *)msg, 256, "Failure in updating token status to permanently lost");
                }
                RA::tdb_activity(rq->connection->client_ip, cuid, "do_token", "failure",
                     msg, cuidUserId, tokenType);

                PR_snprintf( injection, MAX_INJECTION_SIZE,
                             "%s%s%s%s", JS_START,
                             "var error = \"Failed to create LDAPMod: ",
                             "\";\n", JS_STOP );

                buf = getData( errorTemplate, injection );

                ap_log_error( ( const char * ) "tus", __LINE__,
                              APLOG_MODULE_INDEX, APLOG_ERR, 0, rq->server,
                              ( const char * ) "Failed to create LDAPMod" );

                ( void ) ap_rwrite( ( const void * ) buf,
                                    PL_strlen( buf ), rq );

                do_free(buf);
                do_strfree(uri);
                do_strfree(query);

                return DONE;
            } else if( rc > 0 ) {
                if (q == 6) { /* terminated*/
                    RA::Audit(EV_CONFIG_TOKEN, AUDIT_MSG_CONFIG, userid, "Agent", "Failure", oString, pString, "token marked terminated, rc=>0");
                    PR_snprintf((char *)msg, 256, "Failure in updating token status to terminated");
                } else {
                    RA::Audit(EV_CONFIG_TOKEN, AUDIT_MSG_CONFIG, userid, "Agent", "Failure", oString, pString, "token marked permanently lost, rc>0");
                    PR_snprintf((char *)msg, 256, "Failure in updating token status to permanently lost");
                }
                RA::tdb_activity(rq->connection->client_ip, cuid, "do_token", "failure",
                     msg, cuidUserId, tokenType);

                PR_snprintf( injection, MAX_INJECTION_SIZE,
                             "%s%s%s%s%s", JS_START,
                             "var error = \"LDAP mod error: ",
                             ldap_err2string( rc ),
                             "\";\n", JS_STOP );

                buf = getData( errorTemplate, injection );

                ap_log_error( ( const char * ) "tus", __LINE__,
                              APLOG_MODULE_INDEX, APLOG_ERR, 0, rq->server,
                              ( const char * ) "LDAP error: %s",
                              ldap_err2string( rc ) );

                ( void ) ap_rwrite( ( const void * ) buf,
                                    PL_strlen( buf ), rq );

                do_free(buf);
                do_strfree(uri);
                do_strfree(query);

                return DONE;
            }
            if (q == 6) { /* terminated*/
                RA::Audit(EV_CONFIG_TOKEN, AUDIT_MSG_CONFIG, userid, "Agent", "Success", oString, pString, "token marked terminated");
                PR_snprintf((char *)msg, 256, "Token marked terminated");
            } else {
                RA::Audit(EV_CONFIG_TOKEN, AUDIT_MSG_CONFIG, userid, "Agent", "Success", oString, pString, "token marked permanently lost");
                PR_snprintf((char *)msg, 256, "Token marked permanently lost");
            }
            RA::tdb_activity(rq->connection->client_ip, cuid, "do_token", "success",
                 msg, cuidUserId, tokenType);

        /* Is this token temporarily lost? */
        } else if(( q == 3 ) && (transition_allowed(token_ui_state, 3))) {
            bool revocation_errors = false;
            PR_snprintf((char *)msg, 256,
              "'%s' marked token temporarily lost", userid);
            RA::tdb_activity(rq->connection->client_ip, cuid, "do_token", "initiated",
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

                        CERTCertificate **attr_certificate= get_certificates( e );
                        statusNum = certEnroll->
                                    RevokeCertificate (
                                                       true,
                                                       attr_certificate[0],
                                                       revokeReason,
                                                       serial,
                                                       connid,
                                                       statusString );
                        if (attr_certificate[0] != NULL)
                            CERT_DestroyCertificate(attr_certificate[0]);

                        if (statusNum != 0) { // revocation errors
                            if( strcmp( revokeReason, "6" ) == 0 ) {
                                PR_snprintf((char *)msg, 256, "Errors in marking certificate on_hold '%s' : %s", attr_cn, statusString);
                                RA::tdb_activity(rq->connection->client_ip, cuid, "do_token", "failure", msg, cuidUserId, attr_tokenType);

                                RA::Audit(EV_CONFIG_TOKEN, AUDIT_MSG_CERT_STATUS_CHANGE, userid,
                                  "Failure", "revoked_on_hold", serial, connid, statusString);
                            } else {
                                PR_snprintf((char *)msg, 256, "Errors in revoking certificate '%s' : %s", attr_cn, statusString);
                                RA::tdb_activity(rq->connection->client_ip, cuid, "do_token", "failure", msg, cuidUserId, attr_tokenType);

                                RA::Audit(EV_CONFIG_TOKEN, AUDIT_MSG_CERT_STATUS_CHANGE, userid,
                                  "Failure", "revoke", serial, connid, statusString);
                            }
                            revocation_errors = true;
                        } else {
                            // update certificate status
                            if( strcmp( revokeReason, "6" ) == 0 ) {
                                PR_snprintf((char *)msg, 256, "Certificate '%s' is marked as revoked_on_hold", attr_cn);
                                RA::tdb_activity(rq->connection->client_ip, cuid, "do_token", "success", msg, cuidUserId, attr_tokenType);
                                update_cert_status( attr_cn, "revoked_on_hold" );

                                RA::Audit(EV_CONFIG_TOKEN, AUDIT_MSG_CERT_STATUS_CHANGE, userid,
                                  "Success", "revoked_on_hold", serial, connid, "");
                            } else {
                                PR_snprintf((char *)msg, 256, "Certificate '%s' is marked as revoked", attr_cn);
                                RA::tdb_activity(rq->connection->client_ip, cuid, "do_token", "success", msg, cuidUserId, attr_tokenType);
                                update_cert_status( attr_cn, "revoked" );

                                RA::Audit(EV_CONFIG_TOKEN, AUDIT_MSG_CERT_STATUS_CHANGE, userid,
                                  "Success", "revoke", serial, connid, "");
                            }
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

            PR_snprintf(oString, 512, "token_id;;%s", cuid);
            PR_snprintf(pString, 512, "tokenStatus;;lost+tokenReason;;onHold");
            if (revocation_errors) {
                RA::Audit(EV_CONFIG_TOKEN, AUDIT_MSG_CONFIG, userid, "Agent", "Failure", oString, pString, "token marked temporarily lost failed, failed to revoke certificates");
                
                PR_snprintf((char *)msg, 256, "Failed to revoke certificates");
                RA::tdb_activity(rq->connection->client_ip, cuid, "do_token", "failure",
                     msg, cuidUserId, tokenType);

                error_out("Errors in revoking certificates.", "Errors in revoking certificates.");
                do_free(buf);
                do_strfree(uri);
                do_strfree(query);
                return DONE;
            }

            rc = update_token_status_reason( cuidUserId, cuid,
                                             "lost", "onHold" );
            if( rc == -1 ) {
                RA::Audit(EV_CONFIG_TOKEN, AUDIT_MSG_CONFIG, userid, "Agent", "Failure", oString, pString, "token marked temporarily lost, rc=-1");

                PR_snprintf((char *)msg, 256, "Failed to update token status as temporarily lost");
                RA::tdb_activity(rq->connection->client_ip, cuid, "do_token", "failure",
                     msg, cuidUserId, tokenType);

                PR_snprintf( injection, MAX_INJECTION_SIZE,
                             "%s%s%s%s", JS_START,
                             "var error = \"Failed to create LDAPMod: ",
                             "\";\n", JS_STOP );

                buf = getData( errorTemplate, injection );

                ap_log_error( ( const char * ) "tus", __LINE__,
                              APLOG_MODULE_INDEX, APLOG_ERR, 0, rq->server,
                              ( const char * ) "Failed to create LDAPMod" );

                ( void ) ap_rwrite( ( const void * ) buf,
                                    PL_strlen( buf ), rq );
                do_free(buf);
                do_strfree(uri);
                do_strfree(query);

                return DONE;
            } else if( rc > 0 ) {
                RA::Audit(EV_CONFIG_TOKEN, AUDIT_MSG_CONFIG, userid, "Agent", "Failure", oString, pString, "token marked temporarily lost, rc>0");

                PR_snprintf((char *)msg, 256, "Failed to update token status as temporarily lost");
                RA::tdb_activity(rq->connection->client_ip, cuid, "do_token", "failure",
                     msg, cuidUserId, tokenType);

                PR_snprintf( injection, MAX_INJECTION_SIZE,
                             "%s%s%s%s%s", JS_START,
                             "var error = \"LDAP mod error: ",
                             ldap_err2string( rc ),
                             "\";\n", JS_STOP );

                buf = getData( errorTemplate, injection );

                ap_log_error( ( const char * ) "tus", __LINE__,
                              APLOG_MODULE_INDEX, APLOG_ERR, 0, rq->server,
                              ( const char * ) "LDAP error: %s",
                              ldap_err2string( rc ) );

                ( void ) ap_rwrite( ( const void * ) buf,
                                    PL_strlen( buf ), rq );

                do_free(buf);
                do_strfree(uri);
                do_strfree(query);

                return DONE;
            }
            RA::Audit(EV_CONFIG_TOKEN, AUDIT_MSG_CONFIG, userid, "Agent", "Success", oString, pString, "token marked temporarily lost");
            PR_snprintf((char *)msg, 256, "Token marked temporarily lost");
            RA::tdb_activity(rq->connection->client_ip, cuid, "do_token", "success",
                 msg, cuidUserId, tokenType);

        /* Is this temporarily lost token found? */
        } else if(( q == 4 ) && ( transition_allowed(token_ui_state, 4) )) {

            PR_snprintf((char *)msg, 256,
              "'%s' marked lost token found", userid);
            RA::tdb_activity(rq->connection->client_ip, cuid, "do_token", "initiated",
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

                        CERTCertificate **attr_certificate= get_certificates( e );
                         int statusNum = certEnroll->
                                          RevokeCertificate(
                                                     false,
                                                     attr_certificate[0],
                                                     "",
                                                     serial,
                                                     connid,
                                                     statusString );
                        if (attr_certificate[0] != NULL)
                            CERT_DestroyCertificate(attr_certificate[0]);

                        if (statusNum == 0) {
                            PR_snprintf((char *)msg, 256, "Certificate '%s' is marked as active", attr_cn);
                            RA::tdb_activity(rq->connection->client_ip, cuid, "do_token", "success", msg, cuidUserId, attr_tokenType);
                            update_cert_status( attr_cn, "active" );

                            RA::Audit(EV_CONFIG_TOKEN, AUDIT_MSG_CERT_STATUS_CHANGE, userid,
                              "Success", "unrevoke", serial, connid, "");
                        } else {
                            PR_snprintf((char *)msg, 256, "Errors in unrevoking Certificate '%s': %s", attr_cn, statusString);
                            RA::tdb_activity(rq->connection->client_ip, cuid, "do_token", "failure", msg, cuidUserId, attr_tokenType);

                            RA::Audit(EV_CONFIG_TOKEN, AUDIT_MSG_CERT_STATUS_CHANGE, userid,
                              "Failure", "unrevoke", serial, connid, statusString);
                        }
                        
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
            PR_snprintf(oString, 512, "token_id;;%s", cuid);
            PR_snprintf(pString, 512, "tokenStatus;;active+tokenReason;;null");

            if( rc == -1 ) {
                RA::Audit(EV_CONFIG_TOKEN, AUDIT_MSG_CONFIG, userid, "Agent", "Failure", oString, pString, "lost token marked found, rc=-1");
                PR_snprintf((char *)msg, 256, "Failed to update lost token status as found");
                RA::tdb_activity(rq->connection->client_ip, cuid, "do_token", "failure",
                     msg, cuidUserId, tokenType);

                error_out("Failed to create LDAPMod: ", "Failed to create LDAPMod");
                do_free(buf);
                do_strfree(uri);
                do_strfree(query);

                return DONE;
            } else if( rc > 0 ) {
                RA::Audit(EV_CONFIG_TOKEN, AUDIT_MSG_CONFIG, userid, "Agent", "Failure", oString, pString, "lost token marked found, rc>0");
                PR_snprintf((char *)msg, 256, "Failed to update lost token status as found");
                RA::tdb_activity(rq->connection->client_ip, cuid, "do_token", "failure",
                     msg, cuidUserId, tokenType);

                ldap_error_out("LDAP mod error: ", "LDAP error: %s");
                do_free(buf);
                do_strfree(uri);
                do_strfree(query);

                return DONE;
            }
            RA::Audit(EV_CONFIG_TOKEN, AUDIT_MSG_CONFIG, userid, "Agent", "Success", oString, pString, "lost token marked found");
            PR_snprintf((char *)msg, 256, "Lost token marked found");
            RA::tdb_activity(rq->connection->client_ip, cuid, "do_token", "success",
                 msg, cuidUserId, tokenType);

        /* Does this temporarily lost token become permanently lost? */
        } else if ( (q == 5) && (transition_allowed(token_ui_state, 5)) ) {

            PR_snprintf((char *)msg, 256,
              "'%s' marked lost token permanently lost", userid);
            RA::tdb_activity(rq->connection->client_ip, cuid, "do_token", "initiated",
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

                        CERTCertificate **attr_certificate= get_certificates( e );
                        int statusNum = 0;
                        if(( strcmp( attr_status, "revoked_on_hold" ) == 0 ) && (strcmp(revokeReason, "6" ) != 0)) {
                            statusNum = certEnroll->
                                        RevokeCertificate(
                                                     false,
                                                     attr_certificate[0],
                                                     "",
                                                     serial,
                                                     connid,
                                                     statusString );
                            if (statusNum == 0) {
                                PR_snprintf((char *)msg, 256, "Certificate '%s' is marked as active", attr_cn);
                                RA::tdb_activity(rq->connection->client_ip, cuid, "do_token", "initiated", msg, cuidUserId, attr_tokenType);
                                update_cert_status( attr_cn, "active" );

                                RA::Audit(EV_CONFIG_TOKEN, AUDIT_MSG_CERT_STATUS_CHANGE, userid,
                                  "Success", "unrevoke", serial, connid, "");

                                do_free(statusString);

                                statusNum = certEnroll->
                                        RevokeCertificate(
                                                     true,
                                                     attr_certificate[0],
                                                     revokeReason,
                                                     serial,
                                                     connid,
                                                     statusString );
                                if (attr_certificate[0] != NULL)
                                    CERT_DestroyCertificate(attr_certificate[0]);

                                if (statusNum == 0) {
                                    PR_snprintf((char *)msg, 256, "Certificate '%s' is marked as revoked", attr_cn);
                                    RA::tdb_activity(rq->connection->client_ip, cuid, "do_token", "success", msg, cuidUserId, attr_tokenType);
                                    update_cert_status( attr_cn, "revoked" );

                                    RA::Audit(EV_CONFIG_TOKEN, AUDIT_MSG_CERT_STATUS_CHANGE, userid,
                                      "Success", "revoke", serial, connid, "");
                                } else {
                                    PR_snprintf((char *)msg, 256, "Errors in revoking Certificate '%s' : %s", attr_cn, statusString);
                                    RA::tdb_activity(rq->connection->client_ip, cuid, "do_token", "failure", msg, cuidUserId, attr_tokenType);

                                    RA::Audit(EV_CONFIG_TOKEN, AUDIT_MSG_CERT_STATUS_CHANGE, userid,
                                      "Failure", "revoke", serial, connid, statusString);
                                }
                            } else {
                                PR_snprintf((char *)msg, 256, "Errors in unrevoking Certificate '%s' : %s", attr_cn, statusString);
                                RA::tdb_activity(rq->connection->client_ip, cuid, "do_token", "failure", msg, cuidUserId, attr_tokenType);

                                RA::Audit(EV_CONFIG_TOKEN, AUDIT_MSG_CERT_STATUS_CHANGE, userid,
                                  "Failure", "unrevoke", serial, connid, statusString);
                            }

                            do_free(statusString);
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

            PR_snprintf(oString, 512, "token_id;;%s", cuid);
            PR_snprintf(pString, 512, "tokenStatus;;lost+tokenReason;;keyCompromise");
            RA::Audit(EV_CONFIG_TOKEN, AUDIT_MSG_CONFIG, userid, "Agent", "Success", oString, pString, "lost token marked permanently lost");

            PR_snprintf((char *)msg, 256, "Lost token marked permanently lost");
            RA::tdb_activity(rq->connection->client_ip, cuid, "do_token", "success",
                     msg, cuidUserId, tokenType);
        } else {
            // invalid operation or transition
            error_out("Transition or operation not allowed", "Transition or operation not allowed");
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);
            return DONE;
        }
        
        tokendbDebug( "do_token: rc = 0\n" );

        PR_snprintf( injection, injection_size,
                     "%s%s%d%s%s%s%s%s%s%s", JS_START,
                     "var rc = \"", rc, "\";\n",
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid,
                     "\";\n" );

        add_allowed_token_transitions(token_ui_state, injection, injection_size);
        add_authorization_data(userid, is_admin, is_operator, is_agent, &injection, &injection_size, fixed_injection);

        safe_injection_strcat(&injection, &injection_size , JS_STOP, fixed_injection );

        buf = getData( doTokenTemplate, injection );
/* currently not used - alee
    } else if( ( PL_strstr( query, "op=revoke" ) ) ) {
        tokendbDebug("authorization\n");

        if( ! is_agent ) {
            RA::Audit(EV_AUTHZ_FAIL, AUDIT_MSG_AUTHZ, userid, "revoke", "Failure", "Tokendb user authorization");
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);
            return DONE;
        }

        RA::Audit(EV_AUTHZ_SUCCESS, AUDIT_MSG_AUTHZ, userid, "revoke", "Success", "Tokendb user authorization");

        PR_snprintf( injection, injection_size,
                     "%s%s%s%s%s%s%s", JS_START,
                    "var uriBase = \"", uri, "\";\n",
                    "var userid = \"", userid,
                    "\";\n" );
        add_authorization_data(userid, is_admin, is_operator, is_agent, &injection, &injection_size, fixed_injection);
        safe_injection_strcat(&injection, &injection_size , JS_STOP, fixed_injection );

        buf = getData( revokeTemplate, injection );
*/
    } else if( ( PL_strstr( query, "op=search_activity_admin" ) ) ) {
        tokendbDebug( "authorization\n" );

        if (! is_admin) {
            RA::Audit(EV_AUTHZ_FAIL, AUDIT_MSG_AUTHZ, userid, "search_activity_admin", "Failure", "Tokendb user authorization");
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);
            return DONE;
        } 

        RA::Audit(EV_AUTHZ_SUCCESS, AUDIT_MSG_AUTHZ, userid, "search_activity_admin", "Success", "Tokendb user authorization");

        PR_snprintf( injection, injection_size,
                     "%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid,
                     "\";\n" );

        add_authorization_data(userid, is_admin, is_operator, is_agent, &injection, &injection_size, fixed_injection);
        safe_injection_strcat(&injection, &injection_size , JS_STOP, fixed_injection );

        buf = getData( searchActivityAdminTemplate, injection );
    } else if( ( PL_strstr( query, "op=search_activity" ) ) ) {
        tokendbDebug( "authorization\n" );

        if ((! is_agent) && (! is_operator)) {
            RA::Audit(EV_AUTHZ_FAIL, AUDIT_MSG_AUTHZ, userid, "search_activity", "Failure", "Tokendb user authorization");
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);
            return DONE;
        } 
        RA::Audit(EV_AUTHZ_SUCCESS, AUDIT_MSG_AUTHZ, userid, "search_activity", "Success", "Tokendb user authorization");

        PR_snprintf( injection, injection_size,
                     "%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid,
                     "\";\n" );

        topLevel = get_field(query, "top=", SHORT_LEN);
        if ((topLevel != NULL) && (PL_strstr(topLevel, "operator"))) {
            safe_injection_strcat(&injection, &injection_size , "var topLevel = \"operator\";\n", fixed_injection );
        }
        do_free(topLevel);
        add_authorization_data(userid, is_admin, is_operator, is_agent, &injection, &injection_size, fixed_injection);
        safe_injection_strcat(&injection, &injection_size , JS_STOP, fixed_injection );

        buf = getData( searchActivityTemplate, injection );
    } else if( ( PL_strstr( query, "op=search_admin" ) ) || 
               ( PL_strstr( query, "op=search_users"  ) )) { 
        tokendbDebug( "authorization\n" );

        if( ! is_admin ) {
            RA::Audit(EV_AUTHZ_FAIL, AUDIT_MSG_AUTHZ, userid, "search_admin,search_users", "Failure", "Tokendb user authorization");
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);

            return DONE;
        }
        RA::Audit(EV_AUTHZ_SUCCESS, AUDIT_MSG_AUTHZ, userid, "search_admin,search_users", "Success", "Tokendb user authorization");

        PR_snprintf( injection, injection_size,
                     "%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid,
                     "\";\n" );
        add_authorization_data(userid, is_admin, is_operator, is_agent, &injection, &injection_size, fixed_injection);
        safe_injection_strcat(&injection, &injection_size , JS_STOP, fixed_injection );

        if ( PL_strstr( query, "op=search_admin" ) ) {
            buf = getData( searchAdminTemplate, injection );
        } else if ( PL_strstr( query, "op=search_users" ) ) {
            buf = getData( searchUserTemplate, injection );
        }
    } else if ( PL_strstr( query, "op=search_certificate" ) )  {
        tokendbDebug( "authorization\n" );
        if ((! is_agent) && (! is_operator)) { 
            RA::Audit(EV_AUTHZ_FAIL, AUDIT_MSG_AUTHZ, userid, "search_certificate", "Failure", "Tokendb user authorization");
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);
            return DONE;
        }
        RA::Audit(EV_AUTHZ_SUCCESS, AUDIT_MSG_AUTHZ, userid, "search_certificate", "Success", "Tokendb user authorization");

        PR_snprintf( injection, injection_size,
                     "%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid,
                     "\";\n");

        topLevel = get_field(query, "top=", SHORT_LEN);
        if ((topLevel != NULL) && (PL_strstr(topLevel, "operator"))) {
            safe_injection_strcat(&injection, &injection_size , "var topLevel = \"operator\";\n", fixed_injection );
        }
        do_free(topLevel);
        add_authorization_data(userid, is_admin, is_operator, is_agent, &injection, &injection_size, fixed_injection);
        safe_injection_strcat(&injection, &injection_size , JS_STOP, fixed_injection );

        buf = getData( searchCertificateTemplate, injection );
    } else if( ( PL_strstr( query, "op=search" ) ) ) {
        tokendbDebug( "authorization for op=search\n" );
        if ((! is_agent) && (! is_operator)) {
            RA::Audit(EV_AUTHZ_FAIL, AUDIT_MSG_AUTHZ, userid, "search", "Failure", "Tokendb user authorization");
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);
            return DONE;
        }
        RA::Audit(EV_AUTHZ_SUCCESS, AUDIT_MSG_AUTHZ, userid, "search", "Success", "Tokendb user authorization");

        PR_snprintf( injection, injection_size,
                     "%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid,
                     "\";\n");
        
        topLevel = get_field(query, "top=", SHORT_LEN);
        if ((topLevel != NULL) && (PL_strstr(topLevel, "operator"))) {
            safe_injection_strcat(&injection, &injection_size ,"var topLevel = \"operator\";\n" , fixed_injection );
        }
        do_free(topLevel);
        add_authorization_data(userid, is_admin, is_operator, is_agent, &injection, &injection_size, fixed_injection);
        safe_injection_strcat(&injection, &injection_size ,JS_STOP, fixed_injection );

        buf = getData( searchTemplate, injection );
    } else if( ( PL_strstr( query, "op=new" ) ) ) {
        tokendbDebug( "authorization\n" );
        if( ! is_admin ) {
            RA::Audit(EV_AUTHZ_FAIL, AUDIT_MSG_AUTHZ, userid, "new", "Failure", "Tokendb user authorization");
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);
            return DONE;

        }
        RA::Audit(EV_AUTHZ_SUCCESS, AUDIT_MSG_AUTHZ, userid, "new", "Success", "Tokendb user authorization");

        PR_snprintf( injection, injection_size,
                     "%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n", 
                     "var userid = \"", userid,
                     "\";\n" );
        add_authorization_data(userid, is_admin, is_operator, is_agent, &injection,&injection_size, fixed_injection);
        safe_injection_strcat(&injection, &injection_size ,JS_STOP , fixed_injection );

        buf = getData( newTemplate,injection );
    } else if ( ( PL_strstr( query, "op=add_user" ) ) ) {
        tokendbDebug( "authorization for add_user\n" );
        if( ! is_admin ) {
            RA::Audit(EV_AUTHZ_FAIL, AUDIT_MSG_AUTHZ, userid, "add_user", "Failure", "Tokendb user authorization");
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);

            return DONE;
        }
        RA::Audit(EV_AUTHZ_SUCCESS, AUDIT_MSG_AUTHZ, userid, "add_user", "Success", "Tokendb user authorization");

        PR_snprintf( injection, injection_size,
                     "%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid,
                     "\";\n");
        add_authorization_data(userid, is_admin, is_operator, is_agent, &injection, &injection_size, fixed_injection);
        safe_injection_strcat(&injection, &injection_size ,JS_STOP , fixed_injection );

        buf = getData( newUserTemplate,injection );

    } else if ( ( PL_strstr( query, "op=confirm_delete_config" ) ) ) {
        tokendbDebug( "authorization for confirm_delete_config\n" );
        if( ! is_admin ) {
            RA::Audit(EV_AUTHZ_FAIL, AUDIT_MSG_AUTHZ, userid, "confirm_delete_config", "Failure", "Tokendb user authorization");
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);

            return DONE;
        }
        RA::Audit(EV_AUTHZ_SUCCESS, AUDIT_MSG_AUTHZ, userid, "confirm_delete_config", "Success", "Tokendb user authorization");

        char *ptype = NULL;
        char *pname = NULL;
        char *ptimestamp = NULL;
        char *pvalues = NULL;
        char *large_injection = NULL;
        char *pstate = NULL;
        char *disp_conf_type = NULL;

        ptype = get_post_field(post, "ptype", SHORT_LEN);
        pname = get_post_field(post, "pname", SHORT_LEN);
        pstate = get_post_field(post, "pstate", SHORT_LEN);
        ptimestamp = get_post_field(post, "ptimestamp", SHORT_LEN);
        pvalues = get_post_field_s(post, "pvalues");

        PR_snprintf( ( char * ) configname, 256, "target.%s.displayname", ptype ); 
        disp_conf_type = (char *) RA::GetConfigStore()->GetConfigAsString( configname );

        int large_injection_size = PL_strlen(pvalues) + MAX_INJECTION_SIZE; 
        large_injection = (char *) PR_Malloc(large_injection_size);
        PR_snprintf( large_injection, large_injection_size,
                     "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid, "\";\n",
                     "var conf_type = \"", ptype, "\";\n",
                     "var disp_conf_type = \"", disp_conf_type, "\";\n",
                     "var conf_name = \"", pname, "\";\n",
                     "var conf_state = \"", pstate,  "\";\n",
                     "var conf_tstamp = \"", ptimestamp,  "\";\n",
                     "var agent_must_approve = \"", agent_must_approve(ptype)? "true": "false", "\";\n",
                     "var conf_values= \"", pvalues, "\";\n");

        add_authorization_data(userid, is_admin, is_operator, is_agent, &large_injection, &large_injection_size, NULL); 

        safe_injection_strcat(&large_injection, &large_injection_size ,JS_STOP , NULL); 

        buf = getData( confirmDeleteConfigTemplate, large_injection );

        do_free(ptype);
        do_free(pname);
        do_free(ptimestamp);
        do_free(pvalues);
        do_free(pstate);
        do_free(large_injection);
    } else if( ( PL_strstr( query, "op=delete_config_parameter" ) ) ) {
        tokendbDebug( "authorization for op=delete_config_parameter\n" );
        if (! is_admin) {
            RA::Audit(EV_AUTHZ_FAIL, AUDIT_MSG_AUTHZ, userid, "delete_config_parameter", "Failure", "Tokendb user authorization");
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);
            return DONE;
        }
        RA::Audit(EV_AUTHZ_SUCCESS, AUDIT_MSG_AUTHZ, userid, "delete_config_parameter", "Success", "Tokendb user authorization");

        char *ptype = NULL;
        char *pname = NULL;
        char *ptimestamp = NULL;

        char *key_values = NULL;
        char *new_value = NULL;
        char *conf_list = NULL;
        ConfigStore *store = NULL;
        int return_done = 0;
        int status=0;

        ptype = get_post_field(post, "ptype", SHORT_LEN);
        pname = get_post_field(post, "pname", SHORT_LEN);
        ptimestamp = get_post_field(post, "ptimestamp", SHORT_LEN);
        
        if ((ptype == NULL) || (pname == NULL) || (PL_strlen(pname)==0) || (PL_strlen(ptype)==0)) {
            error_out("Invalid Invocation: Parameter type or name is NULL or empty", "Parameter type or name is NULL or empty");
            return_done = 1;
            goto delete_config_parameter_cleanup;
        }

        if (!config_param_exists(ptype, pname)) {
            error_out("Parameter does not exist", "Parameter does not exist");
            return_done = 1;
            goto delete_config_parameter_cleanup;
        }

        status =  set_config_state_timestamp(ptype, pname, ptimestamp, "Writing", "Admin", false, userid);
        if (status != 0) {
            error_out("The data you are viewing has changed.  Please reload the data and try your edits again.", "Data Out of Date");
            return_done=1;
            goto delete_config_parameter_cleanup;
        }

        store = get_pattern_substore(ptype, pname);

        key_values = (char *) store->GetOrderedList();
        if (PL_strlen(key_values) > 0)  parse_and_apply_changes(userid, ptype, pname, "DELETE", key_values);

        // remove from the list for that config type
        PR_snprintf( ( char * ) configname, 256, "target.%s.list", ptype );
        conf_list = (char *) RA::GetConfigStore()->GetConfigAsString( configname );
        new_value = RA::remove_from_comma_list((const char*) pname, (char *)conf_list);
        RA::GetConfigStore()->Add(configname, new_value);

        // remove state and timestamp variables
        remove_config_state_timestamp(ptype, pname);

        tokendbDebug("Committing delete ..");
        char error_msg[512];
        status = RA::GetConfigStore()->Commit(true, error_msg, 512);
        if (status != 0) { 
            tokendbDebug(error_msg);
        }

        PR_snprintf(oString, 512, "%s", pname);
        PR_snprintf(pLongString, 4096, "%s;;%s", configname, new_value);
        RA::Audit(EV_CONFIG, AUDIT_MSG_CONFIG, userid, "Admin", "Success", oString, pLongString, "config item deleted");

        PR_snprintf( injection, injection_size,
                     "%s%s%s%s%s%s%s%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid, "\";\n",
                     "var flash = \"Configuration changes have been saved.\";\n",
                     "var agent_target_list = \"",
                      RA::GetConfigStore()->GetConfigAsString("target.agent_approve.list", ""), "\";\n",
                     "var target_list = \"", RA::GetConfigStore()->GetConfigAsString("target.configure.list", ""), "\";\n");

        add_authorization_data(userid, is_admin, is_operator, is_agent, &injection, &injection_size, fixed_injection);
        safe_injection_strcat(&injection, &injection_size ,JS_STOP , fixed_injection );

        buf = getData( indexTemplate, injection );
    delete_config_parameter_cleanup:
        do_free(ptype);
        do_free(pname);
        do_free(key_values);
        do_free(new_value);
        do_free(ptimestamp);

        if (store != NULL) {
            delete store;
            store = NULL;
        }
        if (return_done == 1) {
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);
            return DONE;
        }

    } else if( ( PL_strstr( query, "op=add_config_parameter" ) ) ) {
        tokendbDebug( "authorization for op=add_config_parameter\n" );
        if (! is_admin) {
            RA::Audit(EV_AUTHZ_FAIL, AUDIT_MSG_AUTHZ, userid, "add_config_parameter", "Failure", "Tokendb user authorization");
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);
            return DONE;
        }
        RA::Audit(EV_AUTHZ_SUCCESS, AUDIT_MSG_AUTHZ, userid, "add_config_parameter", "Success", "Tokendb user authorization");

        char *ptype = NULL;
        char *pname = NULL;

        ConfigStore *store = NULL;
        char *pattern = NULL;
        char *disp_conf_type = NULL;
        int return_done =0;

        ptype = get_post_field(post, "ptype", SHORT_LEN);
        pname = get_post_field(post, "pname", SHORT_LEN);
        
        if ((ptype == NULL) || (pname == NULL) || (PL_strlen(pname)==0) || (PL_strlen(ptype)==0)) {
            error_out("Invalid Invocation: Parameter type or name is NULL or empty", "Parameter type or name is NULL or empty");
            return_done = 1;
            goto add_config_parameter_cleanup;
        }

        if (config_param_exists(ptype, pname)) {
            error_out("Parameter already exists.  Use edit instead.", "Parameter already exists");
            return_done = 1;
            goto add_config_parameter_cleanup;
        }

        /* extra check (just in case) */
        store = get_pattern_substore(ptype, pname);

        if ((store != NULL) && (store->Size() != 0)) {
            error_out("Config entries already exist for this parameter.  This is an error. Manually delete them first.", "Setup Error");
            return_done = 1;
            goto add_config_parameter_cleanup;
        }
 
        PR_snprintf( ( char * ) configname, 256, "target.%s.pattern", ptype );
        pattern = (char *) RA::GetConfigStore()->GetConfigAsString( configname );

        PR_snprintf( ( char * ) configname, 256, "target.%s.displayname", ptype );
        disp_conf_type = (char *) RA::GetConfigStore()->GetConfigAsString( configname );

        PR_snprintf( injection, injection_size,
                     "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid, "\";\n", 
                     "var conf_type = \"", ptype, "\";\n",
                     "var disp_conf_type = \"", disp_conf_type, "\";\n",
                     "var conf_name = \"", pname, "\";\n",
                     "var conf_pattern = \"", pattern, "\";\n");

        add_authorization_data(userid, is_admin, is_operator, is_agent, &injection, &injection_size, fixed_injection); //needed?
        safe_injection_strcat(&injection, &injection_size ,JS_STOP , fixed_injection );

        buf = getData( addConfigTemplate, injection );
    add_config_parameter_cleanup:
        do_free(ptype);
        do_free(pname);

        if (store != NULL) {
            delete store;
            store = NULL;
        }
        if (return_done == 1) {
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);
            return DONE;
        }
    } else if( ( PL_strstr( query, "op=agent_change_config_state" ) ) ) {
        tokendbDebug( "authorization for op=agent_change_config_state\n" );
        if (! is_agent) {
            RA::Audit(EV_AUTHZ_FAIL, AUDIT_MSG_AUTHZ, userid, "agent_change_config_state", "Failure", "Tokendb user authorization");
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);
            return DONE;
        }
        RA::Audit(EV_AUTHZ_SUCCESS, AUDIT_MSG_AUTHZ, userid, "agent_change_config_state", "Success", "Tokendb user authorization");

        char *ptype = NULL;
        char *pname = NULL;
        char *ptimestamp = NULL;
        char *choice = NULL;

        char pstate[128]="";
        int return_done =0;
        int set_status = 0;

        ptype = get_post_field(post, "ptype", SHORT_LEN);
        pname = get_post_field(post, "pname", SHORT_LEN);
        ptimestamp = get_post_field(post, "ptimestamp", SHORT_LEN);
        choice = get_post_field(post, "choice", SHORT_LEN);

        if ((ptype == NULL) || (pname == NULL) || (ptimestamp == NULL) || (choice == NULL)) {
            error_out("Invalid Invocation: A required parameter is NULL", "Invalid Invocation: A required parameter is NULL");
            return_done=1;
            goto agent_change_config_state_cleanup;
        }

        // check if agent has permission to see this config parameter
        if (!agent_must_approve(ptype)) {
            error_out("Invalid Invocation: Agent is not permitted to change the state of this configuration item", 
                "Invalid Invocation: Agent is not permitted to change the state of this configuration item");
            return_done=1;
            goto agent_change_config_state_cleanup;
        }

        if ((PL_strcmp(choice, "Disable") == 0) || (PL_strcmp(choice, "Reject") == 0)) {
            PR_snprintf(pstate, 128, "Disabled");
        } else {
            PR_snprintf(pstate, 128, "Enabled");
        }
 
        set_status = set_config_state_timestamp(ptype, pname, ptimestamp, pstate, "Agent", false, userid);

        if (set_status != 0) {
            error_out("The data you are viewing has been changed by an administrator and is out of date.  Please reload the data and try again.", 
                "Data Out of Date");
            return_done=1;
            goto agent_change_config_state_cleanup;
        }

        char error_msg[512];
        status = RA::GetConfigStore()->Commit(false, error_msg, 512);
        if (status != 0) { 
            tokendbDebug(error_msg);
        }

        PR_snprintf( injection, injection_size,
                     "%s%s%s%s%s%s%s%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid, "\";\n",
                     "var flash = \"Configuration changes have been saved.\";\n",  
                     "var agent_target_list = \"",
                     RA::GetConfigStore()->GetConfigAsString("target.agent_approve.list", ""), "\";\n",
                     "var target_list = \"", RA::GetConfigStore()->GetConfigAsString("target.configure.list", ""), "\";\n");

        add_authorization_data(userid, is_admin, is_operator, is_agent, &injection, &injection_size, fixed_injection); 
        safe_injection_strcat(&injection, &injection_size ,JS_STOP , fixed_injection );

        buf = getData( indexTemplate, injection );
    agent_change_config_state_cleanup:
        do_free(ptype);
        do_free(pname);
        do_strfree(ptimestamp);
        do_strfree(choice);
 
        if (return_done == 1) {
             do_free(buf);
             do_strfree(uri);
             do_strfree(query);
             return DONE;
        }

    } else if( ( PL_strstr( query, "op=agent_view_config" ) ) ) {
        tokendbDebug( "authorization for op=agent_view_config\n" );
        if (! is_agent) {
            RA::Audit(EV_AUTHZ_FAIL, AUDIT_MSG_AUTHZ, userid, "agent_view_config", "Failure", "Tokendb user authorization");
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);
            return DONE;
        }
        RA::Audit(EV_AUTHZ_SUCCESS, AUDIT_MSG_AUTHZ, userid, "agent_view_config", "Success", "Tokendb user authorization");

        char *ptype = NULL;
        char *pname = NULL;
        char *pstate = NULL;
        char *ptimestamp = NULL;
        char *disp_conf_type = NULL;
        int return_done = 0;

        char *key_values = NULL;
        char *large_injection = NULL;
        int  large_injection_size = 0;
        char *escaped = NULL;
        ConfigStore *store = NULL;

        ptype = get_post_field(post, "ptype", SHORT_LEN);
        pname = get_post_field(post, "pname", SHORT_LEN);
        
        if ((ptype == NULL) || (pname == NULL)) {
            error_out("Invalid Invocation: Parameter type or name is NULL", "Invalid Invocation: Parameter type or name is NULL");
            return_done =1;
            goto agent_view_config_cleanup;
        }

        // check if agent has permission to see this config parameter
        if (! agent_must_approve(ptype)) {
            error_out("Invalid Invocation: Agent is not permitted to view this configuration item", 
                "Invalid Invocation: Agent is not permitted to view this configuration item");
            return_done =1;
            goto agent_view_config_cleanup;
        }

        get_config_state_timestamp(ptype, pname, &pstate, &ptimestamp);

        store = get_pattern_substore(ptype, pname);

        if (store == NULL) {
            error_out("Setup Error: Pattern Substore is NULL", "Pattern Substore is NULL");
            return_done =1;
            goto agent_view_config_cleanup;
        }

        key_values = (char *) store->GetOrderedList();
        escaped = escapeSpecialChars(key_values);
        tokendbDebug( "got ordered list");

        PR_snprintf( ( char * ) configname, 256, "target.%s.displayname", ptype );
        disp_conf_type = (char *) RA::GetConfigStore()->GetConfigAsString( configname );

        large_injection_size = PL_strlen(key_values) + MAX_INJECTION_SIZE; 
        large_injection = (char *) PR_Malloc(large_injection_size);
        PR_snprintf( large_injection, large_injection_size,
                     "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid, "\";\n", 
                     "var conf_type = \"", ptype, "\";\n",
                     "var disp_conf_type = \"", disp_conf_type, "\";\n",
                     "var conf_name = \"", pname, "\";\n",
                     "var conf_state = \"", pstate,  "\";\n",
                     "var conf_tstamp = \"", ptimestamp,  "\";\n",
                     "var conf_values= \"", escaped, "\";\n");

        add_authorization_data(userid, is_admin, is_operator, is_agent, &large_injection, &large_injection_size, NULL); //needed?
        safe_injection_strcat(&large_injection, &large_injection_size ,JS_STOP , NULL );

        buf = getData( agentViewConfigTemplate, large_injection );
    agent_view_config_cleanup:
        do_free(ptype);
        do_free(pname);
        do_free(pstate);
        do_free(ptimestamp);
        do_free(key_values);
        do_free(large_injection);
        do_strfree(escaped);

        if (store != NULL) {
            delete store;
            store = NULL;
        }

        if (return_done != 0 ) {
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);
            return DONE;
        }
    } else if( ( PL_strstr( query, "op=edit_config_parameter" ) ) ) {
        tokendbDebug( "authorization for op=edit_config_parameter\n" );
        if (! is_admin) {
            RA::Audit(EV_AUTHZ_FAIL, AUDIT_MSG_AUTHZ, userid, "edit_config_parameter", "Failure", "Tokendb user authorization");
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);
            return DONE;
        }
        RA::Audit(EV_AUTHZ_SUCCESS, AUDIT_MSG_AUTHZ, userid, "edit_config_parameter", "Success", "Tokendb user authorization");

        char *ptype = NULL;
        char *pname = NULL;

        char *pstate = NULL;
        char *ptimestamp = NULL;
        char *key_values = NULL;
        char *escaped = NULL;
        ConfigStore *store = NULL;
        char *large_injection = NULL;
        int  large_injection_size = 0;
        char *pattern = NULL;
        char *disp_conf_type = NULL;
        int return_done = 0;
        
        ptype = get_post_field(post, "ptype", SHORT_LEN);
        pname = get_post_field(post, "pname", SHORT_LEN);
        
        if ((ptype == NULL) || (pname == NULL)) {
            error_out("Invalid Invocation: Parameter type or name is NULL", "Invalid Invocation: Parameter type or name is NULL");
            return_done =1;
            goto edit_config_parameter_cleanup;
        }

        get_config_state_timestamp(ptype, pname, &pstate, &ptimestamp);
        tokendbDebug(pstate);
        tokendbDebug(ptimestamp);

        store = get_pattern_substore(ptype, pname);

        if (store == NULL) {
            error_out("Setup Error", "Pattern Substore is NULL");
            return_done =1;
            goto edit_config_parameter_cleanup;
        }

        key_values = (char *) store->GetOrderedList();
        //escaped = escapeSpecialChars(key_values); 
        escaped = escapeString(key_values); 
        if (escaped == NULL) {
            error_out("Setup Error", "Ordered List is NULL");
            return_done =1;
            goto edit_config_parameter_cleanup;
        }

        tokendbDebug( "got ordered list");
     
        PR_snprintf( ( char * ) configname, 256, "target.%s.pattern", ptype );
        pattern = (char *) RA::GetConfigStore()->GetConfigAsString( configname );

        PR_snprintf( ( char * ) configname, 256, "target.%s.displayname", ptype ); 
        disp_conf_type = (char *) RA::GetConfigStore()->GetConfigAsString( configname );

        large_injection_size = PL_strlen(key_values) + MAX_INJECTION_SIZE; 
        large_injection = (char *) PR_Malloc(large_injection_size);
        PR_snprintf( large_injection, large_injection_size,
                     "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid, "\";\n", 
                     "var conf_type = \"", ptype, "\";\n",
                      "var disp_conf_type = \"", disp_conf_type, "\";\n",
                     "var conf_name = \"", pname, "\";\n",
                     "var conf_state = \"", pstate,  "\";\n",
                     "var conf_tstamp = \"", ptimestamp,  "\";\n",
                     "var agent_must_approve = \"", agent_must_approve(ptype)? "true": "false", "\";\n",
                     "var conf_pattern = \"", pattern, "\";\n",
                     "var conf_values= \"", escaped, "\";\n");

        add_authorization_data(userid, is_admin, is_operator, is_agent, &large_injection, &large_injection_size, NULL); //needed?
        safe_injection_strcat(&large_injection, &large_injection_size ,JS_STOP , NULL );

        buf = getData( editConfigTemplate, large_injection );
    edit_config_parameter_cleanup:
        do_free(ptype);
        do_free(pname);
        do_strfree(ptimestamp);
        do_strfree(pstate);
        do_free(large_injection);
        do_free(key_values);
        do_strfree(escaped);
       
        if (store != NULL) {
            delete store;
            store = NULL;
        } 
        if (return_done == 1) {
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);
            return DONE;
        }
    } else if( ( PL_strstr( query, "op=return_to_edit_config_parameter" ) ) ) {
        tokendbDebug( "authorization for op=return_to_edit_config_parameter\n" );
        if (! is_admin) {
            RA::Audit(EV_AUTHZ_FAIL, AUDIT_MSG_AUTHZ, userid, "return_to_edit_config_parameter", "Failure", "Tokendb user authorization");
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);
            return DONE;
        }
        RA::Audit(EV_AUTHZ_SUCCESS, AUDIT_MSG_AUTHZ, userid, "return_to_edit_config_parameter", "Success", "Tokendb user authorization");

        char *ptype = NULL;
        char *pname = NULL;
        char *pstate = NULL;
        char *ptimestamp = NULL;
        char *pvalues = NULL;

        char *large_injection = NULL;
        int  large_injection_size = 0;
        char *pattern = NULL;
        char *disp_conf_type = NULL;
        int return_done = 0;
        
        ptype = get_post_field(post, "ptype", SHORT_LEN);
        pname = get_post_field(post, "pname", SHORT_LEN);
        pstate = get_post_field(post, "pstate", SHORT_LEN);
        ptimestamp = get_post_field(post, "ptimestamp", SHORT_LEN);
        pvalues = get_post_field_s(post, "pvalues");

        if ((ptype == NULL) || (pname == NULL) || (pstate == NULL) || (ptimestamp == NULL) || (pvalues == NULL)) {
            error_out("Invalid Invocation: A required parameter is missing", "Invalid Invocation: A required parameter is missing");
            return_done =1;
            goto return_to_edit_config_parameter_cleanup;
        }

        PR_snprintf( ( char * ) configname, 256, "target.%s.pattern", ptype );
        pattern = (char *) RA::GetConfigStore()->GetConfigAsString( configname );

        PR_snprintf( ( char * ) configname, 256, "target.%s.displayname", ptype ); 
        disp_conf_type = (char *) RA::GetConfigStore()->GetConfigAsString( configname );

        large_injection_size = PL_strlen(pvalues) + MAX_INJECTION_SIZE; 
        large_injection = (char *) PR_Malloc(large_injection_size);
        PR_snprintf( large_injection, large_injection_size,
                     "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid, "\";\n", 
                     "var conf_type = \"", ptype, "\";\n",
                     "var disp_conf_type = \"", disp_conf_type, "\";\n",
                     "var conf_name = \"", pname, "\";\n",
                     "var conf_state = \"", pstate,  "\";\n",
                     "var conf_tstamp = \"", ptimestamp,  "\";\n",
                     "var agent_must_approve = \"", agent_must_approve(ptype)? "true": "false", "\";\n",
                     "var conf_pattern = \"", pattern, "\";\n",
                     "var conf_values= \"", pvalues, "\";\n");

        add_authorization_data(userid, is_admin, is_operator, is_agent, &large_injection, &large_injection_size, NULL); //needed?
        safe_injection_strcat(&large_injection, &large_injection_size ,JS_STOP , NULL );

        buf = getData( editConfigTemplate, large_injection );
    return_to_edit_config_parameter_cleanup:
        do_free(ptype);
        do_free(pname);
        do_free(ptimestamp);
        do_free(pstate);
        do_free(pvalues);
        do_free(large_injection);
       
        if (return_done == 1) {
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);
            return DONE;
        }
    } else if( ( PL_strstr( query, "op=confirm_config_changes" ) ) ) {
        tokendbDebug( "authorization for op=confirm_config_changes\n" );
        if (! is_admin) {
            RA::Audit(EV_AUTHZ_FAIL, AUDIT_MSG_AUTHZ, userid, "confirm_config_changes", "Failure", "Tokendb user authorization");
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);
            return DONE;
        }
        RA::Audit(EV_AUTHZ_SUCCESS, AUDIT_MSG_AUTHZ, userid, "confirm_config_changes", "Success", "Tokendb user authorization");

        char *ptype = NULL;
        char *pname = NULL;
        char *pvalues = NULL;
        char *ptimestamp = NULL;
        char *choice = NULL;

        char *cur_ts = NULL;
        char *cur_state = NULL;
        char *changed_str = NULL;
        char *added_str = NULL;
        char *deleted_str = NULL;
        char *escaped_deleted_str = NULL;
        char *escaped_added_str = NULL;
        char *escaped_changed_str = NULL;
        char *escaped_pvalues = NULL;
        char *disp_conf_type = NULL;
        int return_done=0;
        char flash[512]="";

        char *pair = NULL;
        char *line = NULL;
        int i;
        int len;
        char *lasts = NULL;
        char *value = NULL;
        ConfigStore *store = NULL;

        ptype = get_post_field(post, "ptype", SHORT_LEN);
        pname = get_post_field(post, "pname", SHORT_LEN);
        ptimestamp = get_post_field(post, "ptimestamp", SHORT_LEN);
        escaped_pvalues = get_post_field_s(post, "pvalues");
        choice = get_post_field(post, "choice", SHORT_LEN);

        if ((ptype == NULL) || (pname == NULL) || (escaped_pvalues == NULL) || (ptimestamp == NULL)) {
            error_out("Invalid Invocation: A required parameter is NULL", "A required parameter is NULL");
            return_done=1;
            goto confirm_config_changes_cleanup;
        }

        tokendbDebug(ptype);        
        tokendbDebug(pname);        
       
        if (escaped_pvalues == NULL || PL_strlen(escaped_pvalues) == 0) {
            error_out("Empty Data not allowed. Use Delete Parameter instead", "Empty Data");
            return_done=1;
            goto confirm_config_changes_cleanup;
        }

        get_config_state_timestamp(ptype, pname, &cur_state, &cur_ts);
        if (PL_strcmp(cur_ts, ptimestamp) != 0) {
            error_out("The data you are viewing has changed.  Please reload the data and try your edits again.", "Data Out of Date");
            return_done=1;
            goto confirm_config_changes_cleanup;
        } 


        store = get_pattern_substore(ptype, pname);
        if (store == NULL) {
            error_out("Setup Error", "Pattern Substore is NULL");
            return_done=1;
            goto confirm_config_changes_cleanup;
        }

        // parse the pvalues string of form foo=bar&&foo2=baz&& ...
        pvalues = unescapeString(escaped_pvalues);
        if (pvalues == NULL) {
            error_out("Setup Error", "Empty Data");
            return_done=1;
            goto confirm_config_changes_cleanup;
        }

        changed_str = (char*) PR_Malloc(PL_strlen(pvalues));
        added_str = (char*) PR_Malloc(PL_strlen(pvalues));

        PR_snprintf(changed_str, PL_strlen(pvalues),"");
        PR_snprintf(added_str, PL_strlen(pvalues), "");

        line = PL_strdup(pvalues);
        pair = PL_strtok_r(line, "&&", &lasts);
        while (pair != NULL) {
            len = strlen(pair);
            i = 0;
            while (1) {
                if (i >= len) {
                    goto skip;
                }
                if (pair[i] == '\0') {
                    goto skip;
                }
                if (pair[i] == '=') {
                    pair[i] = '\0';
                    break;
                }
                i++;
            }
            if ((value= (char *) store->GetConfigAsString(&pair[0]))) {  // key exists
                if (PL_strcmp(value, &pair[i+1]) != 0) {
                    // value has changed
                    PR_snprintf(changed_str, PL_strlen(pvalues), "%s%s%s=%s", changed_str, 
                        (PL_strlen(changed_str) != 0) ? "&&" : "", 
                        &pair[0], &pair[i+1]);
                }
                store->Remove(&pair[0]);
            } else {  // new key
                PR_snprintf(added_str, PL_strlen(pvalues), "%s%s%s=%s", added_str, 
                    (PL_strlen(added_str) != 0) ? "&&" : "", 
                    &pair[0], &pair[i+1]);
            }
        skip:
            pair = PL_strtok_r(NULL, "&&", &lasts);
        }

        // remaining entries have been deleted
        deleted_str = (char *) store->GetOrderedList();

        //escape special characters
        escaped_deleted_str = escapeString(deleted_str);
        escaped_added_str = escapeString(added_str);
        escaped_changed_str = escapeString(changed_str);

        PR_snprintf( ( char * ) configname, 256, "target.%s.displayname", ptype ); 
        disp_conf_type = (char *) RA::GetConfigStore()->GetConfigAsString( configname );

        if (escaped_added_str != NULL && escaped_changed_str != NULL && escaped_deleted_str != NULL &&
            ((PL_strlen(escaped_added_str) + PL_strlen(escaped_changed_str) + PL_strlen(escaped_deleted_str))!=0)) {
            int large_injection_size = PL_strlen(escaped_deleted_str) + PL_strlen(escaped_pvalues) + PL_strlen(escaped_added_str) + 
                PL_strlen(escaped_changed_str) + MAX_INJECTION_SIZE;
            char * large_injection = (char *) PR_Malloc(large_injection_size);

            PR_snprintf( large_injection, large_injection_size,
                     "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid, "\";\n", 
                     "var conf_type = \"", ptype, "\";\n",
                     "var disp_conf_type = \"", disp_conf_type, "\";\n",
                     "var conf_name = \"", pname, "\";\n",
                     "var conf_tstamp = \"", ptimestamp,  "\";\n",
                     "var conf_state = \"", cur_state, "\";\n",
                     "var conf_values = \"", escaped_pvalues, "\";\n",
                     "var added_str= \"", escaped_added_str, "\";\n",
                     "var changed_str= \"", escaped_changed_str, "\";\n",
                     "var conf_approval_requested = \"", (PL_strcmp(choice, "Save") == 0) ? "FALSE" : "TRUE", "\";\n",
                     "var deleted_str= \"", escaped_deleted_str, "\";\n");

            add_authorization_data(userid, is_admin, is_operator, is_agent, &large_injection, &large_injection_size, NULL); //needed?
            safe_injection_strcat(&large_injection, &large_injection_size ,JS_STOP , NULL );

            buf = getData( confirmConfigChangesTemplate, large_injection );

            do_free(large_injection);
           
        } else {
            // no changes need to be saved

            if (PL_strcmp(choice, "Save") != 0) {
                int status =  set_config_state_timestamp(ptype, pname, ptimestamp, "Pending_Approval", "Admin", false, userid);
                if (status != 0) {
                    error_out("The data you are viewing has changed.  Please reload the data and try your edits again.", "Data Out of Date");
                    return_done=1;
                    goto confirm_config_changes_cleanup;
                }
                char error_msg[512]; 
                status = RA::GetConfigStore()->Commit(false, error_msg, 512);
                if (status != 0) { 
                    tokendbDebug(error_msg);
                }

                PR_snprintf(flash, 512, "Configuration Parameters have been submitted for Agent Approval");
            } else {
                PR_snprintf(flash, 512, "The data displayed is up-to-date.  No changes need to be saved.");
            }

            PR_snprintf( injection, injection_size,
                     "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid, "\";\n",
                     "var flash = \"", flash , "\";\n",
                     "var agent_target_list = \"",
                      RA::GetConfigStore()->GetConfigAsString("target.agent_approve.list", ""), "\";\n",
                     "var target_list = \"", RA::GetConfigStore()->GetConfigAsString("target.configure.list", ""), "\";\n");

            add_authorization_data(userid, is_admin, is_operator, is_agent, &injection, &injection_size, fixed_injection);
            safe_injection_strcat(&injection, &injection_size ,JS_STOP , fixed_injection ); 
            buf = getData( indexTemplate, injection );
        }

    confirm_config_changes_cleanup:
        do_strfree(cur_state);
        do_strfree(cur_ts);
        do_free(changed_str);
        do_free(added_str);
        do_free(deleted_str);
        do_strfree(escaped_deleted_str);
        do_strfree(escaped_added_str);
        do_strfree(escaped_changed_str);
        do_strfree(escaped_pvalues);
        do_free(ptype);
        do_free(pname);
        do_free(pvalues);
        do_free(ptimestamp);
        do_free(choice);
        do_strfree(line);

        if (store != NULL) {
            delete store;
            store = NULL;
        } 
        if (return_done != 0) {
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);
            return DONE;
        }
    
    } else if( ( PL_strstr( query, "op=save_config_changes" ) ) ) {
        tokendbDebug( "authorization for op=save_config_changes\n" );
        if (! is_admin) {
            RA::Audit(EV_AUTHZ_FAIL, AUDIT_MSG_AUTHZ, userid, "save_config_changes", "Failure", "Tokendb user authorization");
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);
            return DONE;
        }
        RA::Audit(EV_AUTHZ_SUCCESS, AUDIT_MSG_AUTHZ, userid, "save_config_parameter", "Success", "Tokendb user authorization");

        char *ptype = NULL;
        char *pname = NULL;
        char *ptimestamp = NULL;
        char *escaped_added_str = NULL;
        char *escaped_deleted_str = NULL;
        char *escaped_changed_str = NULL;
        char *new_config = NULL;
        char *approval_requested = NULL;
        char *pstate = NULL;
        char flash[256] = "";
        int return_done = 0;
        bool new_config_bool = false;

        ptype = get_post_field(post, "ptype", SHORT_LEN);
        pname = get_post_field(post, "pname", SHORT_LEN);
        ptimestamp = get_post_field(post, "ptimestamp", SHORT_LEN);
        escaped_added_str = get_post_field_s(post, "added_params");
        escaped_deleted_str =  get_post_field_s(post, "deleted_params");
        escaped_changed_str = get_post_field_s(post, "changed_params");
        new_config = get_post_field(post, "new_config", SHORT_LEN);
        approval_requested = get_post_field(post, "approval_requested", SHORT_LEN);
        new_config_bool = (PL_strcmp(new_config, "true") == 0) ? true : false;
       
        tokendbDebug(ptype);
        tokendbDebug(pname);
        tokendbDebug(new_config);
        tokendbDebug(ptimestamp);
        tokendbDebug(approval_requested);

        char *added_str = unescapeString(escaped_added_str);
        char *deleted_str = unescapeString(escaped_deleted_str);
        char *changed_str = unescapeString(escaped_changed_str);

        tokendbDebug(added_str);
        tokendbDebug(deleted_str);
        tokendbDebug(changed_str);

        if ((ptype == NULL) || (pname == NULL)) {
            error_out("Invalid Invocation: Parameter type, name or values is NULL", "Parameter type, name or values is NULL");
            return_done = 1;
            goto save_config_changes_cleanup;
        }

        if (set_config_state_timestamp(ptype, pname, ptimestamp, "Writing", "Admin", new_config_bool, userid) != 0) {
            error_out("The data you are viewing has changed.  Please reload the data and try your edits again.", "Data Out of Date");
            return_done=1;
            goto save_config_changes_cleanup;
        }

        if (new_config) {
             do_free(ptimestamp);
             get_config_state_timestamp(ptype, pname, &pstate, &ptimestamp);
        }

        if (added_str != NULL   && PL_strlen(added_str) != 0)   parse_and_apply_changes(userid, ptype, pname, "ADD", added_str);
        if (deleted_str != NULL && PL_strlen(deleted_str) != 0) parse_and_apply_changes(userid, ptype, pname, "DELETE", deleted_str);
        if (changed_str != NULL && PL_strlen(changed_str) != 0) parse_and_apply_changes(userid, ptype, pname, "MODIFY", changed_str);

        if (PL_strcmp(new_config, "true") ==0) {
            // add to the list for that config type
            PR_snprintf( ( char * ) configname, 256, "target.%s.list", ptype );
            const char *conf_list = RA::GetConfigStore()->GetConfigAsString( configname );
            char value[4096] = "";
            PR_snprintf(value, 4096, "%s%s%s", conf_list, (PL_strlen(conf_list) > 0) ? "," : "", pname);
            RA::GetConfigStore()->Add(configname, value);

            PR_snprintf(oString, 512, "%s", pname);
            PR_snprintf(pLongString, 4096, "%s;;%s", configname, value);
            RA::Audit(EV_CONFIG, AUDIT_MSG_CONFIG, userid, "Admin", "Success", oString, pLongString, "config item added");
        }

        if (PL_strcmp(approval_requested, "TRUE") == 0) {
            int status =  set_config_state_timestamp(ptype, pname, ptimestamp, "Pending_Approval", "Admin", false, userid);
            if (status != 0) {
                error_out("The data you are viewing has changed.  Please reload the data and try your edits again.", "Data Out of Date");
                return_done=1;
                goto save_config_changes_cleanup;
            }
            PR_snprintf(flash, 256, "Configuration Parameters have been saved and submitted for approval");
        } else {
            int status =  set_config_state_timestamp(ptype, pname, ptimestamp, "Disabled", "Admin", false, userid);
            if (status != 0) {
                error_out("The data you are viewing has changed.  Please reload the data and try your edits again.", "Data Out of Date");
                return_done=1;
                goto save_config_changes_cleanup;
            }
            PR_snprintf(flash, 256, "Configuration Parameters have been saved");
        }

        if ((PL_strlen(added_str) != 0) || (PL_strlen(deleted_str) != 0) ||  (PL_strlen(changed_str) != 0)) {
            char error_msg[512];
            status = RA::GetConfigStore()->Commit(true, error_msg, 512);
            if (status != 0) { 
                tokendbDebug(error_msg);
            }

            RA::Audit(EV_CONFIG, AUDIT_MSG_CONFIG, userid, "Admin", "Success", "", "", "config changes committed to filesystem");
        } else {
            // commit state changes
            char error_msg[512];
            status = RA::GetConfigStore()->Commit(false, error_msg, 512);
            if (status != 0) {        
                tokendbDebug(error_msg);
            }
        }

        PR_snprintf( injection, injection_size,
                     "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid, "\";\n",
                     "var flash = \"" , flash, "\";\n",  
                     "var agent_target_list = \"",
                     RA::GetConfigStore()->GetConfigAsString("target.agent_approve.list", ""), "\";\n",
                     "var target_list = \"", RA::GetConfigStore()->GetConfigAsString("target.configure.list", ""), "\";\n");

        add_authorization_data(userid, is_admin, is_operator, is_agent, &injection, &injection_size, fixed_injection);
        safe_injection_strcat(&injection, &injection_size ,JS_STOP , fixed_injection );

        buf = getData( indexTemplate, injection );
    save_config_changes_cleanup:
        do_free(ptype);
        do_free(pname);
        do_free(added_str);
        do_free(deleted_str);
        do_free(changed_str);
        do_free(escaped_added_str);
        do_free(escaped_deleted_str);
        do_free(escaped_changed_str);
        do_free(new_config);
        do_free(ptimestamp);
        do_free(pstate);
        do_free(approval_requested);
        if (return_done == 1) {
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);
            return DONE;
        }
    } else if( ( PL_strstr( query, "op=view_admin" ) )       ||
               ( PL_strstr( query, "op=view_certificate" ) ) ||
               ( PL_strstr( query, "op=view_activity_admin" ) ) ||
               ( PL_strstr( query, "op=view_activity" ) )    ||
               ( PL_strstr( query, "op=view_users" ) )       ||
               ( PL_strstr( query, "op=view" ) )             ||
               ( PL_strstr( query, "op=edit_user" ) )        ||
               ( PL_strstr( query, "op=edit" ) )             ||
               ( PL_strstr( query, "op=show_certificate" ) ) ||
               ( PL_strstr( query, "op=show" ) )             ||
               ( PL_strstr( query, "op=do_confirm_token" ) ) ||
               ( PL_strstr( query, "op=user_delete_confirm"))||
               ( PL_strstr( query, "op=confirm" ) ) ) {

        op  = get_field(query, "op=", SHORT_LEN);

        if( ( PL_strstr( query, "op=confirm" ) )    ||
            ( PL_strstr( query, "op=view_admin" ) ) ||
            ( PL_strstr( query, "op=view_activity_admin" ) ) ||
            ( PL_strstr( query, "op=show_admin" ) ) ||
            ( PL_strstr( query, "op=view_users") )  ||
            ( PL_strstr( query, "op=edit_user") )   ||
            ( PL_strstr( query, "op=user_delete_confirm") ) ) {
            tokendbDebug( "authorization for admin ops\n" );

            if( ! is_admin ) {
                RA::Audit(EV_AUTHZ_FAIL, AUDIT_MSG_AUTHZ, userid, op, "Failure", "Tokendb user authorization");
                error_out("Authorization Failure", "Failed to authorize request");
                do_free(buf);
                do_strfree(uri);
                do_strfree(query);

                return DONE;
            }
            RA::Audit(EV_AUTHZ_SUCCESS, AUDIT_MSG_AUTHZ, userid, op, "Success", "Tokendb user authorization");
        } else if ((PL_strstr(query, "op=edit")) || 
                   (PL_strstr(query, "do_confirm_token"))) {
            tokendbDebug( "authorization for op=edit and op=do_confirm_token\n" );

            if (! is_agent ) {
                RA::Audit(EV_AUTHZ_FAIL, AUDIT_MSG_AUTHZ, userid, op, "Failure", "Tokendb user authorization");
                error_out("Authorization Failure", "Failed to authorize request");
                do_free(buf);
                do_strfree(uri);
                do_strfree(query);

                return DONE;
            }
            RA::Audit(EV_AUTHZ_SUCCESS, AUDIT_MSG_AUTHZ, userid, op, "Success", "Tokendb user authorization");
        } else if (PL_strstr(query, "op=view_activity")) {
            tokendbDebug( "authorization for view_activity\n" );

            /* check removed -- all roles permitted 
            if ( (! is_agent) && (! is_operator) && (! is_admin)) {
                error_out("Authorization Failure", "Failed to authorize request");
                do_free(buf);
                do_strfree(uri);
                do_strfree(query);

                return DECLINED;
            } */
        } else {
            tokendbDebug( "authorization\n" );

            if ((! is_agent) && (!is_operator)) { 
                RA::Audit(EV_AUTHZ_FAIL, AUDIT_MSG_AUTHZ, userid, op, "Failure", "Tokendb user authorization");
                error_out("Authorization Failure", "Failed to authorize request");
                do_free(buf);
                do_strfree(uri);
                do_strfree(query);

                return DONE;
            }
            RA::Audit(EV_AUTHZ_SUCCESS, AUDIT_MSG_AUTHZ, userid, op, "Success", "Tokendb user authorization");
        }

        do_free(op);

        if ((PL_strstr( query, "op=view_activity_admin")) || 
            (PL_strstr( query, "op=view_activity" ) )) {
            getActivityFilter( filter, 2048, query );
        } else if( PL_strstr( query, "op=view_certificate" ) ) {
            getCertificateFilter( filter, 2048, query );
        } else if( PL_strstr( query, "op=show_certificate" ) ) {
            getCertificateFilter( filter, 2048,  query );
        } else if ((PL_strstr( query, "op=view_users" ) ) ||
                   (PL_strstr( query, "op=user_delete_confirm")) ||
                   (PL_strstr( query, "op=edit_user" ) )) {
            getUserFilter( filter, 2048, query );
        } else {
            getFilter( filter, 2048, query );
        }

        auth_filter = get_authorized_profiles(userid, is_admin);

        tokendbDebug("auth_filter");
        tokendbDebug(auth_filter);

        char *complete_filter = add_profile_filter(filter, auth_filter);
        do_free(auth_filter);

        int time_limit = get_time_limit(query);
        int size_limit = get_size_limit(query);

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

        if (( PL_strstr( query, "op=view_activity_admin_all" )) ||
            ( PL_strstr( query, "op=view_activity_all") )) {
            // TODO: error check to confirm that search filter is non-empty
            status = find_tus_activity_entries_no_vlv( complete_filter, &result, 1 ); 
        } else if (( PL_strstr( query, "op=view_activity_admin" )) ||
            ( PL_strstr( query, "op=view_activity" ) )) {
            if (PL_strcmp(complete_filter, "(&(tokenID=*)(tokenUserID=*))") == 0) {
                tokendbDebug("activity vlv search");
                status = find_tus_activity_entries(complete_filter, maxReturns, &result);
            } else {
                status = find_tus_activity_entries_pcontrol_1( complete_filter, maxReturns, time_limit, size_limit, &result);
            }
        } else if(( PL_strstr( query, "op=view_certificate_all" ) ) ||
            ( PL_strstr( query, "op=show_certificate") )) {

            // TODO: error check to confirm that search filter is non-empty
            ap_log_error( ( const char * ) "tus", __LINE__,
                          APLOG_MODULE_INDEX, APLOG_ERR, 0, rq->server,
                          ( const char * ) "LDAP filter: %s", complete_filter);

            status = find_tus_certificate_entries_by_order_no_vlv( complete_filter,
                                                                   &result,
                                                                   0 );
        } else if( PL_strstr( query, "op=view_certificate" )) {
            ap_log_error( ( const char * ) "tus", __LINE__,
                          APLOG_MODULE_INDEX, APLOG_ERR, 0, rq->server,
                          ( const char * ) "LDAP filter: %s", complete_filter);

            status = find_tus_certificate_entries_by_order( complete_filter,
                                                            maxReturns,
                                                            &result,
                                                            0 );
        } else if( PL_strstr( query, "op=show_admin" ) ||
                   PL_strstr( query, "op=show" )       ||
                   PL_strstr( query, "op=confirm" )    ||
                   PL_strstr( query, "op=do_confirm_token" ) ) {
            status = find_tus_token_entries_no_vlv( complete_filter, &result, 0 );
        } else if ((PL_strstr (query, "op=view_users" ))  ||
                   (PL_strstr (query, "op=user_delete_confirm")) ||
                   (PL_strstr (query, "op=edit_user" )))  {
            status = find_tus_user_entries_no_vlv( filter, &result, 0); 
        } else {
            if (PL_strcmp(complete_filter, "(&(cn=*)(tokenUserID=*))") == 0) {
                tokendbDebug("token vlv search");
                status = find_tus_db_entries(complete_filter, maxReturns, &result);
            } else {
                status = find_tus_db_entries_pcontrol_1( complete_filter, maxReturns, time_limit, size_limit, &result );
            }
        }

        if( status != LDAP_SUCCESS ) {
            ldap_error_out("LDAP search error: ", "LDAP search error: %s");
            do_free(complete_filter);
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);

            return DONE;
        }

        do_free(complete_filter);
        nEntries = get_number_of_entries( result );
        entryNum = 0;
        size = 0;

        PL_strcpy( injection, JS_START );

        safe_injection_strcat(&injection, &injection_size ,"var userid = \"" , fixed_injection );

        safe_injection_strcat(&injection, &injection_size , userid , fixed_injection );

        safe_injection_strcat(&injection, &injection_size , "\";\n" , fixed_injection ); 

        safe_injection_strcat(&injection, &injection_size , "var uriBase = \"" , fixed_injection );

        safe_injection_strcat(&injection, &injection_size ,uri , fixed_injection );

        safe_injection_strcat(&injection, &injection_size , "\";\n" , fixed_injection );

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

            safe_injection_strcat(&injection, &injection_size , "var total = \"" , fixed_injection );

            len = PL_strlen( injection );

            PR_snprintf( &injection[len], ( injection_size-len ),
                         "%d", nEntries );

            safe_injection_strcat(&injection, &injection_size , "\";\n" , fixed_injection );
        } else {
            if( ( vals = get_token_states() ) != NULL ) {
                safe_injection_strcat(&injection, &injection_size , "var tokenStates = \"" , fixed_injection );
                for( i = 0; vals[i] != NULL; i++ ) {
                    if( i > 0 ) {
                        safe_injection_strcat(&injection, &injection_size , "," , fixed_injection );
                    }

                    safe_injection_strcat(&injection, &injection_size , vals[i] , fixed_injection );
                }

                if( i > 0 ) {
                    safe_injection_strcat(&injection, &injection_size , "\";\n" , fixed_injection );
                } else {
                    safe_injection_strcat(&injection, &injection_size , "null;\n" , fixed_injection );
                }
            }
        }

        safe_injection_strcat(&injection, &injection_size , "var results = new Array();\n" , fixed_injection );

        safe_injection_strcat(&injection, &injection_size , "var item = 0;\n" , fixed_injection );

        if( PL_strstr( query, "op=do_confirm_token" ) ) {
                question = PL_strstr( query, "question=" );

                q = question[9] - '0';

                PR_snprintf( question_no, 256, "%d", q );

                safe_injection_strcat(&injection, &injection_size , "\"" , fixed_injection );

                safe_injection_strcat(&injection, &injection_size , "question_no" , fixed_injection ); 

                safe_injection_strcat(&injection, &injection_size , "\";\n" , fixed_injection );
        }

        if (PL_strstr( query, "op=do_confirm_token" ) ||
            PL_strstr( query, "op=show" )) {
                show_token_ui_state = true;
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
              
              safe_injection_strcat(&injection, &injection_size , "\"" , fixed_injection );

              safe_injection_strcat(&injection, &injection_size , flash , fixed_injection );
           
              safe_injection_strcat(&injection, &injection_size , "\";\n" , fixed_injection ); 
              do_free(flash);
           }
           PR_snprintf(msg, 256, "var num_profiles_to_display = %d ;\n", NUM_PROFILES_TO_DISPLAY);
           safe_injection_strcat(&injection, &injection_size , msg , fixed_injection );
        }

        //int injection_size = MAX_INJECTION_SIZE;
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

        if( (maxReturns > 0) && (maxReturns < nEntries)) {
            PR_snprintf(msg, 256, "var limited = %d ;\n", maxReturns);
            safe_injection_strcat(&injection, &injection_size , msg , fixed_injection );
        }

        for( e = get_first_entry( result );
             ( maxReturns > 0 ) && ( e != NULL );
             e = get_next_entry( e ) ) {
            maxReturns--;
            entryNum++;

            if ((entryNum < start_entry_val) || (entryNum >= end_entry_val)) {
                if (one_time == 1) {
                    safe_injection_strcat(&injection, &injection_size , "var my_query = \"" , fixed_injection );

                    safe_injection_strcat(&injection, &injection_size , query , fixed_injection );
 
                    safe_injection_strcat(&injection, &injection_size , "\";\n" , fixed_injection ); 

                    one_time =0;
                }
                // skip values not within the page range
                if (entryNum == end_entry_val) {
                    safe_injection_strcat(&injection, &injection_size , "var has_more_entries = 1;\n" , fixed_injection );
                    break;
                } 
                continue;
            }

            safe_injection_strcat(&injection, &injection_size ,"var o = new Object();\n"  , fixed_injection );

            for( n = 0; attrs[n] != NULL; n++ ) {
                /* Get the values of the attribute. */
                if( ( bvals = get_attribute_values( e, attrs[n] ) ) != NULL ) {
                    int v_start =0;
                    int v_end = MAX_INJECTION_SIZE;

                    safe_injection_strcat(&injection, &injection_size ,"o."  , fixed_injection );

                    safe_injection_strcat(&injection, &injection_size , attrs[n] , fixed_injection );

                    safe_injection_strcat(&injection, &injection_size , " = "  , fixed_injection );

                    if (PL_strstr(attrs[n], PROFILE_ID)) {
                        v_start = start_val;
                        v_end = end_val;
                    } 

                    for( i = v_start; (bvals[i] != NULL) && (i < v_end); i++ ) {
                        if( i > start_val ) {
                            safe_injection_strcat(&injection, &injection_size , "#"  , fixed_injection );
                        } else {
                            safe_injection_strcat(&injection, &injection_size ,"\""  , fixed_injection );
                        }

                        // make sure to escape any special characters
                        if (bvals[i]->bv_val != NULL) {
                            char *escaped = escapeSpecialChars(bvals[i]->bv_val);
                            safe_injection_strcat(&injection, &injection_size ,escaped  , fixed_injection );
                            if (escaped != NULL) {
                                PL_strfree(escaped);
                            }
                        }
                    }

                    if( i > v_start ) {
                        safe_injection_strcat(&injection, &injection_size ,"\";\n"  , fixed_injection );
                    } else {
                        safe_injection_strcat(&injection, &injection_size ,"null;\n"  , fixed_injection );
                    }

                    if ((PL_strcmp(attrs[n], TOKEN_STATUS)==0) && show_token_ui_state && valid_berval(bvals)) {
                        PL_strncpy( tokenStatus, bvals[0]->bv_val, 100 );
                    }

                    if ((PL_strcmp(attrs[n], TOKEN_REASON)==0) && show_token_ui_state && valid_berval(bvals)) {
                        PL_strncpy( tokenReason, bvals[0]->bv_val, 100 );
                    }

                    if (PL_strstr(attrs[n], PROFILE_ID))  {
                        if (bvals[i] != NULL) { 
                            safe_injection_strcat(&injection, &injection_size ,"var has_more_profile_vals = \"true\";\n"  , fixed_injection );
                        } else {
                            safe_injection_strcat(&injection, &injection_size ,"var has_more_profile_vals = \"false\";\n"  , fixed_injection );
                        }
                        PR_snprintf(msg, 256, "var start_val = %d ;\n var end_val = %d ;\n", 
                            start_val, i);
                        safe_injection_strcat(&injection, &injection_size ,msg  , fixed_injection );
                    }

                    /* Free the attribute values from memory when done. */
                    if( bvals != NULL ) {
                        free_values( bvals, 1 );
                        bvals = NULL;
                    }
                }
            }

            safe_injection_strcat(&injection, &injection_size ,"results[item++] = o;\n"  , fixed_injection );

            if( first_pass == 1 && nEntries > 1 && sendPieces == 0 ) {
                first_pass=0;

		PR_snprintf(msg, 256, "var start_entry_val = %d ; \nvar num_entries_per_page= %d ; \n", 
                            start_entry_val, NUM_ENTRIES_PER_PAGE);

                safe_injection_strcat(&injection, &injection_size ,msg  , fixed_injection );
            }

            if( sendPieces ) {
                ( void ) ap_rwrite( ( const void * ) injection,
                                    PL_strlen( injection ), rq );
                injection[0] = '\0';
            }

        }

        if( result != NULL ) {
            free_results( result );
            result = NULL;
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
                if (PL_strstr(dn, "Operators"))
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
                 safe_injection_strcat(&injection, &injection_size, "var operator = \"CHECKED\"\n"  , fixed_injection );
            } else {
                 safe_injection_strcat(&injection, &injection_size ,"var operator = \"\"\n"  , fixed_injection );
            }
            if (agent) {
                 safe_injection_strcat(&injection, &injection_size ,"var agent = \"CHECKED\"\n"  , fixed_injection );
            } else {
                 safe_injection_strcat(&injection, &injection_size ,"var agent = \"\"\n"  , fixed_injection );
            }
            if (admin) {
                 safe_injection_strcat(&injection, &injection_size ,"var admin = \"CHECKED\"\n"  , fixed_injection );
            } else {
                 safe_injection_strcat(&injection, &injection_size ,"var admin = \"\"\n"  , fixed_injection );
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
                safe_injection_strcat(&injection, &injection_size ,"var profile_list = new Array("  , fixed_injection );
                sresult = strtok(pList, ",");
                n_profiles++;
                while (sresult != NULL) {
                    n_profiles++;
                    l_profiles  += PL_strlen(sresult);
                    if ((n_profiles > NUM_PROFILES_TO_DISPLAY) || (l_profiles > MAX_LEN_PROFILES_TO_DISPLAY)) {
                        safe_injection_strcat(&injection, &injection_size ,"\"Other Profiles\"," , fixed_injection );
                        more_profiles = true;
                        break;
                    }

                    safe_injection_strcat(&injection, &injection_size ,"\"" , fixed_injection );

                    safe_injection_strcat(&injection, &injection_size ,sresult , fixed_injection );

                    safe_injection_strcat(&injection, &injection_size ,"\"," , fixed_injection );
                    sresult = strtok(NULL, ",");
                }
                do_free(pList);
                safe_injection_strcat(&injection, &injection_size ,"\"All Profiles\")\n" , fixed_injection );

                if (more_profiles) {
                    safe_injection_strcat(&injection, &injection_size ,"var more_profiles=\"true\";\n"  , fixed_injection );
                } else {
                    safe_injection_strcat(&injection, &injection_size ,"var more_profiles=\"false\";\n" , fixed_injection );
                }
            }
        }
        topLevel = get_field(query, "top=", SHORT_LEN);
        if ((topLevel != NULL) && (PL_strstr(topLevel, "operator"))) {
            safe_injection_strcat(&injection, &injection_size ,"var topLevel = \"operator\";\n", fixed_injection );
        }
        do_free(topLevel);

        /* populate the authorized token transitions */
        if (show_token_ui_state) {
            token_ui_state = get_token_ui_state(tokenStatus, tokenReason);
            add_allowed_token_transitions(token_ui_state, injection, injection_size);
        }

        add_authorization_data(userid, is_admin, is_operator, is_agent, &injection, &injection_size, fixed_injection);
        safe_injection_strcat(&injection, &injection_size ,JS_STOP, fixed_injection );

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
            RA::Audit(EV_AUTHZ_FAIL, AUDIT_MSG_AUTHZ, userid, "add_profile_user", "Failure", "Tokendb user authorization");
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);

            return DONE;
        }
        RA::Audit(EV_AUTHZ_SUCCESS, AUDIT_MSG_AUTHZ, userid, "add_profile_user", "Success", "Tokendb user authorization");
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
                    do_strfree(uri);
                    do_strfree(query);

                    return OK;
               }
            }
            if (PL_strstr(profile, ALL_PROFILES)) {
                status = delete_all_profiles_from_user(userid, uid);
            }

            PR_snprintf(oString, 512, "userid;;%s", uid);
            PR_snprintf(pString, 512, "profile;;%s", profile);

            status = add_profile_to_user(userid, uid, profile);
            if ((status != LDAP_SUCCESS) && (status != LDAP_TYPE_OR_VALUE_EXISTS)) {
                    RA::Audit(EV_CONFIG_ROLE, AUDIT_MSG_CONFIG, userid, "Admin", "Failure", oString, pString, "failure adding profile to user"); 
                    PR_snprintf(msg, 512, "LDAP Error in adding profile %s to user %s",
                        profile, uid);
                    post_ldap_error(msg);
            }
            RA::Audit(EV_CONFIG_ROLE, AUDIT_MSG_CONFIG, userid, "Admin", "success", oString, pString, "profile added to user"); 
        }
        do_free(other_profile);
        do_free(buf);
        do_strfree(uri);
        do_strfree(query);

        PR_snprintf((char *)msg, 512,
            "'%s' has added profile %s to user %s", userid, profile, uid);
        RA::tdb_activity(rq->connection->client_ip, "", "add_profile", "success", msg, uid, NO_TOKEN_TYPE);

        PR_snprintf(oString, 512, "userid;;%s", uid);
        PR_snprintf(pString, 512, "profile;;%s", profile);

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
            RA::Audit(EV_AUTHZ_FAIL, AUDIT_MSG_AUTHZ, userid, "save_user", "Failure", "Tokendb user authorization");
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);

            return DONE;
        }
        RA::Audit(EV_AUTHZ_SUCCESS, AUDIT_MSG_AUTHZ, userid, "save_user", "Success", "Tokendb user authorization");
        // first save user details
        uid = get_post_field(post, "uid", SHORT_LEN);
        firstName = get_post_field(post, "firstName", SHORT_LEN);
        lastName = get_post_field(post, "lastName", SHORT_LEN);
        userCert = get_encoded_post_field(post, "userCert", HUGE_STRING_LEN);
        opOperator = get_post_field(post, "opOperator", SHORT_LEN);
        opAgent = get_post_field(post, "opAgent", SHORT_LEN);
        opAdmin = get_post_field(post, "opAdmin", SHORT_LEN);

        // construct audit log message
        PR_snprintf(oString, 512, "userid;;%s", uid);
        PR_snprintf(pLongString, 4096, "");
        PR_snprintf(filter, 512, "uid=%s", uid);
        status = find_tus_user_entries_no_vlv( filter, &result, 0); 
        e = get_first_entry( result );
        if( e != NULL ) {
            audit_attribute_change(e, "givenName", firstName, pLongString);
            audit_attribute_change(e, "sn", lastName,  pLongString);
        } 

        if( result != NULL ) {
            free_results( result );
            result = NULL;
        }

        // now check cert 
        char *test_user = tus_authenticate(userCert);
        if ((test_user != NULL) && (strcmp(test_user, uid) == 0)) {
            // cert did not change
        } else {
            if (strlen(pLongString) > 0)  PL_strncat(pLongString, "+", 4096);
            PR_snprintf(pLongString, 4096, "%suserCertificate;;%s", pLongString, userCert);
        }

        PR_snprintf((char *)userCN, 256,
            "%s%s%s", ((firstName != NULL && PL_strlen(firstName) > 0)? firstName: ""),
            ((firstName != NULL && PL_strlen(firstName) > 0)? " ": ""), lastName);

        status = update_user_db_entry(userid, uid, lastName, firstName, userCN, userCert);

        do_free(firstName);
        do_free(lastName);
        do_free(userCert);

        if( status != LDAP_SUCCESS ) {
            RA::Audit(EV_CONFIG_ROLE, AUDIT_MSG_CONFIG, userid, "Admin", "failure", oString, pLongString, "user record failed to be updated"); 
            ldap_error_out("LDAP modify error: ", "LDAP error: %s");
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);
            do_free(uid);
            do_free(opOperator);
            do_free(opAgent);
            do_free(opAdmin);

            return DONE;
        }
        if (strlen(pLongString) > 0)
            RA::Audit(EV_CONFIG_ROLE, AUDIT_MSG_CONFIG, userid, "Admin", "success", oString, pLongString, "user record updated"); 

        bool has_role  = tus_authorize(TOKENDB_OPERATORS_IDENTIFIER, uid); 
        PR_snprintf(pString, 512, "role;;operator");
        if ((opOperator != NULL) && (PL_strstr(opOperator, OPERATOR))) {
            if (!has_role) {
                status = add_user_to_role_db_entry(userid, uid, OPERATOR);
                if ((status!= LDAP_SUCCESS) && (status != LDAP_TYPE_OR_VALUE_EXISTS)) {
                    RA::Audit(EV_CONFIG_ROLE, AUDIT_MSG_CONFIG, userid, "Admin", "failure", oString, pString, "Error adding user to role");
                    PR_snprintf(msg, 512, "Error adding user %s to role %s", uid, OPERATOR);
                    post_ldap_error(msg);
                } else {
                    RA::Audit(EV_CONFIG_ROLE, AUDIT_MSG_CONFIG, userid, "Admin", "success", oString, pString, "user added to role");
                }
            }
        } else if (has_role) {
            status = delete_user_from_role_db_entry(userid, uid, OPERATOR);
            if ((status!= LDAP_SUCCESS) && (status != LDAP_NO_SUCH_ATTRIBUTE)) {
                RA::Audit(EV_CONFIG_ROLE, AUDIT_MSG_CONFIG, userid, "Admin", "failure", oString, pString, "Error deleting user from role");
                PR_snprintf(msg, 512, "Error deleting user %s from role %s", uid, OPERATOR);
                post_ldap_error(msg);
            } else {
                RA::Audit(EV_CONFIG_ROLE, AUDIT_MSG_CONFIG, userid, "Admin", "success", oString, pString, "user deleted from role");
            }
        }

        has_role  = tus_authorize(TOKENDB_AGENTS_IDENTIFIER, uid); 
        PR_snprintf(pString, 512, "role;;agent");
        if ((opAgent != NULL) && (PL_strstr(opAgent, AGENT))) {
            if (!has_role) {
                status = add_user_to_role_db_entry(userid, uid, AGENT);
                if ((status!= LDAP_SUCCESS) && (status != LDAP_TYPE_OR_VALUE_EXISTS)) {
                    RA::Audit(EV_CONFIG_ROLE, AUDIT_MSG_CONFIG, userid, "Admin", "failure", oString, pString, "Error adding user to role");
                    PR_snprintf(msg, 512, "Error adding user %s to role %s", uid, AGENT);
                    post_ldap_error(msg);
                } else {
                    RA::Audit(EV_CONFIG_ROLE, AUDIT_MSG_CONFIG, userid, "Admin", "success", oString, pString, "user added to role");
                }
            } 
        } else if (has_role) {
            status = delete_user_from_role_db_entry(userid, uid, AGENT);
            if ((status!= LDAP_SUCCESS) && (status != LDAP_NO_SUCH_ATTRIBUTE)) {
                RA::Audit(EV_CONFIG_ROLE, AUDIT_MSG_CONFIG, userid, "Admin", "failure", oString, pString, "Error deleting user from role");
                PR_snprintf(msg, 512, "Error deleting user %s from role %s", uid, AGENT);
                post_ldap_error(msg);
            } else {
                RA::Audit(EV_CONFIG_ROLE, AUDIT_MSG_CONFIG, userid, "Admin", "success", oString, pString, "user deleted from role");
            }
        }

        has_role  = tus_authorize(TOKENDB_ADMINISTRATORS_IDENTIFIER, uid); 
        PR_snprintf(pString, 512, "role;;administrator");
        if ((opAdmin != NULL) && (PL_strstr(opAdmin, ADMINISTRATOR))) {
            if (!has_role) {
                status = add_user_to_role_db_entry(userid, uid, ADMINISTRATOR);
                if ((status!= LDAP_SUCCESS) && (status != LDAP_TYPE_OR_VALUE_EXISTS)) {
                    RA::Audit(EV_CONFIG_ROLE, AUDIT_MSG_CONFIG, userid, "Admin", "failure", oString, pString, "Error adding user to role");
                    PR_snprintf(msg, 512, "Error adding user %s to role %s", uid, ADMINISTRATOR);
                    post_ldap_error(msg);
                } else {
                    RA::Audit(EV_CONFIG_ROLE, AUDIT_MSG_CONFIG, userid, "Admin", "success", oString, pString, "user added to role");
                }
            }
        } else if (has_role) {
            status = delete_user_from_role_db_entry(userid, uid, ADMINISTRATOR);
            if ((status!= LDAP_SUCCESS) && (status != LDAP_NO_SUCH_ATTRIBUTE)) {
                RA::Audit(EV_CONFIG_ROLE, AUDIT_MSG_CONFIG, userid, "Admin", "failure", oString, pString, "Error deleting user from role");
                PR_snprintf(msg, 512, "Error deleting user %s from role %s", uid, ADMINISTRATOR);
                post_ldap_error(msg);
            } else {
                RA::Audit(EV_CONFIG_ROLE, AUDIT_MSG_CONFIG, userid, "Admin", "success", oString, pString, "user deleted from role");
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
                PR_snprintf(pString, 512, "profile_id;;%s", profile);
                status = delete_profile_from_user(userid, uid, profile);
                if ((status != LDAP_SUCCESS) && (status != LDAP_NO_SUCH_ATTRIBUTE)) {
                    RA::Audit(EV_CONFIG_ROLE, AUDIT_MSG_CONFIG, userid, "Admin", "failure", oString, pString, "error deleting profile from user");
                    PR_snprintf(msg, 512, "LDAP Error in deleting profile %s from user %s",
                        profile, uid);
                    post_ldap_error(msg);
                } else {
                    RA::Audit(EV_CONFIG_ROLE, AUDIT_MSG_CONFIG, userid, "Admin", "success", oString, pString, "profile deleted from user");
                }
            }
            do_free(profile);
            do_free(p_del);
        }

        do_free(buf);
        do_strfree(uri);
        do_strfree(query);

        PR_snprintf((char *)msg, 512,
            "'%s' has modified user %s", userid, uid);
        RA::tdb_activity(rq->connection->client_ip, "", "modify_user", "success", msg, uid, NO_TOKEN_TYPE);

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
            RA::Audit(EV_AUTHZ_FAIL, AUDIT_MSG_AUTHZ, userid, "save", "Failure", "Tokendb user authorization");
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);
            return DONE;
        }
        RA::Audit(EV_AUTHZ_SUCCESS, AUDIT_MSG_AUTHZ, userid, "save", "Success", "Tokendb user authorization");

        getCN( filter, 512, query );
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
    
        int cc;
        PR_snprintf(oString, 512, "token_id;;%s", filter);
        PR_snprintf(pLongString, 4096, "");
        int first_item = 1;
        for (cc = 0; mods[cc] != NULL; cc++) {
           if (! first_item) PL_strncat(pLongString, "+",4096);
           if (mods[cc]->mod_type != NULL) { 
               PL_strncat(pLongString, mods[cc]->mod_type, 4096);
               PL_strncat(pLongString, ";;", 4096);
               PL_strncat(pLongString, *mods[cc]->mod_values, 4096);
               first_item =0;
           } 
        }

        if( mods != NULL ) {
            free_modifications( mods, 0 );
            mods = NULL;
        }

        if( status != LDAP_SUCCESS ) {
            RA::Audit(EV_CONFIG_TOKEN, AUDIT_MSG_CONFIG, userid, "Agent", "Failure", oString, pLongString, "failed to modify token record");
             ldap_error_out("LDAP modify error: ", "LDAP error: %s");
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);
            return DONE;
        }

        RA::Audit(EV_CONFIG_TOKEN, AUDIT_MSG_CONFIG, userid, "Agent", "Success", oString, pLongString, "token record modified");
        PR_snprintf((char *)msg, 256, "Token record modified by %s", userid);
        RA::tdb_activity(rq->connection->client_ip, cuid, "save", "success",
            msg, cuidUserId, tokenType);

        PR_snprintf( injection, injection_size,
                     "%s%s%s%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid, "\";\n",
                     "var tid = \"", filter, "\";\n");
        add_authorization_data(userid, is_admin, is_operator, is_agent, &injection, &injection_size, fixed_injection);
        safe_injection_strcat(&injection, &injection_size, JS_STOP, fixed_injection );

        buf = getData( editResultTemplate, injection );

    } else if ( PL_strstr( query, "op=do_delete_user" ) ) {
        tokendbDebug( "authorization for do_delete_user\n" );

        if( ! is_admin ) {
            RA::Audit(EV_AUTHZ_FAIL, AUDIT_MSG_AUTHZ, userid, "do_delete_user", "Failure", "Tokendb user authorization");
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);

            return DONE;
        }
        RA::Audit(EV_AUTHZ_SUCCESS, AUDIT_MSG_AUTHZ, userid, "do_delete_user", "Success", "Tokendb user authorization");

        uid = get_post_field(post, "uid", SHORT_LEN);

        if (uid == NULL) {
            error_out("Error in delete user. userid is null", "Error in delete user. userid is null");
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);
            
            return DONE;
        }

        bool officer = false;
        bool agent = false;
        bool admin = false;
        status = find_tus_user_role_entries( uid, &result );
        for (e = get_first_entry( result );
            e != NULL;
            e = get_next_entry( e ) ) {
            char *dn = NULL;
            dn = get_dn(e);
            if (PL_strstr(dn, "Operators"))
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

        if (result != NULL) {
            free_results( result );
            result = NULL;
        }

        if (officer) {
            status = delete_user_from_role_db_entry(userid, uid, OPERATOR);
            if ((status!= LDAP_SUCCESS) && (status != LDAP_NO_SUCH_ATTRIBUTE)) {
                PR_snprintf(msg, 512, "Error deleting user %s from role %s", uid, OPERATOR);
                post_ldap_error(msg);
            }
        }

        if (agent) {
            status = delete_user_from_role_db_entry(userid, uid, AGENT);
            if ((status!= LDAP_SUCCESS) && (status != LDAP_NO_SUCH_ATTRIBUTE)) {
                PR_snprintf(msg, 512, "Error deleting user %s from role %s", uid, AGENT);
                post_ldap_error(msg);
            }
        }

        if (admin) {
            status = delete_user_from_role_db_entry(userid, uid, ADMINISTRATOR);
            if ((status!= LDAP_SUCCESS) && (status != LDAP_NO_SUCH_ATTRIBUTE)) {
                PR_snprintf(msg, 512, "Error deleting user %s from role %s", uid, ADMINISTRATOR);
                post_ldap_error(msg);
            }
        }

        status = delete_user_db_entry(userid, uid);

        if ((status != LDAP_SUCCESS) && (status != LDAP_NO_SUCH_OBJECT)) {
            PR_snprintf(oString, 512, "uid;;%s", uid);
            PR_snprintf(pString, 512, "status;;%d", status);
            RA::Audit(EV_CONFIG_ROLE, AUDIT_MSG_CONFIG, userid, "Admin", "failure", oString, pString,  "error in deleting user"); 

            PR_snprintf(msg, 512, "Error deleting user %s", uid);
            ldap_error_out(msg, msg);
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);
            do_free(uid);
           
            return DONE;
        }

        PR_snprintf((char *)msg, 256,
            "'%s' has deleted user %s", userid, uid);
        RA::tdb_activity(rq->connection->client_ip, "", "delete_user", "success", msg, uid, NO_TOKEN_TYPE);
        PR_snprintf(oString, 512, "uid;;%s", uid);
        RA::Audit(EV_CONFIG_ROLE, AUDIT_MSG_CONFIG, userid, "Admin", "success", oString, "", "tokendb user deleted"); 

        PR_snprintf( injection, injection_size,
                     "%s%s%s%s%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid, "\";\n",
                     "var tid = \"",     uid, "\";\n",
                     "var deleteType = \"user\";\n");
        add_authorization_data(userid, is_admin, is_operator, is_agent, &injection, &injection_size, fixed_injection);
        safe_injection_strcat(&injection, &injection_size ,JS_STOP, fixed_injection );

        do_free(uid);
        
        buf = getData( deleteResultTemplate, injection );
    } else if ( PL_strstr( query, "op=addUser" ) ) {
        tokendbDebug( "authorization for addUser\n" );

        if( ! is_admin ) {
            RA::Audit(EV_AUTHZ_FAIL, AUDIT_MSG_AUTHZ, userid, "addUser", "Failure", "Tokendb user authorization");
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);

            return DONE;
        }
        RA::Audit(EV_AUTHZ_SUCCESS, AUDIT_MSG_AUTHZ, userid, "addUser", "Success", "Tokendb user authorization");

        uid = get_post_field(post, "userid", SHORT_LEN);
        firstName = get_post_field(post, "firstName", SHORT_LEN);
        lastName = get_post_field(post, "lastName", SHORT_LEN);
        opOperator = get_post_field(post, "opOperator", SHORT_LEN);
        opAdmin = get_post_field(post, "opAdmin", SHORT_LEN);
        opAgent = get_post_field(post, "opAgent", SHORT_LEN);
        userCert = get_encoded_post_field(post, "cert", HUGE_STRING_LEN); 

        if ((PL_strlen(uid) == 0) || (PL_strlen(lastName) == 0)) {
            error_out("Bad input to op=addUser", "Bad input to op=addUser");
            do_free(uid);
            do_free(firstName);
            do_free(lastName);
            do_free(opOperator);
            do_free(opAdmin);
            do_free(opAgent);
            do_free(userCert);
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);

            return OK;
        }
        PR_snprintf((char *)userCN, 256,
            "%s%s%s", ((firstName != NULL && PL_strlen(firstName) > 0)? firstName: ""),
            ((firstName != NULL && PL_strlen(firstName) > 0)? " ": ""), lastName);

        PR_snprintf(oString, 512, "uid;;%s", uid);
        PR_snprintf(pString, 512, "givenName;;%s+sn;;%s", 
            ((firstName != NULL && PL_strlen(firstName) > 0)? firstName: ""), lastName);

        /* to meet STIG requirements, every user in ldap must have a password, even if that password is never used */
        char *pwd = generatePassword(pwLength);
        status = add_user_db_entry(userid, uid, pwd, lastName, firstName, userCN, userCert);
        do_free(pwd);

        if (status != LDAP_SUCCESS) {
            RA::Audit(EV_CONFIG_ROLE, AUDIT_MSG_CONFIG, userid, "Admin", "Failure", oString, pString, "failure in adding tokendb user"); 
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
            do_strfree(uri);
            do_strfree(query);

            return OK;
        }

        PR_snprintf((char *)msg, 512,
            "'%s' has created new user %s", userid, uid);
        RA::tdb_activity(rq->connection->client_ip, "", "add_user", "success", msg, uid, NO_TOKEN_TYPE);

        RA::Audit(EV_CONFIG_ROLE, AUDIT_MSG_CONFIG, userid, "Admin", "success", oString, pString, "tokendb user added"); 

        PR_snprintf(pString, 512, "role;;operator");
        if ((opOperator != NULL) && (PL_strstr(opOperator, OPERATOR))) {
            status = add_user_to_role_db_entry(userid, uid, OPERATOR);
            if ((status!= LDAP_SUCCESS) && (status != LDAP_TYPE_OR_VALUE_EXISTS)) {
                RA::Audit(EV_CONFIG_ROLE, AUDIT_MSG_CONFIG, userid, "Admin", "failure", oString, pString, "Error adding user to role");
                PR_snprintf(msg, 512, "Error adding user %s to role %s", uid, OPERATOR);
                post_ldap_error(msg);
            } else {
                RA::Audit(EV_CONFIG_ROLE, AUDIT_MSG_CONFIG, userid, "Admin", "success", oString, pString, "user added to role");
            }
        } else {
            status = delete_user_from_role_db_entry(userid, uid, OPERATOR);
            if ((status!= LDAP_SUCCESS) && (status != LDAP_NO_SUCH_ATTRIBUTE)) {
                RA::Audit(EV_CONFIG_ROLE, AUDIT_MSG_CONFIG, userid, "Admin", "failure", oString, pString, "Error deleting user from role");
                PR_snprintf(msg, 512, "Error deleting user %s from role %s", uid, OPERATOR);
                post_ldap_error(msg);
            } else {
                RA::Audit(EV_CONFIG_ROLE, AUDIT_MSG_CONFIG, userid, "Admin", "success", oString, pString, "user deleted from role");
            }

        }

        PR_snprintf(pString, 512, "role;;agent");
        if ((opAgent != NULL) && (PL_strstr(opAgent, AGENT))) {
            status = add_user_to_role_db_entry(userid, uid, AGENT);
            if ((status!= LDAP_SUCCESS) && (status != LDAP_TYPE_OR_VALUE_EXISTS)) {
                RA::Audit(EV_CONFIG_ROLE, AUDIT_MSG_CONFIG, userid, "Admin", "failure", oString, pString, "Error adding user to role");
                PR_snprintf(msg, 512, "Error adding user %s to role %s", uid, AGENT);
                post_ldap_error(msg);
            } else {
                RA::Audit(EV_CONFIG_ROLE, AUDIT_MSG_CONFIG, userid, "Admin", "success", oString, pString, "user added to role");
            }
        } else {
            status = delete_user_from_role_db_entry(userid, uid, AGENT);
            if ((status!= LDAP_SUCCESS) && (status != LDAP_NO_SUCH_ATTRIBUTE)) {
                RA::Audit(EV_CONFIG_ROLE, AUDIT_MSG_CONFIG, userid, "Admin", "failure", oString, pString, "Error deleting user from role");
                PR_snprintf(msg, 512, "Error deleting user %s from role %s", uid, AGENT);
                post_ldap_error(msg);
            } else {
                RA::Audit(EV_CONFIG_ROLE, AUDIT_MSG_CONFIG, userid, "Admin", "success", oString, pString, "user deleted from role");
            }
        }

        PR_snprintf(pString, 512, "role;;admin");
        if ((opAdmin != NULL) && (PL_strstr(opAdmin, ADMINISTRATOR))) {
            status = add_user_to_role_db_entry(userid, uid, ADMINISTRATOR);
            if ((status!= LDAP_SUCCESS) && (status != LDAP_TYPE_OR_VALUE_EXISTS)) {
                RA::Audit(EV_CONFIG_ROLE, AUDIT_MSG_CONFIG, userid, "Admin", "failure", oString, pString, "Error adding user to role");
                PR_snprintf(msg, 512, "Error adding user %s to role %s", uid, ADMINISTRATOR);
                post_ldap_error(msg);
            } else {
                RA::Audit(EV_CONFIG_ROLE, AUDIT_MSG_CONFIG, userid, "Admin", "success", oString, pString, "user added to role");
            }
        } else {
            status = delete_user_from_role_db_entry(userid, uid, ADMINISTRATOR);
            if ((status!= LDAP_SUCCESS) && (status != LDAP_NO_SUCH_ATTRIBUTE)) {
                RA::Audit(EV_CONFIG_ROLE, AUDIT_MSG_CONFIG, userid, "Admin", "failure", oString, pString, "Error deleting user from role");
                PR_snprintf(msg, 512, "Error deleting user %s from role %s", uid, ADMINISTRATOR);
                post_ldap_error(msg);
            } else {
                RA::Audit(EV_CONFIG_ROLE, AUDIT_MSG_CONFIG, userid, "Admin", "success", oString, pString, "user deleted from role");
            }
        }

        do_free(firstName);
        do_free(lastName);
        do_free(opOperator);
        do_free(opAdmin);
        do_free(opAgent);
        do_free(userCert);
       
        PR_snprintf( injection, injection_size,
                     "%s%s%s%s%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid, "\";\n",
                     "var tid = \"",     uid, "\";\n", 
                     "var addType = \"user\";\n");
        add_authorization_data(userid, is_admin, is_operator, is_agent, &injection, &injection_size, fixed_injection);
        safe_injection_strcat(&injection, &injection_size ,JS_STOP, fixed_injection );

        do_free(uid);
        
        buf = getData( addResultTemplate, injection );

    } else if( PL_strstr( query, "op=add" ) ) {
        tokendbDebug( "authorization for op=add\n" );
        RA_Status token_type_status;
        if( ! is_admin ) {
            RA::Audit(EV_AUTHZ_FAIL, AUDIT_MSG_AUTHZ, userid, "add", "Failure", "Tokendb user authorization");
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);
            return DONE;
        }
        RA::Audit(EV_AUTHZ_SUCCESS, AUDIT_MSG_AUTHZ, userid, "add", "Success", "Tokendb user authorization");

        getCN( filter, 512,  query );

        if (m_processor.GetTokenType(OP_PREFIX, 0, 0, filter, (const char*) NULL, (NameValueSet*) NULL,
                token_type_status, tokentype)) {
            PL_strcpy(tokenType, tokentype); 
        } else {
            PL_strcpy(tokenType, NO_TOKEN_TYPE);
        }
            
        if( strcmp( filter, "" ) == 0 ) {
            error_out("No Token ID Found", "Failed to authorize request");
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);
            return DONE;
        }

        status = add_default_tus_db_entry( NULL, userid,
                                           filter, "uninitialized",
                                           NULL, NULL, tokenType );

        PR_snprintf(oString, 512, "token_id;;%s", filter);
        if( status != LDAP_SUCCESS ) {
            RA::Audit(EV_CONFIG_TOKEN, AUDIT_MSG_CONFIG, userid, "Admin", "Failure", oString, "", "failed to add token record");
            ldap_error_out("LDAP add error: ", "LDAP error: %s");
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);
            return DONE;
        }

        RA::Audit(EV_CONFIG_TOKEN, AUDIT_MSG_CONFIG, userid, "Admin", "Success", oString, "", "token record added");

        PR_snprintf((char *)msg, 256,
            "'%s' has created new token", userid);
        RA::tdb_activity(rq->connection->client_ip, filter, "add", "token", msg, "success", tokenType);

        PR_snprintf( injection,injection_size,
                     "%s%s%s%s%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid, "\";\n",
                     "var tid = \"",    filter, "\";\n", 
                     "var addType = \"token\";\n");
        add_authorization_data(userid, is_admin, is_operator, is_agent, &injection, &injection_size, fixed_injection);
        safe_injection_strcat(&injection, &injection_size ,JS_STOP, fixed_injection );

        buf = getData( addResultTemplate, injection );
    } else if( PL_strstr( query, "op=delete" ) ) {
        RA_Status token_type_status;
        tokendbDebug( "authorization for op=delete\n" );

        if( ! is_admin ) {
            RA::Audit(EV_AUTHZ_FAIL, AUDIT_MSG_AUTHZ, userid, "delete", "Failure", "Tokendb user authorization");
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);

            return DONE;
        }
        RA::Audit(EV_AUTHZ_SUCCESS, AUDIT_MSG_AUTHZ, userid, "delete", "Success", "Tokendb user authorization");

        getCN( filter, 512,  query );

        if (m_processor.GetTokenType(OP_PREFIX, 0, 0, filter, (const char*) NULL, (NameValueSet*) NULL,
                token_type_status, tokentype)) {
            PL_strcpy(tokenType, tokentype);
        } else {
            PL_strcpy(tokenType, NO_TOKEN_TYPE);
        }


        PR_snprintf((char *)msg, 256,
            "'%s' has deleted token", userid);
        RA::tdb_activity(rq->connection->client_ip, filter, "delete", "token", msg, "", tokenType);

        PR_snprintf(oString, 512, "token_id;;%s", filter);
        status = delete_tus_db_entry( userid, filter );

        if( status != LDAP_SUCCESS ) {
            RA::Audit(EV_CONFIG_TOKEN, AUDIT_MSG_CONFIG, userid, "Admin", "Failure", oString, "",  "failure in deleting token record");
            ldap_error_out("LDAP delete error: ", "LDAP error: %s");
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);

            return DONE;
        }

        RA::Audit(EV_CONFIG_TOKEN, AUDIT_MSG_CONFIG, userid, "Admin", "Success", oString, "",  "token record deleted");

        PR_snprintf( injection, injection_size,
                     "%s%s%s%s%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid, "\";\n",
                     "var tid = \"", filter, "\";\n", 
                     "var deleteType = \"token\";\n");
        add_authorization_data(userid, is_admin, is_operator, is_agent, &injection, &injection_size, fixed_injection);
        safe_injection_strcat(&injection, &injection_size ,JS_STOP, fixed_injection );

        buf = getData( deleteResultTemplate, injection );
    } else if ( PL_strstr( query, "op=audit_admin") ) {
        tokendbDebug( "authorization for op=audit_admin\n" );

        if (!is_admin )  {
            RA::Audit(EV_AUTHZ_FAIL, AUDIT_MSG_AUTHZ, userid, "audit_admin", "Failure", "Tokendb user authorization");
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);

            return DONE;
        }
        RA::Audit(EV_AUTHZ_SUCCESS, AUDIT_MSG_AUTHZ, userid, "audit_admin", "Success", "Tokendb user authorization");

        PR_snprintf (injection, injection_size,
             "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%d%s%s%d%s%s%s%s%s%s%s%s%s%s", JS_START,
             "var uriBase = \"", uri, "\";\n",
             "var userid = \"", userid, "\";\n",
             "var signedAuditEnable = \"", RA::m_audit_enabled ? "true": "false", "\";\n",
             "var logSigningEnable = \"", RA::m_audit_signed ? "true" : "false", "\";\n",
             "var signedAuditLogInterval = \"", RA::m_flush_interval, "\";\n",
             "var signedAuditLogBufferSize = \"", RA::m_buffer_size, "\";\n",
             "var signedAuditSelectedEvents = \"", RA::m_signedAuditSelectedEvents, "\";\n",
             "var signedAuditSelectableEvents = \"", RA::m_signedAuditSelectableEvents, "\";\n",
             "var signedAuditNonSelectableEvents = \"", RA::m_signedAuditNonSelectableEvents, "\";\n");

         RA::Debug( "mod_tokendb::mod_tokendb_handler",
               "signedAudit: %s %s %d %d %s %s %s", 
               RA::m_audit_enabled ? "true": "false",
               RA::m_audit_signed ? "true": "false",
               RA::m_flush_interval,
               RA::m_buffer_size,
               RA::m_signedAuditSelectedEvents,
               RA::m_signedAuditSelectableEvents, 
               RA::m_signedAuditNonSelectableEvents);
         
        char *flash = get_field(query, "flash=", SHORT_LEN);
        if (flash != NULL) {
            safe_injection_strcat(&injection, &injection_size ,"var flash = \"", fixed_injection );

            safe_injection_strcat(&injection, &injection_size ,flash, fixed_injection );
          
            safe_injection_strcat(&injection, &injection_size ,"\";\n", fixed_injection ); 
            do_free(flash);
        }

        add_authorization_data(userid, is_admin, is_operator, is_agent, &injection, &injection_size,fixed_injection);
        safe_injection_strcat(&injection, &injection_size ,JS_STOP, fixed_injection );
        buf = getData(auditAdminTemplate, injection);
    } else if (PL_strstr( query, "op=update_audit_admin") ) {
        tokendbDebug( "authorization for op=audit_admin\n" );

        if (!is_admin )  {
            RA::Audit(EV_AUTHZ_FAIL, AUDIT_MSG_AUTHZ, userid, "update_audit_admin", "Failure", "Tokendb user authorization");
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);

            return DONE;
        }
        RA::Audit(EV_AUTHZ_SUCCESS, AUDIT_MSG_AUTHZ, userid, "update_audit_admin", "Success", "Tokendb user authorization");
 
        int need_update=0;

        bool o_signing = RA::m_audit_signed;
        bool n_signing = o_signing;
        char *logSigning = get_post_field(post, "logSigningEnable", SHORT_LEN);
        if (logSigning != NULL) {
            n_signing = (PL_strcmp(logSigning, "true") == 0)? true: false;
        } 
        do_free(logSigning);

        bool o_enable = RA::m_audit_enabled;
        bool n_enable = o_enable;
        char *auditEnable = get_post_field(post, "auditEnable", SHORT_LEN);
        if (auditEnable != NULL) {
            n_enable = (PL_strcmp(auditEnable, "true") == 0)? true: false;
        }
        do_free(auditEnable);

        if ((o_signing == n_signing) && (o_enable == n_enable)) {
            // nothing changed, continue
        } else {
            if (o_signing != n_signing) {
                PR_snprintf(pString, 512, "logging.audit.logSigning;;%s", (n_signing)? "true":"false");
                if (o_enable != n_enable) {
                    PL_strncat(pString, "+logging.audit.enable;;", 512);
                    PL_strncat(pString, (n_enable)? "true" : "false", 512);
                }
            } else {
                PR_snprintf(pString, 512, "logging.audit.enable;;%s", (n_enable)? "true":"false");
            }

            RA::Audit(EV_CONFIG_AUDIT, AUDIT_MSG_CONFIG, userid, "Admin", "Success", "", pString, "attempting to modify audit log configuration");

            if (n_enable) { // be sure to log audit log startup messages,if any
                RA::enable_audit_logging(n_enable);
            }

            RA::setup_audit_log(n_signing, n_signing != o_signing);

            if (n_enable && !o_enable) {
                RA::Audit(EV_AUDIT_LOG_STARTUP, AUDIT_MSG_FORMAT, "System", "Success",
                    "audit function startup");
            } else if (!n_enable && o_enable) {
                RA::Audit(EV_AUDIT_LOG_SHUTDOWN, AUDIT_MSG_FORMAT, "System", "Success",
                    "audit function shutdown");
            }
            RA::FlushAuditLogBuffer();

            // sleep to ensure all logs written
            PR_Sleep(PR_SecondsToInterval(1));

            if (!n_enable) { // turn off logging after all logs written
                RA::enable_audit_logging(n_enable);
            }
            need_update = 1;

            RA::Audit(EV_CONFIG_AUDIT, AUDIT_MSG_CONFIG, userid, "Admin", "Success", "", pString, "audit log config modified");
            PR_snprintf((char *)msg, 512, "'%s' has modified audit log config: %s", userid, pString);
               RA::tdb_activity(rq->connection->client_ip, "", "modify_audit_signing", "success", msg, userid, NO_TOKEN_TYPE);
        }

        char *logSigningInterval_str = get_post_field(post, "logSigningInterval", SHORT_LEN);
        int logSigningInterval = atoi(logSigningInterval_str);
        do_free(logSigningInterval_str);

        if ((logSigningInterval>=0) &&(logSigningInterval != RA::m_flush_interval)) {
            RA::SetFlushInterval(logSigningInterval);
            PR_snprintf((char *)msg, 512, "'%s' has modified the  audit log signing interval to %d seconds", userid, logSigningInterval);
            RA::tdb_activity(rq->connection->client_ip, "", "modify_audit_signing", "success", msg, userid, NO_TOKEN_TYPE);

            PR_snprintf(pString, 512, "logging.audit.flush.interval;;%d", logSigningInterval);
            RA::Audit(EV_CONFIG_AUDIT, AUDIT_MSG_CONFIG, userid, "Admin", "Success", "", pString, "audit log configuration modified");
        }

        char *logSigningBufferSize_str = get_post_field(post, "logSigningBufferSize", SHORT_LEN);
        int logSigningBufferSize = atoi(logSigningBufferSize_str);
        do_free(logSigningBufferSize_str);

        if ((logSigningBufferSize >= 512) && (logSigningBufferSize != (int) RA::m_buffer_size)) {
            RA::SetBufferSize(logSigningBufferSize);
            PR_snprintf((char *)msg, 512, "'%s' has modified the  audit log signing buffer size to %d bytes", userid, logSigningBufferSize);
            RA::tdb_activity(rq->connection->client_ip, "", "modify_audit_signing", "success", msg, userid, NO_TOKEN_TYPE);

            PR_snprintf(pString, 512, "logging.audit.buffer.size;;%d", logSigningBufferSize);
            RA::Audit(EV_CONFIG_AUDIT, AUDIT_MSG_CONFIG, userid, "Admin", "Success", "", pString, "audit log configuration modified");
        }

        char *nEvents_str = get_post_field(post, "nEvents", SHORT_LEN);
        int nEvents = atoi(nEvents_str);
        do_free(nEvents_str);

        char new_selected[MAX_INJECTION_SIZE];

        int first_match = 1;
        for (int i=0; i< nEvents; i++) {
            char e_name[256];
            PR_snprintf(e_name, 256, "event_%d", i);
            char *event = get_post_field(post, e_name, SHORT_LEN);
            if ((event != NULL) && RA::IsValidEvent(event)) {
                if (first_match != 1) {
                    PL_strncat(new_selected, ",", MAX_INJECTION_SIZE);
                }
                first_match = 0;
                PL_strncat(new_selected, event, MAX_INJECTION_SIZE);
            }
            do_free(event);
        }

        if (PL_strcmp(new_selected, RA::m_signedAuditSelectedEvents) != 0) {
            need_update = 1;
            RA::update_signed_audit_selected_events(new_selected);

            PR_snprintf((char *)msg, 512,
            "'%s' has modified audit signing configuration", userid);
            RA::tdb_activity(rq->connection->client_ip, "", "modify_audit_signing", "success", msg, userid, NO_TOKEN_TYPE);

            PR_snprintf(pLongString, 4096, "logging.audit.selected.events;;%s", new_selected);
            RA::Audit(EV_CONFIG_AUDIT, AUDIT_MSG_CONFIG, userid, "Admin", "Success", "", pLongString, "audit log configuration modified");

        }

        if (need_update == 1) {
           tokendbDebug("Updating signed audit events in CS.cfg");
           char error_msg[512]; 
           status = RA::GetConfigStore()->Commit(true, error_msg, 512);
           if (status != 0) {        
                tokendbDebug(error_msg);
           }
        } 

        PR_snprintf(injection, MAX_INJECTION_SIZE,
                    "/tus/tus?op=audit_admin&flash=Signed+Audit+configuration+has+been+updated");
        do_free(buf);
        do_strfree(uri);
        do_strfree(query);

        rq->method = apr_pstrdup(rq->pool, "GET");
        rq->method_number = M_GET;

        ap_internal_redirect_handler(injection, rq);
        return OK;
    } else if ( PL_strstr( query, "op=self_test") ) {
        tokendbDebug( "authorization for op=self_test\n" );

        if (!is_admin )  {
            RA::Audit(EV_AUTHZ_FAIL, AUDIT_MSG_AUTHZ, userid, "self_test", "Failure", "Tokendb user authorization");
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_free(uri);
            do_free(query);

            return DONE;
        }
        RA::Audit(EV_AUTHZ_SUCCESS, AUDIT_MSG_AUTHZ, userid, "self_test", "Success", "Tokendb user authorization");

        PR_snprintf (injection, injection_size,
             "%s%s%s%s%s%s%s%s%d%s%s%d%s", JS_START,
             "var uriBase = \"", uri, "\";\n",
             "var userid = \"", userid, "\";\n",
             "var enabled = ", SelfTest::isOnDemandEnabled(), ";\n",
             "var critical = ", SelfTest::isOnDemandCritical(), ";\n");

        if (SelfTest::nTests > 0)
             safe_injection_strcat(&injection, &injection_size ,"var test_list = [", fixed_injection );
        for (int i = 0; i < SelfTest::nTests; i++) {
            RA::Debug( "mod_tokendb::mod_tokendb_handler", "test name: %s", SelfTest::TEST_NAMES[i]);
            if (i > 0)
                 safe_injection_strcat(&injection, &injection_size ,", ", fixed_injection );

             safe_injection_strcat(&injection, &injection_size ,"\"", fixed_injection );
           
             safe_injection_strcat(&injection, &injection_size , (char *) SelfTest::TEST_NAMES[i], fixed_injection ); 
            
             safe_injection_strcat(&injection, &injection_size ,"\"", fixed_injection );
        }
        if (SelfTest::nTests > 0)
             safe_injection_strcat(&injection, &injection_size ,"];\n", fixed_injection );

        add_authorization_data(userid, is_admin, is_operator, is_agent, &injection, &injection_size, fixed_injection);
         safe_injection_strcat(&injection, &injection_size ,JS_STOP, fixed_injection );
        buf = getData(selfTestTemplate, injection);
    } else if ( PL_strstr( query, "op=run_self_test" ) ) {
        tokendbDebug( "authorization for run_self_test\n" );

        if( ! is_admin ) {
            RA::Audit(EV_AUTHZ_FAIL, AUDIT_MSG_AUTHZ, userid, "run_self_test", "Failure", "Tokendb user authorization");
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_free(uri);
            do_free(query);

            return DONE;
        }
        RA::Audit(EV_AUTHZ_SUCCESS, AUDIT_MSG_AUTHZ, userid, "run_self_test", "Success", "Tokendb user authorization");

        rc = SelfTest::runOnDemandSelfTests();

        PR_snprintf( injection, injection_size,
                     "%s%s%s%s%s%s%s%s%d%s%s%d%s", JS_START,
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid, "\";\n",
                     "var enabled = ", SelfTest::isOnDemandEnabled(), ";\n",
                     "var result = \"", rc, "\";\n");

        if (SelfTest::nTests > 0)
            safe_injection_strcat(&injection, &injection_size , "var test_list = [", fixed_injection );
        for (int i = 0; i < SelfTest::nTests; i++) {
            RA::Debug( "mod_tokendb::mod_tokendb_handler", "test name: %s", SelfTest::TEST_NAMES[i]);
            if (i > 0)
                 safe_injection_strcat(&injection, &injection_size ,", ", fixed_injection );

             safe_injection_strcat(&injection, &injection_size ,"\"", fixed_injection ); 
 
             safe_injection_strcat(&injection, &injection_size , (char *) SelfTest::TEST_NAMES[i], fixed_injection );

             safe_injection_strcat(&injection, &injection_size ,"\"", fixed_injection );
        }
        if (SelfTest::nTests > 0)
             safe_injection_strcat(&injection, &injection_size , "];\n", fixed_injection );

        add_authorization_data(userid, is_admin, is_operator, is_agent, &injection, &injection_size, fixed_injection);
         safe_injection_strcat(&injection, &injection_size ,JS_STOP, fixed_injection );

        buf = getData( selfTestResultsTemplate, injection );
    } else if( ( PL_strstr( query, "op=agent_select_config" ) ) ) {
        tokendbDebug( "authorization for op=agent_select_config\n" );
        if (! is_agent) {
            RA::Audit(EV_AUTHZ_FAIL, AUDIT_MSG_AUTHZ, userid, "agent_select_config", "Failure", "Tokendb user authorization");
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);
            return DONE;
        }
        RA::Audit(EV_AUTHZ_SUCCESS, AUDIT_MSG_AUTHZ, userid, "agent_select_config", "Success", "Tokendb user authorization");

        char *conf_type = NULL;
        char *disp_conf_type = NULL;
        conf_type = get_field(query, "type=", SHORT_LEN);

        if (conf_type == NULL) {
            error_out("Invalid Invocation: Type is NULL", "Type is NULL");
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);
            do_free(conf_type);
            return DONE;
        }

        // check if agent has permission to see this config parameter
        if (! agent_must_approve(conf_type)) {
            error_out("Invalid Invocation: Agent is not permitted to view this configuration item", "Agent is not permitted to view this configuration item");
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);
            return DONE;
        }

        PR_snprintf( ( char * ) configname, 256, "target.%s.list", conf_type );
        const char *conf_list = RA::GetConfigStore()->GetConfigAsString( configname );

        PR_snprintf( ( char * ) configname, 256, "target.%s.displayname", conf_type ); 
        disp_conf_type = (char *) RA::GetConfigStore()->GetConfigAsString( configname );

        PR_snprintf( injection, injection_size,
                     "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid, "\";\n",
                     "var conf_type = \"", conf_type, "\";\n",
                     "var disp_conf_type = \"", disp_conf_type, "\";\n",
                     "var conf_list = \"", (conf_list != NULL)? conf_list : "", "\";\n");

        do_free(conf_type);
        add_authorization_data(userid, is_admin, is_operator, is_agent, &injection, &injection_size, fixed_injection); //needed?
         safe_injection_strcat(&injection, &injection_size ,JS_STOP, fixed_injection );

        buf = getData( agentSelectConfigTemplate, injection );
    } else if( ( PL_strstr( query, "op=select_config_parameter" ) ) ) {
        tokendbDebug( "authorization for op=select_config_parameter\n" );
        if (! is_admin) {
            RA::Audit(EV_AUTHZ_FAIL, AUDIT_MSG_AUTHZ, userid, "select_config_parameter", "Failure", "Tokendb user authorization");
            error_out("Authorization Failure", "Failed to authorize request");
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);
            return DONE;
        }
        RA::Audit(EV_AUTHZ_SUCCESS, AUDIT_MSG_AUTHZ, userid, "select_config_parameter", "Success", "Tokendb user authorization");

        char *conf_type = NULL;
        conf_type = get_field(query, "type=", SHORT_LEN);

        if (conf_type == NULL) {
            error_out("Invalid Invocation: Type is NULL", "Type is NULL");
            do_free(buf);
            do_strfree(uri);
            do_strfree(query);
            return DONE;
        }

        PR_snprintf( ( char * ) configname, 256,
            "target.%s.list", conf_type );
        const char *conf_list = RA::GetConfigStore()->GetConfigAsString( configname );

        PR_snprintf( ( char * ) configname, 256, "target.%s.displayname", conf_type ); 
        const char *disp_conf_type = (char *) RA::GetConfigStore()->GetConfigAsString( configname );

        PR_snprintf( injection, injection_size,
                     "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid, "\";\n",
                     "var conf_type = \"", conf_type, "\";\n",
                     "var disp_conf_type = \"", disp_conf_type, "\";\n",
                     "var conf_list = \"", (conf_list != NULL)? conf_list : "", "\";\n");

        do_free(conf_type);
        // do_free(conf_list);
        add_authorization_data(userid, is_admin, is_operator, is_agent, &injection, &injection_size, fixed_injection); //needed?
         safe_injection_strcat(&injection, &injection_size ,JS_STOP, fixed_injection );

        buf = getData( selectConfigTemplate, injection );
    }

    if( buf != NULL ) {
        len = PL_strlen( buf );

        ( void ) ap_rwrite( ( const void * ) buf, len, rq );

        do_free(buf);
    }
    do_free(userid);
    do_strfree(uri);
    do_strfree(query);

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
        ap_log_error( APLOG_MARK, APLOG_ERR, APLOG_MODULE_INDEX, 0, NULL,
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

