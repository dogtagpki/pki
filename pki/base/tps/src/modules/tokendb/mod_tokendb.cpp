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

#include "apr_strings.h"

#include "cms/CertEnroll.h"
#include "engine/RA.h"
#include "tus/tus_db.h"

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

#define BASE64_HEADER "-----BEGIN CERTIFICATE-----\n"
#define BASE64_FOOTER "-----END CERTIFICATE-----\n"

#define TOKENDB_AGENTS_IDENTIFIER         "TUS Agents"
#define TOKENDB_ADMINISTRATORS_IDENTIFIER "TUS Administrators"

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
static char *newTemplate                     = NULL;
static char *searchTemplate                  = NULL;
static char *searchResultTemplate            = NULL;
static char *searchAdminTemplate             = NULL;
static char *searchAdminResultTemplate       = NULL;
static char *searchActivityTemplate          = NULL;
static char *searchCertificateTemplate       = NULL;
static char *searchCertificateResultTemplate = NULL;
static char *searchActivityResultTemplate    = NULL;
static char *editAdminTemplate               = NULL;
static char *editAdminResultTemplate         = NULL;
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

static int sendInPieces = 0;



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

    mods = allocate_modifications( n );

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

    if( ( s = PL_strstr( buf, "tokendb.editAdminTemplate=" ) ) != NULL ) {
        s += PL_strlen( "tokendb.editAdminTemplate=" );
        v = s;

        while( *s != '\x0D' && *s != '\x0A' && *s != '\0' && 
               ( PRUint32 ) ( s - buf ) < size ) {
            s++;
        }

        n = s - v;

        s = PL_strndup( v, n );
        if( s != NULL ) {
            if( editAdminTemplate != NULL ) {
                PL_strfree( editAdminTemplate );
                editAdminTemplate = NULL;
            }
            editAdminTemplate = s;
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

    if( ( s = PL_strstr( buf, "tokendb.editAdminResultTemplate=" ) ) !=
        NULL ) {
        s += PL_strlen( "tokendb.editAdminResultTemplate=" );
        v = s;

        while( *s != '\x0D' && *s != '\x0A' && *s != '\0' && 
               ( PRUint32 ) ( s - buf ) < size ) {
            s++;
        }

        n = s - v;

        s = PL_strndup( v, n );
        if( s != NULL ) {
            if( editAdminResultTemplate != NULL ) {
                PL_strfree( editAdminResultTemplate );
                editAdminResultTemplate = NULL;
            }
            editAdminResultTemplate = s;
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
    char **a            = NULL;
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
    char *statusString;
    char *s1, *s2;
    char *end;
    char **attr_values;

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

            return DECLINED;
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
          PR_snprintf( injection, MAX_INJECTION_SIZE,
                       "%s%s%s%s%s", JS_START,
                       "var error = \"Error: ",
                       "Authentication Failure",
                       "\";\n", JS_STOP );

          buf = getData( errorTemplate, injection );

          ap_log_error( ( const char * ) "tus", __LINE__,
                        APLOG_ERR, 0, rq->server,
                        ( const char * ) "Failed to authenticate request" );

          ( void ) ap_rwrite( ( const void * ) buf, PL_strlen( buf ), rq );

          if( buf != NULL ) {
              PR_Free( buf );
              buf = NULL;
          }

          return DECLINED;
    }

    tokendbDebug( cert );
    tokendbDebug( "\n" );

    base64_cert = stripBase64HeaderAndFooter( cert );

    tokendbDebug( base64_cert );
    tokendbDebug( "\n" );

    userid = tus_authenticate( base64_cert );
    if( userid == NULL ) {
          PR_snprintf( injection, MAX_INJECTION_SIZE,
                       "%s%s%s%s%s", JS_START,
                       "var error = \"Error: ",
                       "Authentication Failure",
                       "\";\n", JS_STOP );

          buf = getData( errorTemplate, injection );

          ap_log_error( ( const char * ) "tus", __LINE__,
                        APLOG_ERR, 0, rq->server,
                        ( const char * ) "Failed to authenticate request" );

          ( void ) ap_rwrite( ( const void * ) buf, PL_strlen( buf ), rq );

          if( buf != NULL ) {
              PR_Free( buf );
              buf = NULL;
          }

          return DECLINED;
    }

    if( rq->uri != NULL ) {
        uri = PL_strdup( rq->uri );
    }

    if( rq->args != NULL ) {
        query = PL_strdup( rq->args );
    }

    RA::Debug( "mod_tokendb_handler::mod_tokendb_handler",
               "uri='%s' params='%s'",
               uri, ( query==NULL?"":query ) );

    if( query == NULL ) {
        tokendbDebug( "authorization\n" );
        if( !tus_authorize( TOKENDB_AGENTS_IDENTIFIER, userid ) ) {
            PR_snprintf( injection, MAX_INJECTION_SIZE,
                         "%s%s%s%s%s", JS_START,
                         "var error = \"Error: ",
                         "Authorization Failure",
                         "\";\n", JS_STOP );

            buf = getData( errorTemplate, injection );

            ap_log_error( ( const char * ) "tus", __LINE__,
                          APLOG_ERR, 0, rq->server,
                          ( const char * ) "Failed to authorize request" );

            ( void ) ap_rwrite( ( const void * ) buf, PL_strlen( buf ), rq );

            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }

            if( uri != NULL ) {
                PR_Free( uri );
                uri = NULL;
            }

            if( query != NULL ) {
                PR_Free( query );
                query = NULL;
            }

            return DECLINED;
        }

        PR_snprintf( injection, MAX_INJECTION_SIZE,
                     "%s%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n", 
                     "var userid = \"", userid,
                     "\";\n", JS_STOP );

        buf = getData( indexTemplate, injection );
    } else if( ( PL_strstr( query, "op=index_admin" ) ) ) {
        tokendbDebug( "authorization\n" );
        if( !tus_authorize( TOKENDB_AGENTS_IDENTIFIER, userid ) ) {
            PR_snprintf( injection, MAX_INJECTION_SIZE,
                         "%s%s%s%s%s", JS_START,
                        "var error = \"Error: ",
                        "Authorization Failure",
                        "\";\n", JS_STOP );

            buf = getData( errorTemplate, injection );

            ap_log_error( ( const char * ) "tus", __LINE__,
                          APLOG_ERR, 0, rq->server,
                          ( const char * ) "Failed to authorize request" );

            ( void ) ap_rwrite( ( const void * ) buf, PL_strlen( buf ), rq );

            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }

            if( uri != NULL ) {
                PR_Free( uri );
                uri = NULL;
            }

            if( query != NULL ) {
                PR_Free( query );
                query = NULL;
            }

            return DECLINED;
        }

        PR_snprintf( injection, MAX_INJECTION_SIZE,
                     "%s%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n", 
                     "var userid = \"", userid,
                     "\";\n", JS_STOP );

        buf = getData( indexAdminTemplate, injection );
    } else if( ( PL_strstr( query, "op=do_token" ) ) ) {
        tokendbDebug( "authorization\n" );

        if( !tus_authorize( TOKENDB_AGENTS_IDENTIFIER, userid ) ) {
            PR_snprintf( injection, MAX_INJECTION_SIZE,
                         "%s%s%s%s%s", JS_START,
                         "var error = \"Error: ",
                         "Authorization Failure",
                         "\";\n", JS_STOP );

            buf = getData( errorTemplate, injection );

            ap_log_error( ( const char * ) "tus", __LINE__,
                          APLOG_ERR, 0, rq->server,
                          ( const char * ) "Failed to authorize request" );

            ( void ) ap_rwrite( ( const void * ) buf, PL_strlen( buf ), rq );

            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }

            if( uri != NULL ) {
                PR_Free( uri );
                uri = NULL;
            }

            if( query != NULL ) {
                PR_Free( query );
                query = NULL;
            }

            return DECLINED;
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
            }
        }

        /* Is this token physically damaged */
        if( q == 1 ) {

            PR_snprintf((char *)msg, 256,
              "'%s' marked token physically damaged", userid);
            RA::tdb_activity(rq->connection->remote_ip, cuid, "do_token", "initiated",
                     msg, cuidUserId);

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
                            RA::tdb_activity(rq->connection->remote_ip, cuid, "do_token", "initiated", msg, cuidUserId);
                            update_cert_status( attr_cn, "revoked_on_hold" );
                        } else {
                            PR_snprintf((char *)msg, 256, "Certificate '%s' is marked as revoked", attr_cn);
                            RA::tdb_activity(rq->connection->remote_ip, cuid, "do_token", "initiated", msg, cuidUserId);
                            update_cert_status( attr_cn, "revoked" );
                        }

                        if( attr_cn != NULL ) {
                            PL_strfree( attr_cn );
                            attr_cn = NULL;
                        }
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

                if( buf != NULL ) {
                    PR_Free( buf );
                    buf = NULL;
                }

                if( uri != NULL ) {
                    PR_Free( uri );
                    uri = NULL;
                }

                if( query != NULL ) {
                    PR_Free( query );
                    query = NULL;
                }

                return DECLINED;
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

                if( buf != NULL ) {
                    PR_Free( buf );
                    buf = NULL;
                }

                if( uri != NULL ) {
                    PR_Free( uri );
                    uri = NULL;
                }

                if( query != NULL ) {
                    PR_Free( query );
                    query = NULL;
                }

                return DECLINED;
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
                     msg, cuidUserId);

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
                            RA::tdb_activity(rq->connection->remote_ip, cuid, "do_token", "initiated", msg, cuidUserId);
                            update_cert_status( attr_cn, "revoked_on_hold" );
                        } else {
                            PR_snprintf((char *)msg, 256, "Certificate '%s' is marked as revoked", attr_cn);
                            RA::tdb_activity(rq->connection->remote_ip, cuid, "do_token", "initiated", msg, cuidUserId);
                            update_cert_status( attr_cn, "revoked" );
                        }

                        if( attr_cn != NULL ) {
                            PL_strfree( attr_cn );
                            attr_cn = NULL;
                        }
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

                if( buf != NULL ) {
                    PR_Free( buf );
                    buf = NULL;
                }

                if( uri != NULL ) {
                    PR_Free( uri );
                    uri = NULL;
                }

                if( query != NULL ) {
                    PR_Free( query );
                    query = NULL;
                }

                return DECLINED;
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

                if( buf != NULL ) {
                    PR_Free( buf );
                    buf = NULL;
                }

                if( uri != NULL ) {
                    PR_Free( uri );
                    uri = NULL;
                }

                if( query != NULL ) {
                    PR_Free( query );
                    query = NULL;
                }

                return DECLINED;
            }

        /* Is this token temporarily lost? */
        } else if( q == 3 ) {

            PR_snprintf((char *)msg, 256,
              "'%s' marked token temporarily lost", userid);
            RA::tdb_activity(rq->connection->remote_ip, cuid, "do_token", "initiated",
                     msg, cuidUserId);

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
                            RA::tdb_activity(rq->connection->remote_ip, cuid, "do_token", "initiated", msg, cuidUserId);
                            update_cert_status( attr_cn, "revoked_on_hold" );
                        } else {
                            PR_snprintf((char *)msg, 256, "Certificate '%s' is marked as revoked", attr_cn);
                            RA::tdb_activity(rq->connection->remote_ip, cuid, "do_token", "initiated", msg, cuidUserId);
                            update_cert_status( attr_cn, "revoked" );
                        }
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
                if( buf != NULL ) {
                    PR_Free( buf );
                    buf = NULL;
                }

                if( uri != NULL ) {
                    PR_Free( uri );
                    uri = NULL;
                }

                if( query != NULL ) {
                    PR_Free( query );
                    query = NULL;
                }

                return DECLINED;
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

                if( buf != NULL ) {
                    PR_Free( buf );
                    buf = NULL;
                }

                if( uri != NULL ) {
                    PR_Free( uri );
                    uri = NULL;
                }

                if( query != NULL ) {
                    PR_Free( query );
                    query = NULL;
                }

                return DECLINED;
            }

        /* Is this temporarily lost token found? */
        } else if( q == 4 ) {

            PR_snprintf((char *)msg, 256,
              "'%s' marked lost token found", userid);
            RA::tdb_activity(rq->connection->remote_ip, cuid, "do_token", "initiated",
                     msg, cuidUserId);

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
                          RA::tdb_activity(rq->connection->remote_ip, cuid, "do_token", "initiated", msg, cuidUserId);
                        update_cert_status( attr_cn, "active" );
                        
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

                if( buf != NULL ) {
                    PR_Free( buf );
                    buf = NULL;
                }

                if( uri != NULL ) {
                    PR_Free( uri );
                    uri = NULL;
                }

                if( query != NULL ) {
                    PR_Free( query );
                    query = NULL;
                }

                return DECLINED;
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

                if( buf != NULL ) {
                    PR_Free( buf );
                    buf = NULL;
                }

                if( uri != NULL ) {
                    PR_Free( uri );
                    uri = NULL;
                }

                if( query != NULL ) {
                    PR_Free( query );
                    query = NULL;
                }

                return DECLINED;
            }

        /* Does this temporarily lost token become permanently lost? */
        } else if (q == 5) {

            PR_snprintf((char *)msg, 256,
              "'%s' marked lost token permanently lost", userid);
            RA::tdb_activity(rq->connection->remote_ip, cuid, "do_token", "initiated",
                     msg, cuidUserId);

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
                        }

                        if( statusNum == 0 ) {
                            statusNum = certEnroll->
                                        RevokeCertificate( revokeReason,
                                                           serial,
                                                           connid, 
                                                           statusString );
                        }

                        if( strcmp( revokeReason, "6" ) == 0 ) {
                          PR_snprintf((char *)msg, 256, "Certificate '%s' is marked as revoked_on_hold", attr_cn);
                          RA::tdb_activity(rq->connection->remote_ip, cuid, "do_token", "initiated", msg, cuidUserId);
                            update_cert_status( attr_cn, "revoked_on_hold" );
                        } else {
                          PR_snprintf((char *)msg, 256, "Certificate '%s' is marked as revoked", attr_cn);
                          RA::tdb_activity(rq->connection->remote_ip, cuid, "do_token", "initiated", msg, cuidUserId);
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
                     "%s%s%d%s%s%s%s%s%s%s%s", JS_START,
                     "var rc = \"", rc, "\";\n",
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid,
                     "\";\n", JS_STOP );

        buf = getData( doTokenTemplate, injection );
    } else if( ( PL_strstr( query, "op=revoke" ) ) ) {
        tokendbDebug("authorization\n");

        if( !tus_authorize( TOKENDB_AGENTS_IDENTIFIER, userid ) ) {
            PR_snprintf( injection, MAX_INJECTION_SIZE,
                         "%s%s%s%s%s", JS_START,
                        "var error = \"Error: ",
                        "Authorization Failure",
                        "\";\n", JS_STOP );

            buf = getData( errorTemplate, injection );
            ap_log_error( ( const char * ) "tus", __LINE__,
                          APLOG_ERR, 0, rq->server,
                          ( const char * ) "Failed to authorize request" );

            ( void ) ap_rwrite( ( const void * ) buf, PL_strlen( buf ), rq );

            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }

            if( uri != NULL ) {
                PR_Free( uri );
                uri = NULL;
            }

            if( query != NULL ) {
                PR_Free( query );
                query = NULL;
            }

            return DECLINED;
        }

        /* XXX - chrisho */
        /* op=revoke */
        /* tid=cuid */

        PR_snprintf( injection, MAX_INJECTION_SIZE,
                     "%s%s%s%s%s%s%s%s", JS_START,
                    "var uriBase = \"", uri, "\";\n",
                    "var userid = \"", userid,
                    "\";\n", JS_STOP );

        buf = getData( revokeTemplate, injection );
    } else if( ( PL_strstr( query, "op=search_activity" ) ) ) {
        tokendbDebug( "authorization\n" );

        if( !tus_authorize( TOKENDB_AGENTS_IDENTIFIER, userid ) ) {
            PR_snprintf( injection, MAX_INJECTION_SIZE,
                         "%s%s%s%s%s", JS_START,
                         "var error = \"Error: ",
                         "Authorization Failure",
                         "\";\n", JS_STOP );

            buf = getData( errorTemplate, injection );

            ap_log_error( ( const char * ) "tus", __LINE__,
                          APLOG_ERR, 0, rq->server,
                          ( const char * ) "Failed to authorize request" );

            ( void ) ap_rwrite( ( const void * ) buf, PL_strlen( buf ), rq );

            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }

            if( uri != NULL ) {
                PR_Free( uri );
                uri = NULL;
            }

            if( query != NULL ) {
                PR_Free( query );
                query = NULL;
            }

            return DECLINED;
        }

        PR_snprintf( injection, MAX_INJECTION_SIZE,
                     "%s%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid,
                     "\";\n", JS_STOP );

        buf = getData( searchActivityTemplate, injection );
    } else if( ( PL_strstr( query, "op=search_admin" ) ) ) {
        tokendbDebug( "authorization\n" );

        if( !tus_authorize( TOKENDB_ADMINISTRATORS_IDENTIFIER, userid ) ) {
            PR_snprintf( injection, MAX_INJECTION_SIZE,
                         "%s%s%s%s%s", JS_START,
                         "var error = \"Error: ",
                         "Authorization Failure",
                         "\";\n", JS_STOP );

            buf = getData( errorTemplate, injection );

            ap_log_error( ( const char * ) "tus", __LINE__,
                          APLOG_ERR, 0, rq->server,
                          ( const char * ) "Failed to authorize request" );

            ( void ) ap_rwrite( ( const void * ) buf, PL_strlen( buf ), rq );

            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }

            if( uri != NULL ) {
                PR_Free( uri );
                uri = NULL;
            }

            if( query != NULL ) {
                PR_Free( query );
                query = NULL;
            }

            return DECLINED;
        }

        PR_snprintf( injection, MAX_INJECTION_SIZE,
                     "%s%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid,
                     "\";\n", JS_STOP );

        buf = getData( searchAdminTemplate, injection );
    } else if( ( PL_strstr( query, "op=search_certificate" ) ) ) {
        tokendbDebug( "authorization\n" );
        if( !tus_authorize( TOKENDB_AGENTS_IDENTIFIER, userid ) ) {
            PR_snprintf( injection, MAX_INJECTION_SIZE,
                         "%s%s%s%s%s", JS_START,
                         "var error = \"Error: ",
                         "Authorization Failure",
                         "\";\n", JS_STOP );

            buf = getData( errorTemplate, injection );

            ap_log_error( ( const char * ) "tus", __LINE__,
                          APLOG_ERR, 0, rq->server,
                          ( const char * ) "Failed to authorize request" );

            ( void ) ap_rwrite( ( const void * ) buf, PL_strlen( buf ), rq );

            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }

            if( uri != NULL ) {
                PR_Free( uri );
                uri = NULL;
            }

            if( query != NULL ) {
                PR_Free( query );
                query = NULL;
            }

            return DECLINED;
        }

        PR_snprintf( injection, MAX_INJECTION_SIZE,
                     "%s%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid,
                     "\";\n", JS_STOP );

        buf = getData( searchCertificateTemplate, injection );
    } else if( ( PL_strstr( query, "op=search" ) ) ) {
        tokendbDebug( "authorization\n" );
        if( !tus_authorize( TOKENDB_AGENTS_IDENTIFIER, userid ) ) {
            PR_snprintf( injection, MAX_INJECTION_SIZE,
                         "%s%s%s%s%s", JS_START,
                         "var error = \"Error: ",
                         "Authorization Failure",
                         "\";\n", JS_STOP );

            buf = getData( errorTemplate, injection );

            ap_log_error( ( const char * ) "tus", __LINE__,
                          APLOG_ERR, 0, rq->server,
                          ( const char * ) "Failed to authorize request" );

            ( void ) ap_rwrite( ( const void * ) buf, PL_strlen( buf ), rq );

            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }

            if( uri != NULL ) {
                PR_Free( uri );
                uri = NULL;
            }

            if( query != NULL ) {
                PR_Free( query );
                query = NULL;
            }

            return DECLINED;
        }

        PR_snprintf( injection, MAX_INJECTION_SIZE,
                     "%s%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid,
                     "\";\n", JS_STOP );

        buf = getData( searchTemplate, injection );
    } else if( ( PL_strstr( query, "op=new" ) ) ) {
        tokendbDebug( "authorization\n" );
        if( !tus_authorize( TOKENDB_ADMINISTRATORS_IDENTIFIER, userid ) ) {
            PR_snprintf( injection, MAX_INJECTION_SIZE,
                         "%s%s%s%s%s", JS_START,
                         "var error = \"Error: ",
                         "Authorization Failure",
                         "\";\n", JS_STOP );

            buf = getData( errorTemplate, injection );

            ap_log_error( ( const char * ) "tus", __LINE__,
                          APLOG_ERR, 0, rq->server,
                          ( const char * ) "Failed to authorize request" );

            ( void ) ap_rwrite( ( const void * ) buf, PL_strlen( buf ), rq );

            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }

            if( uri != NULL ) {
                PR_Free( uri );
                uri = NULL;
            }

            if( query != NULL ) {
                PR_Free( query );
                query = NULL;
            }

            return DECLINED;
        }

        PR_snprintf( injection, MAX_INJECTION_SIZE,
                     "%s%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n", 
                     "var userid = \"", userid,
                     "\";\n", JS_STOP );

        buf = getData( newTemplate,injection );
    } else if( ( PL_strstr( query, "op=view_admin" ) )       ||
               ( PL_strstr( query, "op=view_certificate" ) ) ||
               ( PL_strstr( query, "op=view_activity" ) )    ||
               ( PL_strstr( query, "op=view" ) )             ||
               ( PL_strstr( query, "op=edit_admin" ) )       ||
               ( PL_strstr( query, "op=edit" ) )             ||
               ( PL_strstr( query, "op=show_certificate" ) ) ||
               ( PL_strstr( query, "op=show" ) )             ||
               ( PL_strstr( query, "op=do_confirm_token" ) ) ||
               ( PL_strstr( query, "op=confirm" ) ) ) {
        if( ( PL_strstr( query, "op=confirm" ) )    ||
            ( PL_strstr( query, "op=view_admin" ) ) ||
            ( PL_strstr( query, "op=show_admin" ) ) ||
            ( PL_strstr( query, "op=edit_admin" ) ) ) {
            tokendbDebug( "authorization\n" );

            if( !tus_authorize( TOKENDB_ADMINISTRATORS_IDENTIFIER, userid ) ) {
                PR_snprintf( injection, MAX_INJECTION_SIZE,
                             "%s%s%s%s%s", JS_START,
                             "var error = \"Error: ",
                             "Authorization Failure",
                             "\";\n", JS_STOP );

                buf = getData( errorTemplate, injection );

                ap_log_error( ( const char * ) "tus", __LINE__,
                              APLOG_ERR, 0, rq->server,
                              ( const char * ) "Failed to authorize request" );

                ( void ) ap_rwrite( ( const void * ) buf,
                                    PL_strlen( buf ), rq );

                if( buf != NULL ) {
                  PR_Free( buf );
                  buf = NULL;
                }

                if( uri != NULL ) {
                    PR_Free( uri );
                    uri = NULL;
                }

                if( query != NULL ) {
                    PR_Free( query );
                    query = NULL;
                }

                return DECLINED;
            }
        } else {
            tokendbDebug( "authorization\n" );

            if( !tus_authorize( TOKENDB_AGENTS_IDENTIFIER, userid ) ) 
            {
                PR_snprintf( injection, MAX_INJECTION_SIZE,
                             "%s%s%s%s%s", JS_START,
                            "var error = \"Error: ",
                            "Authorization Failure",
                            "\";\n", JS_STOP );

                buf = getData( errorTemplate, injection );

                ap_log_error( ( const char * ) "tus", __LINE__,
                              APLOG_ERR, 0, rq->server,
                              ( const char * ) "Failed to authorize request" );

                ( void ) ap_rwrite( ( const void * ) buf,
                                    PL_strlen( buf ), rq );

                if( buf != NULL ) {
                    PR_Free( buf );
                    buf = NULL;
                }

                if( uri != NULL ) {
                    PR_Free( uri );
                    uri = NULL;
                }

                if( query != NULL ) {
                    PR_Free( query );
                    query = NULL;
                }

                return DECLINED;
            }
        }

        if( PL_strstr( query, "op=view_activity" ) ) {
            getActivityFilter( filter, query );
        } else if( PL_strstr( query, "op=view_certificate" ) ) {
            getCertificateFilter( filter, query );
        } else if( PL_strstr( query, "op=show_certificate" ) ) {
            getCertificateFilter( filter, query );
        } else {
            getFilter( filter, query );
        }

        tokendbDebug( "looking for filter:" );
        tokendbDebug( filter );
        tokendbDebug( "\n" );

        /*  retrieve maxCount */
        s1 = PL_strstr( query, "maxCount=" );
        if( s1 == NULL ) {
            maxReturns = 20;
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

        if( PL_strstr( query, "op=view_activity" ) ) {
            status = find_tus_activity_entries_no_vlv( filter, &result, 0 );
        } else if( PL_strstr( query, "op=view_certificate" ) ) {

            ap_log_error( ( const char * ) "tus", __LINE__,
                          APLOG_ERR, 0, rq->server,
                          ( const char * ) "LDAP filter: %s", filter);

            status = find_tus_certificate_entries_by_order_no_vlv( filter,
                                                                   &result,
                                                                   0 );
        } else if( PL_strstr( query, "op=show_certificate" ) ||
                   PL_strstr( query, "op=view_certificate" ) ) {
            /* status = find_tus_certificate_entries( filter,
                                                      maxReturns,
                                                      &result ); */

            ap_log_error( ( const char * ) "tus", __LINE__,
                          APLOG_ERR, 0, rq->server,
                          ( const char * ) "LDAP filter: %s", filter);

            status = find_tus_certificate_entries_by_order_no_vlv( filter,
                                                                   &result,
                                                                   0 );
        } else if( PL_strstr( query, "op=show_admin" ) ||
                   PL_strstr( query, "op=show" )       ||
                   PL_strstr( query, "op=edit_admin" ) ||
                   PL_strstr( query, "op=confirm" )    ||
                   PL_strstr( query, "op=do_confirm_token" ) ) {
            status = find_tus_token_entries_no_vlv( filter, &result, 0 );
        } else {
            status = find_tus_db_entries( filter, maxReturns, &result );
        }

        if( status != LDAP_SUCCESS ) {
            PR_snprintf( injection, MAX_INJECTION_SIZE,
                         "%s%s%s%s%s", JS_START,
                         "var error = \"LDAP search error: ",
                         ldap_err2string( status ),
                         "\";\n", JS_STOP );

            buf = getData( errorTemplate, injection );

            ap_log_error( ( const char * ) "tus", __LINE__,
                          APLOG_ERR, 0, rq->server,
                          ( const char * ) "LDAP search error: %s",
                          ldap_err2string( status ) );

            ( void ) ap_rwrite( ( const void * ) buf, PL_strlen( buf ), rq );

            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }

            if( uri != NULL ) {
                PR_Free( uri );
                uri = NULL;
            }

            if( query != NULL ) {
                PR_Free( query );
                query = NULL;
            }

            return DECLINED;
        }

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
            if( sendInPieces && PL_strstr( query, "op=view_activity" ) ) {
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

        if( PL_strstr( query, "op=view_activity" ) ) {
            a = get_activity_attributes();
        } else if( PL_strstr( query, "op=view_certificate" ) ) {
            a = get_certificate_attributes();
        } else if( PL_strstr( query, "op=show_certificate" ) ) {
            a = get_certificate_attributes();
        } else {
            a = get_token_attributes();
        }

        for( e = get_first_entry( result );
             ( maxReturns > 0 ) && ( e != NULL );
             e = get_next_entry( e ) ) {
            maxReturns--;

            PL_strcat( injection, "var o = new Object();\n" );

            for( n = 0; a[n] != NULL; n++ ) {
                /* Get the values of the attribute. */
                if( ( vals = get_attribute_values( e, a[n] ) ) != NULL ) {
                    PL_strcat( injection, "o." );
                    PL_strcat( injection, a[n] );
                    PL_strcat( injection, " = " );

                    for( i = 0; vals[i] != NULL; i++ ) {
                        if( i > 0 ) {
                            PL_strcat( injection, "#" );
                        } else {
                            PL_strcat( injection, "\"" );
                        }

                        PL_strcat( injection, vals[i] );
                    }

                    if( i > 0 ) {
                        PL_strcat( injection, "\";\n" );
                    } else {
                        PL_strcat( injection, "null;\n" );
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

            entryNum++;

            if( entryNum == 1 && nEntries > 1 && sendPieces == 0 ) {
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
            if( PL_strstr( query, "op=view_activity" ) ) {
                buf = getData( searchActivityResultTemplate, injection );
            } else if( PL_strstr( query, "op=view_certificate" ) ) {
                buf = getData( searchCertificateResultTemplate, injection );
            } else if( PL_strstr( query, "op=edit_admin" ) ) {
                buf = getData( editAdminTemplate, injection );
            } else if( PL_strstr( query, "op=show_admin" ) ) {
                buf = getData( showAdminTemplate, injection );
            } else if( PL_strstr( query, "op=view_admin" ) ) {
                buf = getData( searchAdminResultTemplate, injection );
            } else if( PL_strstr( query, "op=view" ) ) {
                buf = getData( searchResultTemplate, injection );
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
            }
        }

        if( injection != fixed_injection ) {
            if( injection != NULL ) {
                PR_Free( injection );
                injection = NULL;
            }

            injection = fixed_injection;
        }
    } else if( PL_strstr( query, "op=save_admin" ) ) {
        tokendbDebug( "authorization\n" );

        if( !tus_authorize( TOKENDB_ADMINISTRATORS_IDENTIFIER, userid ) ) {
            PR_snprintf( injection, MAX_INJECTION_SIZE,
                         "%s%s%s%s%s", JS_START,
                         "var error = \"Error: ",
                         "Authorization Failure",
                         "\";\n", JS_STOP );

            buf = getData( errorTemplate, injection );

            ap_log_error( ( const char * ) "tus", __LINE__,
                          APLOG_ERR, 0, rq->server,
                          ( const char * ) "Failed to authorize request" );

            ( void ) ap_rwrite( ( const void * ) buf, PL_strlen( buf ), rq );

            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }

            if( uri != NULL ) {
                PR_Free( uri );
                uri = NULL;
            }

            if( query != NULL ) {
                PR_Free( query );
                query = NULL;
            }

            return DECLINED;
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
            PR_snprintf( injection, MAX_INJECTION_SIZE,
                         "%s%s%s%s%s", JS_START,
                         "var error = \"LDAP modify error: ",
                         ldap_err2string( status ),
                         "\";\n", JS_STOP );

            buf = getData( errorTemplate, injection );

            ap_log_error( ( const char * ) "tus", __LINE__,
                          APLOG_ERR, 0, rq->server,
                          ( const char * ) "LDAP error: %s",
                          ldap_err2string( status ) );

            ( void ) ap_rwrite( ( const void * ) buf, PL_strlen( buf ), rq );

            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }

            if( uri != NULL ) {
                PR_Free( uri );
                uri = NULL;
            }

            if( query != NULL ) {
                PR_Free( query );
                query = NULL;
            }

            return DECLINED;
        }

        PR_snprintf( injection, MAX_INJECTION_SIZE,
                     "%s%s%s%s%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid, "\";\n",
                     "var tid = \"", filter, "\";\n", JS_STOP );

        buf = getData( editAdminResultTemplate, injection );
    } else if( PL_strstr( query, "op=save" ) ) {
        tokendbDebug( "authorization\n" );

        if( !tus_authorize( TOKENDB_AGENTS_IDENTIFIER, userid ) ) {
            PR_snprintf( injection, MAX_INJECTION_SIZE,
                         "%s%s%s%s%s", JS_START,
                         "var error = \"Error: ",
                         "Authorization Failure",
                         "\";\n", JS_STOP );

            buf = getData( errorTemplate, injection );

            ap_log_error( ( const char * ) "tus", __LINE__,
                          APLOG_ERR, 0, rq->server,
                          ( const char * ) "Failed to authorize request" );

            ( void ) ap_rwrite( ( const void * ) buf, PL_strlen( buf ), rq );

            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }

            if( uri != NULL ) {
                PR_Free( uri );
                uri = NULL;
            }

            if( query != NULL ) {
                PR_Free( query );
                query = NULL;
            }

            return DECLINED;
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
            PR_snprintf( injection, MAX_INJECTION_SIZE,
                         "%s%s%s%s%s", JS_START,
                         "var error = \"LDAP modify error: ",
                         ldap_err2string( status ),
                         "\";\n", JS_STOP );

            buf = getData( errorTemplate, injection );

            ap_log_error( ( const char * ) "tus", __LINE__,
                          APLOG_ERR, 0, rq->server,
                          ( const char * ) "LDAP error: %s",
                          ldap_err2string( status ) );

            ( void ) ap_rwrite( ( const void * ) buf, PL_strlen( buf ), rq );

            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }

            if( uri != NULL ) {
                PR_Free( uri );
                uri = NULL;
            }

            if( query != NULL ) {
                PR_Free( query );
                query = NULL;
            }

            return DECLINED;
        }

        PR_snprintf( injection, MAX_INJECTION_SIZE,
                     "%s%s%s%s%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid, "\";\n",
                     "var tid = \"", filter, "\";\n", JS_STOP );

        buf = getData( editResultTemplate, injection );

    } else if( PL_strstr( query, "op=add" ) ) {
        tokendbDebug( "authorization\n" );

        if( !tus_authorize( TOKENDB_ADMINISTRATORS_IDENTIFIER, userid ) ) {
            PR_snprintf( injection, MAX_INJECTION_SIZE,
                         "%s%s%s%s%s", JS_START,
                         "var error = \"Error: ",
                         "Authorization Failure",
                         "\";\n", JS_STOP );

            buf = getData( errorTemplate, injection );

            ap_log_error( ( const char * ) "tus", __LINE__,
                          APLOG_ERR, 0, rq->server,
                          ( const char * ) "Failed to authorize request" );

            ( void ) ap_rwrite( ( const void * ) buf, PL_strlen( buf ), rq );

            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }

            if( uri != NULL ) {
                PR_Free( uri );
                uri = NULL;
            }

            if( query != NULL ) {
                PR_Free( query );
                query = NULL;
            }

            return DECLINED;
        }

        getCN( filter, query );

        PR_snprintf((char *)msg, 256,
            "'%s' has created new token", userid);
        RA::tdb_activity(rq->connection->remote_ip, filter, "add", "token", msg, "");

        if( strcmp( filter, "" ) == 0 ) {
            PR_snprintf( injection, MAX_INJECTION_SIZE,
                         "%s%s%s%s%s", JS_START,
                          "var error = \"Error: ",
                          "No Token ID Found",
                          "\";\n", JS_STOP );

            buf = getData( errorTemplate, injection );

            ap_log_error( ( const char * ) "tus", __LINE__,
                          APLOG_ERR, 0, rq->server,
                          ( const char * ) "Failed to authorize request" );

            ( void ) ap_rwrite( ( const void * ) buf, PL_strlen( buf ), rq );

            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }

            if( uri != NULL ) {
                PR_Free( uri );
                uri = NULL;
            }

            if( query != NULL ) {
                PR_Free( query );
                query = NULL;
            }

            return DECLINED;
        }

        status = add_default_tus_db_entry( NULL, userid,
                                           filter, "uninitialized",
                                           NULL, NULL );

        if( status != LDAP_SUCCESS ) {
            PR_snprintf( injection, MAX_INJECTION_SIZE,
                         "%s%s%s%s%s", JS_START,
                        "var error = \"LDAP add error: ",
                        ldap_err2string( status ),
                        "\";\n", JS_STOP );

            buf = getData( errorTemplate, injection );

            ap_log_error( ( const char * ) "tus", __LINE__,
                          APLOG_ERR, 0, rq->server,
                          ( const char * ) "LDAP error: %s",
                          ldap_err2string( status ) );

            ( void ) ap_rwrite( ( const void * ) buf, PL_strlen( buf ), rq );

            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }

            if( uri != NULL ) {
                PR_Free( uri );
                uri = NULL;
            }

            if( query != NULL ) {
                PR_Free( query );
                query = NULL;
            }

            return DECLINED;
        }

        PR_snprintf( injection, MAX_INJECTION_SIZE,
                     "%s%s%s%s%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid, "\";\n",
                     "var tid = \"", filter, "\";\n", JS_STOP );

        buf = getData( addResultTemplate, injection );
    } else if( PL_strstr( query, "op=delete" ) ) {
        tokendbDebug( "authorization\n" );

        if( !tus_authorize( TOKENDB_ADMINISTRATORS_IDENTIFIER, userid ) ) {
            PR_snprintf( injection, MAX_INJECTION_SIZE,
                         "%s%s%s%s%s", JS_START,
                         "var error = \"Error: ",
                         "Authorization Failure", "\";\n", JS_STOP );

            buf = getData( errorTemplate, injection );

            ap_log_error( ( const char * ) "tus", __LINE__,
                          APLOG_ERR, 0, rq->server,
                          ( const char * ) "Failed to authorize request" );

            ( void ) ap_rwrite( ( const void * ) buf, PL_strlen( buf ), rq );

            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }

            if( uri != NULL ) {
                PR_Free( uri );
                uri = NULL;
            }

            if( query != NULL ) {
                PR_Free( query );
                query = NULL;
            }

            return DECLINED;
        }

        getCN( filter, query );

        PR_snprintf((char *)msg, 256,
            "'%s' has deleted token", userid);
        RA::tdb_activity(rq->connection->remote_ip, filter, "delete", "token", msg, "");

        status = delete_tus_db_entry( userid, filter );

        if( status != LDAP_SUCCESS ) {
            PR_snprintf( injection, MAX_INJECTION_SIZE,
                         "%s%s%s%s%s", JS_START,
                         "var error = \"LDAP delete error: ",
                         ldap_err2string( status ),
                         "\";\n", JS_STOP );

            buf = getData( errorTemplate, injection );

            ap_log_error( ( const char * ) "tus", __LINE__,
                          APLOG_ERR, 0, rq->server,
                          ( const char * ) "LDAP error: %s",
                          ldap_err2string( status ) );

            ( void ) ap_rwrite( ( const void * ) buf, PL_strlen( buf ), rq );

            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }

            if( uri != NULL ) {
                PR_Free( uri );
                uri = NULL;
            }

            if( query != NULL ) {
                PR_Free( query );
                query = NULL;
            }

            return DECLINED;
        }

        PR_snprintf( injection, MAX_INJECTION_SIZE,
                     "%s%s%s%s%s%s%s%s%s%s%s", JS_START,
                     "var uriBase = \"", uri, "\";\n",
                     "var userid = \"", userid, "\";\n",
                     "var tid = \"", filter, "\";\n", JS_STOP );

        buf = getData( deleteResultTemplate, injection );
    } else if( PL_strstr( query, "op=load" ) ) {
        tokendbDebug( "authorization\n" );

        if( !tus_authorize( TOKENDB_AGENTS_IDENTIFIER, userid ) ) {
            PR_snprintf( injection, MAX_INJECTION_SIZE,
                         "%s%s%s%s%s", JS_START,
                         "var error = \"Error: ",
                         "Authorization Failure", "\";\n", JS_STOP );

            buf = getData( errorTemplate, injection );

            ap_log_error( ( const char * ) "tus", __LINE__,
                          APLOG_ERR, 0, rq->server,
                          ( const char * ) "Failed to authorize request" );

            ( void ) ap_rwrite( ( const void * ) buf, PL_strlen( buf ), rq );

            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }

            if( uri != NULL ) {
                PR_Free( uri );
                uri = NULL;
            }

            if( query != NULL ) {
                PR_Free( query );
                query = NULL;
            }

            return DECLINED;
        }

        getTemplateName( template1, query );

        buf = getData( template1, injection );
    }

    if( buf != NULL ) {
        len = PL_strlen( buf );

        ( void ) ap_rwrite( ( const void * ) buf, len, rq );

        if( buf != NULL ) {
            PR_Free( buf );
            buf = NULL;
        }
    }

    if( uri != NULL ) {
        PR_Free( uri );
        uri = NULL;
    }

    if( query != NULL ) {
        PR_Free( query );
        query = NULL;
    }

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

