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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include "nspr.h"
#include "httpd/httpd.h"
#include "httpd/http_protocol.h"

#include "engine/RA.h"
#include "main/Util.h"
#include "main/RA_Msg.h"
#include "main/RA_pblock.h"
#include "main/RA_Session.h"
#include "msg/RA_Begin_Op_Msg.h"
#include "msg/RA_Login_Response_Msg.h"
#include "msg/RA_Extended_Login_Response_Msg.h"
#include "msg/RA_SecureId_Response_Msg.h"
#include "msg/RA_ASQ_Response_Msg.h"
#include "msg/RA_New_Pin_Response_Msg.h"
#include "msg/RA_Token_PDU_Response_Msg.h"
#include "msg/RA_Login_Request_Msg.h"
#include "msg/RA_Extended_Login_Request_Msg.h"
#include "msg/RA_SecureId_Request_Msg.h"
#include "msg/RA_ASQ_Request_Msg.h"
#include "msg/RA_New_Pin_Request_Msg.h"
#include "msg/RA_Token_PDU_Request_Msg.h"
#include "msg/RA_End_Op_Msg.h"
#include "msg/RA_Status_Update_Request_Msg.h"
#include "msg/RA_Status_Update_Response_Msg.h"
#include "modules/tps/AP_Session.h"
#include "main/Memory.h"
#include "apr_strings.h"

/**
 * http parameters used in the protocol 
 */
#define PARAM_MSG_TYPE                "msg_type"
#define PARAM_OPERATION               "operation"
#define PARAM_INVALID_PW              "invalid_pw"
#define PARAM_BLOCKED                 "blocked"
#define PARAM_SCREEN_NAME             "screen_name"
#define PARAM_PASSWORD                "password"
#define PARAM_PIN_REQUIRED            "pin_required"
#define PARAM_NEXT_VALUE              "next_value"
#define PARAM_VALUE                   "value"
#define PARAM_PIN                     "pin"
#define PARAM_QUESTION                "question"
#define PARAM_ANSWER                  "answer"
#define PARAM_MINIMUM_LENGTH          "minimum_length"
#define PARAM_MAXIMUM_LENGTH          "maximum_length"
#define PARAM_NEW_PIN                 "new_pin"
#define PARAM_PDU_SIZE                "pdu_size"
#define PARAM_PDU_DATA                "pdu_data"
#define PARAM_RESULT                  "result"
#define PARAM_MESSAGE                 "message"
#define PARAM_STATUS                  "current_state"
#define PARAM_INFO                    "next_task_name"
#define PARAM_EXTENSIONS              "extensions"

#define MAX_RA_MSG_SIZE               4096
#define MAX_LOG_MSG_SIZE              4096

// maximum number of digits for message length
#define MAX_LEN_DIGITS                4


static int contains_sensitive_keywords(char *msg)
{
    if (strstr(msg, "password" ) != NULL ) {
      return 1;
    }
    if (strstr(msg, "PASSWORD" ) != NULL ) {
      return 1;
    }
    if (strstr(msg, "new_pin" ) != NULL ) {
      return 1;
    }
    return 0;
}


/**
 * AP_Session represents an active connection between the
 * Registration authority and the token client.
 *
 * Note that AP_Session encapsulates all the glue logic 
 * between Apache and the RA. If we need to go to anther platform 
 * (i.e. NPE, NES, or other web servers) later, we just need 
 * to implement a new Session implementation.
 */
AP_Session::AP_Session( request_rec *rq )
{
    m_rq = rq;
    /* REQUEST_CHUNKED_DECHUNK  If chunked, remove the chunks for me */
    ap_setup_client_block( rq, REQUEST_CHUNKED_DECHUNK);
}


AP_Session::~AP_Session()
{
    /* no clean up */
}


char *AP_Session::GetRemoteIP()
{
    return ( m_rq->connection->client_ip );
}


/**
 * reads from network "s=xx" where xx is the length of the message
 * that follows.  The length is returned as int.
 * @return length in int
 */
static int GetMsgLen( request_rec *rq )
{
    int len=0;
    char msg_len[MAX_LEN_DIGITS]; // msg_len can't take more than 4 digits
    char *p_msg_len = msg_len;
    int sum = 0;

    /* read msg size */
    len = ( int ) ap_get_client_block( rq, p_msg_len,
                                       ( apr_size_t ) 1 ); /* s */
    if( len != 1 ) {
        RA::Error( "AP_Session::GetMsgLen",
                   "ap_get_client_block returned error: %d", len );

        return 0;
    }

    len = ( int ) ap_get_client_block( rq, p_msg_len,
                                       ( apr_size_t ) 1 ); /* = */

    if( len != 1 ) {
        RA::Error( "AP_Session::GetMsgLen",
                   "ap_get_client_block returned error: %d", len );

        return 0;
    }

    while( 1 ) {
        if( sum > ( MAX_LEN_DIGITS -1 ) ) {
            /* the length is too large */
            RA::Error( "AP_Session::ReadMsg", "Message Size is too large." );
            return -1;
        }

        len = ( int ) ap_get_client_block( rq, p_msg_len, ( apr_size_t ) 1 );

        if( len != 1 ) {
            break;   
        }

        if( len != 0 ) {
            if( *p_msg_len == '&' ) {
                break;
            }

            p_msg_len++;
            sum++;
        }
    }

    *p_msg_len = '\0';

    return atoi( msg_len );
}

static int GetMsg( request_rec *rq, char *buf, int size )
{
    int len;
    int sum = 0;
    char *p_msg = buf;

    while( 1 ) {
        len = ( int ) ap_get_client_block( rq, p_msg, ( apr_size_t ) 1 );
        if( len != 1 ) {
            return -1;
        }
        p_msg += len;
        sum += len;
        buf[sum] = '\0';
        if( sum == size ) {
            break;
        }
    }

    buf[sum] = '\0';

    return sum;
}

char *stripEmptyArgs( char *data )
{
    char *n_data = ( char * ) PR_Malloc( strlen( data ) + 2 );
    n_data[0] = '\0';
    int nv_count = 0;

    if( data != NULL && strlen( data ) > 0 ) {
        char *lasts = NULL;
        char *tok = PL_strtok_r( data, " ", &lasts ); 

        while( tok != NULL ) {
            if( tok[strlen( tok )-1] != '=' ) {
                n_data = strcat( n_data, tok );
                n_data = strcat( n_data, " " );
                nv_count++;
            }

            tok = PL_strtok_r( NULL, " ", &lasts ); 
        }
        int len = strlen( n_data );
        n_data[len-1] = '\0';
    }

    if( ( nv_count > MAX_NVS ) || ( n_data[0] == '\0' ) ) {
        PR_Free( n_data );
        n_data = NULL;
    }

    return n_data;
}


int pblock_str2pblock( char *n_data, apr_array_header_t *tm_pblock , request_rec *rec)
{
    int element = 0;

    if( n_data != NULL && strlen( n_data ) > 0 ) {
        char *lasts = NULL;
        char *tok = PL_strtok_r( n_data, " ", &lasts ); 

        /* store each name/value pair in the string into the pblock array */
        while( tok != NULL ) {
            char name[4096];
            char value[4096];

            for( int i = 0; i < ( int ) strlen( tok ); i++ ) {
                if( tok[i] != '=' ) {
                    /* extract and add to the name portion */
                    name[i] = tok[i];
                } else {
                    /* null terminate the name portion */
                    name[i] = '\0';
                    /* extract the entire value portion */
                    strcpy( value, &tok[i+1] );
                    break;
                }
            }

            /* store the name/value pair as an entry in the pblock array */
            ( ( apr_table_entry_t * ) tm_pblock->elts )[element].key =
              apr_pstrdup(rec->pool, name);
            ( ( apr_table_entry_t * ) tm_pblock->elts )[element].val =
              apr_pstrdup(rec->pool, value);

            /* increment the entry to the pblock array */
            element++;

            /* get the next name/value pair from the string */
            tok = PL_strtok_r( NULL, " ", &lasts ); 
        }
    }

    return element;
}


/**
 * Parses the data and creates an RA_pblock to store name/value pairs
 * @param data null-terminated string containing a string with format:
 *        n1=v1&n2=v2&n3=v3&...
 * @return
 *        pointer to RA_pblock if success
 *        NULL if failure;
 */
RA_pblock *AP_Session::create_pblock( char *data )
{
    if( ( data == NULL ) || ( data[0] == '\0' ) ) {
        RA::Error( "AP_Session::create_pblock",
                   "data is NULL" );
        return NULL;
    }

    if(contains_sensitive_keywords(data)) {
      RA::Debug( LL_PER_PDU,
               "AP_Session::create_pblock",
               "Data '(sensitive)'");
    } else {
      RA::Debug( LL_PER_PDU,
               "AP_Session::create_pblock",
               "Data '%s'", data);
    }

    //
    // The data contains a set of name value pairs separated by an '&'
    // (i. e. - n1=v1&n2=v2...).  Replace each '&' with a ' '.
    //
    // Note that since the values are expected to have been url-encoded,
    // they must be url-decoded within the subclass method.
    //
    int i, j;
    int len = strlen( data );

    for( i = 0; i < len; i++ ) {
        // need to check if data[i] is a valid url-encoded char...later
        if( data[i] == '&' ) {
            data[i] = ' ';
        }
    }

    apr_array_header_t *tm_pblock = apr_array_make( m_rq->pool,
                                                    MAX_NVS,
                                                    sizeof( apr_table_entry_t )
                                                  );

    if( tm_pblock == NULL ) {
        RA::Error( "AP_Session::create_pblock",
                   "apr_array_make returns NULL" );
        return NULL;
    }

    //
    // The data is in the format of "name=v1 name=v2 name=v3".  If the data
    // has content like "name=v1 name= name=v3", the pblock_str2pblock will
    // return (-1).  This is because pblock_str2pblock does not know how to
    // handle the case of an empty value.  Therefore, before we invoke
    // pblock_str2pblock, we make sure to remove any input data which
    // contains an empty value.
    //
    char *n_data = stripEmptyArgs( data );
    if( n_data == NULL ) {
        RA::Error( "AP_Session::create_pblock",
                   "stripEmptyArgs was either empty or "
                   "contained more than %d name/value pairs!",
                   MAX_NVS );
        return NULL;
    }

    int tm_nargs = pblock_str2pblock( n_data, tm_pblock , m_rq);
    apr_table_entry_t *pe = NULL;

    RA::Debug( LL_PER_PDU,
               "AP_Session::create_pblock",
               "Found Arguments=%d, nalloc=%d",
               tm_nargs,
               tm_pblock->nalloc );

    // url decode all values and place into Buffer_nv's
    Buffer_nv *tm_nvs[MAX_NVS];

    for( i = 0, j = 0; i < tm_nargs; i++, j++ ) {
        tm_nvs[j] = NULL;

        pe = ( apr_table_entry_t * ) tm_pblock->elts;

        if( pe == NULL ) {
            continue;
        }

        if( ( pe[i].key == NULL ) ||
            ( ( PR_CompareStrings( pe[i].key, "" ) == 1 ) ) ||
            ( pe[i].val == NULL ) ||
            ( ( PR_CompareStrings( pe[i].val, "" ) == 1 ) ) ) {
            RA::Debug( LL_ALL_DATA_IN_PDU,
                       "AP_Session::create_pblock",
                       "name/value pair contains NULL...skip" );
            continue;
        }

        if(contains_sensitive_keywords(pe[i].key)) {
            RA::Debug( LL_PER_PDU,
                       "AP_Session::create_pblock",
                       "entry name=%s, value=<...do not print...>",
                       pe[i].key );
        } else {
            RA::Debug( LL_PER_PDU,
                       "AP_Session::create_pblock",
                       "entry name=%s, value=%s",
                       pe[i].key,
                       pe[i].val );
        }

        Buffer *decoded = NULL;

        decoded = Util::URLDecode( pe[i].val );

        tm_nvs[j] = ( struct Buffer_nv * )
                    PR_Malloc( sizeof( struct Buffer_nv ) );

        if( tm_nvs[j] != NULL ) {
            tm_nvs[j]->name = PL_strdup( pe[i].key );
            tm_nvs[j]->value_s =  PL_strdup( pe[i].val );
            tm_nvs[j]->value = decoded;
        } else {
            RA::Debug( LL_PER_PDU,
                       "AP_Session::create_pblock",
                       "tm_nvs[%d] is NULL",
                       j );
        }
    } // for

    RA_pblock *ra_pb = new RA_pblock( tm_nargs, tm_nvs );

    if( n_data != NULL ) {
        PR_Free( n_data );
        n_data = NULL;
    }

    if( ra_pb == NULL ) {
        RA::Error( "AP_Session::create_pblock",
                   "RA_pblock is NULL" );
        return NULL;
    }

    return ra_pb;
}

RA_Msg *AP_Session::ReadMsg()
{
    int len;
    int msg_len = 0;
    char msg[MAX_RA_MSG_SIZE];
    char *msg_type = NULL;
    int i_msg_type;
    Buffer *msg_type_b = NULL;

    RA::Debug( LL_PER_PDU, "AP_Session::ReadMsg",
               "========== ReadMsg Begins =======" );

    msg_len = GetMsgLen( m_rq );

    if( ( msg_len <= 0 ) || ( msg_len > MAX_RA_MSG_SIZE ) ) {
        RA::Error( "AP_Session::ReadMsg",
                   "Message Size not in range. size =%d. Operation may have been cancelled.", msg_len );
        return NULL;
    }

    RA::Debug( LL_PER_PDU, "AP_Session::ReadMsg", "msg_len=%d", msg_len );

    len = GetMsg( m_rq, msg, msg_len );

    if( len != msg_len ) {
        RA::Error( "AP_Session::ReadMsg", 
                   "Message Size Mismatch. Expected '%d' Received '%d'", 
                   msg_len, len );
        return NULL;
    }

    if(!contains_sensitive_keywords(msg)) {
        RA::Debug( LL_PER_PDU, "AP_Session::ReadMsg",
                   "Received len='%d' msg='%s'", len, msg );
    } else {
        RA::Debug( LL_PER_PDU, "AP_Session::ReadMsg",
                   "Received len='%d' msg='<Password or new pin>'", len );
    }

    RA_Msg *ret_msg = NULL;

    // format into array of name/value pair with value Buffer's
    RA_pblock *ra_pb = ( RA_pblock * ) create_pblock( msg );

    if( ra_pb == NULL ) {
        goto loser;
    }

    // msg_type_b will be freed by destructor of RA_pblock
    msg_type_b =  ra_pb->find_val( PARAM_MSG_TYPE );
    if( msg_type_b == NULL ) {
        goto loser;
    }

    // msg_type should be freed when done using
    msg_type = msg_type_b->string();

    if( msg_type == NULL ) {
        RA::Error( "AP_Session::ReadMsg",
                   "Parameter Not Found %s", PARAM_MSG_TYPE );
        goto loser;
    }

    i_msg_type = atoi( msg_type );

    switch( i_msg_type )
    {
        case MSG_BEGIN_OP: /* BEGIN_OP */
        {
            RA::Debug( LL_PER_PDU, "AP_Session::ReadMsg",
                       "Found %s=%s (%s)", PARAM_MSG_TYPE,
                       "BEGIN_OP", msg_type );

            Buffer *opB = ra_pb->find_val( PARAM_OPERATION );

            if( opB == NULL ) {
                goto loser;
            }

            RA::DebugBuffer( "AP_Session::ReadMsg", "content=", opB );

            char *op_c = opB->string();

            if( op_c == NULL ) {
                goto loser;
            }

            int i_op = atoi( op_c );

            if( op_c != NULL ) {
                PR_Free( op_c );
                op_c = NULL;
            }

            NameValueSet *exts = NULL;

            Buffer *opE = ra_pb->find_val( PARAM_EXTENSIONS ); // optional

            if( opE != NULL ) {
                char *op_e = opE->string();
                if( op_e == NULL ) {
                    RA::Debug( LL_PER_PDU, "AP_Session::ReadMsg",
                               "No extensions" );
                } else {
                    RA::Debug( LL_PER_PDU, "AP_Session::ReadMsg", 
                               "Extensions %s", op_e );
                    exts = NameValueSet::Parse( op_e, "&" );
                    if( op_e != NULL ) {
                        PR_Free( op_e );
                        op_e = NULL;
                    }
                }
            }

            switch( i_op )
            {
                case OP_ENROLL:
                {
                    RA::Debug( LL_PER_PDU, "AP_Session::ReadMsg", 
                               "begin_op_msg msg_type=ENROLL" );
                    ret_msg = new RA_Begin_Op_Msg( OP_ENROLL, exts );
                    break;
                }
                case OP_UNBLOCK:
                {
                    RA::Debug( LL_PER_PDU, "AP_Session::ReadMsg", 
                               "begin_op_msg msg_type=UNBLOCK" );
                    ret_msg = new RA_Begin_Op_Msg( OP_UNBLOCK, exts );
                    break;
                }
                case OP_RESET_PIN:
                {
                    RA::Debug( LL_PER_PDU, "AP_Session::ReadMsg", 
                               "begin_op_msg msg_type=RESET_PIN" );
                    ret_msg = new RA_Begin_Op_Msg( OP_RESET_PIN, exts );
                    break;
                }
                case OP_RENEW:
                {
                    RA::Debug( LL_PER_PDU, "AP_Session::ReadMsg", 
                               "begin_op_msg msg_type=RENEW" );
                    ret_msg = new RA_Begin_Op_Msg( OP_RENEW, exts );
                    break;
                }
                case OP_FORMAT:
                {
                    RA::Debug( LL_PER_PDU, "AP_Session::ReadMsg", 
                               "begin_op_msg msg_type=FORMAT" );
                    ret_msg = new RA_Begin_Op_Msg( OP_FORMAT, exts );
                    break;
                }
                default:
                {
                    break;
                    /* error */
                }
            } // switch( i_op )

            break;
        }
        case MSG_EXTENDED_LOGIN_RESPONSE: /* LOGIN_RESPONSE */
        {
            char *name = NULL;
            Buffer* value = NULL;
            char *bufferStr = NULL;
            AuthParams *params = new AuthParams();
            int i;

            RA::Debug( LL_PER_PDU, "AP_Session::ReadMsg",
                       "Found %s=%s (%s)", PARAM_MSG_TYPE,
                       "EXTENDED_LOGIN_RESPONSE", msg_type );

            i = ra_pb->get_num_of_names();

            for( i = 0; i < ra_pb->get_num_of_names(); i++ ) {
                name = ra_pb->get_name( i );
                if( name != NULL ) {
                    value = ra_pb->find_val( ( const char * ) name );
                    bufferStr = value->string();
                    if( value != NULL ) {
                        params->Add( name, bufferStr );
                    }
                    if (bufferStr != NULL) {
                        PR_Free(bufferStr);
                        bufferStr = NULL;
                    }
                }
            }

            ret_msg = new RA_Extended_Login_Response_Msg( params );

            break;
        }
        case MSG_LOGIN_RESPONSE: /* LOGIN_RESPONSE */
        {
            char *uid = NULL, *password = NULL;
            Buffer *uid_b, *pwd_b = NULL;

            RA::Debug( LL_PER_PDU, "AP_Session::ReadMsg",
                       "Found %s=%s (%s)", PARAM_MSG_TYPE,
                       "LOGIN_RESPONSE", msg_type );

            uid_b = ra_pb->find_val( PARAM_SCREEN_NAME );

            if( uid_b == NULL ) {
                goto aloser;
            }

            uid = uid_b->string();

            if( uid == NULL ) {
                goto aloser;
            }

            pwd_b = ra_pb->find_val( PARAM_PASSWORD );

            if( pwd_b == NULL ) {
                goto aloser;
            }

            password = pwd_b->string();

            if( password == NULL ) {
                goto aloser;
            }

            ret_msg = new RA_Login_Response_Msg( uid, password );

        aloser:
            if( uid != NULL ) {
                PR_Free( uid );
                uid = NULL;
            }

            if( password != NULL ) {
                PR_Free( password );
                password = NULL;
            }

            goto loser;
        
            break;
        }
        case MSG_STATUS_UPDATE_RESPONSE: /* SECUREID_RESPONSE */
        {
            char *value = NULL;
            Buffer *value_b;

            RA::Debug( LL_PER_PDU, "AP_Session::ReadMsg",
                       "Found %s=%s (%s)", PARAM_MSG_TYPE,
                       "STATUS_UPDATE_RESPONSE", msg_type );

            value_b = ra_pb->find_val( PARAM_STATUS );

            if( value_b == NULL ) {
                goto zloser;
            }

            value = value_b->string();

            if( value == NULL ) {
                goto zloser;
            }

            ret_msg = new RA_Status_Update_Response_Msg( atoi( value ) );

        zloser:
            if( value != NULL ) {
                PR_Free( value );
                value = NULL;
            }

            goto loser;

            break;
        }
        case MSG_SECUREID_RESPONSE: /* SECUREID_RESPONSE */
        {
            char *value = NULL, *pin = NULL;
            Buffer *value_b = NULL, *pin_b = NULL;

            RA::Debug( LL_PER_PDU, "AP_Session::ReadMsg",
                       "Found %s=%s (%s)", PARAM_MSG_TYPE,
                       "SECUREID_RESPONSE", msg_type );

            value_b = ra_pb->find_val( PARAM_VALUE );

            if( value_b == NULL ) {
                goto bloser;
            }

            value = value_b->string();

            if( value == NULL ) {
                goto bloser;
            }

            pin_b = ra_pb->find_val( PARAM_PIN );

            if( pin_b == NULL ) {
                goto bloser;
            }

            pin = pin_b->string();

            if( pin == NULL ) {
                pin_b->zeroize();
                goto bloser;
            }

            ret_msg = new RA_SecureId_Response_Msg( value, pin );

            if( pin != NULL ) {
                // zeroize memory before releasing
                unsigned int i = 0;
                for( i = 0; i < strlen( pin ); i++ ) {
                    pin[i] = '\0';
                }
                if( pin != NULL ) {
                    PR_Free( pin );
                    pin = NULL;
                }
            }

            pin_b->zeroize();

        bloser:
            if( value != NULL ) {
                PR_Free( value );
                value = NULL;
            }

            if( pin != NULL ) {
                PR_Free( pin );
                pin = NULL;
            }

            goto loser;

            break;
        }
        case MSG_ASQ_RESPONSE: /* ASQ_RESPONSE */
        {
            RA::Debug( LL_PER_PDU, "AP_Session::ReadMsg",
                       "Found %s=%s (%s)", PARAM_MSG_TYPE,
                       "ASQ_RESPONSE", msg_type );

            Buffer *ans_b = ra_pb->find_val( PARAM_ANSWER );

            if( ans_b == NULL ) {
                goto loser;
            }

            char *answer = ans_b->string();

            if( answer == NULL ) {
                goto loser;
            }

            ret_msg = new RA_ASQ_Response_Msg( answer );

            if( answer != NULL ) {
                PR_Free( answer );
                answer = NULL;
            }

            break;
        }
        case MSG_TOKEN_PDU_RESPONSE: /* TOKEN_PDU_RESPONSE */
        {
            RA::Debug( LL_PER_PDU, "AP_Session::ReadMsg",
                       "Found %s=%s (%s)", PARAM_MSG_TYPE,
                       "TOKEN_PDU_RESPONSE", msg_type );

            unsigned int pdu_size =0;

            Buffer *pdu_size_b = ra_pb->find_val( PARAM_PDU_SIZE );

            if( pdu_size_b == NULL ) {
                goto loser;
            }

            char *p = pdu_size_b->string();

            pdu_size = atoi( p );

            if( p != NULL ) {
                PR_Free( p );
                p = NULL;
            }

            RA::Debug( LL_PER_PDU, "AP_Session::ReadMsg",
                       "Found %s=%d", PARAM_PDU_SIZE, pdu_size );

            if( pdu_size > 261 ) {
                RA::Error( LL_PER_PDU, "AP_Session::ReadMsg",
                           "%s exceeds limit", PARAM_PDU_SIZE );
                goto loser;
            }

            Buffer *decoded_pdu = ra_pb->find_val( PARAM_PDU_DATA );

            if( decoded_pdu == NULL ) {
                goto loser;
            }

            RA::Debug( LL_PER_PDU, "AP_Session::ReadMsg",
                       "decoded_pdu size= %d", decoded_pdu->size() );

            if( pdu_size != decoded_pdu->size() ) {
                goto loser;
            }

            RA::DebugBuffer( "AP_Session::ReadMsg",
                             "decoded pdu = ", decoded_pdu );

            APDU_Response *response = new APDU_Response( *decoded_pdu );

            ret_msg = new RA_Token_PDU_Response_Msg( response );

            break;
        }
        case MSG_NEW_PIN_RESPONSE: /* NEW_PIN_RESPONSE */
        {
            char *new_pin = NULL;
            Buffer *new_pin_b = NULL;

            RA::Debug( LL_PER_PDU, "AP_Session::ReadMsg",
                       "Found %s=%s (%s)", PARAM_MSG_TYPE,
                       "NEW_PIN_RESPONSE", msg_type );

            new_pin_b = ra_pb->find_val( PARAM_NEW_PIN );

            if( new_pin_b == NULL ) {
                goto loser;
            }

            new_pin = new_pin_b->string();

            if( new_pin == NULL ) {
                new_pin_b->zeroize();
                goto loser;
            }

            ret_msg = new RA_New_Pin_Response_Msg( new_pin );

            if( new_pin != NULL ) {
                // zeroize memory before releasing
                unsigned int i = 0;

                for( i = 0; i< strlen( new_pin ); i++ ) {
                    new_pin[i] = '\0';
                }

                if( new_pin != NULL ) {
                    PR_Free( new_pin );
                    new_pin = NULL;
                }
            }

            new_pin_b->zeroize();

            break;
        }
        default:
        {
            RA::Error( "AP_Session::ReadMsg", "Found %s=%s", 
                       PARAM_MSG_TYPE, "UNDEFINED" );
            /* error */
            break;
        }
    } // switch( i_msg_type )

loser:
    if( msg_type != NULL ) {
        PR_Free( msg_type );
        msg_type = NULL;
    }

    if( ra_pb != NULL ) {
        delete ra_pb;
        ra_pb = NULL;
    }

    RA::Debug( LL_PER_PDU, "AP_Session::ReadMsg",
               "========= ReadMsg Ends =========" );

    return ret_msg;
}

static void CreateChunk( char *msgbuf, char *buf, int buflen )
{
    int len;

    len = strlen( msgbuf );
    sprintf( buf, "s=%d&%s", len, msgbuf );
}

void AP_Session::WriteMsg( RA_Msg *msg )
{
    char msgbuf[MAX_RA_MSG_SIZE];
    char buf[MAX_RA_MSG_SIZE];

    switch( msg->GetType() )
    {
        case MSG_EXTENDED_LOGIN_REQUEST:
        {
            RA_Extended_Login_Request_Msg *login_request_msg = 
            ( RA_Extended_Login_Request_Msg * ) msg;
            int invalid_password = login_request_msg->IsInvalidPassword();
            int is_blocked = login_request_msg->IsBlocked();

            char *title = Util::URLEncode( login_request_msg->GetTitle() );
            char *desc = Util::URLEncode( login_request_msg->GetDescription() );

            sprintf( msgbuf, "%s=%d&%s=%d&%s=%d&%s=%s&%s=%s", 
                     PARAM_MSG_TYPE, MSG_EXTENDED_LOGIN_REQUEST,
                     "invalid_login", invalid_password,
                     PARAM_BLOCKED, is_blocked,
                     "title", title, 
                     "description", desc);  
            if (title != NULL) {
                PR_Free(title);
                title = NULL;
            }

            if (desc != NULL) {
                PR_Free(desc);
                desc = NULL;
            }

            for( int i = 0; i < login_request_msg->GetLen(); i++ ) {
                char *p = login_request_msg->GetParam( i );
                char *encp = Util::URLEncode1( p );
                sprintf( msgbuf, "%s&required_parameter%d=%s", 
                         msgbuf, i, encp );
                if (encp != NULL) {
                    PR_Free(encp);
                    encp = NULL;
                }
            }

            CreateChunk( msgbuf, buf, MAX_RA_MSG_SIZE );

            RA::Debug( "AP_Session::WriteMsg", "Sent '%s'", buf );

            ( void ) ap_rwrite( ( const void * ) buf, strlen( buf ), m_rq );
            break;
        }
        case MSG_LOGIN_REQUEST:
        {
            RA_Login_Request_Msg *login_request_msg = 
            ( RA_Login_Request_Msg * ) msg;
            int invalid_password = login_request_msg->IsInvalidPassword();
            int is_blocked = login_request_msg->IsBlocked();

            sprintf( msgbuf, "%s=%d&%s=%d&%s=%d", 
                     PARAM_MSG_TYPE, MSG_LOGIN_REQUEST,
                     PARAM_INVALID_PW, invalid_password,
                     PARAM_BLOCKED, is_blocked );

            CreateChunk( msgbuf, buf, MAX_RA_MSG_SIZE );

            RA::Debug( "AP_Session::WriteMsg", "Sent '%s'", buf );

            ( void ) ap_rwrite( ( const void * ) buf, strlen( buf ), m_rq );

            break;
        }
        case MSG_END_OP:
        {
            RA_End_Op_Msg *end_op = ( RA_End_Op_Msg * ) msg;
            int result = end_op->GetResult();
            int local_msg = end_op->GetMsg();
            int op = end_op->GetOpType();

            sprintf( msgbuf, "%s=%d&%s=%d&%s=%d&%s=%d\r\n0\r\n", 
                     PARAM_MSG_TYPE, MSG_END_OP,
                     PARAM_OPERATION, op,
                     PARAM_RESULT, result,
                     PARAM_MESSAGE, local_msg );

            CreateChunk( msgbuf, buf, MAX_RA_MSG_SIZE );

            RA::Debug( "AP_Session::WriteMsg", "Sent '%s'", buf );

            ( void ) ap_rwrite( ( const void * ) buf, strlen( buf ), m_rq );

            break;
        }
        case MSG_STATUS_UPDATE_REQUEST:
        {
            RA_Status_Update_Request_Msg *status_update_request_msg = 
            ( RA_Status_Update_Request_Msg * ) msg;
            int status = status_update_request_msg->GetStatus();
            char *info = status_update_request_msg->GetInfo();

            sprintf( msgbuf, "%s=%d&%s=%d&%s=%s", 
                     PARAM_MSG_TYPE, MSG_STATUS_UPDATE_REQUEST,
                     PARAM_STATUS, status,
                     PARAM_INFO, info );

            CreateChunk( msgbuf, buf, MAX_RA_MSG_SIZE );

            RA::Debug( "AP_Session::WriteMsg", "Sent '%s'", buf );

            ( void ) ap_rwrite( ( const void * ) buf, strlen( buf ), m_rq );

            break;
        }
        case MSG_SECUREID_REQUEST:
        {
            RA_SecureId_Request_Msg *secureid_request_msg = 
            ( RA_SecureId_Request_Msg * ) msg;
            int is_pin_required = secureid_request_msg->IsPinRequired();
            int is_next_value = secureid_request_msg->IsNextValue();

            sprintf( msgbuf, "%s=%d&%s=%d&%s=%d", 
                     PARAM_MSG_TYPE, MSG_SECUREID_REQUEST,
                     PARAM_PIN_REQUIRED, is_pin_required,
                     PARAM_NEXT_VALUE, is_next_value );

            CreateChunk( msgbuf, buf, MAX_RA_MSG_SIZE );

            RA::Debug( "AP_Session::WriteMsg", "Sent '%s'", buf );

            ( void ) ap_rwrite( ( const void * ) buf, strlen( buf ), m_rq );

            break;
        }
        case MSG_ASQ_REQUEST:
        {
            RA_ASQ_Request_Msg *asq_request_msg = ( RA_ASQ_Request_Msg * ) msg;
            char *question = asq_request_msg->GetQuestion();

            sprintf( msgbuf, "%s=%d&%s=%s", 
                     PARAM_MSG_TYPE, MSG_ASQ_REQUEST,
                     PARAM_QUESTION, question );

            CreateChunk( msgbuf, buf, MAX_RA_MSG_SIZE );

            RA::Debug( "AP_Session::WriteMsg", "Sent '%s'", buf );

            ( void ) ap_rwrite( ( const void * ) buf, strlen( buf ), m_rq );

            break;
        }
        case MSG_NEW_PIN_REQUEST:
        {
            RA_New_Pin_Request_Msg *new_pin_request_msg = 
            ( RA_New_Pin_Request_Msg * ) msg;
            int min = new_pin_request_msg->GetMinLen();
            int max = new_pin_request_msg->GetMaxLen();

            sprintf( msgbuf, "%s=%d&%s=%d&%s=%d", 
                     PARAM_MSG_TYPE, MSG_NEW_PIN_REQUEST,
                     PARAM_MINIMUM_LENGTH, min,
                     PARAM_MAXIMUM_LENGTH, max );

            CreateChunk( msgbuf, buf, MAX_RA_MSG_SIZE );

            RA::Debug( "AP_Session::WriteMsg", "Sent '%s'", buf );

            ( void ) ap_rwrite( ( const void * ) buf, strlen( buf ), m_rq );

            break;
        }
        case MSG_TOKEN_PDU_REQUEST:
        {
            RA_Token_PDU_Request_Msg *token_pdu_request_msg = 
            ( RA_Token_PDU_Request_Msg * ) msg;
            APDU *apdu = token_pdu_request_msg->GetAPDU();
            Buffer encoding;

            apdu->GetEncoding( encoding );

            int pdu_len = encoding.size();

            RA::Debug( LL_PER_CONNECTION, "AP_Session::WriteMsg",
                       "pdu_len='%d'", pdu_len );

            Buffer pdu = encoding;
            char *pdu_encoded = NULL;

            if( RA::GetConfigStore()->GetConfigAsBool( "pdu_encoding.hex_mode",
                                                       1 ) ) {
                // pdu will be encoded in Hex mode which is easier to read
                pdu_encoded = Util::URLEncodeInHex( pdu );
            } else {
                pdu_encoded = Util::URLEncode( pdu );
            }

            sprintf( msgbuf, "%s=%d&%s=%d&%s=%s", 
                     PARAM_MSG_TYPE, MSG_TOKEN_PDU_REQUEST,
                     PARAM_PDU_SIZE, pdu_len,
                     PARAM_PDU_DATA, pdu_encoded );

            CreateChunk( msgbuf, buf, MAX_RA_MSG_SIZE );

            if( pdu_encoded != NULL ) {
                PR_Free( pdu_encoded );
                pdu_encoded = NULL;
            }

            RA::Debug( "AP_Session::WriteMsg", "Sent '%s'", buf );

            ( void ) ap_rwrite( ( const void * ) buf, strlen( buf ), m_rq );

            break;
        }
        default:
        {
            break;
            /* error */
        }
    } // switch( msg->GetType() )

    ap_rflush(m_rq);

}

#ifdef __cplusplus
}
#endif

