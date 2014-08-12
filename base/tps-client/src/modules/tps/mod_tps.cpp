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
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */



/*  _________________________________________________________________
**
**  TPS Module Headers
**  _________________________________________________________________
*/

#include <stdio.h>
#include <unistd.h>
#include "nspr.h"

#include "httpd/httpd.h"
#include "httpd/http_config.h"
#include "httpd/http_log.h"
#include "httpd/http_protocol.h"
#include "httpd/http_main.h"

#include "apr_strings.h"

#include "engine/RA.h"
#include "main/Memory.h"
#include "main/RA_Msg.h"
#include "main/RA_Session.h"
#include "modules/tps/AP_Context.h"
#include "modules/tps/AP_Session.h"
#include "msg/RA_Begin_Op_Msg.h"
#include "msg/RA_End_Op_Msg.h"
#include "processor/RA_Enroll_Processor.h"
#include "processor/RA_Format_Processor.h"
#include "processor/RA_Pin_Reset_Processor.h"
#include "processor/RA_Renew_Processor.h"
#include "processor/RA_Unblock_Processor.h"
#include "ssl.h"

#define MOD_TPS_KEY_NAME "mod_tps"

/*  _________________________________________________________________
**
**  TPS Module Request Data
**  _________________________________________________________________
*/

/**
 * Processors for different operations.
 */
static RA_Enroll_Processor m_enroll_processor;
static RA_Unblock_Processor m_unblock_processor;
static RA_Pin_Reset_Processor m_pin_reset_processor;
static RA_Renew_Processor m_renew_processor;
static RA_Format_Processor m_format_processor;


/*  _________________________________________________________________
**
**  TPS Module Command Data
**  _________________________________________________________________
*/

static const char MOD_TPS_CONFIGURATION_FILE_PARAMETER[] = "TPSConfigPathFile";

static const char MOD_TPS_CONFIGURATION_FILE_USAGE[] =
"TPS Configuration Filename prefixed by a complete path, or\n"
"a path that is relative to the Apache server root.";

/* per-process config structure */
typedef struct {
    int nInitCount;
    int nSignedAuditInitCount;
} mod_tps_global_config;


/*  _________________________________________________________________
**
**  TPS Module Server Configuration Creation Data
**  _________________________________________________________________
*/

typedef struct {
    char *TPS_Configuration_File;
    AP_Context *context;
    mod_tps_global_config *gconfig; /* pointer to per-process config */
} mod_tps_server_configuration;



/*  _________________________________________________________________
**
**  TPS Module Registration Data
**  _________________________________________________________________
*/

#define MOD_TPS_CONFIG_KEY tps_module
APLOG_USE_MODULE(tps);

static const char MOD_TPS_CONFIG_KEY_NAME[] = "tps_module";

extern module TPS_PUBLIC MOD_TPS_CONFIG_KEY;



/*  _________________________________________________________________
**
**  TPS Module Helper Functions
**  _________________________________________________________________
*/

mod_tps_global_config *mod_tps_config_global_create(server_rec *s)
{
    apr_pool_t *pool = s->process->pool;
    mod_tps_global_config *globalc = NULL;
    void *vglobalc = NULL;

    apr_pool_userdata_get(&vglobalc, MOD_TPS_KEY_NAME, pool);
    if (vglobalc) {
        return (mod_tps_global_config *) vglobalc; /* reused for lifetime of the server */
    }

    /*
     * allocate an own subpool which survives server restarts
     */
    globalc = (mod_tps_global_config *)apr_palloc(pool, sizeof(*globalc));

    /*
     * initialize per-module configuration
     */
    globalc->nInitCount = 0;
    globalc->nSignedAuditInitCount = 0;

    apr_pool_userdata_set(globalc, MOD_TPS_KEY_NAME,
                          apr_pool_cleanup_null,
                          pool);

    return globalc;
}

/**
 * Terminate Apache
 */
void tps_die( void )
{
    /*
     * This is used for fatal errors and here
     * it is common module practice to really
     * exit from the complete program.
     */
    exit( 1 );
}


/**
 * Creates an RA_Session from the RA framework.
 *
 * Centralize the allocation of the session object here so that
 * we can provide our own session management here in the future.
 */
static RA_Session *
mod_tps_create_session( request_rec *rq )
{
    return new AP_Session( rq );
} /* mod_tps_create_session */


/**
 * Returns RA_Session to the RA framework.
 */
static void
mod_tps_destroy_session( RA_Session *session )
{
    if( session != NULL ) {
        delete session;
        session = NULL;
    }
} /* mod_tps_destroy_session */



/*  _________________________________________________________________
**
**  TPS Module Request Phase
**  _________________________________________________________________
*/

/**
 * Terminate the TPS module
 */
static apr_status_t
mod_tps_terminate( void *data )
{
    /* This routine is ONLY called when this server's */
    /* pool has been cleared or destroyed.            */

    /* Log TPS module debug information. */
    RA::Debug( "mod_tps::mod_tps_terminate",
               "The TPS module has been terminated!" );

    /* Free TPS resources. */
    RA::Shutdown();

    /* Since all members of mod_tps_server_configuration are allocated */
    /* from a pool, there is no need to unset any of these members.    */

#ifdef MEM_PROFILING
    /* If memory profiling is enabled, turn off memory profiling. */
    MEM_shutdown();
#endif

    SSL_ClearSessionCache();
    /* Shutdown all APR library routines.                   */
    /* NOTE:  This automatically destroys all memory pools. */
    /*        Allow the NSS Module to perform this task.    */
    /* apr_terminate(); */


    /* Terminate the entire Apache server                */
    /* NOTE:  Allow the NSS Module to perform this task. */
    /* tps_die(); */ 

    return OK;
}

static apr_status_t
mod_tps_child_terminate (void *data)
{
    RA::Debug("mod_tps::mod_tps_child_terminate",
              "The TPS module has been terminated!" );
    
     /* Free TPS resources. */
    RA::Child_Shutdown();

    return OK;
}

static int
mod_tps_initialize( apr_pool_t *p,
                    apr_pool_t *plog,
                    apr_pool_t *ptemp,
                    server_rec *sv )
{
    mod_tps_server_configuration *sc = NULL;
    char *cfg_path_file = NULL;
    int status;

    /* Retrieve the TPS module. */
    sc = ( ( mod_tps_server_configuration * )
           ap_get_module_config( sv->module_config,
                                 &MOD_TPS_CONFIG_KEY ) );

    /* Check to see if the TPS module has been loaded. */
    if( sc->context != NULL ) {
        return OK;
    }

    sc->gconfig->nInitCount++;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, sv,
                 "Entering mod_tps_initialize - init count is [%d]",
                 sc->gconfig->nInitCount);

    /* Load the TPS module. */

#ifdef MEM_PROFILING
    /* If memory profiling is enabled, turn on memory profiling. */
    MEM_init( MEM_AUDIT_FILE, MEM_DUMP_FILE );
#endif

    /* Retrieve the path to where the configuration files are located,    */
    /* and insure that the TPS module configuration file is located here. */
    if( sc->TPS_Configuration_File != NULL ) {
        /* provide TPS Config File from <apache_server_root>/conf/httpd.conf */
        if( sc->TPS_Configuration_File[0] == '/' ) {
            /* Complete path to TPS Config File is denoted */
            cfg_path_file = apr_psprintf( p,
                                          "%s",
                                          ( char * )
                                          sc->TPS_Configuration_File );
        } else {
            /* TPS Config File is located relative to the Apache server root */
            cfg_path_file = apr_psprintf( p,
                                          "%s/%s",
                                          ( char * ) ap_server_root,
                                          ( char * )
                                          sc->TPS_Configuration_File );
        }
   } else {
        /* Log information regarding this failure. */
        ap_log_error( "mod_tps_initialize",
                      __LINE__, APLOG_MODULE_INDEX, APLOG_ERR, 0, sv,
                      "The tps module was installed incorrectly since the "
                      "parameter named '%s' is missing from the Apache "
                      "Configuration file!",
                      ( char * ) MOD_TPS_CONFIGURATION_FILE_PARAMETER );

        /* Display information on the screen regarding this failure. */
        printf( "\nUnable to start Apache:\n"
                "    The tps module is missing the required parameter named\n"
                "    '%s' in the Apache Configuration file!\n",
                ( char * ) MOD_TPS_CONFIGURATION_FILE_PARAMETER );

        goto loser;
   }

    /* Initialize the "server" member of mod_tps_server_configuration. */
    sc->context = new AP_Context( sv );

    status = RA::Initialize( cfg_path_file, sc->context );
    if( status != RA_INITIALIZATION_SUCCESS ) {
        /* Log information regarding this failure. */
        ap_log_error( "mod_tps_initialize",
                      __LINE__, APLOG_MODULE_INDEX, APLOG_ERR, 0, sv,
                      "The tps module was installed incorrectly "
                      "since the file named '%s' does not exist!",
                      cfg_path_file );

        /* Display information on the screen regarding this failure. */
        printf( "\nUnable to start Apache:\n"
                "    The tps module configuration file called\n"
                "    '%s' does not exist!\n",
                cfg_path_file );

        /* Since all members of mod_tps_server_configuration are allocated */
        /* from a pool, there is no need to unset any of these members.    */

        goto loser;
    }
  
    if (sc->gconfig->nInitCount < 2 ) {
        sc->gconfig->nSignedAuditInitCount++;
        status = RA::InitializeInChild( sc->context,
                   sc->gconfig->nSignedAuditInitCount);
    } else {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, sv,
            "mod_tps_initialize - pid is [%d] - post config already done once -"
            " additional config will be done in init_child",
            getpid());
        status = RA_INITIALIZATION_SUCCESS;
    }

    if (status !=  RA_INITIALIZATION_SUCCESS ) {
        ap_log_error( "mod_tps_initialize",
                      __LINE__, APLOG_MODULE_INDEX, APLOG_ERR, 0, sv,
                      "The tps module failed to do the initializeInChild tasks. ");
        printf( "\nUnable to start Apache:\n"
                "    The tps module failed to do the initializeInChild tasks. ");
        goto loser;
    }

    /* Register a server termination routine. */
    apr_pool_cleanup_register( p,
                               sv,
                               mod_tps_terminate,
                               apr_pool_cleanup_null );

    /* Log TPS module debug information. */
    RA::Debug( "mod_tps::mod_tps_initialize",
               "The TPS module has been successfully loaded!" );

    return OK;

loser:
    /* Log TPS module debug information. */
    RA::Debug( "mod_tps::mod_tps_initialize",
               "Failed loading the TPS module!" );

    if( sc->context != NULL ) {
        /* Free TPS resources. */
        RA::Shutdown();

        /* Since all members of mod_tps_server_configuration are allocated */
        /* from a pool, there is no need to unset any of these members.    */
    }

#ifdef MEM_PROFILING
    /* If memory profiling is enabled, turn off memory profiling. */
    MEM_shutdown();
#endif

    /* Shutdown all APR library routines.                   */
    /* NOTE:  This automatically destroys all memory pools. */
    apr_terminate();

    /* Terminate the entire Apache server */
    tps_die();

    return DECLINED;
}

/**
 * mod_tps_handler handles the protocol between the token client
 * and the RA (Session)
 */
static int
mod_tps_handler( request_rec *rq )
{
    char buf[1024];
    int ret_code = DECLINED;
    int status = DECLINED;
    RA_Session *session = NULL;
    RA_Begin_Op_Msg *begin_op_msg = NULL;
    NameValueSet *extensions = NULL;
    const char *tenc = apr_table_get(rq->headers_in, "Transfer-Encoding");

    /* Log TPS module debug information. */
    RA::Debug( "mod_tps::mod_tps_handler",
               "mod_tps::mod_tps_handler" );

    RA::Debug( "mod_tps::mod_tps_handler",
               "uri '%s'", rq->uri);

    /* XXX: We need to change "nk_service" to "tps", 
            and need to update ESC. */
    if (strcmp(rq->handler,"nk_service") != 0) {
      RA::Debug( "mod_tps::mod_tps_handler",
               "DECLINED uri '%s'", rq->uri);
      return DECLINED;
    }

    RA::Debug( "mod_tps::mod_tps_handler",
               "uri '%s' DONE", rq->uri);

    /* 
     * check to see if the http request contains 
     * "transfer-encoding: chunked"
     */  
    /* XXX: rq->chunked not set to true even in the chunked mode */
    if(!tenc || PL_strcasecmp(tenc, "chunked") != 0) {
        /* print the following when browser accesses directly */
        strcpy( buf, "<HTML>Registration Authority</HTML>" );

        /* write out the data */
        ( void ) ap_rwrite( ( const void * ) buf, strlen( buf ), rq );

        ret_code = OK;

        return ret_code;
    } 

    /* request contains chunked encoding */
    session = mod_tps_create_session( rq );

    /* read in the data present on the connection */
    begin_op_msg = ( RA_Begin_Op_Msg * ) session->ReadMsg();
    if( begin_op_msg == NULL ) {
        /* Log TPS module error information. */
        RA::Error( "mod_tps::mod_tps_handler",
                   "no begin op found" );
        goto loser;
    }

    /* retrieve the extensions */
    extensions = begin_op_msg->GetExtensions();

    /* perform the appropriate processing based upon the type of operation */
    if( begin_op_msg->GetOpType() == OP_ENROLL ) {
        status = m_enroll_processor.Process( session, extensions );
    } else if( begin_op_msg->GetOpType() == OP_UNBLOCK ) {
        status = m_unblock_processor.Process( session, extensions );
    } else if( begin_op_msg->GetOpType() == OP_RESET_PIN ) {
        status = m_pin_reset_processor.Process( session, extensions );
    } else if( begin_op_msg->GetOpType() == OP_RENEW ) {
        status = m_renew_processor.Process( session, extensions );
    } else if( begin_op_msg->GetOpType() == OP_FORMAT ) {
        status = m_format_processor.Process( session, extensions );
    } else {
        /* Log TPS module error information. */
        RA::Error( "mod_tps::mod_tps_handler",
                   "unknown operation requested (op='%d')", 
                   begin_op_msg->GetOpType() );
        goto loser;
    } /* if */

    ret_code = OK;

loser:
    /* determine the results of the operation and report it */
    if( begin_op_msg != NULL ) {
        int result;         

        if( status  == 0 ) {
            result = RESULT_GOOD;
        } else {
            result = RESULT_ERROR;
        }

        RA_End_Op_Msg *end_op = new RA_End_Op_Msg( begin_op_msg->GetOpType(), 
                                                   result, 
                                                   status );

        session->WriteMsg( end_op );

        if( end_op != NULL ) {
            delete end_op;
            end_op = NULL;
        }
    }

    /* remove any operational messages */
    if( begin_op_msg != NULL ) {
        delete begin_op_msg;
        begin_op_msg = NULL;
    }

    /* remove any sessions */
    if( session != NULL ) {
        mod_tps_destroy_session( session );
        session = NULL;
    }

    return ret_code;
} /* mod_tps_handler */



/*  _________________________________________________________________
**
**  TPS Module Command Phase
**  _________________________________________________________________
*/

static const char *mod_tps_get_config_path_file( cmd_parms *cmd,
                                                 void *mconfig,
                                                 const char *tpsconf )
{
    if( cmd->path ) {
        ap_log_error( APLOG_MARK, APLOG_ERR, 0, NULL,
                      "The %s config param cannot be specified "
                      "in a Directory section.",
                      cmd->directive->directive );
    } else {
        mod_tps_server_configuration *sc = NULL;

        /* Retrieve the TPS module. */
        sc = ( ( mod_tps_server_configuration * )
               ap_get_module_config( cmd->server->module_config,
                                     &MOD_TPS_CONFIG_KEY ) );

        /* Initialize the "TPS Configuration File" */
        /* member of mod_tps_server_configuration. */
        sc->TPS_Configuration_File = apr_pstrdup( cmd->pool, tpsconf );
    }

    return NULL;
}


static const command_rec mod_tps_config_cmds[] = {
    AP_INIT_TAKE1( MOD_TPS_CONFIGURATION_FILE_PARAMETER,
                   ( const char*(*)() ) mod_tps_get_config_path_file,
                   NULL,
                   RSRC_CONF,
                   MOD_TPS_CONFIGURATION_FILE_USAGE ),
   { NULL }
};



/*  _________________________________________________________________
**
**  TPS Module Server Configuration Creation Phase
**  _________________________________________________________________
*/

/**
 * Create TPS module server configuration
 */
static void *
mod_tps_config_server_create( apr_pool_t *p, server_rec *sv )
{
    /* Initialize all APR library routines. */
    apr_initialize();

    /* Create a memory pool for this server. */
    mod_tps_server_configuration *sc = ( mod_tps_server_configuration * )
                                       apr_pcalloc( p,
                                                    ( apr_size_t )
                                                    sizeof( *sc ) );
    
    /* Initialize all members of mod_tps_server_configuration. */
    sc->TPS_Configuration_File = NULL;
    sc->context = NULL;
    sc->gconfig = mod_tps_config_global_create(sv);

    return sc;
}

static void mod_tps_init_child(apr_pool_t *p, server_rec *sv)
{
     int status = -1;
    mod_tps_server_configuration *srv_cfg = NULL;
    srv_cfg = ( ( mod_tps_server_configuration * )
           ap_get_module_config(sv->module_config, &MOD_TPS_CONFIG_KEY));

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0 /* status */, NULL,
                 "Entering mod_tps_init_child pid [%d] init count is [%d]",
                 getpid(), srv_cfg->gconfig->nInitCount);

    srv_cfg = ( ( mod_tps_server_configuration * )
           ap_get_module_config(sv->module_config, &MOD_TPS_CONFIG_KEY));

    if (srv_cfg->gconfig->nInitCount > 1) {
        srv_cfg->gconfig->nSignedAuditInitCount++; 
        status = RA::InitializeInChild(srv_cfg->context,
                   srv_cfg->gconfig->nSignedAuditInitCount); 


         if (status !=  RA_INITIALIZATION_SUCCESS) {
        /* Need to shut down, the child was not initialized properly. */
           ap_log_error( "mod_tps_init_child",
                      __LINE__, APLOG_MODULE_INDEX, APLOG_ERR, 0, sv,
                      "The tps module failed to do the initializeInChild tasks. ");
           printf( "\nUnable to start Apache:\n"
                "    The tps module failed to do the initializeInChild tasks. ");
           goto loser;
        }

        /* Register a server termination routine. */
        apr_pool_cleanup_register( p,
                                   sv,
                                   mod_tps_child_terminate,
                                   apr_pool_cleanup_null );
    } else {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, sv,
                     "mod_tps_init_child - pid is [%d] - config should be done in regular post config",
                     getpid());
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0 /* status */, NULL,
                 "Leaving mod_tps_init_child");
    return;
loser:
     /* Log TPS module debug information. */
    RA::Debug( "mod_tps::mod_tps_initialize",
               "Failed loading the TPS module!" );

    /* Free TPS resources. */
    /* If we are here, the parent should be up. */
    RA::Shutdown();

    /* Since all members of mod_tps_server_configuration are allocated */
    /* from a pool, there is no need to unset any of these members.    */

#ifdef MEM_PROFILING
    /* If memory profiling is enabled, turn off memory profiling. */
    MEM_shutdown();
#endif

    /* Shutdown all APR library routines.                   */
    /* NOTE:  This automatically destroys all memory pools. */
    apr_terminate();

    /* Terminate the entire Apache server */
    _exit(APEXIT_CHILDFATAL);

    return;

}



/*  _________________________________________________________________
**
**  TPS Module Registration Phase
**  _________________________________________________________________
*/
                                                                                
static void
mod_tps_register_hooks( apr_pool_t *p )
{
    static const char *const mod_tps_preloaded_modules[]  = { "mod_nss.c",
                                                              NULL };
    static const char *const mod_tps_postloaded_modules[] = { NULL };

    ap_hook_post_config( mod_tps_initialize,
                         mod_tps_preloaded_modules,
                         mod_tps_postloaded_modules,
                         APR_HOOK_MIDDLE );
  
    ap_hook_child_init(mod_tps_init_child, NULL,NULL, APR_HOOK_MIDDLE);

    ap_hook_handler( mod_tps_handler,
                     mod_tps_preloaded_modules,
                     mod_tps_postloaded_modules,
                     APR_HOOK_MIDDLE );
}


module TPS_PUBLIC MOD_TPS_CONFIG_KEY = {
    STANDARD20_MODULE_STUFF,
    NULL,                           /* create per-dir    config structures */
    NULL,                           /* merge  per-dir    config structures */
    mod_tps_config_server_create,   /* create per-server config structures */
    NULL,                           /* merge  per-server config structures */
    mod_tps_config_cmds,            /* table of configuration directives   */
    mod_tps_register_hooks          /* register hooks */
};



#ifdef __cplusplus
}
#endif

