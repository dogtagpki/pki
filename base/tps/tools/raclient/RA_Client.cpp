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

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "prinrval.h"

#include "prmem.h"
#include "prsystem.h"
#include "plstr.h"
#include "prio.h"
#include "prprf.h"
#include "pk11func.h"

#include "main/NameValueSet.h"
#include "main/Util.h"
#include "main/RA_Msg.h"
#include "authentication/AuthParams.h"
#include "apdu/APDU_Response.h"
#include "apdu/Initialize_Update_APDU.h"
#include "apdu/External_Authenticate_APDU.h"
#include "apdu/Set_Pin_APDU.h"
#include "msg/RA_Begin_Op_Msg.h"
#include "msg/RA_End_Op_Msg.h"
#include "msg/RA_Login_Request_Msg.h"
#include "msg/RA_Login_Response_Msg.h"
#include "msg/RA_Extended_Login_Request_Msg.h"
#include "msg/RA_Extended_Login_Response_Msg.h"
#include "msg/RA_Token_PDU_Request_Msg.h"
#include "msg/RA_Token_PDU_Response_Msg.h"
#include "msg/RA_New_Pin_Request_Msg.h"
#include "msg/RA_New_Pin_Response_Msg.h"
#include "msg/RA_SecureId_Request_Msg.h"
#include "msg/RA_SecureId_Response_Msg.h"
#include "msg/RA_ASQ_Request_Msg.h"
#include "msg/RA_ASQ_Response_Msg.h"
#include "msg/RA_Status_Update_Request_Msg.h"
#include "msg/RA_Status_Update_Response_Msg.h"
#include "RA_Token.h"
#include "RA_Client.h"

#include "nss.h"

static PRFileDesc *m_fd_debug = (PRFileDesc *) NULL;
PRBool old_style = PR_TRUE;

/**
 * Constructs a RA client that talks to RA.
 */
RA_Client::RA_Client ()
{
  /* default global variables */
  m_vars.Add ("ra_host", "air");
  m_vars.Add ("ra_port", "8000");
  m_vars.Add ("ra_uri", "/nk_service");
}

/**
 * Destructs this RA client.
 */
RA_Client::~RA_Client ()
{
  if (m_fd_debug != NULL)
    {
      PR_Close (m_fd_debug);
      m_fd_debug = NULL;
    }
}

static void
PrintHeader ()
{
  printf ("Registration Authority Client\n");
  printf ("'op=help' for Help\n");
}

static void
Output (const char *fmt, ...)
{
  va_list ap;
  va_start (ap, fmt);
  printf ("Output> ");
  vprintf (fmt, ap);
  printf ("\n");
  va_end (ap);
}

static void
PrintPrompt ()
{
  printf ("Command>");
}

static void
OutputSuccess (const char *fmt, ...)
{
  va_list ap;
  va_start (ap, fmt);
  printf ("Result> Success - ");
  vprintf (fmt, ap);
  printf ("\n");
  va_end (ap);
}

static void
OutputError (const char *fmt, ...)
{
  va_list ap;
  va_start (ap, fmt);
  printf ("Result> Error - ");
  vprintf (fmt, ap);
  printf ("\n");
  va_end (ap);
}

static int
ReadLine (char *buf, int len)
{
  char *cur = buf;

  while (1)
    {
      *cur = getchar ();
      if (*cur == '\r')
	{
	  continue;
	}
      if (*cur == '\n')
	{
	  *cur = '\0';
	  return 1;
	}
      cur++;
    }
  return 0;
}

void
RA_Client::Debug (const char *func_name, const char *fmt, ...)
{
  PRTime now;
  const char *time_fmt = "%Y-%m-%d %H:%M:%S";
  char datetime[1024];
  PRExplodedTime time;

  if (m_fd_debug == NULL)
    return;
  va_list ap;
  va_start (ap, fmt);
  now = PR_Now ();
  PR_ExplodeTime (now, PR_LocalTimeParameters, &time);
  PR_FormatTimeUSEnglish (datetime, 1024, time_fmt, &time);
  PR_fprintf (m_fd_debug, "[%s] %s - ", datetime, func_name);
  PR_vfprintf (m_fd_debug, fmt, ap);
  va_end (ap);
  PR_Write (m_fd_debug, "\n", 1);
}

int
RA_Client::OpHelp (NameValueSet * params)
{
  Output ("Available Operations:");
  Output ("op=debug filename=<filename> - enable debugging");
  Output ("op=help");
  Output
    ("op=ra_enroll uid=<uid> pwd=<pwd> num_threads=<number of threads> secureid_pin=<secureid_pin> keygen=<true|false> - Enrollment Via RA");
  Output
    ("op=ra_reset_pin uid=<uid> pwd=<pwd> num_threads=<number of threads> secureid_pin=<secureid_pin> new_pin=<new_pin> - Reset Pin Via RA");
  Output
    ("op=ra_update uid=<uid> pwd=<pwd> num_threads=<number of threads> secureid_pin=<secureid_pin> new_pin=<new_pin> - Reset Pin Via RA");
  Output ("op=token_set <name>=<value> - Set Token Value");
  Output ("op=token_status - Print Token Status");
  Output ("op=var_get name=<name> - Get Value of Variable");
  Output ("op=var_list - List All Variables");
  Output ("op=var_set name=<name> value=<value> - Set Value to Variable");

  return 1;
}

static void
GetBuffer (Buffer & buf, char *output, int len)
{
  int i;

  output[0] = '\0';
  for (i = 0; i < (int) buf.size (); ++i)
    {
      sprintf (output, "%s%02x", output, ((BYTE *) buf)[i]);
    }
}

static BYTE
ToVal (char c)
{
  if (c >= '0' && c <= '9')
    {
      return c - '0';
    }
  else if (c >= 'A' && c <= 'Z')
    {
      return c - 'A' + 10;
    }
  else if (c >= 'a' && c <= 'z')
    {
      return c - 'a' + 10;
    }

  /* The following return is needed to suppress compiler warnings on Linux. */
  return 0;
}

static Buffer *
ToBuffer (char *input)
{
  int len = strlen (input) / 2;
  BYTE *buffer = NULL;

  buffer = (BYTE *) malloc (len);
  if (buffer == NULL)
    {
      return NULL;
    }

  for (int i = 0; i < len; i++)
    {
      buffer[i] = (ToVal (input[i * 2]) * 16) + ToVal (input[i * 2 + 1]);
    }
  Buffer *j;
  j = new Buffer (buffer, len);

  if (buffer != NULL)
    {
      free (buffer);
      buffer = NULL;
    }

  return j;
}

int
RA_Client::OpTokenStatus (NameValueSet * params)
{
  int i;
  char output[2048];

  Output ("life_cycle_state : '%x'", m_token.GetLifeCycleState ());
  Output ("pin : '%s'", m_token.GetPIN ());
  GetBuffer (m_token.GetAppletVersion (), output, 2048);
  Output ("app_ver : '%s' (%d bytes)", output,
	  m_token.GetAppletVersion ().size ());
  Output ("major_ver : '%x'", m_token.GetMajorVersion ());
  Output ("minor_ver : '%x'", m_token.GetMinorVersion ());
  GetBuffer (m_token.GetCUID (), output, 2048);
  Output ("cuid : '%s' (%d bytes)", output, m_token.GetCUID ().size ());
  GetBuffer (m_token.GetMSN (), output, 2048);
  Output ("msn : '%s' (%d bytes)", output, m_token.GetMSN ().size ());
  GetBuffer (m_token.GetKeyInfo (), output, 2048);
  Output ("key_info : '%s' (%d bytes)", output,
	  m_token.GetKeyInfo ().size ());
  GetBuffer (m_token.GetAuthKey (), output, 2048);
  Output ("auth_key : '%s' (%d bytes)", output,
	  m_token.GetAuthKey ().size ());
  GetBuffer (m_token.GetMacKey (), output, 2048);
  Output ("mac_key : '%s' (%d bytes)", output, m_token.GetMacKey ().size ());
  GetBuffer (m_token.GetKekKey (), output, 2048);
  Output ("kek_key : '%s' (%d bytes)", output, m_token.GetKekKey ().size ());

  /* print all the public/private keys */
  if (params->GetValue ("print_cert") != NULL)
    {
      for (i = 0; i < m_token.NoOfCertificates (); i++)
	{
	  CERTCertificate *cert = m_token.GetCertificate (i);
	  Output ("Certificate #%d: '%s'", i, cert->nickname);
	}
    }

  if (params->GetValue ("print_private") != NULL)
    {
      for (i = 0; i < m_token.NoOfPrivateKeys (); i++)
	{
	  SECKEYPrivateKey *key = m_token.GetPrivateKey (i);
#if 0
	  SECKEYPublicKey *pubKey = SECKEY_ConvertToPublicKey (key);
	  Buffer modulus = Buffer (pubKey->u.rsa.modulus.data,
				   pubKey->u.rsa.modulus.len);
	  Buffer exponent = Buffer (pubKey->u.rsa.publicExponent.data,
				    pubKey->u.rsa.publicExponent.len);
#endif
	  Output ("Private Key #%d: '%s'", i,
		  PK11_GetPrivateKeyNickname (key));
	}
    }

  return 1;
}

int
RA_Client::OpTokenSet (NameValueSet * params)
{
  if (params->GetValue ("cuid") != NULL)
    {
      Buffer *CUID = ToBuffer (params->GetValue ("cuid"));
      m_token.SetCUID (*CUID);
      if (CUID != NULL)
	{
	  delete CUID;
	  CUID = NULL;
	}
    }
  if (params->GetValue ("msn") != NULL)
    {
      Buffer *MSN = ToBuffer (params->GetValue ("msn"));
      m_token.SetMSN (*MSN);
      if (MSN != NULL)
	{
	  delete MSN;
	  MSN = NULL;
	}
    }
  if (params->GetValue ("app_ver") != NULL)
    {
      Buffer *Version = ToBuffer (params->GetValue ("app_ver"));
      m_token.SetAppletVersion (*Version);
      if (Version != NULL)
	{
	  delete Version;
	  Version = NULL;
	}
    }
  if (params->GetValue ("major_ver") != NULL)
    {
      m_token.SetMajorVersion (atoi (params->GetValue ("major_ver")));
    }
  if (params->GetValue ("minor_ver") != NULL)
    {
      m_token.SetMinorVersion (atoi (params->GetValue ("minor_ver")));
    }
  if (params->GetValue ("key_info") != NULL)
    {
      Buffer *KeyInfo = ToBuffer (params->GetValue ("key_info"));
      m_token.SetKeyInfo (*KeyInfo);
      if (KeyInfo != NULL)
	{
	  delete KeyInfo;
	  KeyInfo = NULL;
	}
    }
  if (params->GetValue ("auth_key") != NULL)
    {
      Buffer *Key = ToBuffer (params->GetValue ("auth_key"));
      m_token.SetAuthKey (*Key);
      if (Key != NULL)
	{
	  delete Key;
	  Key = NULL;
	}
    }
  if (params->GetValue ("mac_key") != NULL)
    {
      Buffer *Key = ToBuffer (params->GetValue ("mac_key"));
      m_token.SetMacKey (*Key);
      if (Key != NULL)
	{
	  delete Key;
	  Key = NULL;
	}
    }
  if (params->GetValue ("kek_key") != NULL)
    {
      Buffer *Key = ToBuffer (params->GetValue ("kek_key"));
      m_token.SetKekKey (*Key);
      if (Key != NULL)
	{
	  delete Key;
	  Key = NULL;
	}
    }
  return 1;
}

static int
HandleStatusUpdateRequest (RA_Client * client,
			   RA_Status_Update_Request_Msg * req,
			   RA_Token * token, RA_Conn * conn,
			   NameValueSet * vars, NameValueSet * params)
{
  client->Debug ("RA_Client::HandleStatusUpdateRequest",
		 "RA_Client::HandleStatusUpdateRequest");
  RA_Status_Update_Response_Msg resp =
    RA_Status_Update_Response_Msg (req->GetStatus ());
  conn->SendMsg (&resp);
  return 1;
}

static int
HandleExtendedLoginRequest (RA_Client * client,
			    RA_Extended_Login_Request_Msg * req,
			    RA_Token * token, RA_Conn * conn,
			    NameValueSet * vars, NameValueSet * params)
{
  client->Debug ("RA_Client::HandleExtendLoginRequest",
		 "RA_Client::HandleExtendedLoginRequest");
  AuthParams *auths = new AuthParams;
  auths->SetUID (params->GetValue ("uid"));
  auths->SetPassword (params->GetValue ("pwd"));
  if (vars->GetValueAsBool ("test_enable", 0) == 1)
    {
      if (vars->GetValueAsBool ("test_el_resp_exclude_uid", 0) == 1)
	{
	  auths->Remove ("UID");
	}
      if (vars->GetValueAsBool ("test_el_resp_exclude_pwd", 0) == 1)
	{
	  auths->Remove ("PASSWORD");
	}
      if (vars->GetValueAsBool ("test_el_resp_include_invalid_param", 0) == 1)
	{
	  auths->Add ("XXX", "YYY");
	}
    }
  RA_Extended_Login_Response_Msg resp =
    RA_Extended_Login_Response_Msg (auths);
  conn->SendMsg (&resp);
  return 1;
}

static int
HandleLoginRequest (RA_Client * client,
		    RA_Login_Request_Msg * req,
		    RA_Token * token, RA_Conn * conn,
		    NameValueSet * vars, NameValueSet * params)
{
  client->Debug ("RA_Client::HandleLoginRequest",
		 "RA_Client::HandleLoginRequest");
  RA_Login_Response_Msg resp =
    RA_Login_Response_Msg (params->GetValue ("uid"),
			   params->GetValue ("pwd"));
  conn->SendMsg (&resp);
  return 1;
}

static int
HandleNewPinRequest (RA_Client * client,
		     RA_New_Pin_Request_Msg * req,
		     RA_Token * token, RA_Conn * conn,
		     NameValueSet * vars, NameValueSet * params)
{
  client->Debug ("RA_Client::HandleNewPinRequest",
		 "RA_Client::HandleNewPinRequest");
  int min_len = req->GetMinLen ();
  int max_len = req->GetMaxLen ();
  Output ("Min Len: '%d' Max Len: '%d'", min_len, max_len);
  RA_New_Pin_Response_Msg resp =
    RA_New_Pin_Response_Msg (params->GetValue ("new_pin"));
  conn->SendMsg (&resp);

  return 1;
}

static int
HandleASQRequest (RA_Client * client,
		  RA_ASQ_Request_Msg * req,
		  RA_Token * token, RA_Conn * conn,
		  NameValueSet * vars, NameValueSet * params)
{
  client->Debug ("RA_Client::HandleASQRequest",
		 "RA_Client::HandleASQRequest");
  Output ("ASQ Question: '%s'", req->GetQuestion ());
  RA_ASQ_Response_Msg resp =
    RA_ASQ_Response_Msg (params->GetValue ("answer"));
  conn->SendMsg (&resp);

  return 1;
}

static int
HandleSecureIdRequest (RA_Client * client,
		       RA_SecureId_Request_Msg * req,
		       RA_Token * token, RA_Conn * conn,
		       NameValueSet * vars, NameValueSet * params)
{
  client->Debug ("RA_Client::HandleSecureIdRequest",
		 "RA_Client::HandleSecureIdRequest");
  int pin_required = req->IsPinRequired ();
  int next_value = req->IsNextValue ();
  Output ("Pin Required: '%d' Next Value: '%d'", pin_required, next_value);
  RA_SecureId_Response_Msg resp =
    RA_SecureId_Response_Msg (params->GetValue ("secureid_value"),
			      params->GetValue ("secureid_pin"));
  conn->SendMsg (&resp);
  return 1;
}

static int
HandleTokenPDURequest (RA_Client * client,
		       RA_Token_PDU_Request_Msg * req,
		       RA_Token * token, RA_Conn * conn,
		       NameValueSet * vars, NameValueSet * params)
{
  client->Debug ("RA_Client::HandleTokenPDURequest",
		 "RA_Client::HandleTokenPDURequest");
  APDU *apdu = req->GetAPDU ();
  APDU_Response *apdu_resp = token->Process (apdu, vars, params);
  if (apdu_resp == NULL)
    {
      return 0;
    }
  RA_Token_PDU_Response_Msg *resp = new RA_Token_PDU_Response_Msg (apdu_resp);
  conn->SendMsg (resp);

  if (resp != NULL)
    {
      delete resp;
      resp = NULL;
    }
  // if( apdu_resp != NULL ) {
  //     delete apdu_resp;
  //     apdu_resp = NULL;
  // }

  return 1;
}


typedef struct _ThreadArg
{
  PRTime time;			/* processing time */
  int status;			/* status result */
  NameValueSet *params;		/* parameters */
  RA_Client *client;		/* client */
  RA_Token *token;		/* token */

  PRLock *donelock;		/* lock */
  int done;			/* are we done? */
} ThreadArg;

#ifdef __cplusplus
extern "C"
{
#endif

  static void ThreadConnUpdate (void *arg)
  {
    PRTime start, end;
    ThreadArg *targ = (ThreadArg *) arg;

      start = PR_Now ();
    RA_Conn conn (targ->client->m_vars.GetValue ("ra_host"),
		  atoi (targ->client->m_vars.GetValue ("ra_port")),
		  targ->client->m_vars.GetValue ("ra_uri"));

    if (!conn.Connect ())
      {
	OutputError ("Cannot connect to %s:%d",
		     targ->client->m_vars.GetValue ("ra_host"),
		     atoi (targ->client->m_vars.GetValue ("ra_port")));
	targ->status = 0;
	if (!old_style)
	  {
	    PR_Lock (targ->donelock);
	    targ->done = PR_TRUE;
	    PR_Unlock (targ->donelock);
	  }

	return;
      }

    NameValueSet *exts = NULL;
    char *extensions =
      targ->params->GetValueAsString ((char *) "extensions", NULL);
    if (extensions != NULL)
      {
	exts = NameValueSet::Parse (extensions, "&");
      }

    RA_Begin_Op_Msg beginOp = RA_Begin_Op_Msg (OP_FORMAT, exts);
    conn.SendMsg (&beginOp);

    /* handle secure ID (optional) */
    while (1)
      {
	RA_Msg *msg = (RA_Msg *) conn.ReadMsg (targ->token);
	if (msg == NULL)
	  break;
	if (msg->GetType () == MSG_LOGIN_REQUEST)
	  {
	    targ->status =
	      HandleLoginRequest (targ->client, (RA_Login_Request_Msg *) msg,
				  targ->token, &conn, &targ->client->m_vars,
				  targ->params);
	  }
	else if (msg->GetType () == MSG_EXTENDED_LOGIN_REQUEST)
	  {
	    targ->status =
	      HandleExtendedLoginRequest (targ->client,
					  (RA_Extended_Login_Request_Msg *)
					  msg, targ->token, &conn,
					  &targ->client->m_vars,
					  targ->params);
	  }
	else if (msg->GetType () == MSG_STATUS_UPDATE_REQUEST)
	  {
	    targ->status =
	      HandleStatusUpdateRequest (targ->client,
					 (RA_Status_Update_Request_Msg *) msg,
					 targ->token, &conn,
					 &targ->client->m_vars, targ->params);
	  }
	else if (msg->GetType () == MSG_SECUREID_REQUEST)
	  {
	    targ->status =
	      HandleSecureIdRequest (targ->client,
				     (RA_SecureId_Request_Msg *) msg,
				     targ->token, &conn,
				     &targ->client->m_vars, targ->params);
	  }
	else if (msg->GetType () == MSG_ASQ_REQUEST)
	  {
	    targ->status =
	      HandleASQRequest (targ->client, (RA_ASQ_Request_Msg *) msg,
				targ->token, &conn, &targ->client->m_vars,
				targ->params);
	  }
	else if (msg->GetType () == MSG_TOKEN_PDU_REQUEST)
	  {
	    targ->status =
	      HandleTokenPDURequest (targ->client,
				     (RA_Token_PDU_Request_Msg *) msg,
				     targ->token, &conn,
				     &targ->client->m_vars, targ->params);
	  }
	else if (msg->GetType () == MSG_NEW_PIN_REQUEST)
	  {
	    targ->status =
	      HandleNewPinRequest (targ->client,
				   (RA_New_Pin_Request_Msg *) msg,
				   targ->token, &conn, &targ->client->m_vars,
				   targ->params);
	  }
	else if (msg->GetType () == MSG_END_OP)
	  {
	    RA_End_Op_Msg *endOp = (RA_End_Op_Msg *) msg;
	    if (endOp->GetResult () == 0)
	      {
		targ->status = 1;	/* error */
	      }
	    else
	      {
		targ->status = 0;
	      }
	    if (msg != NULL)
	      {
		delete msg;
		msg = NULL;
	      }
	    break;
	  }
	else
	  {
	    /* error */
	    targ->status = 0;
	  }
	if (msg != NULL)
	  {
	    delete msg;
	    msg = NULL;
	  }

	if (targ->status == 0)
	  break;
      }

    conn.Close ();
    end = PR_Now ();
    targ->time = (end - start) / 1000;

    if (!old_style)
      {
	PR_Lock (targ->donelock);
	targ->done = PR_TRUE;
	PR_Unlock (targ->donelock);
      }
  }

  static void ThreadConnResetPin (void *arg)
  {
    PRTime start, end;
    ThreadArg *targ = (ThreadArg *) arg;

    start = PR_Now ();
    RA_Conn conn (targ->client->m_vars.GetValue ("ra_host"),
		  atoi (targ->client->m_vars.GetValue ("ra_port")),
		  targ->client->m_vars.GetValue ("ra_uri"));

    if (!conn.Connect ())
      {
	OutputError ("Cannot connect to %s:%d",
		     targ->client->m_vars.GetValue ("ra_host"),
		     atoi (targ->client->m_vars.GetValue ("ra_port")));
	targ->status = 0;

	if (!old_style)
	  {
	    PR_Lock (targ->donelock);
	    targ->done = PR_TRUE;
	    PR_Unlock (targ->donelock);
	  }

	return;
      }

    NameValueSet *exts = NULL;
    char *extensions =
      targ->params->GetValueAsString ((char *) "extensions", NULL);
    if (extensions != NULL)
      {
	exts = NameValueSet::Parse (extensions, "&");
      }

    RA_Begin_Op_Msg beginOp = RA_Begin_Op_Msg (OP_RESET_PIN, exts);
    conn.SendMsg (&beginOp);

    /* handle secure ID (optional) */
    while (1)
      {
	RA_Msg *msg = (RA_Msg *) conn.ReadMsg (targ->token);
	if (msg == NULL)
	  break;
	if (msg->GetType () == MSG_LOGIN_REQUEST)
	  {
	    targ->status =
	      HandleLoginRequest (targ->client, (RA_Login_Request_Msg *) msg,
				  targ->token, &conn, &targ->client->m_vars,
				  targ->params);
	  }
	else if (msg->GetType () == MSG_EXTENDED_LOGIN_REQUEST)
	  {
	    targ->status =
	      HandleExtendedLoginRequest (targ->client,
					  (RA_Extended_Login_Request_Msg *)
					  msg, targ->token, &conn,
					  &targ->client->m_vars,
					  targ->params);
	  }
	else if (msg->GetType () == MSG_STATUS_UPDATE_REQUEST)
	  {
	    targ->status =
	      HandleStatusUpdateRequest (targ->client,
					 (RA_Status_Update_Request_Msg *) msg,
					 targ->token, &conn,
					 &targ->client->m_vars, targ->params);
	  }
	else if (msg->GetType () == MSG_SECUREID_REQUEST)
	  {
	    targ->status =
	      HandleSecureIdRequest (targ->client,
				     (RA_SecureId_Request_Msg *) msg,
				     targ->token, &conn,
				     &targ->client->m_vars, targ->params);
	  }
	else if (msg->GetType () == MSG_ASQ_REQUEST)
	  {
	    targ->status =
	      HandleASQRequest (targ->client, (RA_ASQ_Request_Msg *) msg,
				targ->token, &conn, &targ->client->m_vars,
				targ->params);
	  }
	else if (msg->GetType () == MSG_TOKEN_PDU_REQUEST)
	  {
	    targ->status =
	      HandleTokenPDURequest (targ->client,
				     (RA_Token_PDU_Request_Msg *) msg,
				     targ->token, &conn,
				     &targ->client->m_vars, targ->params);
	  }
	else if (msg->GetType () == MSG_NEW_PIN_REQUEST)
	  {
	    targ->status =
	      HandleNewPinRequest (targ->client,
				   (RA_New_Pin_Request_Msg *) msg,
				   targ->token, &conn, &targ->client->m_vars,
				   targ->params);
	  }
	else if (msg->GetType () == MSG_END_OP)
	  {
	    RA_End_Op_Msg *endOp = (RA_End_Op_Msg *) msg;
	    if (endOp->GetResult () == 0)
	      {
		targ->status = 1;	/* error */
	      }
	    else
	      {
		targ->status = 0;
	      }
	    if (msg != NULL)
	      {
		delete msg;
		msg = NULL;
	      }
	    break;
	  }
	else
	  {
	    /* error */
	    targ->status = 0;
	  }
	if (msg != NULL)
	  {
	    delete msg;
	    msg = NULL;
	  }

	if (targ->status == 0)
	  break;
      }

    conn.Close ();
    end = PR_Now ();
    targ->time = (end - start) / 1000;

    if (!old_style)
      {
	PR_Lock (targ->donelock);
	targ->done = PR_TRUE;
	PR_Unlock (targ->donelock);
      }
  }

#ifdef __cplusplus
}
#endif

int
RA_Client::OpConnUpdate (NameValueSet * params)
{
  int num_threads = params->GetValueAsInt ((char *) "num_threads", 1);
  int i;
  int status = 0;
  PRThread **threads;
  ThreadArg *arg;

  threads = (PRThread **) malloc (sizeof (PRThread *) * num_threads);
  if (threads == NULL)
    {
      return 0;
    }
  arg = (ThreadArg *) malloc (sizeof (ThreadArg) * num_threads);
  if (arg == NULL)
    {
      return 0;
    }

  /* start threads */
  for (i = 0; i < num_threads; i++)
    {
      arg[i].time = 0;
      arg[i].status = 0;
      arg[i].client = this;
      if (i == 0)
	{
	  arg[i].token = &this->m_token;
	}
      else
	{
	  arg[i].token = this->m_token.Clone ();
	}
      arg[i].params = params;
      threads[i] = PR_CreateThread (PR_USER_THREAD, ThreadConnUpdate, &arg[i], PR_PRIORITY_NORMAL,	/* Priority */
				    PR_GLOBAL_THREAD,	/* Scope */
				    PR_JOINABLE_THREAD,	/* State */
				    0	/* Stack Size */
	);
    }

  /* join threads */
  for (i = 0; i < num_threads; i++)
    {
      PR_JoinThread (threads[i]);
    }

  for (i = 0; i < num_threads; i++)
    {
      Output ("Thread (%d) status='%d' time='%d msec'", i,
	      arg[i].status, arg[i].time);
    }

  status = arg[0].status;

  return status;
}

int
RA_Client::OpConnResetPin (NameValueSet * params)
{
  int num_threads = params->GetValueAsInt ((char *) "num_threads", 1);
  int i;
  int status = 0;
  PRThread **threads;
  ThreadArg *arg;

  threads = (PRThread **) malloc (sizeof (PRThread *) * num_threads);
  if (threads == NULL)
    {
      return 0;
    }
  arg = (ThreadArg *) malloc (sizeof (ThreadArg) * num_threads);
  if (arg == NULL)
    {
      return 0;
    }

  /* start threads */
  for (i = 0; i < num_threads; i++)
    {
      arg[i].time = 0;
      arg[i].status = 0;
      arg[i].client = this;
      if (i == 0)
	{
	  arg[i].token = &this->m_token;
	}
      else
	{
	  arg[i].token = this->m_token.Clone ();
	}
      arg[i].params = params;
      threads[i] = PR_CreateThread (PR_USER_THREAD, ThreadConnResetPin, &arg[i], PR_PRIORITY_NORMAL,	/* Priority */
				    PR_GLOBAL_THREAD,	/* Scope */
				    PR_JOINABLE_THREAD,	/* State */
				    0	/* Stack Size */
	);
    }

  /* join threads */
  for (i = 0; i < num_threads; i++)
    {
      PR_JoinThread (threads[i]);
    }

  for (i = 0; i < num_threads; i++)
    {
      Output ("Thread (%d) status='%d' time='%d msec'", i,
	      arg[i].status, arg[i].time);
    }

  status = arg[0].status;

  return status;
}

#ifdef __cplusplus
extern "C"
{
#endif

  static void ThreadConnEnroll (void *arg)
  {
    PRTime start, end;
    ThreadArg *targ = (ThreadArg *) arg;

      start = PR_Now ();
    RA_Conn conn (targ->client->m_vars.GetValue ("ra_host"),
		  atoi (targ->client->m_vars.GetValue ("ra_port")),
		  targ->client->m_vars.GetValue ("ra_uri"));

    if (!conn.Connect ())
      {
	OutputError ("Cannot connect to %s:%d",
		     targ->client->m_vars.GetValue ("ra_host"),
		     atoi (targ->client->m_vars.GetValue ("ra_port")));
	targ->status = 0;

	if (!old_style)
	  {
	    PR_Lock (targ->donelock);
	    targ->done = PR_TRUE;
	    PR_Unlock (targ->donelock);
	  }

	return;
      }

    NameValueSet *exts = NULL;
    char *extensions =
      targ->params->GetValueAsString ((char *) "extensions", NULL);
    if (extensions != NULL)
      {
	exts = NameValueSet::Parse (extensions, "&");
      }

    RA_Begin_Op_Msg beginOp = RA_Begin_Op_Msg (OP_ENROLL, exts);
    conn.SendMsg (&beginOp);

    /* handle secure ID (optional) */
    while (1)
      {
	RA_Msg *msg = (RA_Msg *) conn.ReadMsg (targ->token);
	if (msg == NULL)
	  break;
	if (msg->GetType () == MSG_LOGIN_REQUEST)
	  {
	    targ->status = HandleLoginRequest (targ->client,
					       (RA_Login_Request_Msg *) msg,
					       targ->token, &conn,
					       &targ->client->m_vars,
					       targ->params);
	  }
	else if (msg->GetType () == MSG_EXTENDED_LOGIN_REQUEST)
	  {
	    targ->status = HandleExtendedLoginRequest (targ->client,
						       (RA_Extended_Login_Request_Msg
							*) msg, targ->token,
						       &conn,
						       &targ->client->m_vars,
						       targ->params);
	  }
	else if (msg->GetType () == MSG_STATUS_UPDATE_REQUEST)
	  {
	    targ->status =
	      HandleStatusUpdateRequest (targ->client,
					 (RA_Status_Update_Request_Msg *) msg,
					 targ->token, &conn,
					 &targ->client->m_vars, targ->params);
	  }
	else if (msg->GetType () == MSG_SECUREID_REQUEST)
	  {
	    targ->status = HandleSecureIdRequest (targ->client,
						  (RA_SecureId_Request_Msg *)
						  msg, targ->token, &conn,
						  &targ->client->m_vars,
						  targ->params);
	  }
	else if (msg->GetType () == MSG_ASQ_REQUEST)
	  {
	    targ->status = HandleASQRequest (targ->client,
					     (RA_ASQ_Request_Msg *) msg,
					     targ->token, &conn,
					     &targ->client->m_vars,
					     targ->params);
	  }
	else if (msg->GetType () == MSG_TOKEN_PDU_REQUEST)
	  {
	    targ->status = HandleTokenPDURequest (targ->client,
						  (RA_Token_PDU_Request_Msg *)
						  msg, targ->token, &conn,
						  &targ->client->m_vars,
						  targ->params);
	    targ->status = 1;
	  }
	else if (msg->GetType () == MSG_NEW_PIN_REQUEST)
	  {
	    targ->status = HandleNewPinRequest (targ->client,
						(RA_New_Pin_Request_Msg *)
						msg, targ->token, &conn,
						&targ->client->m_vars,
						targ->params);
	  }
	else if (msg->GetType () == MSG_END_OP)
	  {
	    RA_End_Op_Msg *endOp = (RA_End_Op_Msg *) msg;
	    if (endOp->GetResult () == 0)
	      {
		targ->status = 1;	/* error */
	      }
	    else
	      {
		targ->status = 0;
	      }
	    if (msg != NULL)
	      {
		delete msg;
		msg = NULL;
	      }
	    break;
	  }
	else
	  {
	    /* error */
	    targ->status = 0;	/* error */
	  }
	if (msg != NULL)
	  {
	    delete msg;
	    msg = NULL;
	  }
      }

    conn.Close ();
    end = PR_Now ();
    targ->time = (end - start) / 1000;

    if (!old_style)
      {
	PR_Lock (targ->donelock);
	targ->done = PR_TRUE;
	PR_Unlock (targ->donelock);
      }
  }

#ifdef __cplusplus
}
#endif

int
RA_Client::OpConnEnroll (NameValueSet * params)
{
  int num_threads = params->GetValueAsInt ((char *) "num_threads", 1);
  int i;
  int status = 0;
  PRThread **threads;
  ThreadArg *arg;

  threads = (PRThread **) malloc (sizeof (PRThread *) * num_threads);
  if (threads == NULL)
    {
      return 0;			/* error */
    }
  arg = (ThreadArg *) malloc (sizeof (ThreadArg) * num_threads);
  if (arg == NULL)
    {
      return 0;
    }

  /* start threads */
  for (i = 0; i < num_threads; i++)
    {
      arg[i].time = 0;
      arg[i].status = 0;
      arg[i].client = this;
      if (i == 0)
	{
	  arg[i].token = &this->m_token;
	}
      else
	{
	  arg[i].token = this->m_token.Clone ();
	}
      arg[i].params = params;
      threads[i] = PR_CreateThread (PR_USER_THREAD, ThreadConnEnroll, &arg[i], PR_PRIORITY_NORMAL,	/* Priority */
				    PR_GLOBAL_THREAD,	/* Scope */
				    PR_JOINABLE_THREAD,	/* State */
				    0	/* Stack Size */
	);
    }

  /* join threads */
  for (i = 0; i < num_threads; i++)
    {
      PR_JoinThread (threads[i]);
    }

  status = 1;

  for (i = 0; i < num_threads; i++)
    {
      Output ("Thread (%d) status='%d' time='%d msec'", i,
	      arg[i].status, arg[i].time);
      if (arg[i].status != 1)
	{
	  // if any thread fails, this operation 
	  // is considered as failure     
	  status = arg[i].status;
	}
    }


  return status;
}


/*
 * no more than num_threads will be running concurrently
 * no more than a total of max_ops requests will be started
 */
int
StartThreads (int num_threads, ThreadArg * arg, PRThread ** threads,
	      int max_ops, RA_Client * _this, NameValueSet * params,
	      RequestType op_type)
{
  int i;
  int started = 0;

  if (arg == NULL)
    {
      goto loser;
    }

  /* start threads */
  for (i = 0; i < num_threads; i++)
    {
      if (started == max_ops)
	{
	  break;
	}
      if (threads[i] == NULL)
	{
	  arg[i].time = 0;
	  arg[i].status = 0;
	  arg[i].client = _this;
	  arg[i].done = PR_FALSE;

	  if (i == 0)
	    {
	      arg[i].token = &_this->m_token;
	    }
	  else
	    {

	      if (arg[i].token != NULL)
		{
		  if (arg[i].token->m_pin)
		    {
		      PL_strfree (arg[i].token->m_pin);
		      arg[i].token->m_pin = NULL;
		    }
		  if (arg[i].token->m_session_key != NULL)
		    {
		      PORT_Free (arg[i].token->m_session_key);
		      arg[i].token->m_session_key = NULL;
		    }
		  if (arg[i].token->m_enc_session_key != NULL)
		    {
		      PORT_Free (arg[i].token->m_enc_session_key);
		      arg[i].token->m_enc_session_key = NULL;
		    }
		  if (arg[i].token->m_object != NULL)
		    {
		      delete (arg[i].token->m_object);
		      arg[i].token->m_object = NULL;
		    }

		  delete (arg[i].token);
		  arg[i].token = NULL;

		}

	      arg[i].token = _this->m_token.Clone ();
	    }
	  arg[i].params = params;
	  Output ("WWWWWWWWW StartThreads -- thread (%d) begins", i);
	  if (op_type == OP_CLIENT_ENROLL)
	    {
	      threads[i] = PR_CreateThread (PR_USER_THREAD, ThreadConnEnroll, &arg[i], PR_PRIORITY_NORMAL,	/* Priority */
					    PR_GLOBAL_THREAD,	/* Scope */
					    PR_JOINABLE_THREAD,	/* State */
					    0	/* Stack Size */
		);
	    }
	  else if (op_type == OP_CLIENT_FORMAT)
	    {
	      threads[i] = PR_CreateThread (PR_USER_THREAD, ThreadConnUpdate, &arg[i], PR_PRIORITY_NORMAL,	/* Priority */
					    PR_GLOBAL_THREAD,	/* Scope */
					    PR_JOINABLE_THREAD,	/* State */
					    0	/* Stack Size */
		);
	    }
	  else
	    {			// OP_CLIENT_RESET_PIN
	      threads[i] = PR_CreateThread (PR_USER_THREAD, ThreadConnResetPin, &arg[i], PR_PRIORITY_NORMAL,	/* Priority */
					    PR_GLOBAL_THREAD,	/* Scope */
					    PR_JOINABLE_THREAD,	/* State */
					    0	/* Stack Size */
		);
	    }

	  started++;
	}
      else
	{
	  Output ("thread[%d] is not NULL", i);
	}
    }

loser:
  Output ("StartThreads -- %d threads started", started);
  return started;
}

/*
 * no more than num_threads will be running concurrently
 * no more than a total of max_ops requests will be started
 */
int
RA_Client::OpConnStart (NameValueSet * params, RequestType op_type)
{
  // number of concurrent threads
  int num_threads = params->GetValueAsInt ((char *) "num_threads", 1);
  // number of total enrollments
  int max_ops = params->GetValueAsInt ((char *) "max_ops", num_threads);
  int count = 0;
  int i;
  int status = 1;
  int started = 0;
  PRThread **threads;
  ThreadArg *arg;

  threads = (PRThread **) malloc (sizeof (PRThread *) * num_threads);
  if (threads == NULL)
    {
      return 0;			/* error */
    }
  arg = (ThreadArg *) malloc (sizeof (ThreadArg) * num_threads);
  if (arg == NULL)
    {
      return 0;
    }

  for (i = 0; i < num_threads; i++)
    {
      arg[i].donelock = PR_NewLock ();
      arg[i].token = NULL;
      threads[i] = NULL;
    }

  count = 0;
  PRBool hasFreeThread = PR_TRUE;
  while (count < max_ops)
    {
      // fully populate the thread pool

      if (hasFreeThread)
	{
	  started =
	    StartThreads (num_threads, arg, threads, max_ops - count, this,
			  params, op_type);
	  count += started;
	  Output ("OpConnStart: # requests started =%d", count);
	  hasFreeThread = PR_FALSE;
	}

      //        PR_Sleep(PR_MillisecondsToInterval(500));
      PR_Sleep (PR_SecondsToInterval (1));
      Output ("OpConnStart: checking for free threads...");
      // check if any threads are done
      for (i = 0; i < num_threads; i++)
	{
	  if (threads[i] != NULL)
	    {
	      PR_Lock (arg[i].donelock);
	      int arg_done = arg[i].done;
	      PR_Unlock (arg[i].donelock);
	      if (arg_done)
		{
		  PR_JoinThread (threads[i]);
		  Output ("Thread (%d) status='%d' time='%d msec'", i,
			  arg[i].status, arg[i].time);

		  if (arg[i].status != 1)
		    {
		      // if any thread fails, this operation 
		      // is considered as failure     
		      status = arg[i].status;
		    }
		  threads[i] = NULL;

		  hasFreeThread = PR_TRUE;

		}
	    }
	}
      Output ("OpConnStart: done checking for free threads...");
    }				// while

  Output ("OpConnStart: TOTAL REQUESTS: %d", count);

  for (i = 0; i < num_threads; i++)
    {
      if (threads[i] != NULL)
	{
	  PR_JoinThread (threads[i]);
	}
      if (arg[i].donelock != NULL)
	{
	  PR_DestroyLock (arg[i].donelock);
	}
    }

  return status;

}

int
RA_Client::OpVarSet (NameValueSet * params)
{
  m_vars.Add (params->GetValue ("name"), params->GetValue ("value"));
  Output ("%s: '%s'", params->GetValue ("name"),
	  m_vars.GetValue (params->GetValue ("name")));
  return 1;
}

int
RA_Client::OpVarDebug (NameValueSet * params)
{
  if (m_fd_debug != NULL)
    {
      PR_Close (m_fd_debug);
      m_fd_debug = NULL;
    }
  m_fd_debug = PR_Open (params->GetValue ("filename"),
			PR_RDWR | PR_CREATE_FILE | PR_APPEND, 400 | 200);
  return 1;
}

int
RA_Client::OpVarGet (NameValueSet * params)
{
  char *value = m_vars.GetValue (params->GetValue ("name"));
  Output ("%s: '%s'", params->GetValue ("name"), value);

  return 1;
}

int
RA_Client::OpVarList (NameValueSet * params)
{
  int i;
  char *name;

  for (i = 0; i < m_vars.Size (); i++)
    {
      name = m_vars.GetNameAt (i);
      Output ("%s: '%s'", name, m_vars.GetValue (name));
    }
  return 1;
}

/**
 * Invoke operation.
 */
void
RA_Client::InvokeOperation (char *op, NameValueSet * params)
{
  PRTime start, end;
  int status = 0;

  start = PR_Now ();
  Debug ("RA_Client::InvokeOperation", "op='%s'", op);
  int max_ops = params->GetValueAsInt ((char *) "max_ops");
  if (max_ops != 0)
    old_style = PR_FALSE;

  if (strcmp (op, "help") == 0)
    {
      status = OpHelp (params);
    }
  else if (strcmp (op, "ra_format") == 0)
    {
      if (old_style)
	status = OpConnUpdate (params);
      else
	status = OpConnStart (params, OP_CLIENT_FORMAT);
    }
  else if (strcmp (op, "ra_reset_pin") == 0)
    {
      if (old_style)
	status = OpConnResetPin (params);
      else
	status = OpConnStart (params, OP_CLIENT_RESET_PIN);
    }
  else if (strcmp (op, "ra_enroll") == 0)
    {
      if (old_style)
	status = OpConnEnroll (params);
      else
	status = OpConnStart (params, OP_CLIENT_ENROLL);
    }
  else if (strcmp (op, "token_status") == 0)
    {
      status = OpTokenStatus (params);
    }
  else if (strcmp (op, "token_set") == 0)
    {
      status = OpTokenSet (params);
    }
  else if (strcmp (op, "debug") == 0)
    {
      status = OpVarDebug (params);
    }
  else if (strcmp (op, "var_set") == 0)
    {
      status = OpVarSet (params);
    }
  else if (strcmp (op, "var_get") == 0)
    {
      status = OpVarGet (params);
    }
  else if (strcmp (op, "var_list") == 0)
    {
      status = OpVarList (params);
    }
  end = PR_Now ();

  if (status)
    {
      OutputSuccess ("Operation '%s' Success (%d msec)", op,
		     (end - start) / 1000);
    }
  else
    {
      OutputError ("Operation '%s' Failure (%d msec)", op,
		   (end - start) / 1000);
    }
}

/**
 * Execute RA client.
 */
void
RA_Client::Execute ()
{
  char line[1024];
  int rc;
  char *op;
  int done = 0;
  char *lasts = NULL;

  /* start main loop */
  PrintHeader ();
  while (!done)
    {
      PrintPrompt ();
      rc = ReadLine (line, 1024);
      printf ("%s\n", line);
      if (rc <= 0)
	{
	  break;		/* exit if no more line */
	}
      if (line[0] == '#')
	{
	  continue;		/* ignore comment line */
	}
      /* format: 'op=cmd <parameters>' */
      NameValueSet *params = NameValueSet::Parse (line, " ");
      if (params == NULL)
	{
	  continue;
	}
      op = params->GetValue ("op");
      if (op == NULL)
	{
	  /* user did not type op= */
	  op = PL_strtok_r (line, " ", &lasts);
	  if (op == NULL)
	    continue;
	}
      if (strcmp (op, "exit") == 0)
	{
	  done = 1;
	}
      else
	{
	  InvokeOperation (op, params);
	}
      if (params != NULL)
	{
	  delete params;
	  params = NULL;
	}
    }
}				/* Execute */

char *
ownPasswd (PK11SlotInfo * slot, PRBool retry, void *arg)
{
  return PL_strdup ("password");
}

/**
 * User certutil -d . -N to create a database.
 * The database should have 'password' as the password.
 */
int
main (int argc, char *argv[])
{
  char buffer[513];
  SECStatus rv;
  PK11SlotInfo *slot = NULL;
  PRUint32 flags = 0;
  // char *newpw = NULL;

  /* Initialize NSPR & NSS */
  PR_Init (PR_SYSTEM_THREAD, PR_PRIORITY_NORMAL, 1);
  PK11_SetPasswordFunc (ownPasswd);
  rv = NSS_Initialize (".", "", "", "", flags);
  if (rv != SECSuccess)
    {
      PR_GetErrorText (buffer);
      fprintf (stderr, "unable to initialize NSS library (%d - '%s')\n",
	       PR_GetError (), buffer);
      exit (0);
    }
  slot = PK11_GetInternalKeySlot ();
  if (PK11_NeedUserInit (slot))
    {
      rv = PK11_InitPin (slot, (char *) NULL, (char *) "password");
      if (rv != SECSuccess)
	{
	  PR_GetErrorText (buffer);
	  fprintf (stderr, "unable to set new PIN (%d - '%s')\n",
		   PR_GetError (), buffer);
	  exit (0);
	}

    }
  if (PK11_NeedLogin (slot))
    {
      rv = PK11_Authenticate (slot, PR_TRUE, NULL);
      if (rv != SECSuccess)
	{
	  PR_GetErrorText (buffer);
	  fprintf (stderr, "unable to authenticate (%d - '%s')\n",
		   PR_GetError (), buffer);
	  exit (0);
	}
    }

  /* Start RA Client */
  RA_Client client;
  client.Execute ();

  /* Shutdown NSS and NSPR */
  NSS_Shutdown ();
  PR_Cleanup ();

  return 1;
}
