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

#include "plstr.h"
#include "prthread.h"
#include "pk11func.h"
#include "nss.h"

#include "main/RA_Client.h"

enum RequestType {
  OP_CLIENT_ENROLL = 0,
  OP_CLIENT_FORMAT = 1,
  OP_CLIENT_RESET_PIN = 2
};

typedef struct _ThreadArg
{
  PRTime time;          /* processing time */
  int status;           /* status result */
  NameValueSet *params;     /* parameters */
  RA_Client *client;        /* client */
  RA_Token *token;      /* token */

  PRLock *donelock;     /* lock */
  int done;         /* are we done? */
} ThreadArg;

void
PrintHeader ()
{
  printf ("Registration Authority Client\n");
  printf ("'op=help' for Help\n");
}

void
PrintPrompt ()
{
  printf ("Command> ");
}

int
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

int
HandleLoginRequest (RA_Client * client,
            RA_Login_Request_Msg * req,
            RA_Token * token, RA_Conn * conn,
            NameValueSet * vars, NameValueSet * params)
{
  client->Debug ("HandleLoginRequest", "HandleLoginRequest");
  RA_Login_Response_Msg resp =
    RA_Login_Response_Msg (params->GetValue ("uid"),
               params->GetValue ("pwd"));
  conn->SendMsg (&resp);
  return 1;
}

int FormatToken (
  RA_Client *client,
  NameValueSet *params,
  NameValueSet *exts,
  RA_Token *token,
  RA_Conn *conn)
{
  int status;

  RA_Begin_Op_Msg beginOp = RA_Begin_Op_Msg (OP_FORMAT, exts);
  conn->SendMsg (&beginOp);

  /* handle secure ID (optional) */
  while (1)
    {
  RA_Msg *msg = (RA_Msg *) conn->ReadMsg (token);
  if (msg == NULL)
    break;
  if (msg->GetType () == MSG_LOGIN_REQUEST)
    {
      status =
        HandleLoginRequest (client, (RA_Login_Request_Msg *) msg,
                token, conn, &client->m_vars,
                params);
    }
  else if (msg->GetType () == MSG_EXTENDED_LOGIN_REQUEST)
    {
      status =
        HandleExtendedLoginRequest (client,
                    (RA_Extended_Login_Request_Msg *)
                    msg, token, conn,
                    &client->m_vars,
                    params);
    }
  else if (msg->GetType () == MSG_STATUS_UPDATE_REQUEST)
    {
      status =
        HandleStatusUpdateRequest (client,
                   (RA_Status_Update_Request_Msg *) msg,
                   token, conn,
                   &client->m_vars, params);
    }
  else if (msg->GetType () == MSG_SECUREID_REQUEST)
    {
      status =
        HandleSecureIdRequest (client,
                   (RA_SecureId_Request_Msg *) msg,
                   token, conn,
                   &client->m_vars, params);
    }
  else if (msg->GetType () == MSG_ASQ_REQUEST)
    {
      status =
        HandleASQRequest (client, (RA_ASQ_Request_Msg *) msg,
              token, conn, &client->m_vars,
              params);
    }
  else if (msg->GetType () == MSG_TOKEN_PDU_REQUEST)
    {
      status =
        HandleTokenPDURequest (client,
                   (RA_Token_PDU_Request_Msg *) msg,
                   token, conn,
                   &client->m_vars, params);
    }
  else if (msg->GetType () == MSG_NEW_PIN_REQUEST)
    {
      status =
        HandleNewPinRequest (client,
                 (RA_New_Pin_Request_Msg *) msg,
                 token, conn, &client->m_vars,
                 params);
    }
  else if (msg->GetType () == MSG_END_OP)
    {
      RA_End_Op_Msg *endOp = (RA_End_Op_Msg *) msg;
      if (endOp->GetResult () == 0)
        {
      status = 1; /* error */
        }
      else
        {
      status = 0;
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
      status = 0;
    }
  if (msg != NULL)
    {
      delete msg;
      msg = NULL;
    }

  if (status == 0)
    break;
    }

  return status;
}

int ResetPIN (
  RA_Client *client,
  NameValueSet *params,
  NameValueSet *exts,
  RA_Token *token,
  RA_Conn *conn)
{
  int status;

  RA_Begin_Op_Msg beginOp = RA_Begin_Op_Msg (OP_RESET_PIN, exts);
  conn->SendMsg (&beginOp);

  /* handle secure ID (optional) */
  while (1)
    {
  RA_Msg *msg = (RA_Msg *) conn->ReadMsg (token);
  if (msg == NULL)
    break;
  if (msg->GetType () == MSG_LOGIN_REQUEST)
    {
      status =
        HandleLoginRequest (client, (RA_Login_Request_Msg *) msg,
                token, conn, &client->m_vars,
                params);
    }
  else if (msg->GetType () == MSG_EXTENDED_LOGIN_REQUEST)
    {
      status =
        HandleExtendedLoginRequest (client,
                    (RA_Extended_Login_Request_Msg *)
                    msg, token, conn,
                    &client->m_vars,
                    params);
    }
  else if (msg->GetType () == MSG_STATUS_UPDATE_REQUEST)
    {
      status =
        HandleStatusUpdateRequest (client,
                   (RA_Status_Update_Request_Msg *) msg,
                   token, conn,
                   &client->m_vars, params);
    }
  else if (msg->GetType () == MSG_SECUREID_REQUEST)
    {
      status =
        HandleSecureIdRequest (client,
                   (RA_SecureId_Request_Msg *) msg,
                   token, conn,
                   &client->m_vars, params);
    }
  else if (msg->GetType () == MSG_ASQ_REQUEST)
    {
      status =
        HandleASQRequest (client, (RA_ASQ_Request_Msg *) msg,
              token, conn, &client->m_vars,
              params);
    }
  else if (msg->GetType () == MSG_TOKEN_PDU_REQUEST)
    {
      status =
        HandleTokenPDURequest (client,
                   (RA_Token_PDU_Request_Msg *) msg,
                   token, conn,
                   &client->m_vars, params);
    }
  else if (msg->GetType () == MSG_NEW_PIN_REQUEST)
    {
      status =
        HandleNewPinRequest (client,
                 (RA_New_Pin_Request_Msg *) msg,
                 token, conn, &client->m_vars,
                 params);
    }
  else if (msg->GetType () == MSG_END_OP)
    {
      RA_End_Op_Msg *endOp = (RA_End_Op_Msg *) msg;
      if (endOp->GetResult () == 0)
        {
      status = 1; /* error */
        }
      else
        {
      status = 0;
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
      status = 0;
    }
  if (msg != NULL)
    {
      delete msg;
      msg = NULL;
    }

  if (status == 0)
    break;
    }

  return status;
}

int EnrollToken (
  RA_Client *client,
  NameValueSet *params,
  NameValueSet *exts,
  RA_Token *token,
  RA_Conn *conn)
{

  RA_Begin_Op_Msg beginOp = RA_Begin_Op_Msg (OP_ENROLL, exts);
  conn->SendMsg (&beginOp);

  /* handle secure ID (optional) */
  int status;
  while (1)
    {
  RA_Msg *msg = (RA_Msg *) conn->ReadMsg (token);
  if (msg == NULL)
    break;
  if (msg->GetType () == MSG_LOGIN_REQUEST)
    {
      status = HandleLoginRequest (client,
                         (RA_Login_Request_Msg *) msg,
                         token, conn,
                         &client->m_vars,
                         params);
    }
  else if (msg->GetType () == MSG_EXTENDED_LOGIN_REQUEST)
    {
      status = HandleExtendedLoginRequest (client,
                             (RA_Extended_Login_Request_Msg
                          *) msg, token,
                             conn,
                             &client->m_vars,
                             params);
    }
  else if (msg->GetType () == MSG_STATUS_UPDATE_REQUEST)
    {
      status =
        HandleStatusUpdateRequest (client,
                   (RA_Status_Update_Request_Msg *) msg,
                   token, conn,
                   &client->m_vars, params);
    }
  else if (msg->GetType () == MSG_SECUREID_REQUEST)
    {
      status = HandleSecureIdRequest (client,
                        (RA_SecureId_Request_Msg *)
                        msg, token, conn,
                        &client->m_vars,
                        params);
    }
  else if (msg->GetType () == MSG_ASQ_REQUEST)
    {
      status = HandleASQRequest (client,
                       (RA_ASQ_Request_Msg *) msg,
                       token, conn,
                       &client->m_vars,
                       params);
    }
  else if (msg->GetType () == MSG_TOKEN_PDU_REQUEST)
    {
      status = HandleTokenPDURequest (client,
                        (RA_Token_PDU_Request_Msg *)
                        msg, token, conn,
                        &client->m_vars,
                        params);
      status = 1;
    }
  else if (msg->GetType () == MSG_NEW_PIN_REQUEST)
    {
      status = HandleNewPinRequest (client,
                      (RA_New_Pin_Request_Msg *)
                      msg, token, conn,
                      &client->m_vars,
                      params);
    }
  else if (msg->GetType () == MSG_END_OP)
    {
      RA_End_Op_Msg *endOp = (RA_End_Op_Msg *) msg;
      if (endOp->GetResult () == 0)
        {
      status = 1; /* error */
        }
      else
        {
      status = 0;
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
      status = 0; /* error */
    }
  if (msg != NULL)
    {
      delete msg;
      msg = NULL;
    }
    }

  return status;
}

void ThreadConnUpdate (void *arg)
{
  ThreadArg *targ = (ThreadArg *) arg;
  char *extensions;
  NameValueSet *exts = NULL;

  PRTime start = PR_Now ();

  char *hostname = targ->client->m_vars.GetValue ("ra_host");
  int port = atoi (targ->client->m_vars.GetValue ("ra_port"));
  char *uri = targ->client->m_vars.GetValue ("ra_uri");

  RA_Conn *conn = new RA_Conn(hostname, port, uri);
  if (!conn->Connect ())
    {
  OutputError ("Cannot connect to %s:%d", hostname, port);
  targ->status = 0;
  goto done;
    }

  extensions = targ->params->GetValueAsString ((char *) "extensions", NULL);
  if (extensions != NULL)
    {
  exts = NameValueSet::Parse (extensions, "&");
    }

  targ->status = FormatToken (targ->client, targ->params, exts, targ->token, conn);
  conn->Close ();

done:
  delete conn;

  PRTime end = PR_Now ();
  targ->time = (end - start) / 1000;

  if (!targ->client->old_style)
    {
  PR_Lock (targ->donelock);
  targ->done = PR_TRUE;
  PR_Unlock (targ->donelock);
    }
}

void ThreadConnResetPin (void *arg)
{
  ThreadArg *targ = (ThreadArg *) arg;
  char *extensions;
  NameValueSet *exts = NULL;

  PRTime start = PR_Now ();

  char *hostname = targ->client->m_vars.GetValue ("ra_host");
  int port = atoi (targ->client->m_vars.GetValue ("ra_port"));
  char *uri = targ->client->m_vars.GetValue ("ra_uri");

  RA_Conn *conn = new RA_Conn(hostname, port, uri);
  if (!conn->Connect ())
    {
  OutputError ("Cannot connect to %s:%d", hostname, port);
  targ->status = 0;
  goto done;
    }

  extensions = targ->params->GetValueAsString ((char *) "extensions", NULL);
  if (extensions != NULL)
    {
  exts = NameValueSet::Parse (extensions, "&");
    }

  targ->status = ResetPIN (targ->client, targ->params, exts, targ->token, conn);
  conn->Close ();

done:
  delete conn;

  PRTime end = PR_Now ();
  targ->time = (end - start) / 1000;

  if (!targ->client->old_style)
    {
  PR_Lock (targ->donelock);
  targ->done = PR_TRUE;
  PR_Unlock (targ->donelock);
    }
}

void ThreadConnEnroll (void *arg)
{
  ThreadArg *targ = (ThreadArg *) arg;
  char *extensions;
  NameValueSet *exts = NULL;

  PRTime start = PR_Now ();

  char *hostname = targ->client->m_vars.GetValue ("ra_host");
  int port = atoi (targ->client->m_vars.GetValue ("ra_port"));
  char *uri = targ->client->m_vars.GetValue ("ra_uri");

  RA_Conn *conn = new RA_Conn(hostname, port, uri);
  if (!conn->Connect ())
    {
  OutputError ("Cannot connect to %s:%d", hostname, port);
  targ->status = 0;
  goto done;
    }

  extensions = targ->params->GetValueAsString ((char *) "extensions", NULL);
  if (extensions != NULL)
    {
  exts = NameValueSet::Parse (extensions, "&");
    }

  targ->status = EnrollToken (targ->client, targ->params, exts, targ->token, conn);
  conn->Close ();

done:
  delete conn;

  PRTime end = PR_Now ();
  targ->time = (end - start) / 1000;

  if (!targ->client->old_style)
    {
  PR_Lock (targ->donelock);
  targ->done = PR_TRUE;
  PR_Unlock (targ->donelock);
    }
}

int
OpConnUpdate (RA_Client* client, NameValueSet * params)
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
      if(threads) {
          free(threads);
          threads = NULL;
      }
      return 0;
    }

  /* start threads */
  for (i = 0; i < num_threads; i++)
    {
      arg[i].time = 0;
      arg[i].status = 0;
      arg[i].client = client;
      if (i == 0)
    {
      arg[i].token = &client->m_token;
    }
      else
    {
      arg[i].token = client->m_token.Clone ();
    }
      arg[i].params = params;
      threads[i] = PR_CreateThread (PR_USER_THREAD, ThreadConnUpdate, &arg[i], PR_PRIORITY_NORMAL,  /* Priority */
                    PR_GLOBAL_THREAD,   /* Scope */
                    PR_JOINABLE_THREAD, /* State */
                    0   /* Stack Size */
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

  if(arg) {
     free(arg);
     arg = NULL;
  }

  if(threads) {
     free(threads);
     threads = NULL;
  }

  return status;
}

int
OpConnResetPin (RA_Client* client, NameValueSet * params)
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
      if(threads) {
          free(threads);
          threads = NULL;
      }
      return 0;
    }

  /* start threads */
  for (i = 0; i < num_threads; i++)
    {
      arg[i].time = 0;
      arg[i].status = 0;
      arg[i].client = client;
      if (i == 0)
    {
      arg[i].token = &client->m_token;
    }
      else
    {
      arg[i].token = client->m_token.Clone ();
    }
      arg[i].params = params;
      threads[i] = PR_CreateThread (PR_USER_THREAD, ThreadConnResetPin, &arg[i], PR_PRIORITY_NORMAL,    /* Priority */
                    PR_GLOBAL_THREAD,   /* Scope */
                    PR_JOINABLE_THREAD, /* State */
                    0   /* Stack Size */
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

  if(arg) {
     free(arg);
     arg = NULL;
  }

  if(threads) {
     free(threads);
     threads = NULL;
  }

  return status;
}

int
OpConnEnroll (RA_Client* client, NameValueSet * params)
{
  int num_threads = params->GetValueAsInt ((char *) "num_threads", 1);
  int i;
  int status = 0;
  PRThread **threads;
  ThreadArg *arg;

  threads = (PRThread **) malloc (sizeof (PRThread *) * num_threads);
  if (threads == NULL)
    {
      return 0;         /* error */
    }
  arg = (ThreadArg *) malloc (sizeof (ThreadArg) * num_threads);
  if (arg == NULL)
    {
      if(threads) {
          free(threads);
          threads = NULL;
      }
      return 0;
    }

  /* start threads */
  for (i = 0; i < num_threads; i++)
    {
      arg[i].time = 0;
      arg[i].status = 0;
      arg[i].client = client;
      if (i == 0)
    {
      arg[i].token = &client->m_token;
    }
      else
    {
      arg[i].token = client->m_token.Clone ();
    }
      arg[i].params = params;
      threads[i] = PR_CreateThread (PR_USER_THREAD, ThreadConnEnroll, &arg[i], PR_PRIORITY_NORMAL,  /* Priority */
                    PR_GLOBAL_THREAD,   /* Scope */
                    PR_JOINABLE_THREAD, /* State */
                    0   /* Stack Size */
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

  if(arg) {
     free(arg);
     arg = NULL;
  }

  if(threads) {
     free(threads);
     threads = NULL;
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
          threads[i] = PR_CreateThread (PR_USER_THREAD, ThreadConnEnroll, &arg[i], PR_PRIORITY_NORMAL,  /* Priority */
                        PR_GLOBAL_THREAD,   /* Scope */
                        PR_JOINABLE_THREAD, /* State */
                        0   /* Stack Size */
        );
        }
      else if (op_type == OP_CLIENT_FORMAT)
        {
          threads[i] = PR_CreateThread (PR_USER_THREAD, ThreadConnUpdate, &arg[i], PR_PRIORITY_NORMAL,  /* Priority */
                        PR_GLOBAL_THREAD,   /* Scope */
                        PR_JOINABLE_THREAD, /* State */
                        0   /* Stack Size */
        );
        }
      else
        {           // OP_CLIENT_RESET_PIN
          threads[i] = PR_CreateThread (PR_USER_THREAD, ThreadConnResetPin, &arg[i], PR_PRIORITY_NORMAL,    /* Priority */
                        PR_GLOBAL_THREAD,   /* Scope */
                        PR_JOINABLE_THREAD, /* State */
                        0   /* Stack Size */
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
OpConnStart (RA_Client* client, NameValueSet * params, RequestType op_type)
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
      return 0;         /* error */
    }
  arg = (ThreadArg *) malloc (sizeof (ThreadArg) * num_threads);
  if (arg == NULL)
    {
      if(threads) {
          free(threads);
          threads = NULL;
      }
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
        StartThreads (num_threads, arg, threads, max_ops - count, client,
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
    }               // while

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

  if(arg) {
     free(arg);
     arg = NULL;
  }

  if(threads) {
     free(threads);
     threads = NULL;
  }

  return status;

}

/**
 * Invoke operation.
 */
void
InvokeOperation (RA_Client* client, char *op, NameValueSet * params)
{
  PRTime start, end;
  int status = 0;

  start = PR_Now ();
  int max_ops = params->GetValueAsInt ((char *) "max_ops");
  if (max_ops != 0)
    client->old_style = PR_FALSE;

  if (strcmp (op, "help") == 0)
    {
      status = client->OpHelp (params);
    }
  else if (strcmp (op, "ra_format") == 0)
    {
      if (client->old_style)
    status = OpConnUpdate (client, params);
      else
    status = OpConnStart (client, params, OP_CLIENT_FORMAT);
    }
  else if (strcmp (op, "ra_reset_pin") == 0)
    {
      if (client->old_style)
    status = OpConnResetPin (client, params);
      else
    status = OpConnStart (client, params, OP_CLIENT_RESET_PIN);
    }
  else if (strcmp (op, "ra_enroll") == 0)
    {
      if (client->old_style)
    status = OpConnEnroll (client, params);
      else
    status = OpConnStart (client, params, OP_CLIENT_ENROLL);
    }
  else if (strcmp (op, "token_status") == 0)
    {
      status = client->OpTokenStatus (params);
    }
  else if (strcmp (op, "token_set") == 0)
    {
      status = client->OpTokenSet (params);
    }
  else if (strcmp (op, "debug") == 0)
    {
      status = client->OpVarDebug (params);
    }
  else if (strcmp (op, "var_set") == 0)
    {
      status = client->OpVarSet (params);
    }
  else if (strcmp (op, "var_get") == 0)
    {
      status = client->OpVarGet (params);
    }
  else if (strcmp (op, "var_list") == 0)
    {
      status = client->OpVarList (params);
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
Execute (RA_Client* client)
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
      break;        /* exit if no more line */
    }
      if (line[0] == '#')
    {
      continue;     /* ignore comment line */
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
      InvokeOperation (client, op, params);
    }
      if (params != NULL)
    {
      delete params;
      params = NULL;
    }
    }
}                              /* Execute */

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

  fprintf(stderr, "WARNING: tpsclient has been deprecated. Use pki tps-client instead.\n");

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
  RA_Client* client = new RA_Client();
  Execute(client);
  delete client;

  /* Shutdown NSS and NSPR */
  NSS_Shutdown ();
  PR_Cleanup ();

  return 1;
}
