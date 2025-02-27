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
#include "pk11func.h"
#include "nss.h"

#include "main/RA_Client.h"

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
      client->InvokeOperation (op, params);
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
