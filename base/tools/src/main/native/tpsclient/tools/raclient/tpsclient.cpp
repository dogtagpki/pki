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

#include "pk11func.h"
#include "nss.h"

#include "main/RA_Client.h"

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
  RA_Client client;
  client.Execute ();

  /* Shutdown NSS and NSPR */
  NSS_Shutdown ();
  PR_Cleanup ();

  return 1;
}
