/** BEGIN COPYRIGHT BLOCK
 *
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is the Netscape security libraries.
 *
 * The Initial Developer of the Original Code is
 * Netscape Communications Corporation.
 * Portions created by the Initial Developer are Copyright (C) 1994-2000
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 * 
 * Copyright (C) 2007 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK **/

/* This file is based upon the file originally obtained from:
 * 
 *     CVSROOT=:pserver:anonymous@cvs-mirror.mozilla.org:/cvsroot
 *     cvs export -r NSS_3_11_3_RTM -N
 *     mozilla/security/nss/cmd/p7content/p7content.c
 */

/*
 * p7tool -- A command to display/process pkcs7 content.
 *
 */

#ifdef HAVE_CONFIG_H
#ifndef AUTOTOOLS_CONFIG_H
#define AUTOTOOLS_CONFIG_H

/* Eliminate warnings when using Autotools */
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#include <config.h>
#endif /* AUTOTOOLS_CONFIG_H */
#endif /* HAVE_CONFIG_H */

#include "nspr.h"
#include "secutil.h"
#include "plgetopt.h"
#include "secpkcs7.h"
#include "cert.h"
#include "certdb.h"
#include "nss.h"

#if defined(XP_UNIX)
#include <unistd.h>
#endif

#include <stdio.h>
#include <string.h>

#if (defined(XP_WIN) && !defined(WIN32)) || (defined(__sun) && !defined(SVR4))
extern int fwrite(char *, size_t, size_t, FILE*);
extern int fprintf(FILE *, char *, ...);
#endif


static void
Usage(char *progName)
{
    fprintf(stderr,
	    "Usage:  %s [-d dbdir] [-p chainFilePrefix] [-a] [-i input] [-o output]\n",
	    progName);
    fprintf(stderr,
	    "%-20s Key/Cert database directory (default is ~/.netscape)\n",
	    "-d dbdir");
    fprintf(stderr, "%-20s Define the cert chain file name prefix(default is chaincert)\n",
        "-p chainFilePrefix");
    fprintf(stderr, "%-20s Input is in ascii encoded form (RFC1113)\n",
        "-a");
    fprintf(stderr, "%-20s Define an input file to use (default is stdin)\n",
	    "-i input");
    fprintf(stderr, "%-20s Define an output file to use (default is stdout)\n",
	    "-o output");
    exit(-1);
}

static PRBool saw_content;

static void
PrintBytes(void *arg, const char *buf, unsigned long len)
{
    FILE *out;

    out = arg; 
    fwrite (buf, len, 1, out);

    saw_content = PR_TRUE;
}

/*
 * XXX Someday we may want to do real policy stuff here.  This allows
 * anything to be decrypted, which is okay for a test program but does
 * not set an example of how a real client with a real policy would
 * need to do it.
 */
static PRBool
decryption_allowed(SECAlgorithmID *algid, PK11SymKey *key)
{
    return PR_TRUE;
}

int
DecodeAndPrintFile(FILE *out, PRFileDesc *in, char *progName, int ascii,
                  char *prefix)
{
    SECItem derdata;
    SEC_PKCS7ContentInfo *cinfo = NULL;
    SEC_PKCS7DecoderContext *dcx;
    int rv;

    if (SECU_ReadDERFromFile(&derdata, in, ascii)) {
        SECU_PrintError(progName, "error converting der");
	return -1;
    }

    fprintf(out, "Pretty Print of PKCS#7 content:\n");
    rv = SECU_PrintPKCS7ContentInfo(out, &derdata,
                    "PKCS #7 Content Info", 0);
/*
    fprintf(out,
	    "Content printed between bars (newline added before second bar):");
    fprintf(out, "\n---------------------------------------------\n");
*/
    if (rv) {
        fprintf(stderr, "%s: problem converting data (%s)\n",
        progName, SECU_Strerror(PORT_GetError()));
        return -1;
    }

    saw_content = PR_FALSE;
    dcx = SEC_PKCS7DecoderStart(PrintBytes, out, NULL, NULL,
				NULL, NULL, decryption_allowed);
    if (dcx != NULL) {
#if 0	/* Test that decoder works when data is really streaming in. */
	{
	    unsigned long i;
	    for (i = 0; i < derdata.len; i++)
		SEC_PKCS7DecoderUpdate(dcx, derdata.data + i, 1);
	}
#else
	SEC_PKCS7DecoderUpdate(dcx, (char *)derdata.data, derdata.len);
#endif
	cinfo = SEC_PKCS7DecoderFinish(dcx);
    }
/*
    fprintf(out, "\n---------------------------------------------\n");
*/
    if (cinfo == NULL)
	return -1;
/*
    fprintf(out, "Content was%s encrypted.\n",
	    SEC_PKCS7ContentIsEncrypted(cinfo) ? "" : " not");
*/

    if (SEC_PKCS7ContentIsSigned(cinfo)) {
	char *signer_cname, *signer_ename;
	SECItem *signing_time;

	if (saw_content) {
	    fprintf(out, "Signature is ");
	    PORT_SetError(0);
	    if (SEC_PKCS7VerifySignature(cinfo, certUsageEmailSigner, PR_FALSE))
		fprintf(out, "valid.\n");
	    else
		fprintf(out, "invalid (Reason: %s).\n",
			SECU_Strerror(PORT_GetError()));
	} else {
	    fprintf(out,
		    "Content is detached; signature cannot be verified.\n");
	}

	signer_cname = SEC_PKCS7GetSignerCommonName(cinfo);
	if (signer_cname != NULL) {
	    fprintf(out, "The signer's common name is %s\n", signer_cname);
	    PORT_Free(signer_cname);
	} else {
	    fprintf(out, "No signer common name.\n");
	}

	signer_ename = SEC_PKCS7GetSignerEmailAddress(cinfo);
	if (signer_ename != NULL) {
	    fprintf(out, "The signer's email address is %s\n", signer_ename);
	    PORT_Free(signer_ename);
	} else {
	    fprintf(out, "No signer email address.\n");
	}

	signing_time = SEC_PKCS7GetSigningTime(cinfo);
	if (signing_time != NULL) {
	    SECU_PrintTimeChoice(out, signing_time, "Signing time", 0);
	} else {
	    fprintf(out, "No signing time included.\n");
	}
    } else {
/*  	    fprintf(out, "Content was not signed.\n");*/
    }
/*
    fprintf(out, "There were%s certs or crls included.\n",
	    SEC_PKCS7ContainsCertsOrCrls(cinfo) ? "" : " no");
*/

    /* write out certs */
    SECItem **items = NULL;
    SECOidTag kind;

    kind = SEC_PKCS7ContentType (cinfo);
    if (kind == SEC_OID_PKCS7_SIGNED_DATA) {
/*        fprintf(out, "content is SEC_OID_PKCS7_SIGNED_DATA\n");*/
        SEC_PKCS7SignedData *sdp;

        sdp = cinfo->content.signedData;
        if (sdp != NULL) {
        items = sdp->rawCerts;
        }
    } else {
/*        fprintf(out, "content is not SEC_OID_PKCS7_SIGNED_DATA\n");*/

    }

    int i= 0;
    if (items != NULL) {
        CERTCertificate *cert;
        if (prefix == NULL) {
            prefix = "chaincert";
        }
        while ((items[i]) != NULL) {
            cert = (CERTCertificate*) items[i]->data;
            FILE *outFile;
            char filename[256];
            int nb = 0;

            sprintf(filename, "%s%d.der", prefix, i);

            outFile = fopen(filename, "wb");
            nb = fwrite((char *) cert, 1, items[i]->len, outFile);
            fclose(outFile);

            i++;
        }
    } else {
        fprintf(out, "certs is NULL\n");
    }

    SEC_PKCS7DestroyContentInfo(cinfo);
    return i;
}


/*
 * Print the contents of a PKCS7 message, indicating signatures, etc.
 */

int
main(int argc, char **argv)
{
    char *progName;
    FILE *outFile;
    PRFileDesc *inFile;
    PLOptState *optstate;
    PLOptStatus status;
    SECStatus rv;
    int ascii = 0;
    char *prefix = NULL;
    int exitStatus = 0;

    progName = strrchr(argv[0], '/');
    progName = progName ? progName+1 : argv[0];

    inFile = NULL;
    outFile = NULL;

    /*
     * Parse command line arguments
     */
    optstate = PL_CreateOptState(argc, argv, "ad:i:o:p:");
    while ((status = PL_GetNextOpt(optstate)) == PL_OPT_OK) {
	switch (optstate->option) {
	  case 'd':
	    SECU_ConfigDirectory(optstate->value);
	    break;

      case 'a':
        ascii = 1;
        break;

	  case 'i':
	    inFile = PR_Open(optstate->value, PR_RDONLY, 0);
	    if (!inFile) {
		fprintf(stderr, "%s: unable to open \"%s\" for reading\n",
			progName, optstate->value);
		return -1;
	    }
	    break;

	  case 'o':
	    outFile = fopen(optstate->value, "w");
	    if (!outFile) {
		fprintf(stderr, "%s: unable to open \"%s\" for writing\n",
			progName, optstate->value);
		return -1;
	    }
	    break;

      case 'p':
        prefix = optstate->value;
        break;

	  default:
	    Usage(progName);
	    break;
	}
    }
    if (status == PL_OPT_BAD)
	Usage(progName);

    if (!inFile) inFile = PR_STDIN;
    if (!outFile) outFile = stdout;

    /* Call the initialization routines */
    PR_Init(PR_SYSTEM_THREAD, PR_PRIORITY_NORMAL, 1);
    rv = NSS_Init(SECU_ConfigDirectory(NULL));
    if (rv != SECSuccess) {
	SECU_PrintPRandOSError(progName);
	return -1;
    }

    exitStatus = DecodeAndPrintFile(outFile, inFile, progName, ascii, prefix);
    if (exitStatus < 0) {
	    SECU_PrintError(progName, "problem decoding data");
	    return -1;
    }
    
    if (NSS_Shutdown() != SECSuccess) {
        exit(1);
    }

    return exitStatus;
/*    return 0;*/
}
