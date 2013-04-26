/* --- BEGIN COPYRIGHT BLOCK ---
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 * 
 * Copyright (C) 2007 Red Hat, Inc.
 * All rights reserved.
 * --- END COPYRIGHT BLOCK ---
 */

/* vi: set ts=4 sw=4 : */
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

#include <stdio.h>
#include <string.h>
#include <time.h>

#if defined(XP_UNIX)
#include <unistd.h>
#endif

#include "ssl.h"

#include "prerror.h"

#include "pk11func.h"
#include "secitem.h"


#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>

#include "nspr.h"
#include "prio.h"
#include "prnetdb.h"
#include "nss.h"


/*  set Tabs to 8 */


/*from nss2.8.4 secopt.h*/
#ifdef XP_PC

/*
**  This comes from the AT&T public-domain getopt published in mod.sources
**  (i.e., comp.sources.unix before the great Usenet renaming).
*/

extern int	opterr;
extern int	optind;
extern int	optopt;
extern char	*optarg;

#ifdef _WIN32
static void do_opterr(const char *s, int c, char * const av[]);
#define ERR(s, c) do_opterr(s, c, av)
#else
#define ERR(s, c) /* Win16 doesn't do stderr */
#endif

/*
**  Return options and their values from the command line.
*/
int getopt(int ac, char * const av[], const char * opts);
#else
#if defined(LINUX)
#include <getopt.h>
#endif
#endif /* XP_PC */
/*end secopt.h*/

#define VERSIONSTRING "$Revision$ ($Date$)"

#ifndef PORT_Sprintf
#define PORT_Sprintf sprintf
#endif

#ifndef PORT_Strstr
#define PORT_Strstr strstr
#endif

#ifndef PORT_Malloc
#define PORT_Malloc PR_Malloc
#endif

#define RD_BUF_SIZE (60 * 1024)

#define PRINTF  if (verbose)  printf
#define FPRINTF if (verbose) fprintf
#define FPUTS   if (verbose) fputs

#define MAX_SERIAL_LEN 8192

int MakeCertOK=1;

int	verbose;
SECItem	bigBuf;


char * ownPasswd( PK11SlotInfo *slot, PRBool retry, void *arg)
{
    char *passwd = NULL;

    if ( (!retry) && arg ) {
	passwd = PL_strdup((char *)arg);
    }

    return passwd;
}

static void
Usage(const char *progName)
{
    fprintf(stderr, 
    	"Usage: %s [-n nickname] [-p password | -w pwfile ] [-d dbdir] \n"
	"          [-e post] [-v] [-V] -r url hostname[:port]\n"
    "     -n  : nickname or hsm:nickname\n"
    "     -v  : verbose\n"
    "     -V  : report version information\n",
	progName);
    exit(1);
}


static void
errWarn(char * funcString)
{
    PRErrorCode  perr      = PR_GetError();

    FPRINTF(stderr, "exit after %s with error %d:\n", funcString,perr );
}

static void
errExit(char * funcString)
{
    errWarn(funcString);
    exit(1);
}

/* This invokes the "default" AuthCert handler in libssl.
** The only reason to use this one is that it prints out info as it goes. 
*/
static SECStatus
mySSLAuthCertificate(void *arg, PRFileDesc *fd, PRBool checkSig,
		     PRBool isServer)
{
    SECStatus rv;
    CERTCertificate *    peerCert;

    peerCert = SSL_PeerCertificate(fd);

    PRINTF("Subject: %s\nIssuer : %s\n", 
           peerCert->subjectName, peerCert->issuerName); 
    /* invoke the "default" AuthCert handler. */
    rv = SSL_AuthCertificate(arg, fd, checkSig, isServer);

    if (rv == SECSuccess) {
	FPUTS("-- SSL3: Server Certificate Validated.\n", stderr);
    } 
    /* error, if any, will be displayed by the Bad Cert Handler. */
    return rv;  
}

static SECStatus 
myBadCertHandler( void *arg, PRFileDesc *fd)
{
    /* int err = PR_GetError(); */
    /* fprintf(stderr, "-- SSL: Server Certificate Invalid, err %d.\n%s\n", 
            err, SECU_Strerror(err)); */
    return (MakeCertOK ? SECSuccess : SECFailure);
}


SECStatus
my_GetClientAuthData(void *                       arg,
                      PRFileDesc *                 socket,
              struct CERTDistNamesStr *    caNames,
              struct CERTCertificateStr ** pRetCert,
              struct SECKEYPrivateKeyStr **pRetKey)
{
  CERTCertificate *  cert = NULL;
  SECKEYPrivateKey * privkey = NULL;
  char *             chosenNickName = (char *)arg;    /* CONST */
  void *             proto_win  = NULL;
  SECStatus          rv         = SECFailure;

  FPRINTF(stderr,"Called mygetclientauthdata - nickname = %s\n",chosenNickName);

  proto_win = SSL_RevealPinArg(socket);

  if (chosenNickName) {
    cert = PK11_FindCertFromNickname(chosenNickName, proto_win);
    FPRINTF(stderr,"   mygetclientauthdata - cert = %x\n",(unsigned int)cert);
    if ( cert ) {
      privkey = PK11_FindKeyByAnyCert(cert, proto_win);
      FPRINTF(stderr,"   mygetclientauthdata - privkey = %x\n",(unsigned int)privkey);
      if ( privkey ) {
    rv = SECSuccess;
      } else {
    CERT_DestroyCertificate(cert);
      }
    }
  } else { /* no name given, automatically find the right cert. */
    CERTCertNicknames * names;
    int                 i;

    names = CERT_GetCertNicknames(CERT_GetDefaultCertDB(),
                  SEC_CERT_NICKNAMES_USER, proto_win);
    if (names != NULL) {
      for (i = 0; i < names->numnicknames; i++) {
    cert = PK11_FindCertFromNickname(names->nicknames[i],proto_win);
    if ( !cert )
      continue;
    /* Only check unexpired certs */
    if (CERT_CheckCertValidTimes(cert, PR_Now(), PR_TRUE) !=
        secCertTimeValid ) {
      CERT_DestroyCertificate(cert);
      continue;
    }
    rv = NSS_CmpCertChainWCANames(cert, caNames);
    if ( rv == SECSuccess ) {
      privkey = PK11_FindKeyByAnyCert(cert, proto_win);
      if ( privkey )
        break;
    }
    rv = SECFailure;
    CERT_DestroyCertificate(cert);
      }
      CERT_FreeNicknames(names);
    }
  }
  if (rv == SECSuccess) {
    *pRetCert = cert;
    *pRetKey  = privkey;
  }
  return rv;
}




void 
printSecurityInfo(PRFileDesc *fd)
{
    char * cp;	/* bulk cipher name */
    char * ip;	/* cert issuer DN */
    char * sp;	/* cert subject DN */
    int    op;	/* High, Low, Off */
    int    kp0;	/* total key bits */
    int    kp1;	/* secret key bits */
    int    result;

    static int only_once;

    if (! only_once++ && fd) {
	result = SSL_SecurityStatus(fd, &op, &cp, &kp0, &kp1, &ip, &sp);
	if (result != SECSuccess)
	    return;
#if 0
	PRINTF("bulk cipher %s, %d secret key bits, %d key bits, status: %d\n"
	       "subject DN: %s\n"
	       "issuer  DN: %s\n", cp, kp1, kp0, op, sp, ip);
#else
	PRINTF("bulk cipher %s, %d secret key bits, %d key bits, status: %d\n",
	       cp, kp1, kp0, op);
#endif
	PR_Free(cp);
	PR_Free(ip);
	PR_Free(sp);
    }

}


PRBool useModelSocket = PR_TRUE;

static const char outHeader[] = {
    "HTTP/1.0 200 OK\r\n"
    "Server: Netscape-Enterprise/2.0a\r\n"
    "Date: Tue, 26 Aug 1997 22:10:05 GMT\r\n"
    "Content-type: text/plain\r\n"
    "\r\n"
};


PRInt32
do_writes(
    void *       a
)
{
    PRFileDesc *	ssl_sock	= (PRFileDesc *)a;
    PRUint32		sent  		= 0;
    PRInt32		count		= 0;

    while (sent < bigBuf.len) {

	count = PR_Write(ssl_sock, bigBuf.data + sent, bigBuf.len - sent);
	if (count < 0) {
	    errWarn("PR_Write bigBuf");
            exit(4);
	    break;
	}
	FPRINTF(stderr, "PR_Write wrote %d bytes from bigBuf\n", count );
	FPRINTF(stderr, "bytes: [%*s]\n",count,bigBuf.data);

	sent += (PRUint32)count;
    }
    if (count >= 0) {	/* last write didn't fail. */
	FPRINTF(stderr, "do_writes shutting down send socket\n");
    	/* PR_Shutdown(ssl_sock, PR_SHUTDOWN_SEND);  */
    }

    FPRINTF(stderr, "do_writes exiting with (failure = %d)\n",sent<bigBuf.len == SECFailure);
    return (sent < bigBuf.len) ? SECFailure : SECSuccess;
}


int isLinkLocalAddress(char *address, int family)
{
    if ( !address || ( strlen(address) == 0 ) ) {
        return 0;
    }

    if ( ( family != PR_AF_INET ) && ( family != PR_AF_INET6 ) ) {
        return 0;
    }

    /* Check for both ipv4 and ipv6 link local addresses */
    if ( family == PR_AF_INET6 ) {
        /* ipv6 link local addresses: */
        if ( ( strncasecmp( address, "fe80", 4 ) >= 0 ) &&
             ( strncasecmp( address, "feb0", 4 ) <= 0 ) ) {
            return 1; 
        }
    } else {
        /* ipv4 link local addresses */
        if ( ( strcasecmp( address, "169.254.1.0" ) >= 0 ) &&
             ( strcasecmp( address, "169.254.254.255" ) <= 0 ) ) {
            return 1;
        }
    }

    return 0;
}


SECStatus
do_io( PRFileDesc *ssl_sock, int connection)
{
    int countRead = 0;
    PRInt32 rv;
    char *buf;
    char *buf2;
    int first=1;

    buf = PR_Malloc(RD_BUF_SIZE);
    if (!buf) exit(5);
	
    /* send the http request here. */

    rv = do_writes(ssl_sock);

    if (rv == SECFailure) {
	errWarn("returning from after calling do_writes");
	PR_Free(buf);
	buf = 0;
	exit(6);
    }
    printSecurityInfo(ssl_sock);

    /* read until EOF */
    while (1) {
	rv = PR_Read(ssl_sock, buf, RD_BUF_SIZE);
	if (rv == 0) {
	    break;	/* EOF */
	}
	if (rv < 0) {
	    errWarn("PR_Read");
            PR_Free(buf);
            buf = 0;
	    exit(1);
	}

	countRead += rv;
	FPRINTF(stderr, "connection %d read %d bytes (%d total).\n", 
		connection, rv, countRead );
	FPRINTF(stderr, "these bytes read:\n");
	PR_Write(PR_STDOUT,buf,rv);

        if (first) {
             first=0;
	     if (rv < 13) {
                 int ret = 0;
                 buf2 = PR_Malloc(RD_BUF_SIZE);
                 if (!buf2) {
                     PR_Free(buf);
                     buf = 0;
                     exit(5);
                 }

                 for (ret=0; rv < 13 ; rv += ret) {
                     ret = PR_Read(ssl_sock, buf2, RD_BUF_SIZE - rv); 
                     if (ret <  0 ) {
                         errWarn("PR_Read");
                         PR_Free(buf);
                         buf = 0;
                         PR_Free(buf2);
                         buf2 = 0;
                         exit(1);
                     }
                     if (ret == 0) {
                         errWarn("not enough bytes read in first read");
                         PR_Free(buf);
                         buf = 0;
                         PR_Free(buf2);
                         buf2 = 0;
                         exit(2);
                     }
                     countRead +=  ret;
                     FPRINTF(stderr, "connection %d read %d bytes (%d total).\n",
                         connection, ret, countRead );
                     FPRINTF(stderr, "these bytes read:\n");
                     PR_Write(PR_STDOUT, buf2, ret);

                     PR_snprintf(buf, RD_BUF_SIZE, "%s%s", buf, buf2);
                 }
                 PR_Free(buf2);
                 buf2 = 0;
             }

             char *status_string = PL_strndup(buf+9, 3);
             int status = atoi(status_string);
             PL_strfree(status_string);

             if (status >= 300) {
                 PR_Free(buf);
                 buf = 0;
                 exit(3);
             }
	}
    }
    PR_fprintf(PR_STDOUT, "\n");

    PR_Free(buf);
    buf = 0;

    /* Caller closes the socket. */

    FPRINTF(stderr, 
    "connection %d read %d bytes total. -----------------------------\n", 
    	    connection, countRead);

    return SECSuccess;	/* success */
}

int
do_connect(
    PRNetAddr *addr,
    PRFileDesc *model_sock,
    int         connection)
{
    PRFileDesc *        ssl_sock;
    PRFileDesc *        tcp_sock;
    PRStatus            prStatus;
    SECStatus           result;
    int                 rv = SECSuccess;
    PRSocketOptionData  opt;

    int family = PR_NetAddrFamily( addr );

    tcp_sock = PR_OpenTCPSocket( family );
    if (tcp_sock == NULL) {
        errExit("PR_OpenTCPSocket on tcp socket");
    }

    opt.option             = PR_SockOpt_Nonblocking;
    opt.value.non_blocking = PR_FALSE;
    prStatus = PR_SetSocketOption(tcp_sock, &opt);
    if (prStatus != PR_SUCCESS) {
        if( tcp_sock != NULL ) {
            PR_Close(tcp_sock);
            tcp_sock = NULL;
        }
        /* Don't return SECFailure? */
        return SECSuccess;
    } 

    prStatus = PR_Connect(tcp_sock, addr, PR_SecondsToInterval(3));
    if (prStatus != PR_SUCCESS) {
        errWarn("PR_Connect");
        if( tcp_sock != NULL ) {
            PR_Close(tcp_sock);
            tcp_sock = NULL;
        }
        exit(6);
    }

    ssl_sock = SSL_ImportFD(model_sock, tcp_sock);
    /* XXX if this import fails, close tcp_sock and return. */
    if (!ssl_sock) {
        if( tcp_sock != NULL ) {
            PR_Close(tcp_sock);
            tcp_sock = NULL;
        }
        exit(7);
    }

    rv = SSL_ResetHandshake(ssl_sock, /* asServer */ 0);
    if (rv != SECSuccess) {
        errWarn("SSL_ResetHandshake");
        exit(8);
    }

    result = do_io( ssl_sock, connection);

    if( ssl_sock != NULL ) {
        PR_Close(ssl_sock);
        ssl_sock = NULL;
    }
    return SECSuccess;
}

/* Returns IP address for hostname as PRUint32 in Host Byte Order.
** Since the value returned is an integer (not a string of bytes), 
** it is inherently in Host Byte Order. 
*/
PRUint32
getIPAddress(const char * hostName) 
{
    const unsigned char *p;
    PRStatus	         prStatus;
    PRUint32	         rv;
    PRHostEnt	         prHostEnt;
    char                 scratch[PR_NETDB_BUF_SIZE];

    prStatus = PR_GetHostByName(hostName, scratch, sizeof scratch, &prHostEnt);
    if (prStatus != PR_SUCCESS)
	errExit("PR_GetHostByName");

#undef  h_addr
#define h_addr  h_addr_list[0]   /* address, for backward compatibility */

    p = (const unsigned char *)(prHostEnt.h_addr); /* in Network Byte order */
    FPRINTF(stderr, "%s -> %d.%d.%d.%d\n", hostName, p[0], p[1], p[2], p[3]);
    rv = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
    return rv;
}

void
client_main(
    unsigned short      port, 
    int                 connections, 
    SECKEYPrivateKey ** privKey,
    CERTCertificate **  cert, 
    const char *        hostName,
    char *              nickName)
{
    PRFileDesc *model_sock = NULL;
    int         rv;


    FPRINTF(stderr, "port: %d\n", port);

    /* all suites except RSA_NULL_MD5 are enabled by Domestic Policy */
    NSS_SetDomesticPolicy();

    /* all the SSL2 and SSL3 cipher suites are enabled by default. */

    /* enable FIPS ciphers */
    SSL_CipherPrefSetDefault(0xc004 /* TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA */, PR_TRUE);
    SSL_CipherPrefSetDefault(0xc003 /* TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA */, PR_TRUE);
    SSL_CipherPrefSetDefault(0xC005 /* TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA */, PR_TRUE);
    SSL_CipherPrefSetDefault(0xc00a /* TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA */, PR_TRUE);
    SSL_CipherPrefSetDefault(0x2f /* TLS_RSA_WITH_AES_128_CBC_SHA */, PR_TRUE);
    SSL_CipherPrefSetDefault(0x35 /* TLS_RSA_WITH_AES_256_CBC_SHA */, PR_TRUE);
    SSL_CipherPrefSetDefault(0xc008 /* TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA */, PR_TRUE);
    SSL_CipherPrefSetDefault(0xc009 /* TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA */, PR_TRUE);
    SSL_CipherPrefSetDefault(0xc012 /* TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA */, PR_TRUE);
    SSL_CipherPrefSetDefault(0xc013 /* TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA */, PR_TRUE);
    SSL_CipherPrefSetDefault(0xc014 /* TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA */, PR_TRUE);
    SSL_CipherPrefSetDefault(0x32 /* TLS_DHE_DSS_WITH_AES_128_CBC_SHA */, PR_TRUE);
    SSL_CipherPrefSetDefault(0x38 /* TLS_DHE_DSS_WITH_AES_256_CBC_SHA */, PR_TRUE);
    SSL_CipherPrefSetDefault(0x33 /* TLS_DHE_RSA_WITH_AES_128_CBC_SHA */, PR_TRUE);
    SSL_CipherPrefSetDefault(0x39 /* TLS_DHE_RSA_WITH_AES_256_CBC_SHA */, PR_TRUE);

    /*
     *  Rifle through the values for the host
     */

    PRAddrInfo *ai;
    void *iter;
    PRNetAddr addr;
    char addrBuf[80];
    int family = PR_AF_INET;

    ai = PR_GetAddrInfoByName(hostName, PR_AF_UNSPEC, PR_AI_ADDRCONFIG);
    if (ai) {
        FPRINTF( stderr, "addr='%s'\n", PR_GetCanonNameFromAddrInfo( ai ) );
        iter = NULL;
        while ((iter = PR_EnumerateAddrInfo(iter, ai, 0, &addr)) != NULL) {
            family = PR_NetAddrFamily(&addr);
            FPRINTF( stderr, "family='%d'\n", family );

            PR_NetAddrToString(&addr, addrBuf, 80);
            FPRINTF( stderr, "IP='%s'\n", addrBuf );

            if ( isLinkLocalAddress(addrBuf, family) ) {
                FPRINTF( stderr,
                         "Skipping link local address '%s' (family '%d')\n",
                         addrBuf, family );
                continue;
            }

            PR_SetNetAddr( PR_IpAddrNull, family, port, &addr );

            model_sock = PR_OpenTCPSocket( family );
            if (model_sock == NULL) {
                errExit("PR_OpenTCPSocket on tcp socket");
            }

            /* Should we really be re-using the same socket? */
            model_sock = SSL_ImportFD(NULL, model_sock);

            /* check on success of call to SSL_ImportFD() */
            if (model_sock == NULL) {
                errExit("SSL_ImportFD");
            }

            /* enable ECC cipher also */

            /* do SSL configuration. */

            rv = SSL_OptionSet(model_sock, SSL_SECURITY, 1);

            if (rv < 0) {
                if( model_sock != NULL ) {
                    PR_Close( model_sock );
                    model_sock = NULL;
                }
                errExit("SSL_OptionSet SSL_SECURITY");
            }

            SSL_SetURL(model_sock, hostName);
            SSL_AuthCertificateHook(model_sock, mySSLAuthCertificate,
                                    (void *)CERT_GetDefaultCertDB());
            SSL_BadCertHook(model_sock, myBadCertHandler, NULL);
            if( nickName) {
                SSL_GetClientAuthDataHook(model_sock,
                    (SSLGetClientAuthData)my_GetClientAuthData,
                    nickName);
            }

            /* I'm not going to set the HandshakeCallback function. */

            /* end of ssl configuration. */

            rv = do_connect(&addr, model_sock, 1);

            if( model_sock != NULL ) {
                PR_Close( model_sock );
                model_sock = NULL;
            }

            break;
        }

        if( model_sock != NULL ) {
            PR_Close( model_sock );
            model_sock = NULL;
        }

        FPRINTF( stderr, "Done with possible addresses - exiting.\n" );
        PR_FreeAddrInfo(ai);
    }
}


SECStatus
createRequest(char * url, char *post)
{
	char * newstr;

    if (post == NULL) {
        newstr = PR_smprintf(
			"GET %s HTTP/1.0\r\n\r\n",
			url);
    } else {
        int len = strlen(post);
        newstr = PR_smprintf(
			"POST %s HTTP/1.0\r\nContent-Length: %d\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n%s", url, len, post);
    }

    bigBuf.data = (unsigned char *)newstr;

    FPUTS((char *)bigBuf.data, stderr);

    bigBuf.len  = PORT_Strlen((char *)bigBuf.data);

    return SECSuccess;
}

int
main(int argc, char **argv)
{
    char *              dir         = ".";
    char *              hostName    = NULL;
    char *              nickName    = NULL;
    char *              progName    = NULL;
    char *              tmp         = NULL;
    char *              post        = NULL;
    CERTCertificate *   cert   [kt_kea_size] = { NULL };
    SECKEYPrivateKey *  privKey[kt_kea_size] = { NULL };
    int                 optchar;
    int                 connections = 1;
    int 		tmpI;
    unsigned short      port        = 443;
    SECStatus           rv;
    char *		passwd      = NULL;
    char *		passwdfile      = NULL;
    char *		url = NULL;
	FILE *fp;
    char pwbuf[256];
	int co;
	char *crlf;

    /* Call the NSPR initialization routines */
    PR_Init( PR_SYSTEM_THREAD, PR_PRIORITY_NORMAL, 1);

    tmp      = strrchr(argv[0], '/');
    tmp      = tmp ? tmp + 1 : argv[0];
    progName = strrchr(tmp, '\\');
    progName = progName ? progName + 1 : tmp;
 

    while ((optchar = getopt(argc, argv, "Vd:e:n:p:r:w:v")) != -1) {
	switch(optchar) {

/* Version */
	case 'V':
	  printf("%s\n",VERSIONSTRING);
	  PR_Cleanup();
	  return 0;

/* Directory which holds cert8.db and key3.db */
	case 'd':
	    dir = optarg;
	    break;

/* Nickname of certificate to use */
	case 'n':
	    nickName = optarg;
	    break;

/* password to open key3.db */
	case 'p':
	    passwd = optarg;
	    break;

/* name of file holding password for key3.db */
	case 'w':
	    passwdfile = optarg;
	    break;

/* url */
	case 'r':
	    url = optarg;
	    break;

/* post parameters */
	case 'e':
	    post = optarg;
	    break;

        case 'v':
            verbose++;
	    break;

	default:
	case '?':
	    fprintf( stderr, "ERROR:  Invalid option!\n" );
	    Usage(progName);
	    break;

	}
    }

    if (optind != argc - 1) {
	    fprintf( stderr, "ERROR:  Invalid number of arguments!\n" );
    	Usage(progName);
    }

    hostName = argv[optind];
    tmp      = strchr(hostName, ':');
    if (tmp) {
	*tmp++ = 0;
	tmpI = atoi(tmp);
	if (tmpI <= 0) {
	    fprintf( stderr, "ERROR:  Invalid port!\n" );
	    Usage(progName);
    }
     	port = (unsigned short)tmpI;
    }

    if ( !url) {
	fprintf( stderr, "ERROR:  Invalid url!\n" );
	Usage(progName);
    }

    createRequest(url, post);

	if (passwdfile) {
		fp = fopen(passwdfile,"r");
		if (!fp) { fprintf(stderr, "Couldn't open password file\n"); exit(7); }
		co = fread(pwbuf,1,256,fp);
		pwbuf[co] = '\0';
		crlf  = PL_strchr(pwbuf,'\n');
		if (crlf) {
			*crlf = '\0';
		}
		passwd = pwbuf;
	}

    /* set our password function */
    if (passwd == NULL) {
		fprintf( stderr, "ERROR:  Invalid password!\n" );
		PRINTF("Password must be provided on command line in this version of revoker.\n");
		Usage(progName);
    }
    PK11_SetPasswordFunc(ownPasswd);

    /* Call the libsec initialization routines */
    rv = NSS_Init(dir);
    if (rv != SECSuccess) {
    	fputs("NSS_Init failed.\n", stderr);
	exit(1);
    }

    if(nickName) {
    	cert[kt_rsa] = PK11_FindCertFromNickname(nickName, passwd);
    	if (cert[kt_rsa] == NULL) {
		fprintf(stderr, "Can't find certificate %s\n", nickName);
		exit(1);
    	}
    
    	privKey[kt_rsa] = PK11_FindKeyByAnyCert(cert[kt_rsa], passwd);
    	if (privKey[kt_rsa] == NULL) {
		fprintf(stderr, "Can't find Private Key for cert %s (possibly incorrect password)\n", nickName);
		exit(1);
    	}
    }

    client_main(port, connections, privKey, cert, hostName, nickName);

    NSS_Shutdown();
    PR_Cleanup();
    return 0;
}

