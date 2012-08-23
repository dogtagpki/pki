/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/** BEGIN COPYRIGHT BLOCK
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301  USA 
 * 
 * Copyright (C) 2007 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK **/

#include "nspr.h"
#include "sslproto.h"
#include "prerror.h"

#include "ssl.h"
#include "nss.h"
#include "pk11func.h"
#include "cert.h"
#include "certt.h"
#include "sslerr.h"
#include "secerr.h"

#include "httpClient/httpc/engine.h"
#include "httpClient/httpc/http.h"
#include "httpClient/httpc/PSPRUtil.h"
#include "httpClient/httpc/Defines.h"
//-- #include "httpClient/httpc/DebugLogger.h"
#include "engine/RA.h"
#include "main/Memory.h"

char* certName = NULL;
char* password = NULL;
int ciphers[32];
int cipherCount = 0;
int _doVerifyServerCert = 1;

//-- static const char *DEBUG_MODULE = "httpclient";
//-- static const char *DEBUG_CLASS_NAME = "HttpEngine";

PRIntervalTime Engine::globaltimeout = PR_TicksPerSecond()*30;

static char * ownPasswd( PK11SlotInfo *slot, PRBool retry, void *arg) {
	if (!retry) {
       if( password != NULL ) {
            return PL_strdup(password);
       } else {
            return PL_strdup( "httptest" );
       }
	} else {
		return NULL;
	}
}

/**
 * Function: SECStatus myBadCertHandler()
 * <BR>
 * Purpose: This callback is called when the incoming certificate is not
 * valid. We define a certain set of parameters that still cause the
 * certificate to be "valid" for this session, and return SECSuccess to cause
 * the server to continue processing the request when any of these conditions
 * are met. Otherwise, SECFailure is return and the server rejects the 
 * request.
 */
SECStatus myBadCertHandler( void *arg, PRFileDesc *socket ) {

    SECStatus	secStatus = SECFailure;
    PRErrorCode	err;

    /* log invalid cert here */

    if ( !arg ) {
		return secStatus;
    }

    *(PRErrorCode *)arg = err = PORT_GetError();

    /* If any of the cases in the switch are met, then we will proceed   */
    /* with the processing of the request anyway. Otherwise, the default */	
    /* case will be reached and we will reject the request.              */

    switch (err) {
    case SEC_ERROR_INVALID_AVA:
    case SEC_ERROR_INVALID_TIME:
    case SEC_ERROR_BAD_SIGNATURE:
    case SEC_ERROR_EXPIRED_CERTIFICATE:
    case SEC_ERROR_UNKNOWN_ISSUER:
    case SEC_ERROR_UNTRUSTED_CERT:
    case SEC_ERROR_CERT_VALID:
    case SEC_ERROR_EXPIRED_ISSUER_CERTIFICATE:
    case SEC_ERROR_CRL_EXPIRED:
    case SEC_ERROR_CRL_BAD_SIGNATURE:
    case SEC_ERROR_EXTENSION_VALUE_INVALID:
    case SEC_ERROR_CA_CERT_INVALID:
    case SEC_ERROR_CERT_USAGES_INVALID:
    case SEC_ERROR_UNKNOWN_CRITICAL_EXTENSION:
	case SEC_ERROR_EXTENSION_NOT_FOUND: // Added by Rob 5/21/2002
		secStatus = SECSuccess;
	break;
    default:
		secStatus = SECFailure;
	break;
    }

    return secStatus;
}


PRBool __EXPORT InitSecurity(char* certDir, char* certname, char* certpassword, char *prefix,int verify ) {
    if (certpassword) {
        password = PL_strdup(certpassword);
	} else {
        password = PL_strdup( "httptest" );
    }
    if (certname) {
        certName = PL_strdup(certname);
    }

    SECStatus stat;
	PR_Init( PR_USER_THREAD, PR_PRIORITY_NORMAL, 0 );
     if (!NSS_IsInitialized()) { 
        stat = NSS_Initialize( certDir, prefix, prefix,"secmod.db",
									 NSS_INIT_READONLY);
     } else {
        stat = SECSuccess;
        RA::Debug( LL_PER_PDU,
                        "initSecurity: ",
                        "NSS Already initialized" );

    }

    if (SECSuccess != stat) {
		// int err = PR_GetError();
        return PR_FAILURE;
	}
    PK11_SetPasswordFunc(ownPasswd);

    stat = NSS_SetDomesticPolicy();
    SSL_CipherPrefSetDefault( SSL_RSA_WITH_NULL_MD5, PR_TRUE );

	_doVerifyServerCert = verify;


     return PR_TRUE;
}


int ssl2Suites[] = {
    SSL_EN_RC4_128_WITH_MD5,                    /* A */
    SSL_EN_RC4_128_EXPORT40_WITH_MD5,           /* B */
    SSL_EN_RC2_128_CBC_WITH_MD5,                /* C */
    SSL_EN_RC2_128_CBC_EXPORT40_WITH_MD5,       /* D */
    SSL_EN_DES_64_CBC_WITH_MD5,                 /* E */
    SSL_EN_DES_192_EDE3_CBC_WITH_MD5,           /* F */
    0
};

int ssl3Suites[] = {
    SSL_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA,     /* a */
    SSL_FORTEZZA_DMS_WITH_RC4_128_SHA,          /* b */
    SSL_RSA_WITH_RC4_128_MD5,                   /* c */
    SSL_RSA_WITH_3DES_EDE_CBC_SHA,              /* d */
    SSL_RSA_WITH_DES_CBC_SHA,                   /* e */
    SSL_RSA_EXPORT_WITH_RC4_40_MD5,             /* f */
    SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5,         /* g */
    SSL_FORTEZZA_DMS_WITH_NULL_SHA,             /* h */
    SSL_RSA_WITH_NULL_MD5,                      /* i */
    SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA,         /* j */
    SSL_RSA_FIPS_WITH_DES_CBC_SHA,              /* k */
    TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA,        /* l */
    TLS_RSA_EXPORT1024_WITH_RC4_56_SHA,         /* m */
    0
};

int tlsSuites[] = {
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
    TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    TLS_RSA_WITH_AES_128_CBC_SHA,
    TLS_RSA_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
    0
};

void disableAllCiphersOnSocket(PRFileDesc* sock) {
    int i;
    int numsuites = SSL_NumImplementedCiphers;

    /* disable all the cipher suites for that socket */
    for (i = 0; i<numsuites; i++) {
        SSL_CipherPrefSet(sock, SSL_ImplementedCiphers[i], SSL_NOT_ALLOWED);
    }
}

void __EXPORT EnableAllSSL3Ciphers(PRFileDesc* sock) {
	int i =0;
	while (ssl3Suites[i]) {
        SSL_CipherPrefSet(sock, ssl3Suites[i], SSL_ALLOWED);
	}
}
 
void __EXPORT EnableAllTLSCiphers(PRFileDesc* sock) {
	int i =0;
	while (tlsSuites[i]) {
        SSL_CipherPrefSet(sock, tlsSuites[i++], SSL_ALLOWED);
	}
}
 
PRBool __EXPORT EnableCipher(const char* cipherString) {
     int ndx;
  
     if (!cipherString) {
        return PR_FALSE;
	 }

     while (0 != (ndx = *cipherString++)) {
        int* cptr;
        int cipher;

        if (! isalpha(ndx)) {
           continue;
		}
        cptr = islower(ndx) ? ssl3Suites : ssl2Suites;
        for (ndx &= 0x1f; (cipher = *cptr++) != 0 && --ndx > 0; ) {
			/* do nothing */;
		}
        ciphers[cipherCount++] = cipher;
     }

     return PR_TRUE;
}

SECStatus certcallback (
    void *arg,
    PRFileDesc *fd,
    PRBool checksig,
    PRBool isServer) {
     return SECSuccess; // always succeed
}

/**
 * Function: SECStatus myAuthCertificate()
 * <BR>
 * Purpose: This function is our custom certificate authentication handler.
 * <BR>
 * Note: This implementation is essentially the same as the default 
 *       SSL_AuthCertificate().
 */
extern "C" {

static SECStatus myAuthCertificate( void *arg,
                             PRFileDesc *socket, 
							 PRBool checksig,
                             PRBool isServer ) {

	SECCertUsage        certUsage;
	CERTCertificate *   cert;
	void *              pinArg;
	char *              hostName = NULL;
	SECStatus           secStatus = SECSuccess;
//--	static const char *DEBUG_METHOD_NAME = "myAuthCertificate";
//-- 	DebugLogger *logger = DebugLogger::GetDebugLogger( "httpclient");

	if ( !arg || !socket ) {
		return SECFailure;
	}

	/* Define how the cert is being used based upon the isServer flag. */

	certUsage = isServer ? certUsageSSLClient : certUsageSSLServer;

	cert = SSL_PeerCertificate( socket );
	
	pinArg = SSL_RevealPinArg( socket );

	// Skip the server cert verification fconditionally, because our test
    // servers do not have a valid root CA cert.
    if ( _doVerifyServerCert ) {

        PRLock *verify_lock = RA::GetVerifyLock();
        if (verify_lock == NULL) {
		  return SECFailure;
        }
        PR_Lock(verify_lock);
        /* This function is not thread-safe. So we need to use a global lock */
        secStatus = CERT_VerifyCertNow( (CERTCertDBHandle *)arg,
                                        cert,
                                        checksig,
                                        certUsage,
                                        pinArg);
        PR_Unlock(verify_lock);

		if( SECSuccess != secStatus ) {
//-- 			logger->Log( LOGLEVEL_SEVERE, DEBUG_CLASS_NAME,
//-- 						 DEBUG_METHOD_NAME,
	           if (cert == NULL) {	
                        RA::Debug( LL_PER_PDU,
                        "myAuthCertificate: ",
                        "Server Certificate Not Found" );
	           } else {
			   if (cert->subjectName == NULL) {
                        	RA::Debug( LL_PER_PDU,
                        	"myAuthCertificate: ",
                        	"Untrusted server certificate" );
			   } else {
                        	RA::Debug( LL_PER_PDU,
                        	"myAuthCertificate: ",
                        	"Untrusted server certificate error=%d subject='%s'", PORT_GetError(), cert->subjectName );
			   }
	           }
		}
    }

	/* If this is a server, we're finished. */
	if (isServer || secStatus != SECSuccess) {
		return secStatus;
	}

	/* Certificate is OK.  Since this is the client side of an SSL
	 * connection, we need to verify that the name field in the cert
	 * matches the desired hostname.  This is our defense against
	 * man-in-the-middle attacks.
	 */

	/* SSL_RevealURL returns a hostName, not an URL. */
	hostName = SSL_RevealURL( socket );

	if (hostName && hostName[0]) {
		secStatus = CERT_VerifyCertName( cert, hostName );
		if( SECSuccess != secStatus ) {
//-- 			logger->Log( LOGLEVEL_SEVERE, DEBUG_CLASS_NAME,
//-- 						 DEBUG_METHOD_NAME,
                 RA::Debug( LL_PER_PDU,
                            "myAuthCertificate: ",
                            "Server name does not match that in certificate" );
		}
	} else {
		secStatus = SECFailure;
//-- 		logger->Log( LOGLEVEL_SEVERE, DEBUG_CLASS_NAME,
//-- 					 DEBUG_METHOD_NAME,
            RA::Debug( LL_PER_PDU,
                       "myAuthCertificate: ",
                       "server name has been specified" );
	}

    if( hostName != NULL ) {
        PR_Free( hostName );
        hostName = NULL;
    }

	return secStatus;
}


/* Function: SECStatus ownGetClientAuthData()
 *
 * Purpose: This callback is used by SSL to pull client certificate 
 * information upon server request.
 */
static SECStatus ownGetClientAuthData(void *arg, PRFileDesc *socket,
				    CERTDistNames *caNames,
				    CERTCertificate **pRetCert,/*return */
				    SECKEYPrivateKey **pRetKey) {
    CERTCertificate *               cert = NULL;
    SECKEYPrivateKey *              privKey = NULL;
    void *                          proto_win = NULL;
    SECStatus                       rv = SECFailure;
    char *			    localNickName = (char *)arg;

    proto_win = SSL_RevealPinArg(socket);
   
    if (localNickName) {
        RA::Debug( LL_PER_PDU,
                   "ownGetClientAuthData: ",
                   "ownGetClientAuthData looking for nickname=%s",
                   localNickName );
     cert = PK11_FindCertFromNickname(localNickName, proto_win);
        if (cert) {
        RA::Debug( LL_PER_PDU,
                   "ownGetClientAuthData: ",
                   "ownGetClientAuthData found cert" );
            privKey = PK11_FindKeyByAnyCert(cert, proto_win);
            if (privKey) {
                RA::Debug( LL_PER_PDU,
                           "ownGetClientAuthData: ",
                           "ownGetClientAuthData found priv key for cert" );
                    rv = SECSuccess;
            } else {
                    if( cert != NULL ) {
                        CERT_DestroyCertificate( cert );
                        cert = NULL;
                    }
            }
        }
        else {
            RA::Debug( LL_PER_PDU,
                       "ownGetClientAuthData: ",
                       "ownGetClientAuthData did NOT find cert" );
        }

        if (rv == SECSuccess) {
			*pRetCert = cert;
			*pRetKey  = privKey;
        }

        // if( localNickName != NULL ) {
        //     free( localNickName );
        //     localNickName = NULL;
        // }
        return rv;
    }
    else {
            RA::Debug( LL_PER_PDU,
                       "ownGetClientAuthData: ",
                       "ownGetClientAuthData does not have nickname" );
    }

    char* chosenNickName = certName ? (char *)PL_strdup(certName) : NULL;
    if (chosenNickName) {
        cert = PK11_FindCertFromNickname(chosenNickName, proto_win);
        if (cert) {
            privKey = PK11_FindKeyByAnyCert(cert, proto_win);
            if (privKey) {
				rv = SECSuccess;
            } else {
                if( cert != NULL ) {
                    CERT_DestroyCertificate( cert );
                    cert = NULL;
                }
            }
        }
    } else {
        /* no nickname given, automatically find the right cert */
        CERTCertNicknames *     names;
        int                     i;

        names = CERT_GetCertNicknames(  CERT_GetDefaultCertDB(), 
                                        SEC_CERT_NICKNAMES_USER,
                                        proto_win);

        if (names != NULL) {
            for( i=0; i < names->numnicknames; i++ ) {
                cert = PK11_FindCertFromNickname(names->nicknames[i],
												 proto_win);
                if (!cert) {
                    continue;
                }

                /* Only check unexpired certs */
                if (CERT_CheckCertValidTimes(cert, PR_Now(), PR_FALSE) != 
					secCertTimeValid) {
                    if( cert != NULL ) {
                        CERT_DestroyCertificate( cert );
                        cert = NULL;
                    }
                    continue;
                }

                rv = NSS_CmpCertChainWCANames(cert, caNames);

                if (rv == SECSuccess) {
                    privKey = PK11_FindKeyByAnyCert(cert, proto_win);
                    if (privKey) {
                        // got the key
                        break;
                    }

                    // cert database password was probably wrong
                    rv = SECFailure;
                    break;
                };
            } /* for loop */
            CERT_FreeNicknames(names);
        } // names
    } // no nickname chosen

    if (rv == SECSuccess) {
		*pRetCert = cert;
		*pRetKey  = privKey;
    }

    if( chosenNickName != NULL ) {
        free( chosenNickName );
        chosenNickName = NULL;
    }

    return rv;
}
} // extern "C"

void nodelay(PRFileDesc* fd) {
    PRSocketOptionData opt;
    PRStatus rv;

    opt.option = PR_SockOpt_NoDelay;
    opt.value.no_delay = PR_FALSE;

    rv = PR_GetSocketOption(fd, &opt);
    if (rv == PR_FAILURE) {
        return;
    }

    opt.option = PR_SockOpt_NoDelay;
    opt.value.no_delay = PR_TRUE;
    rv = PR_SetSocketOption(fd, &opt);
    if (rv == PR_FAILURE) {
        return;
    }

    return;
}


void __EXPORT setDefaultAllTLSCiphers() {
	int i =0;
    char alg[256];
	while (tlsSuites[i]) {
        PR_snprintf((char *)alg, 256, "%x", tlsSuites[i]);
        RA::Debug( LL_PER_PDU,
            "setDefaultAllTLSCiphers",
            alg);
        SSL_CipherPrefSetDefault(tlsSuites[i++], PR_TRUE);
	}
    RA::Debug( LL_PER_PDU,
        "setDefaultAllTLSCiphers",
        "number of ciphers set:%d", i);
}
 
/**
 * Returns a file descriptor for I/O if the HTTP connection is successful
 * @param addr PRnetAddr structure which points to the server to connect to
 * @param SSLOn boo;elan to state if this is an SSL client
 */
PRFileDesc * Engine::_doConnect(PRNetAddr *addr, PRBool SSLOn,
								const PRInt32* cipherSuite, 
                                PRInt32 count, const char *nickName,
								PRBool handshake,
								/*const SecurityProtocols& secprots,*/
                                const char *serverName, PRIntervalTime timeout) {
//--	static const char *DEBUG_METHOD_NAME = "doConnect";
//-- 	DebugLogger *logger = DebugLogger::GetDebugLogger( "httpclient");
	PRFileDesc *tcpsock = NULL;
	PRFileDesc *sock = NULL;

    setDefaultAllTLSCiphers();

    tcpsock = PR_OpenTCPSocket(addr->raw.family);

    if (nickName != NULL)
        RA::Debug( LL_PER_PDU,
                   "Engine::_doConnect: ",
                   "_doConnect has nickname=%s",
                   nickName );
    else
        RA::Debug( LL_PER_PDU,
                   "Engine::_doConnect: ",
                   "_doConnect has nickname=NULL" );

    if (!tcpsock) {
//-- 	    logger->Log( LOGLEVEL_SEVERE, DEBUG_CLASS_NAME,
//--                  DEBUG_METHOD_NAME,
//XXXX log NSPR error code
        RA::Debug( LL_PER_PDU,
                   "Engine::_doConnect: ",
                   "PR_OpenTCPSocket returned NULL" );
        return NULL;
    }

    nodelay(tcpsock);

    if (PR_TRUE == SSLOn) {
        RA::Debug( LL_PER_PDU,
                   "Engine::_doConnect: ",
                   "SSL is ON" );
        sock=SSL_ImportFD(NULL, tcpsock);
        if (!sock) {
            //xxx log
            if( tcpsock != NULL ) {
                PR_Close( tcpsock );
                tcpsock = NULL;
            }
            return NULL;
        }

        int error = 0;
        PRBool rv = SSL_OptionSet(sock, SSL_SECURITY, 1);
        if ( SECSuccess == rv ) {
			rv = SSL_OptionSet(sock, SSL_HANDSHAKE_AS_CLIENT, 1);
		}
        if ( SECSuccess == rv ) {
			rv = SSL_OptionSet(sock, SSL_ENABLE_SSL3, PR_TRUE);
		}
        if ( SECSuccess == rv ) {
			rv = SSL_OptionSet(sock, SSL_ENABLE_TLS, PR_TRUE);
		}
        if ( SECSuccess != rv ) {
            error = PORT_GetError();
            if( sock != NULL ) {
                PR_Close( sock );
                sock = NULL;
            }
//-- 			logger->Log( LOGLEVEL_SEVERE, DEBUG_CLASS_NAME,
//-- 						 DEBUG_METHOD_NAME,
            RA::Debug( LL_PER_PDU,
                       "Engine::_doConnect: ",
                       "SSL_OptionSet error: %d",
                       error );
            return NULL;
		}

		rv = SSL_GetClientAuthDataHook( sock,
										ownGetClientAuthData,
										(void*)nickName);
        if ( SECSuccess != rv ) {
            error = PORT_GetError();
            if( sock != NULL ) {
                PR_Close( sock );
                sock = NULL;
            }
//-- 			logger->Log( LOGLEVEL_SEVERE, DEBUG_CLASS_NAME,
//-- 						 DEBUG_METHOD_NAME,
            RA::Debug( LL_PER_PDU,
                       "Engine::_doConnect: ",
                       "SSL_GetClientAuthDataHook error: %d",
                       error );
            return NULL;
		}
		
        rv = SSL_AuthCertificateHook(sock,
									 (SSLAuthCertificate)myAuthCertificate,
									 (void *)CERT_GetDefaultCertDB()); 

        if (rv != SECSuccess ) {
            if( sock != NULL ) {
                PR_Close( sock );
                sock = NULL;
            }
            return NULL;
        }

		PRErrorCode errCode = 0;

        rv = SSL_BadCertHook( sock,
							  (SSLBadCertHandler)myBadCertHandler,
							  &errCode );
		rv = SSL_SetURL( sock, serverName );

		if (rv != SECSuccess ) {
			error = PORT_GetError();
            if( sock != NULL ) {
                PR_Close( sock );
                sock = NULL;
            }
//-- 			logger->Log( LOGLEVEL_SEVERE, DEBUG_CLASS_NAME,
//-- 						 DEBUG_METHOD_NAME,
            RA::Debug( LL_PER_PDU,
                               "Engine::_doConnect: ",
                               "SSL_SetURL error: %d",
                               error );
            return NULL;
		}

        RA::Debug( LL_PER_PDU,
                   "Engine::_doConnect: ",
                   "end SSL is ON" );
		//EnableAllTLSCiphers( sock);
		//EnableAllSSL3Ciphers( sock);
    } else {
        RA::Debug( LL_PER_PDU,
                   "Engine::_doConnect: ",
                   "SSL is OFF" );
        sock = tcpsock;
    }

    RA::Debug( LL_PER_PDU,
               "Engine::_doConnect: ",
               "about to call PR_Connect, timeout =%d",
               timeout );

    if ( PR_Connect(sock, addr, timeout) == PR_FAILURE ) {
//-- 	    logger->Log( LOGLEVEL_SEVERE, DEBUG_CLASS_NAME,
//--                  DEBUG_METHOD_NAME,
             RA::Debug( LL_PER_PDU,
                        "Engine::_doConnect: ",
                        "PR_Connect error: %d Msg=%s",
                        PR_GetError(),
                        "XXX" );
        if( sock != NULL ) {
            PR_Close( sock );
            sock = NULL;
        }
        return NULL;
    }

    return (sock);
}

/**
 * Called from higher level to connect, sends a request 
 * and gets a response as an HttpResponse object
 *
 * @param request Contains the entire request url + headers etc
 * @param server Has the host, port, protocol info
 * @param timeout Time in seconds to wait for a response
 * @return The response body and headers
 */
PSHttpResponse * HttpEngine::makeRequest( PSHttpRequest &request, 
										  const PSHttpServer& server,
										  int timeout, PRBool expectChunked ) {
    PRNetAddr addr;
    PRFileDesc *sock = NULL;
    PSHttpResponse *resp = NULL;

    PRBool response_code = 0;

	server.getAddr(&addr);

	char *nickName = request.getCertNickName();

	char *serverName = (char *)server.getAddr();

    sock = _doConnect( &addr, request.isSSL(), 0, 0,nickName, 0, serverName );

    if ( sock != NULL) {
        PRBool status = request.send( sock );
        if ( status ) {
            resp = new PSHttpResponse( sock, &request, timeout, expectChunked );
            response_code = resp->processResponse();

            RA::Debug( LL_PER_PDU,
                       "HttpEngine::makeRequest: ",
                       "makeRequest response %d",
                       response_code );

            if(!response_code)
            {
                RA::Debug( LL_PER_PDU,
                           "HttpEngine::makeRequest: ",
                           "Deleting response because of FALSE return, returning NULL." );
                if( resp != NULL ) {
                    delete resp;
                    resp = NULL;
                }
                if( sock != NULL ) {
                    PR_Close( sock );
                    sock = NULL;
                }

                return NULL;

            }
        }
        if( sock != NULL ) {
            PR_Close( sock );
            sock = NULL;
        }
    }

    return resp;
}
