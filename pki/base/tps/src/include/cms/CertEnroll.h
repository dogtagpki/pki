/* --- BEGIN COPYRIGHT BLOCK ---
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
 * --- END COPYRIGHT BLOCK ---
 */

#ifndef CERTENROLL_H
#define CERTENROLL_H

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

#include "main/Buffer.h"

#include "httpClient/httpc/response.h"
#include "keythi.h"

#ifdef XP_WIN32
#define TOKENDB_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TOKENDB_PUBLIC
#endif /* !XP_WIN32 */

class CertEnroll
{
  public:

  TOKENDB_PUBLIC CertEnroll();
  TOKENDB_PUBLIC ~CertEnroll();

  SECKEYPublicKey *ParsePublicKeyBlob(unsigned char * /*blob*/,
			 Buffer * /*challenge*/);
  Buffer *EnrollCertificate(SECKEYPublicKey * /*pk_parsed*/,
		            const char *profileId,
			    const char * /*uid*/,
			    const char * /*token cuid*/, const char *connid,
			    	SECItem** encodedPublicKeyInfo = NULL);
  ReturnStatus verifyProof(SECKEYPublicKey* /*pk*/, SECItem* /*siProof*/,
			   unsigned short /*pkeyb_len*/, unsigned char* /*pkeyb*/,
			   Buffer* /*challenge*/);
  TOKENDB_PUBLIC Buffer *RenewCertificate(PRUint64 serialno, const char *connid, const char *profileId);
  TOKENDB_PUBLIC int RevokeCertificate(const char *reason, const char *serialno, const char *connid, char *&status);
  TOKENDB_PUBLIC int UnrevokeCertificate(const char *serialno, const char *connid, char *&status);
  PSHttpResponse * sendReqToCA(const char *servlet, const char *parameters, const char *connid);
  Buffer * parseResponse(PSHttpResponse * /*resp*/);
};
#endif /* CERTENROLL_H */
