// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.profile.output;


import java.security.cert.*;
import java.io.*;
import java.util.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.profile.*;
import com.netscape.certsrv.request.*;
import com.netscape.certsrv.property.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.ca.*;

import netscape.security.x509.*;
import netscape.security.util.*;
import netscape.security.pkcs.*;

import org.mozilla.jss.asn1.*;
import org.mozilla.jss.pkix.crmf.*;
import org.mozilla.jss.pkix.cmmf.*;
import org.mozilla.jss.pkix.primitive.*;

import com.netscape.cms.profile.common.*;


/**
 * This class implements the output plugin that outputs
 * DER for the issued certificate for token keys
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public class nsNKeyOutput extends EnrollOutput implements IProfileOutput { 

    public static final String VAL_DER = "der";

    public nsNKeyOutput() {
        addValueName(VAL_DER);
    }

    /**
     * Initializes this default policy.
     */
    public void init(IProfile profile, IConfigStore config)
        throws EProfileException {
        super.init(profile, config);
    }

    /**
     * Retrieves the localizable name of this policy.
     */
    public String getName(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_OUTPUT_CERT_TOKENKEY_NAME");
    }

    /**
     * Retrieves the localizable description of this policy.
     */
    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_OUTPUT_CERT_TOKENKEY_TEXT");
    }

    /**
     * Populates the request with this policy default.
     */
    public void populate(IProfileContext ctx, IRequest request)
        throws EProfileException {
    }

    /**
     * Retrieves the descriptor of the given value
     * parameter by name.
     */
    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(VAL_DER)) {
            return new Descriptor("der_b64", null,
                    null,
                    CMS.getUserMessage(locale, 
                        "CMS_PROFILE_OUTPUT_DER_B64"));
        }
        return null;
    }

    public String getValue(String name, Locale locale, IRequest request)
        throws EProfileException {
        if (name.equals(VAL_DER)) {

            try {
              X509CertImpl cert = request.getExtDataInCert(
                    EnrollProfile.REQUEST_ISSUED_CERT);
              if (cert == null)
                  return null;
			  return CMS.BtoA(cert.getEncoded());
            } catch (Exception e) {
              return "";
            }
        } else {
            return null;
        }
    }

}
