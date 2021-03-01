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
// (C) 2020 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.profile.def;

import java.io.IOException;
import java.util.Locale;

import org.mozilla.jss.netscape.security.x509.CertificateExtensions;
import org.mozilla.jss.netscape.security.x509.Extension;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.netscape.security.util.DerOutputStream;
import org.mozilla.jss.netscape.security.util.DerValue;
import org.mozilla.jss.netscape.security.util.ObjectIdentifier;

import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.profile.common.EnrollProfile;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.cert.CertUtils;

import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * This class implements an enrollment default policy
 * that populates a Certificate Transparency Poison Extension
 * into the certificate template.
 * It will be processed and replaced with SignedCertificateTimestampList
 * extension at signing by CAService.
 *
 * @author cfu
 */
public class SignedCertificateTimestampListExtDefault extends EnrollExtDefault {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SignedCertificateTimestampListExtDefault.class);

    public static final boolean CT_POISON_CRITICAL = true;
    public static final String CT_POISON_OID = "1.3.6.1.4.1.11129.2.4.3";
    public static final byte CT_POISON_DATA[] =  new byte[] { 0x05, 0x00 };

    public SignedCertificateTimestampListExtDefault() {
        super();
    }

    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        return null;
    }

    public IDescriptor getValueDescriptor(Locale locale, String name) {
        return null;
    }

    public void setValue(String name, Locale locale,
            X509CertInfo info, String value)
            throws EPropertyException {
        // Nothing to do for read-only values
    }

    public String getValue(String name, Locale locale,
            X509CertInfo info)
            throws EPropertyException {
        return null;
    }

    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_DEF_CT_PRECERT_EXT");
    }

    /**
     * Populates the request with this policy default.
     */
    public void populate(IRequest request, X509CertInfo info)
            throws EProfileException {
        String method = "SignedCertificateTimestampListExtDefault: populate:";

        try {
            CertUtils.addCTv1PoisonExt(info);
        } catch (Exception e) {
            logger.debug(method + "addCTv1PoisonExt failed");
            throw new EProfileException(method + "addCTv1PoisonExt failed");
        }

        logger.debug(method + " Certificate Transparency Poison extension set");
    }
}
