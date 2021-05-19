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
package com.netscape.cms.profile.output;

import java.util.Locale;
import java.util.Map;

import org.mozilla.jss.netscape.security.util.Utils;

import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.profile.common.EnrollProfile;
import com.netscape.cmscore.apps.CMS;

/**
 * This class implements the output plugin that outputs
 * PKCS12 response for the issued certificate for Server-side keygen enrollment.
 *
 * Christina Fu
 */
public class PKCS12Output extends EnrollOutput {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PKCS12Output.class);

    public static final String VAL_P12_RESPONSE = "p12_response";

    public PKCS12Output() {
        addValueName(VAL_P12_RESPONSE);
    }

    /**
     * Retrieves the localizable name of this policy.
     */
    @Override
    public String getName(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_OUTPUT_PKCS12");
    }

    /**
     * Retrieves the localizable description of this policy.
     */
    @Override
    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_OUTPUT_PKCS12_TEXT");
    }

    /**
     * Populates the request with this policy default.
     */
    @Override
    public void populate(Map<String, String> ctx, IRequest request)
            throws EProfileException {
    }

    /**
     * Retrieves the descriptor of the given value
     * parameter by name.
     */
    @Override
    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(VAL_P12_RESPONSE)) {
            return new Descriptor(IDescriptor.SERVER_SIDE_KEYGEN_PKCS12, null,
                    null,
                    CMS.getUserMessage(locale,
                            "CMS_PROFILE_OUTPUT_PKCS12"));
        }
        return null;
    }

    @Override
    public String getValue(String name, Locale locale, IRequest request)
            throws EProfileException {

        if (name.equals(VAL_P12_RESPONSE)) {
            try {
                byte pkcs12[] = request.getExtDataInByteArray(
                        EnrollProfile.REQUEST_ISSUED_P12);
                if (pkcs12 != null) {
                    logger.debug("PKCS12Output:getValue: found p12");
                    String pkcs12Str = Utils.base64encodeSingleLine(pkcs12);
                    return pkcs12Str;
                }
            } catch (Exception e) {
                return null;
            }
        }
        return null;
    }

}
