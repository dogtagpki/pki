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
// (C) 2025 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.profile.constraint;

import java.util.Locale;

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.password.EPasswordCheckException;
import com.netscape.certsrv.profile.ERejectException;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.cms.password.PasswordChecker;
import com.netscape.cms.profile.def.NoDefault;
import com.netscape.cms.profile.def.PolicyDefault;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.request.Request;

/**
 * This class implement a policy constraint for the pkcs12 export password
 *
 * The policy has several configurations, the are:
 *   - password.minSize
 *   - password.minUpperLetter
 *   - password.minLowerLetter
 *   - password.minNumber
 *   - password.minSpecialChar
 *   - password.seqLength
 *   - password.maxRepeatedChar
 *   - password.cracklibCheck
 *
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
public class P12ExportPasswordConstraint extends EnrollConstraint {

    public static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(P12ExportPasswordConstraint.class);

    public static final String CONFIG_PASSWORD_MIN_SIZE = "password.minSize";
    public static final String CONFIG_PASSWORD_MIN_UPPER_LETTER = "password.minUpperLetter";
    public static final String CONFIG_PASSWORD_MIN_LOWER_LETTER = "password.minLowerLetter";
    public static final String CONFIG_PASSWORD_MIN_NUMBER = "password.minNumber";
    public static final String CONFIG_PASSWORD_MIN_SPECIAL_CHAR = "password.minSpecialChar";
    public static final String CONFIG_PASSWORD_SEQUENCE_LENGTH = "password.seqLength";
    public static final String CONFIG_PASSWORD_MAX_REPEATED_CHAR = "password.maxRepeatedChar";
    public static final String CONFIG_PASSWORD_CRACKLIB_CHECK = "password.cracklibCheck";

    public P12ExportPasswordConstraint() {
        super();
        addConfigName(CONFIG_PASSWORD_MIN_SIZE);
        addConfigName(CONFIG_PASSWORD_MIN_UPPER_LETTER);
        addConfigName(CONFIG_PASSWORD_MIN_LOWER_LETTER);
        addConfigName(CONFIG_PASSWORD_MIN_NUMBER);
        addConfigName(CONFIG_PASSWORD_MIN_SPECIAL_CHAR);
        addConfigName(CONFIG_PASSWORD_SEQUENCE_LENGTH);
        addConfigName(CONFIG_PASSWORD_MAX_REPEATED_CHAR);
        addConfigName(CONFIG_PASSWORD_CRACKLIB_CHECK);

    }

    @Override
    public void setConfig(String name, String value)
            throws EPropertyException {
        if (name.equals(CONFIG_PASSWORD_MIN_SIZE) ||
                name.equals(CONFIG_PASSWORD_MIN_UPPER_LETTER) ||
                name.equals(CONFIG_PASSWORD_MIN_LOWER_LETTER) ||
                name.equals(CONFIG_PASSWORD_MIN_NUMBER) ||
                name.equals(CONFIG_PASSWORD_MIN_SPECIAL_CHAR) ||
                name.equals(CONFIG_PASSWORD_SEQUENCE_LENGTH) ||
                name.equals(CONFIG_PASSWORD_MAX_REPEATED_CHAR)) {
            try {
                Integer.parseInt(value);
            } catch (Exception e) {
                throw new EPropertyException(CMS.getUserMessage(
                            "CMS_INVALID_PROPERTY", name));
            }
        }
        super.setConfig(name, value);
    }

    @Override
    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        return null;
    }

    @Override
    public void validate(Request req, X509CertInfo info)
            throws ERejectException {
        String method = "P12ExportPasswordConstraint: validate: ";
        String password = req.getExtDataInString("serverSideKeygenP12Passwd");
        PasswordChecker pCheck = getChecker();

        try {
            if (!pCheck.isGoodPassword(password)) {
                throw new ERejectException(pCheck.getReason(getLocale(req)));
            }
        } catch (EPasswordCheckException e) {
            logger.error("{password rejected because }", method, e.getMessage());
            throw new ERejectException(CMS.getUserMessage(getLocale(req),
                    "CMS_PROFILE_P12EXPORT_PASSWORD_ERROR", e.getMessage()));
        }
    }

    @Override
    public String getText(Locale locale) {
        PasswordChecker pCheck =  getChecker();
        String[] params = {
                Integer.toString(pCheck.getMinSize()),
                Integer.toString(pCheck.getMinUpperLetter()),
                Integer.toString(pCheck.getMinLowerLetter()),
                Integer.toString(pCheck.getMinNumber()),
                Integer.toString(pCheck.getMinSpecialChar()),
                Integer.toString(pCheck.getSeqLength()),
                Integer.toString(pCheck.getMaxRepeatedChar()),
                Boolean.toString(pCheck.isCracklibCheck())
                };
        return CMS.getUserMessage(locale, "CMS_PROFILE_CONSTRAINT_P12EXPORT_PASSWORD_TEXT", params);
    }

    @Override
    public boolean isApplicable(PolicyDefault def) {
        return (def instanceof NoDefault);
    }

    private PasswordChecker getChecker() {
        CAEngine engine = CAEngine.getInstance();
        PasswordChecker pCheck = engine.getPasswordChecker();

        if (!getConfig(CONFIG_PASSWORD_MIN_SIZE).isEmpty()) {
            pCheck.setMinSize(Integer.parseInt(getConfig(CONFIG_PASSWORD_MIN_SIZE)));
        }
        if (!getConfig(CONFIG_PASSWORD_MIN_UPPER_LETTER).isEmpty()) {
            pCheck.setMinUpperLetter(Integer.parseInt(getConfig(CONFIG_PASSWORD_MIN_UPPER_LETTER)));
        }
        if (!getConfig(CONFIG_PASSWORD_MIN_LOWER_LETTER).isEmpty()) {
            pCheck.setMinLowerLetter(Integer.parseInt(getConfig(CONFIG_PASSWORD_MIN_LOWER_LETTER)));
        }
        if (!getConfig(CONFIG_PASSWORD_MIN_NUMBER).isEmpty()) {
            pCheck.setMinNumber(Integer.parseInt(getConfig(CONFIG_PASSWORD_MIN_NUMBER)));
        }
        if (!getConfig(CONFIG_PASSWORD_MIN_SPECIAL_CHAR).isEmpty()) {
            pCheck.setMinSpecialChar(Integer.parseInt(getConfig(CONFIG_PASSWORD_MIN_SPECIAL_CHAR)));
        }
        if (!getConfig(CONFIG_PASSWORD_SEQUENCE_LENGTH).isEmpty()) {
            pCheck.setSeqLength(Integer.parseInt(getConfig(CONFIG_PASSWORD_SEQUENCE_LENGTH)));
        }
        if (!getConfig(CONFIG_PASSWORD_MAX_REPEATED_CHAR).isEmpty()) {
            pCheck.setMaxRepeatedChar(Integer.parseInt(getConfig(CONFIG_PASSWORD_MAX_REPEATED_CHAR)));
        }
        if (!getConfig(CONFIG_PASSWORD_MAX_REPEATED_CHAR).isEmpty()) {
            pCheck.setCracklibCheck(getConfigBoolean(CONFIG_PASSWORD_CRACKLIB_CHECK));
        }

        return pCheck;
    }
}
