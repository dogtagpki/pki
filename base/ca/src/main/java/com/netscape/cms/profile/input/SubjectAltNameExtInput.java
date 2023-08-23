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
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.profile.input;

import java.util.Enumeration;
import java.util.Locale;
import java.util.Map;
import java.util.Vector;

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.CAEngineConfig;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.cms.profile.common.Profile;
import com.netscape.cms.profile.common.ProfileInputConfig;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.request.Request;


/**
 * This plugin populates text fields to the enrollment
 * page so that SAN parameters
 * can be collected from the user.
 * <p>
 * The collected parameters could be used for
 * fomulating the SAN attributes in the certificate.
 * <p>
 *
 */
public class SubjectAltNameExtInput extends EnrollInput {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SubjectAltNameExtInput.class);

    public static final int DEF_REQ_ENTRIES = 4;

    public static final String CONFIG_SAN_REQ_PATTERN = "req_san_pattern_";
    public static final String CONFIG_SAN_REQ_TYPE = "req_san_type_";

    public static final String VAL_SAN_REQ_PATTERN = "req_san_pattern_";
    public static final String VAL_SAN_REQ_TYPE = "req_san_type_";

    /* defined in CS.cfg: "ca.SAN.entryNum" */
    private int mSANentryNum = DEF_REQ_ENTRIES;

    public SubjectAltNameExtInput() {
        for (int i = 0; i< mSANentryNum; i++) {
            addValueName(CONFIG_SAN_REQ_PATTERN + i);
            addValueName(CONFIG_SAN_REQ_TYPE + i);
        }
    }

    /**
     * Initializes this default policy.
     */
    @Override
    public void init(Profile profile, ProfileInputConfig config) throws EProfileException {
        super.init(profile, config);

        CAEngine engine = CAEngine.getInstance();
        CAEngineConfig cs = engine.getConfig();

        try {
            mSANentryNum = cs.getInteger("ca.SAN.entryNum", DEF_REQ_ENTRIES);
        } catch (EBaseException e) {
            /* mSANentryNum has default; ok */
            logger.warn("SubjectAltNameExtInput: init(): getting config failed on ca.SAN.entryNum: " + e.getMessage(), e);
        }
    }

    /**
     * Retrieves the localizable name of this policy.
     */
    @Override
    public String getName(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_INPUT_SUBJECT_ALT_NAME_EXT_NAME");
    }

    /**
     * Retrieves the localizable description of this policy.
     */
    @Override
    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_INPUT_SUBJECT_ALT_NAME_EXT_TEXT");
    }

    /**
     * Returns selected value names based on the configuration.
     */
    @Override
    public Enumeration<String> getValueNames() {
        Vector<String> v = new Vector<>();

        for (int i = 0; i< mSANentryNum; i++) {
            v.addElement(VAL_SAN_REQ_TYPE + i); // default case
            v.addElement(VAL_SAN_REQ_PATTERN + i); // default case
        }

        return v.elements();
    }

    /**
     * Populates the request with this policy default.
     */
    @Override
    public void populate(Map<String, String> ctx, Request request) throws Exception {
        //
    }

    /**
     * Retrieves the descriptor of the given value
     * parameter by name.
     */
    @Override
    public IDescriptor getValueDescriptor(Locale locale, String name) {
       if (name.startsWith(VAL_SAN_REQ_TYPE)) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_REQ_SAN_TYPE"));
        } else if (name.startsWith(VAL_SAN_REQ_PATTERN)) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_REQ_SAN_PATTERN"));
        }
        return null;
    }
}
