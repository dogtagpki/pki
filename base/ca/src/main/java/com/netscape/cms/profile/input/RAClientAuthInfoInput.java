//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cms.profile.input;

import java.util.Locale;
import java.util.Map;

import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.cms.profile.common.Profile;
import com.netscape.cms.profile.common.ProfileInputConfig;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.request.Request;

/**
 * This class implements the client authentication information
 * input that collects RA client information such as uid, name,
 * and certificate.
 */
public class RAClientAuthInfoInput extends EnrollInput {

    public static final String UID = "ra_client_uid";
    public static final String NAME = "ra_client_name";
    public static final String CERT = "ra_client_certificate";

    public RAClientAuthInfoInput() {
        addValueName(UID);
        addValueName(NAME);
        addValueName(CERT);
    }

    /**
     * Initializes this default policy.
     */
    @Override
    public void init(Profile profile, ProfileInputConfig config) throws EProfileException {
        super.init(profile, config);
    }

    /**
     * Retrieves the localizable name of this policy.
     */
    @Override
    public String getName(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_INPUT_RA_CLIENT_AUTH_NAME");
    }

    /**
     * Retrieves the localizable description of this policy.
     */
    @Override
    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_INPUT_RA_CLIENT_AUTH_TEXT");
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
        if (name.equals(UID)) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_RA_CLIENT_UID"));
        } else if (name.equals(NAME)) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_RA_CLIENT_NAME"));
        } else if (name.equals(CERT)) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_RA_CLIENT_CERTIFICATE"));
        }
        return null;
    }
}
