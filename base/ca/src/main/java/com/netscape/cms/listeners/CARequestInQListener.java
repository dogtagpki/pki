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
package com.netscape.cms.listeners;

import org.dogtagpki.server.ca.CAEngine;

import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.cms.profile.input.SubjectNameInput;
import com.netscape.cms.profile.input.SubmitterInfoInput;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.request.Request;

public class CARequestInQListener extends RequestInQListener {

    public void init(ConfigStore config) throws EBaseException {
        CAEngine engine = CAEngine.getInstance();
        CertificateAuthority ca = engine.getCA();
        mConfig = ca.getConfigStore();

        init(null, config);
    }

    protected Object getRequestorEmail(Request r) {

        String profileId = r.getExtDataInString(Request.PROFILE_ID);

        if (profileId == null) {
            return r.getExtDataInString(Request.HTTP_PARAMS, "csrRequestorEmail");
        }

        // use the submitter info if available, otherwise, use the
        // subject name input email
        Object val = r.getExtDataInString(SubmitterInfoInput.EMAIL);

        if (val == null || ((String) val).compareTo("") == 0) {
            val = r.getExtDataInString(SubjectNameInput.VAL_EMAIL);
        }

        return val;
    }

    protected Object getCertType(Request r) {

        String profileId = r.getExtDataInString(Request.PROFILE_ID);

        if (profileId == null) {
            return r.getExtDataInString(Request.HTTP_PARAMS, Request.CERT_TYPE);
        }

        return profileId;
    }
}
