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
package com.netscape.cmscore.connector;

import java.util.Enumeration;
import java.util.Vector;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cmscore.authentication.ChallengePhraseAuthentication;

public class RequestTransfer {

    private static String[] transferAttributes = {
            IRequest.HTTP_PARAMS,
            IRequest.AGENT_PARAMS,
            IRequest.CERT_INFO,
            IRequest.ISSUED_CERTS,
            IRequest.OLD_CERTS,
            IRequest.OLD_SERIALS,
            IRequest.REVOKED_CERTS,
            IRequest.CACERTCHAIN,
            IRequest.CRL,
            IRequest.ERRORS,
            IRequest.RESULT,
            IRequest.ERROR,
            IRequest.SVCERRORS,
            IRequest.REMOTE_STATUS,
            IRequest.REMOTE_REQID,
            IRequest.REVOKED_CERT_RECORDS,
            IRequest.CERT_STATUS,
            ChallengePhraseAuthentication.CHALLENGE_PHRASE,
            ChallengePhraseAuthentication.SUBJECTNAME,
            ChallengePhraseAuthentication.SERIALNUMBER,
            ChallengePhraseAuthentication.SERIALNOARRAY,
            IRequest.ISSUERDN,
            IRequest.CERT_FILTER,
            "keyRecord",
            "uid", // UidPwdDirAuthentication.CRED_UID,
            "udn", // UdnPwdDirAuthentication.CRED_UDN,
    };

    public static boolean isProfileRequest(IRequest request) {
        String profileId = request.getExtDataInString("profileId");

        if (profileId == null || profileId.equals(""))
            return false;
        else
            return true;
    }

    public static String[] getTransferAttributes(IRequest r) {
        if (isProfileRequest(r)) {
            // copy everything in the request
            CMS.debug("RequestTransfer: profile request " +
                    r.getRequestId().toString());
            Enumeration<String> e = r.getExtDataKeys();
            Vector<String> v = new Vector<String>();

            while (e.hasMoreElements()) {
                String k = e.nextElement();

                if (k.equals("requestType"))
                    continue;
                if (k.equals("requestId"))
                    continue;
                if (k.equals("requestVersion"))
                    continue;
                if (k.equals("AUTH_TOKEN"))
                    continue;
                CMS.debug("RequestTransfer: attribute=" + k);
                if (k.equals("requestStatus")) {
                    CMS.debug("RequestTransfer : requestStatus=" +
                            r.getExtDataInString("requestStatus"));
                }
                v.addElement(k);
            }
            CMS.debug("RequestTransfer: attribute size=" + v.size());
            return v.toArray(new String[v.size()]);
        } else {
            return transferAttributes;
        }
    }

    public static void transfer(IRequest src, IRequest dest) {
        CMS.debug("Transfer srcId=" +
                src.getRequestId().toString() +
                " destId=" + dest.getRequestId().toString());
        String attrs[] = getTransferAttributes(src);

        for (int i = 0; i < attrs.length; i++) {
            String key = attrs[i];
            if (src.isSimpleExtDataValue(key)) {
                dest.setExtData(key, src.getExtDataInString(key));
            } else {
                dest.setExtData(key, src.getExtDataInHashtable(key));
            }
        }
    }
}
