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

import com.netscape.cmscore.authentication.ChallengePhraseAuthentication;
import com.netscape.cmscore.request.Request;

public class RequestTransfer {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(RequestTransfer.class);

    private static String[] transferAttributes = {
            Request.HTTP_PARAMS,
            Request.AGENT_PARAMS,
            Request.CERT_INFO,
            Request.ISSUED_CERTS,
            Request.OLD_CERTS,
            Request.OLD_SERIALS,
            Request.REVOKED_CERTS,
            Request.CACERTCHAIN,
            Request.CRL,
            Request.ERRORS,
            Request.RESULT,
            Request.ERROR,
            Request.SVCERRORS,
            Request.REMOTE_STATUS,
            Request.REMOTE_REQID,
            Request.REVOKED_CERT_RECORDS,
            Request.CERT_STATUS,
            ChallengePhraseAuthentication.CHALLENGE_PHRASE,
            ChallengePhraseAuthentication.SUBJECTNAME,
            ChallengePhraseAuthentication.SERIALNUMBER,
            ChallengePhraseAuthentication.SERIALNOARRAY,
            Request.ISSUERDN,
            Request.CERT_FILTER,
            "keyRecord",
            "uid", // UidPwdDirAuthentication.CRED_UID,
    };

    public static boolean isProfileRequest(Request request) {
        String profileId = request.getExtDataInString(Request.PROFILE_ID);
        return profileId != null && !profileId.equals("");
    }

    public static String[] getTransferAttributes(Request r) {
        if (isProfileRequest(r)) {
            // copy everything in the request
            logger.debug("RequestTransfer: profile request id = " +
                    r.getRequestId().toString());
            Enumeration<String> e = r.getExtDataKeys();
            Vector<String> v = new Vector<>();

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
                // logger.debug("RequestTransfer: attribute=" + k);
                if (k.equalsIgnoreCase("requestStatus")) {
                    logger.debug("RequestTransfer : requestStatus=" +
                            r.getExtDataInString("requestStatus"));
                }
                //logger.debug("RequestTransfer: profile request; transfer name:"+k);
                v.addElement(k);
            }
            logger.debug("RequestTransfer: attribute size=" + v.size());
            return v.toArray(new String[v.size()]);
        }
        // logger.debug("RequestTransfer: not profile request; returning default transferAttributes");
        return transferAttributes;
    }

    public static void transfer(Request src, Request dest) {
        logger.debug("Transfer srcId=" +
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
