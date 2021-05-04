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
// (C) 2018 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.logging.event;

import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.SignedAuditEvent;

public class CMCUserSignedRequestSigVerifyEvent extends SignedAuditEvent {

    private static final long serialVersionUID = 1L;

    public final static String CMC_USER_SIGNED_REQUEST_SIG_VERIFY_SUCCESS =
            "LOGGING_SIGNED_AUDIT_CMC_USER_SIGNED_REQUEST_SIG_VERIFY_SUCCESS";

    public final static String CMC_USER_SIGNED_REQUEST_SIG_VERIFY_FAILURE =
            "LOGGING_SIGNED_AUDIT_CMC_USER_SIGNED_REQUEST_SIG_VERIFY_FAILURE";

    public CMCUserSignedRequestSigVerifyEvent(String messageID) {
        super(messageID);
    }

    public static CMCUserSignedRequestSigVerifyEvent createSuccessEvent(
            String subjectID,
            String reqType,
            String certSubject,
            String signerInfo) {

        CMCUserSignedRequestSigVerifyEvent event = new CMCUserSignedRequestSigVerifyEvent(
                CMC_USER_SIGNED_REQUEST_SIG_VERIFY_SUCCESS);

        event.setAttribute("SubjectID", subjectID);
        event.setAttribute("Outcome", ILogger.SUCCESS);
        event.setAttribute("ReqType", reqType);
        event.setAttribute("CertSubject", certSubject);
        event.setAttribute("SignerInfo", signerInfo);

        return event;
    }

    public static CMCUserSignedRequestSigVerifyEvent createFailureEvent(
            String subjectID,
            String reqType,
            String certSubject,
            String cmcSignerInfo,
            String info) {

        CMCUserSignedRequestSigVerifyEvent event = new CMCUserSignedRequestSigVerifyEvent(
                CMC_USER_SIGNED_REQUEST_SIG_VERIFY_FAILURE);

        event.setAttribute("SubjectID", subjectID);
        event.setAttribute("Outcome", ILogger.FAILURE);
        event.setAttribute("ReqType", reqType);
        event.setAttribute("CertSubject", certSubject);
        event.setAttribute("CMCSignerInfo", cmcSignerInfo);
        event.setAttribute("info", info);

        return event;
    }
}
