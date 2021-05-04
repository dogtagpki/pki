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

public class ComputeSessionKeyRequestProcessedEvent extends SignedAuditEvent {

    private static final long serialVersionUID = 1L;

    public final static String SUCCESS =
            "LOGGING_SIGNED_AUDIT_COMPUTE_SESSION_KEY_REQUEST_PROCESSED_SUCCESS";

    public final static String FAILURE =
            "LOGGING_SIGNED_AUDIT_COMPUTE_SESSION_KEY_REQUEST_PROCESSED_FAILURE";

    public ComputeSessionKeyRequestProcessedEvent(String messageID) {
        super(messageID);
    }

    public static ComputeSessionKeyRequestProcessedEvent success(
            String CUID_decoded,
            String KDD_decoded,
            String status,
            String agentID,
            String isCryptoValidate,
            String isServerSideKeygen,
            String selectedToken,
            String keyNickName,
            String keyset,
            String keyInfo_KeyVersion,
            String nistSP800_108KdfOnKeyVersion,
            String nistSP800_108KdfUseCuidAsKdd) {

        ComputeSessionKeyRequestProcessedEvent event = new ComputeSessionKeyRequestProcessedEvent(SUCCESS);

        event.setAttribute("CUID_decoded", CUID_decoded);
        event.setAttribute("KDD_decoded", KDD_decoded);
        event.setAttribute("Outcome", ILogger.SUCCESS);
        event.setAttribute("status", status);
        event.setAttribute("AgentID", agentID);
        event.setAttribute("IsCryptoValidate", isCryptoValidate);
        event.setAttribute("IsServerSideKeygen", isServerSideKeygen);
        event.setAttribute("SelectedToken", selectedToken);
        event.setAttribute("KeyNickName", keyNickName);
        event.setAttribute("TKSKeyset", keyset);
        event.setAttribute("KeyInfo_KeyVersion", keyInfo_KeyVersion);
        event.setAttribute("NistSP800_108KdfOnKeyVersion", nistSP800_108KdfOnKeyVersion);
        event.setAttribute("NistSP800_108KdfUseCuidAsKdd", nistSP800_108KdfUseCuidAsKdd);

        return event;
    }

    public static ComputeSessionKeyRequestProcessedEvent failure(
            String CUID_decoded,
            String KDD_decoded,
            String status,
            String agentID,
            String isCryptoValidate,
            String isServerSideKeygen,
            String selectedToken,
            String keyNickName,
            String keyset,
            String keyInfo_KeyVersion,
            String nistSP800_108KdfOnKeyVersion,
            String nistSP800_108KdfUseCuidAsKdd,
            String error) {

        ComputeSessionKeyRequestProcessedEvent event = new ComputeSessionKeyRequestProcessedEvent(FAILURE);

        event.setAttribute("CUID_decoded", CUID_decoded);
        event.setAttribute("KDD_decoded", KDD_decoded);
        event.setAttribute("Outcome", ILogger.FAILURE);
        event.setAttribute("status", status);
        event.setAttribute("AgentID", agentID);
        event.setAttribute("IsCryptoValidate", isCryptoValidate);
        event.setAttribute("IsServerSideKeygen", isServerSideKeygen);
        event.setAttribute("SelectedToken", selectedToken);
        event.setAttribute("KeyNickName", keyNickName);
        event.setAttribute("TKSKeyset", keyset);
        event.setAttribute("KeyInfo_KeyVersion", keyInfo_KeyVersion);
        event.setAttribute("NistSP800_108KdfOnKeyVersion", nistSP800_108KdfOnKeyVersion);
        event.setAttribute("NistSP800_108KdfUseCuidAsKdd", nistSP800_108KdfUseCuidAsKdd);
        event.setAttribute("Error", error);

        return event;
    }
}
