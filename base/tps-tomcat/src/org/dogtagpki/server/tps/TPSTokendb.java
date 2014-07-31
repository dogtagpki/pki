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
// (C) 2014 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.dogtagpki.server.tps;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import org.dogtagpki.server.tps.dbs.TokenRecord;
import org.dogtagpki.server.tps.processor.EnrolledCertsInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.tps.token.TokenStatus;

/*
 * TPSTokendb class offers a collection of tokendb management convenience routines
 */
public class TPSTokendb {
    private Map<TokenStatus, Collection<TokenStatus>> allowedTransitions = new HashMap<TokenStatus, Collection<TokenStatus>>();

    public TPSTokendb() throws EBaseException {
        try {
            initAllowedTransitions();
        } catch (Exception e) {
            CMS.debug("TPSTokendb: initAllowedTransitions() failed:" + e);
            throw new EBaseException(e.toString());
        }
    }

    void initAllowedTransitions()
            throws Exception {
        CMS.debug("TPSTokendb.initAllowedTransitions()");
        IConfigStore configStore = CMS.getConfigStore();

        // load allowed token state transitions
        CMS.debug("TPSTokendbs: allowed transitions:");

        for (String transition : configStore.getString("tokendb.allowedTransitions").split(",")) {
            String states[] = transition.split(":");
            TokenStatus fromState = TokenStatus.fromInt(Integer.valueOf(states[0]));
            TokenStatus toState = TokenStatus.fromInt(Integer.valueOf(states[1]));
            CMS.debug("TPSTokendb:  - " + fromState + " to " + toState);

            Collection<TokenStatus> nextStates = allowedTransitions.get(fromState);
            if (nextStates == null) {
                nextStates = new HashSet<TokenStatus>();
                allowedTransitions.put(fromState, nextStates);
            }
            nextStates.add(toState);
        }
    }

    public boolean isTransitionAllowed(TokenRecord tokenRecord, TokenStatus newState) {
        boolean result = false;
        TokenStatus currentTokenStatus = tokenRecord.getTokenStatus();
        CMS.debug("TokenRecord.isTransitionAllowed(): current status: " + currentTokenStatus);
        Collection<TokenStatus> nextStatuses = allowedTransitions.get(currentTokenStatus);
        CMS.debug("TokenRecord.isTransitionAllowed(): allowed next statuses: " + nextStatuses);
        if (nextStatuses == null || !nextStatuses.contains(newState)) {
            CMS.debug("TokenRecord.isTransitionAllowed(): next status not allowed: " + newState);

            result = false;
        } else {
            //status change allowed
            result = true;
        }
        return result;
    }

    /*
     * tdbActivity logs token activities; This version is called by non-administrative functions
     */
    public void tdbActivity(
            TPSSubsystem tpsSubsystem, String op, TokenRecord tokenRecord, String ip, String msg, String result) {
        try {
            tpsSubsystem.activityDatabase.log(
                    ip,
                    (tokenRecord != null)? tokenRecord.getId():null,
                    op,
                    result,
                    msg,
                    (tokenRecord != null)? tokenRecord.getUserID():null,
                    (tokenRecord != null)? tokenRecord.getType():null);
        } catch (Exception e) {
            msg = msg + ";" + " tokendb activity logging failure: " + e;
        }
    }

    /*
     * tdbActivity logs token activities; This version is called by administrative functions
     */
    public void tdbActivity(
            TPSSubsystem tpsSubsystem, String op, TokenRecord tokenRecord, String ip, String msg, String result, String uid) {
        try {
            tpsSubsystem.activityDatabase.log(
                    ip,
                    (tokenRecord != null)? tokenRecord.getId():null,
                    op,
                    result,
                    msg,
                    uid,
                    (tokenRecord != null)? tokenRecord.getType():null);
        } catch (Exception e) {
            msg = msg + ";" + " tokendb activity logging failure: " + e;
        }
    }

    public boolean isTokenPresent(TPSSubsystem tpsSubsystem, String cuid) {
        boolean present = false;
        try {
            tpsSubsystem.tokenDatabase.getRecord(cuid);
            present = true;
        } catch (Exception e) {
            CMS.debug("TPSTokendb.isTokenPresent: token entry not found");
            present = false;
        }
        return present;
    }

    public TokenRecord tdbGetTokenEntry(TPSSubsystem tpsSubsystem, String cuid)
            throws Exception {
        return tpsSubsystem.tokenDatabase.getRecord(cuid);
    }

    public void tdbAddTokenEntry(TPSSubsystem tpsSubsystem, TokenRecord tokenRecord, String status)
            throws Exception {
        tokenRecord.setStatus(status);

        tpsSubsystem.tokenDatabase.addRecord(tokenRecord.getId(), tokenRecord);
    }

    public void tdbUpdateTokenEntry(TPSSubsystem tpsSubsystem, TokenRecord tokenRecord)
            throws Exception {
        String id = tokenRecord.getId();
        TokenRecord existingTokenRecord;
        try {
            existingTokenRecord = tpsSubsystem.tokenDatabase.getRecord(id);
        } catch (Exception e) {
            CMS.debug("TPSTokendb.tdbUpdateTokenEntry: token entry not found; Adding");
            // add and exit
            tdbAddTokenEntry(tpsSubsystem, tokenRecord, tokenRecord.getStatus());
            return;
        }
        // token found; modify
        CMS.debug("TPSTokendb.tdbUpdateTokenEntry: token entry found; Modifying with status: "+ tokenRecord.getStatus());
        // don't change the create time of an existing token record; put it back
        tokenRecord.setCreateTimestamp(existingTokenRecord.getCreateTimestamp());
        tpsSubsystem.tokenDatabase.updateRecord(id, tokenRecord);
    }

    public void tdbUpdateCertificates(TPSSubsystem tpsSubsystem, String cuid, EnrolledCertsInfo certs)
            throws Exception {
        boolean tokenExist = isTokenPresent(tpsSubsystem, cuid);
        if (!tokenExist){
            throw new Exception("TPSTokendb:tdbUpdateCertificates: token "+ cuid + " does not exist");
        }


    }
}
