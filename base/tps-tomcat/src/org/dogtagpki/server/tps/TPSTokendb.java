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

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;

import org.dogtagpki.server.tps.dbs.TPSCertRecord;
import org.dogtagpki.server.tps.dbs.TokenRecord;
import org.dogtagpki.tps.main.TPSException;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.tps.token.TokenStatus;

/*
 * TPSTokendb class offers a collection of tokendb management convenience routines
 */
public class TPSTokendb {
    private TPSSubsystem tps;
    private Map<TokenStatus, Collection<TokenStatus>> allowedTransitions = new HashMap<TokenStatus, Collection<TokenStatus>>();

    public TPSTokendb(TPSSubsystem tps) throws EBaseException {
        if (tps == null) {
            String msg = "TPStokendb.TPSTokendb: tps cannot be null";
            CMS.debug(msg);
            throw new EBaseException(msg);
        }
        this.tps = tps;
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
            String op, TokenRecord tokenRecord, String ip, String msg, String result) {
        try {
            tps.activityDatabase.log(
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
            String op, TokenRecord tokenRecord, String ip, String msg, String result, String uid) {
        try {
            tps.activityDatabase.log(
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

    public boolean isTokenPresent(String cuid) {
        boolean present = false;
        try {
            tps.tokenDatabase.getRecord(cuid);
            present = true;
        } catch (Exception e) {
            CMS.debug("TPSTokendb.isTokenPresent: token entry not found");
            present = false;
        }
        return present;
    }

    public TokenRecord tdbGetTokenEntry(String cuid)
            throws Exception {
        return tps.tokenDatabase.getRecord(cuid);
    }

    /*
     * tdbFindTokenRecordsByUID finds and returns token records belong to one user
     * @param uid the uid of the owner to the token
     * @return ArrayList of the token records
     */
    public ArrayList<TokenRecord> tdbFindTokenRecordsByUID(String uid)
            throws Exception {
        ArrayList<TokenRecord> tokenRecords = new ArrayList<TokenRecord>();
        String filter = uid;
        Iterator<TokenRecord> records = null;
        records = tps.tokenDatabase.findRecords(filter).iterator();

       while (records.hasNext()) {
           TokenRecord tokenRecord = records.next();
           tokenRecords.add(tokenRecord);
       }

       return tokenRecords;
    }

    public void tdbHasActiveToken(String userid)
           throws Exception {
        if (userid == null)
            throw new Exception("TPSTokendb.tdbhasActiveToken: uerid null");

        ArrayList<TokenRecord> tokens =
                tdbFindTokenRecordsByUID(userid);
        boolean foundActive = false;
        for (TokenRecord tokenRecord:tokens) {
            if (tokenRecord.getStatus().equals("active")) {
                foundActive = true;
            }
        }
        if (!foundActive) {
            throw new Exception("TPSTokendb.tdbhasActiveToken: active token not found");
        }
    }

    public void tdbAddTokenEntry(TokenRecord tokenRecord, String status)
            throws Exception {
        tokenRecord.setStatus(status);

        tps.tokenDatabase.addRecord(tokenRecord.getId(), tokenRecord);
    }

    public void tdbUpdateTokenEntry(TokenRecord tokenRecord)
            throws Exception {
        String id = tokenRecord.getId();
        TokenRecord existingTokenRecord;
        try {
            existingTokenRecord = tps.tokenDatabase.getRecord(id);
        } catch (Exception e) {
            CMS.debug("TPSTokendb.tdbUpdateTokenEntry: token entry not found; Adding");
            // add and exit
            tdbAddTokenEntry(tokenRecord, "uninitialized");
            return;
        }
        // token found; modify
        CMS.debug("TPSTokendb.tdbUpdateTokenEntry: token entry found; Modifying with status: "+ tokenRecord.getStatus());
        // don't change the create time of an existing token record; put it back
        tokenRecord.setCreateTimestamp(existingTokenRecord.getCreateTimestamp());
        tps.tokenDatabase.updateRecord(id, tokenRecord);
    }

    /*
     * tdbAddCertificatesForCUID adds certificates issued for the token CUID
     * @param cuid the cuid of the token
     * @param certs an ArrayList of TPSCertRecord
     */
    public void tdbAddCertificatesForCUID(String cuid, ArrayList<TPSCertRecord> certs)
            throws TPSException {
        boolean tokenExist = isTokenPresent(cuid);
        if (!tokenExist){
            CMS.debug("TPSTokendb.tdbAddCertificatesForCUID: token not found: "+ cuid);
            throw new TPSException("TPSTokendb:tdbUpdateCertificates: token "+ cuid + " does not exist");
        }

        CMS.debug("TPSTokendb.tdbAddCertificatesForCUID: found token "+ cuid);
        CMS.debug("TPSTokendb.tdbAddCertificatesForCUID: number of certs to update:"+ certs.size());
        try {
            for (TPSCertRecord cert: certs) {
               // cert.setOrigin(cuid);

                try {
                tps.certDatabase.addRecord(cert.getId(), cert);
                } catch (Exception e) {

                    //If this is due to a dup, try to update the record.
                    tps.certDatabase.updateRecord(cert.getId(), cert);
                }
            }
        } catch (Exception e) {
            CMS.debug("TPSTokendb.tdbAddCertificatesForCUID: "+ e);
            // TODO: what if it throws in the middle of the cert list -- some cert records already updated?
            throw new TPSException(e.getMessage());
        }
    }

    /*
     * tdbGetCertificatesByCUID finds and returns certificate records belong to a token cuid
     * @param cuid the cuid of the token
     * @return ArrayList of the cert records
     */
    public ArrayList<TPSCertRecord> tdbGetCertificatesByCUID(String cuid)
            throws TPSException {
        if (cuid == null)
            throw new TPSException("TPSTokendb.tdbGetCertificatesByCUID: cuid null");

        ArrayList<TPSCertRecord> certRecords = new ArrayList<TPSCertRecord>();
        String filter = cuid;
        Iterator<TPSCertRecord> records;
        try {
             records = tps.certDatabase.findRecords(filter).iterator();
        } catch (Exception e) {
            CMS.debug("TPSTokendb.tdbGetCertificatesByCUID:" + e);
            throw new TPSException(e.getMessage());
        }

        while (records.hasNext()) {
            TPSCertRecord certRecord = records.next();
            certRecords.add(certRecord);
        }

        return certRecords;
    }
}
