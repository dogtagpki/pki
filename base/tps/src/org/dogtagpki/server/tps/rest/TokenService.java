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

package org.dogtagpki.server.tps.rest;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

import org.dogtagpki.server.tps.TPSSubsystem;
import org.dogtagpki.server.tps.dbs.ActivityDatabase;
import org.dogtagpki.server.tps.dbs.TokenDatabase;
import org.dogtagpki.server.tps.dbs.TokenRecord;
import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.tps.token.TokenCollection;
import com.netscape.certsrv.tps.token.TokenData;
import com.netscape.certsrv.tps.token.TokenResource;
import com.netscape.certsrv.tps.token.TokenStatus;
import com.netscape.cms.servlet.base.PKIService;

/**
 * @author Endi S. Dewata
 */
public class TokenService extends PKIService implements TokenResource {

    @Context
    private UriInfo uriInfo;

    @Context
    private HttpHeaders headers;

    @Context
    private Request request;

    @Context
    private HttpServletRequest servletRequest;

    public Map<TokenStatus, Collection<TokenStatus>> transitions = new HashMap<TokenStatus, Collection<TokenStatus>>();

    public TokenService() throws Exception {
        CMS.debug("TokenService.<init>()");
        IConfigStore configStore = CMS.getConfigStore();

        // load allowed token state transitions
        CMS.debug("TokenService: allowed transitions:");

        for (String transition : configStore.getString("tokendb.allowedTransitions").split(",")) {
            String states[] = transition.split(":");
            TokenStatus fromState = TokenStatus.fromInt(Integer.valueOf(states[0]));
            TokenStatus toState = TokenStatus.fromInt(Integer.valueOf(states[1]));
            CMS.debug("TokenService:  - " + fromState + " to " + toState);

            Collection<TokenStatus> nextStates = transitions.get(fromState);
            if (nextStates == null) {
                nextStates = new HashSet<TokenStatus>();
                transitions.put(fromState, nextStates);
            }
            nextStates.add(toState);
        }

    }

    public TokenStatus getTokenStatus(TokenRecord tokenRecord) {
        String status = tokenRecord.getStatus();

        if ("uninitialized".equals(status)) {
            return TokenStatus.UNINITIALIZED;

        } else if ("active".equals(status)) {
            return TokenStatus.ACTIVE;

        } else if ("lost".equals(status)) {
            String reason = tokenRecord.getReason();

            if ("keyCompromise".equals(reason)) {
                return TokenStatus.PERM_LOST;

            } else if ("destroyed".equals(reason)) {
                return TokenStatus.DAMAGED;

            } else if ("onHold".equals(reason)) {
                return TokenStatus.TEMP_LOST;
            }

        } else if ("terminated".equals(status)) {
            return TokenStatus.TERMINATED;
        }

        return TokenStatus.PERM_LOST;
    }

    public void setTokenStatus(TokenRecord tokenRecord, TokenStatus tokenState) throws Exception {
        TPSSubsystem tps = (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);

        switch (tokenState) {
        case UNINITIALIZED:
            tokenRecord.setStatus("uninitialized");
            tokenRecord.setReason(null);
            break;
        case ACTIVE:
            String origStatus = tokenRecord.getStatus();
            String origReason = tokenRecord.getReason();
            if (origStatus.equalsIgnoreCase("lost") &&
                    origReason.equalsIgnoreCase("onHold")) {
                //unrevoke certs
                tps.tdb.unRevokeCertsByCUID(tokenRecord.getId());
            }

            tokenRecord.setStatus("active");
            tokenRecord.setReason(null);
            break;
        case PERM_LOST:
        case TEMP_LOST_PERM_LOST:
            tokenRecord.setStatus("lost");
            tokenRecord.setReason("keyCompromise");

            //revoke certs
            tps.tdb.revokeCertsByCUID(tokenRecord.getId(), "keyCompromise");
            break;
        case DAMAGED:
            tokenRecord.setStatus("lost");
            tokenRecord.setReason("destroyed");

            //revoke certs
            tps.tdb.revokeCertsByCUID(tokenRecord.getId(), "destroyed");

            break;
        case TEMP_LOST:
            tokenRecord.setStatus("lost");
            tokenRecord.setReason("onHold");

            // put certs onHold
            tps.tdb.revokeCertsByCUID(tokenRecord.getId(), "onHold");
            break;
        case TERMINATED:
            String reason = "keyCompromise";
            String origStatus2 = tokenRecord.getStatus();
            String origReason2 = tokenRecord.getReason();
            // temp token looks at "onHold"
            if (origStatus2.equalsIgnoreCase("lost") &&
                    origReason2.equalsIgnoreCase("onHold")) {
                reason = "onHold";
            }
            tokenRecord.setStatus("terminated");
            tokenRecord.setReason(reason);

            //revoke certs
            tps.tdb.revokeCertsByCUID(tokenRecord.getId(), reason) ;
            break;
        default:
            throw new PKIException("Unsupported token state: " + tokenState);
        }

    }

    public TokenData createTokenData(TokenRecord tokenRecord) {

        TokenData tokenData = new TokenData();
        tokenData.setID(tokenRecord.getId());
        tokenData.setTokenID(tokenRecord.getId());
        tokenData.setUserID(tokenRecord.getUserID());
        tokenData.setType(tokenRecord.getType());
        tokenData.setStatus(getTokenStatus(tokenRecord));
        tokenData.setAppletID(tokenRecord.getAppletID());
        tokenData.setKeyInfo(tokenRecord.getKeyInfo());
        tokenData.setPolicy(tokenRecord.getPolicy());
        tokenData.setCreateTimestamp(tokenRecord.getCreateTimestamp());
        tokenData.setModifyTimestamp(tokenRecord.getModifyTimestamp());

        String tokenID = tokenRecord.getId();
        try {
            tokenID = URLEncoder.encode(tokenID, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }

        URI uri = uriInfo.getBaseUriBuilder().path(TokenResource.class).path("{tokenID}").build(tokenID);
        tokenData.setLink(new Link("self", uri));

        return tokenData;
    }

    public TokenRecord createTokenRecord(TokenData tokenData) throws Exception {

        TokenRecord tokenRecord = new TokenRecord();
        tokenRecord.setId(tokenData.getID());
        tokenRecord.setUserID(tokenData.getUserID());
        tokenRecord.setType(tokenData.getType());
        setTokenStatus(tokenRecord, tokenData.getStatus());
        tokenRecord.setAppletID(tokenData.getAppletID());
        tokenRecord.setKeyInfo(tokenData.getKeyInfo());
        tokenRecord.setPolicy(tokenData.getPolicy());
        tokenRecord.setCreateTimestamp(tokenData.getCreateTimestamp());
        tokenRecord.setModifyTimestamp(tokenData.getModifyTimestamp());

        return tokenRecord;
    }

    @Override
    public Response findTokens(String filter, Integer start, Integer size) {

        CMS.debug("TokenService.findTokens()");

        if (filter != null && filter.length() < MIN_FILTER_LENGTH) {
            throw new BadRequestException("Filter is too short.");
        }

        start = start == null ? 0 : start;
        size = size == null ? DEFAULT_SIZE : size;

        try {
            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            TokenDatabase database = subsystem.getTokenDatabase();

            Iterator<TokenRecord> tokens = database.findRecords(filter).iterator();

            TokenCollection response = new TokenCollection();
            int i = 0;

            // skip to the start of the page
            for ( ; i<start && tokens.hasNext(); i++) tokens.next();

            // return entries up to the page size
            for ( ; i<start+size && tokens.hasNext(); i++) {
                response.addEntry(createTokenData(tokens.next()));
            }

            // count the total entries
            for ( ; tokens.hasNext(); i++) tokens.next();
            response.setTotal(i);

            if (start > 0) {
                URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", Math.max(start-size, 0)).build();
                response.addLink(new Link("prev", uri));
            }

            if (start+size < i) {
                URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", start+size).build();
                response.addLink(new Link("next", uri));
            }

            return createOKResponse(response);

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public Response getToken(String tokenID) {

        if (tokenID == null) throw new BadRequestException("Token ID is null.");

        CMS.debug("TokenService.getToken(\"" + tokenID + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            TokenDatabase database = subsystem.getTokenDatabase();

            return createOKResponse(createTokenData(database.getRecord(tokenID)));

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public Response addToken(TokenData tokenData) {

        if (tokenData == null) throw new BadRequestException("Token data is null.");

        String tokenID = tokenData.getTokenID();
        CMS.debug("TokenService.addToken(\"" + tokenID + "\")");

        String remoteUser = servletRequest.getRemoteUser();
        String ipAddress = servletRequest.getRemoteAddr();

        TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
        TokenRecord tokenRecord = null;
        String msg = "add token";

        try {
            TokenDatabase database = subsystem.getTokenDatabase();

            // new tokens are uninitialized when created
            tokenData.setStatus(TokenStatus.UNINITIALIZED);

            tokenRecord = createTokenRecord(tokenData);
            tokenRecord.setId(tokenID);
            database.addRecord(tokenID, tokenRecord);
            subsystem.tdb.tdbActivity(ActivityDatabase.OP_ADD, tokenRecord,
                ipAddress, msg, "success", remoteUser);
            tokenData = createTokenData(database.getRecord(tokenID));

            return createCreatedResponse(tokenData, tokenData.getLink().getHref());

        } catch (Exception e) {
            e.printStackTrace();
            subsystem.tdb.tdbActivity(ActivityDatabase.OP_ADD, tokenRecord,
                ipAddress, msg, "failure", remoteUser);
            msg = msg + ":" + e;

            throw new PKIException(msg);
        }
    }

    @Override
    public Response replaceToken(String tokenID, TokenData tokenData) {

        if (tokenID == null) throw new BadRequestException("Token ID is null.");
        if (tokenData == null) throw new BadRequestException("Token data is null.");

        CMS.debug("TokenService.replaceToken(\"" + tokenID + "\")");

        String remoteUser = servletRequest.getRemoteUser();
        String ipAddress = servletRequest.getRemoteAddr();

        TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
        TokenRecord tokenRecord = null;
        String msg = "replace token";
        try {
            TokenDatabase database = subsystem.getTokenDatabase();

            tokenRecord = database.getRecord(tokenID);
            tokenRecord.setUserID(remoteUser);
            tokenRecord.setType(tokenData.getType());
            tokenRecord.setAppletID(tokenData.getAppletID());
            tokenRecord.setKeyInfo(tokenData.getKeyInfo());
            tokenRecord.setPolicy(tokenData.getPolicy());
            database.updateRecord(tokenID, tokenRecord);
            subsystem.tdb.tdbActivity(ActivityDatabase.OP_DO_TOKEN, tokenRecord,
                ipAddress, msg, "success", remoteUser);

            tokenData = createTokenData(database.getRecord(tokenID));

            return createOKResponse(tokenData);

        } catch (Exception e) {
            e.printStackTrace();
            subsystem.tdb.tdbActivity(ActivityDatabase.OP_DO_TOKEN, tokenRecord,
                ipAddress, msg, "failure",
                remoteUser);
            msg = msg + ":" + e;

            throw new PKIException(msg);
        }
    }

    @Override
    public Response modifyToken(String tokenID, TokenData tokenData) {

        if (tokenID == null) throw new BadRequestException("Token ID is null.");
        if (tokenData == null) throw new BadRequestException("Token data is null.");

        CMS.debug("TokenService.modifyToken(\"" + tokenID + "\")");

        String remoteUser = servletRequest.getRemoteUser();
        String ipAddress = servletRequest.getRemoteAddr();

        TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
        TokenRecord tokenRecord = null;
        String msg = "modify token";
        try {
            TokenDatabase database = subsystem.getTokenDatabase();

            // get existing record
            tokenRecord = database.getRecord(tokenID);

            // update user ID if specified
            String userID = tokenData.getUserID();
            if (userID != null) {
                if (userID.equals("")) { // remove value if empty
                    tokenRecord.setUserID(null);
                } else { // otherwise replace value
                    tokenRecord.setUserID(userID);
                }
            }

            // update type if specified
            String type = tokenData.getType();
            if (type != null) {
                if (type.equals("")) { // remove value if empty
                    tokenRecord.setType(null);
                } else { // otherwise replace value
                    tokenRecord.setType(type);
                }
            }

            // update applet ID if specified
            String appletID = tokenData.getAppletID();
            if (appletID != null) {
                if (appletID.equals("")) { // remove value if empty
                    tokenRecord.setAppletID(null);
                } else { // otherwise replace value
                    tokenRecord.setAppletID(appletID);
                }
            }

            // update key info if specified
            String keyInfo = tokenData.getKeyInfo();
            if (keyInfo != null) {
                if (keyInfo.equals("")) { // remove value if empty
                    tokenRecord.setKeyInfo(null);
                } else { // otherwise replace value
                    tokenRecord.setKeyInfo(keyInfo);
                }
            }

            // update policy if specified
            String policy = tokenData.getPolicy();
            if (policy != null) {
                if (policy.equals("")) { // remove value if empty
                    tokenRecord.setPolicy(null);
                } else { //otherwise replace value
                    tokenRecord.setPolicy(policy);
                }
            }

            database.updateRecord(tokenID, tokenRecord);
            subsystem.tdb.tdbActivity(ActivityDatabase.OP_DO_TOKEN, tokenRecord,
                ipAddress, msg, "success", remoteUser);

            tokenData = createTokenData(database.getRecord(tokenID));

            return createOKResponse(tokenData);

        } catch (Exception e) {
            e.printStackTrace();
            subsystem.tdb.tdbActivity(ActivityDatabase.OP_DO_TOKEN, tokenRecord,
                ipAddress, msg, "failure",
                remoteUser);
            msg = msg + ":" + e;

            throw new PKIException(msg);
        }
    }

    @Override
    public Response changeTokenStatus(String tokenID, TokenStatus tokenStatus) {

        if (tokenID == null) throw new BadRequestException("Token ID is null.");
        if (tokenStatus == null) throw new BadRequestException("Token state is null.");

        CMS.debug("TokenService.changeTokenStatus(\"" + tokenID + "\", \"" + tokenStatus + "\")");

        String remoteUser = servletRequest.getRemoteUser();
        String ipAddress = servletRequest.getRemoteAddr();

        TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
        TokenRecord tokenRecord = null;
        String msg = "";
        try {
            TokenDatabase database = subsystem.getTokenDatabase();

            tokenRecord = database.getRecord(tokenID);
            TokenStatus currentTokenStatus = getTokenStatus(tokenRecord);
            CMS.debug("TokenService.changeTokenStatus(): current status: " + currentTokenStatus);
            msg = "change token status from " + currentTokenStatus + " to " + tokenStatus;

            // make sure transition is allowed
            Collection<TokenStatus> nextStatuses = transitions.get(currentTokenStatus);
            CMS.debug("TokenService.changeTokenStatus(): allowed next statuses: " + nextStatuses);
            if (nextStatuses == null || !nextStatuses.contains(tokenStatus)) {
                CMS.debug("TokenService.changeTokenStatus(): next status not allowed: " + tokenStatus);
                msg = msg + ": Invalid token status transition";
                subsystem.tdb.tdbActivity(ActivityDatabase.OP_DO_TOKEN, tokenRecord,
                    ipAddress, msg,
                    "failure",
                    remoteUser);
                throw new BadRequestException(msg);
            }

            CMS.debug("TokenService.changeTokenStatus(): next status allowed: " + tokenStatus);
            setTokenStatus(tokenRecord, tokenStatus);
            database.updateRecord(tokenID, tokenRecord);
            subsystem.tdb.tdbActivity(ActivityDatabase.OP_DO_TOKEN, tokenRecord,
                ipAddress, msg, "success",
                remoteUser);

            TokenData tokenData = createTokenData(database.getRecord(tokenID));

            return createOKResponse(tokenData);

        } catch (Exception e) {
            e.printStackTrace();
            msg = msg + e;
            subsystem.tdb.tdbActivity(ActivityDatabase.OP_DO_TOKEN, tokenRecord,
                ipAddress, msg, "failure",
                remoteUser);

            throw new PKIException(msg);
        }
    }

    @Override
    public Response removeToken(String tokenID) {

        if (tokenID == null) throw new BadRequestException("Token ID is null.");

        CMS.debug("TokenService.removeToken(\"" + tokenID + "\")");

        String remoteUser = servletRequest.getRemoteUser();
        String ipAddress = servletRequest.getRemoteAddr();

        TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
        TokenRecord tokenRecord = null;
        String msg = "remove token";
        try {
            TokenDatabase database = subsystem.getTokenDatabase();
            tokenRecord = database.getRecord(tokenID);

            //delete all certs associated with this token
            CMS.debug("TokenService.removeToken: about to remove all certificates associated with the token first");
            subsystem.tdb.tdbRemoveCertificatesByCUID(tokenRecord.getId());

            database.removeRecord(tokenID);
            subsystem.tdb.tdbActivity(ActivityDatabase.OP_DELETE, tokenRecord,
                ipAddress, msg, "success", remoteUser);

            return createNoContentResponse();

        } catch (Exception e) {
            e.printStackTrace();
            subsystem.tdb.tdbActivity(ActivityDatabase.OP_DELETE, tokenRecord,
                ipAddress, msg, "failure",
                remoteUser);
            msg = msg + ":" + e;

            throw new PKIException(msg);
        }
    }
}
