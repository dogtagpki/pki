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
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

import javax.ws.rs.core.Response;

import org.apache.commons.lang3.StringUtils;
import org.dogtagpki.server.tps.TPSEngineConfig;
import org.dogtagpki.server.tps.TPSSubsystem;
import org.dogtagpki.server.tps.dbs.ActivityDatabase;
import org.dogtagpki.server.tps.dbs.TokenDatabase;
import org.dogtagpki.server.tps.dbs.TokenRecord;
import org.dogtagpki.server.tps.engine.TPS;

import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.dbs.DBVirtualList;
import com.netscape.certsrv.dbs.EDBException;
import com.netscape.certsrv.ldap.LDAPExceptionConverter;
import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.tps.token.TokenCollection;
import com.netscape.certsrv.tps.token.TokenData;
import com.netscape.certsrv.tps.token.TokenData.TokenStatusData;
import com.netscape.certsrv.tps.token.TokenResource;
import com.netscape.certsrv.tps.token.TokenStatus;
import com.netscape.certsrv.user.UserResource;
import com.netscape.cms.realm.PKIPrincipal;
import com.netscape.cms.servlet.base.SubsystemService;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.usrgrp.User;

import netscape.ldap.LDAPException;

/**
 * @author Endi S. Dewata
 */
public class TokenService extends SubsystemService implements TokenResource {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(TokenService.class);

    public void setTokenStatus(TokenRecord tokenRecord, TokenStatus tokenState, String ipAddress, String remoteUser,
            Map<String, String> auditModParams)
                    throws Exception {

        String method = "TPSService:setTokenStatus: ";
        String msg = "";

        List<String> authorizedProfiles = getAuthorizedProfiles();
        if (authorizedProfiles == null) {
            msg = "authorizedProfiles null";
            logger.debug(method + msg);
            throw new PKIException(method + msg);
        }
        String type = tokenRecord.getType();
        // if token not associated with any keyType/profile, disallow access,
        // unless the user has the "ALL_PROFILES" privilege
        if (!authorizedProfiles.contains(UserResource.ALL_PROFILES)) {
            if (((type == null) || type.isEmpty()) || !authorizedProfiles.contains(type))
               throw new PKIException(method + "Token record restricted");
        }

        org.dogtagpki.server.tps.TPSEngine engine = org.dogtagpki.server.tps.TPSEngine.getInstance();
        TPSEngineConfig config = engine.getConfig();

        TPSSubsystem tps = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);

        TokenStatus oldStatus = tokenRecord.getTokenStatus();
        String oldReason = tokenRecord.getReason();
        TokenStatus newStatus = tokenState;
        String newReason = null;

        boolean clearOnUnformatUserID = config.getBoolean(TPS.CFG_TOKENSERVICE_UNFORMATTED_CLEAR_USERID, true);
        boolean clearOnUnformatType = config.getBoolean(TPS.CFG_TOKENSERVICE_UNFORMATTED_CLEAR_TYPE, true);
        boolean clearOnUnformatAppletID = config.getBoolean(TPS.CFG_TOKENSERVICE_UNFORMATTED_CLEAR_APPLETID, true);
        boolean clearOnUnformatKeyInfo = config.getBoolean(TPS.CFG_TOKENSERVICE_UNFORMATTED_CLEAR_KEYINFO, true);
        boolean clearOnUnformatPolicy = config.getBoolean(TPS.CFG_TOKENSERVICE_UNFORMATTED_CLEAR_POLICY, true);

        auditModParams.put("UserID", tokenRecord.getUserID());

        switch (tokenState.getValue()) {
        case TokenStatus.TOKEN_UNFORMATTED:
            if(clearOnUnformatUserID) {
                tokenRecord.setUserID(null);
            }
            if(clearOnUnformatType) {
                tokenRecord.setType(null);
            }
            if(clearOnUnformatAppletID) {
                tokenRecord.setAppletID(null);
            }
            if(clearOnUnformatKeyInfo) {
                tokenRecord.setKeyInfo(null);
            }
            if(clearOnUnformatPolicy) {
                tokenRecord.setPolicy(null);
            }
            tokenRecord.setTokenStatus(tokenState);
            tokenRecord.setReason(null);
            break;

        case TokenStatus.TOKEN_FORMATTED:
            tokenRecord.setTokenStatus(tokenState);
            tokenRecord.setReason(null);
            break;

        case TokenStatus.TOKEN_ACTIVE:
            if (tokenRecord.getTokenStatus() == TokenStatus.SUSPENDED) {
                // unrevoke certs
                tps.tdb.unRevokeCertsByCUID(tokenRecord.getId(), ipAddress, remoteUser);
            }

            tokenRecord.setTokenStatus(tokenState);
            tokenRecord.setReason(null);
            break;

        case TokenStatus.TOKEN_PERM_LOST:
        case TokenStatus.TOKEN_TEMP_LOST_PERM_LOST:
            tokenRecord.setTokenStatus(tokenState);
            tokenRecord.setReason("keyCompromise");
            newReason = "keyCompromise";

            //revoke certs
            tps.tdb.revokeCertsByCUID(tokenRecord.getId(), "keyCompromise", ipAddress, remoteUser);
            break;

        case TokenStatus.TOKEN_DAMAGED:
            tokenRecord.setTokenStatus(tokenState);
            tokenRecord.setReason("destroyed");
            newReason = "destroyed";

            //revoke certs
            tps.tdb.revokeCertsByCUID(tokenRecord.getId(), "destroyed", ipAddress, remoteUser);
            break;

        case TokenStatus.TOKEN_SUSPENDED:
            tokenRecord.setTokenStatus(tokenState);
            tokenRecord.setReason("onHold");
            newReason = "onHold";

            // put certs onHold
            tps.tdb.revokeCertsByCUID(tokenRecord.getId(), "onHold", ipAddress, remoteUser);
            break;

        case TokenStatus.TOKEN_TERMINATED:
            String reason = "terminated";
            tokenRecord.setTokenStatus(tokenState);
            tokenRecord.setReason(reason);
            newReason = reason;

            //revoke certs
            tps.tdb.revokeCertsByCUID(tokenRecord.getId(), reason, ipAddress, remoteUser);
            break;

        default:
            PKIException e = new PKIException("Unsupported token state: " + tokenState);
            auditTokenStateChange(ILogger.FAILURE, oldStatus,
                    newStatus, oldReason, newReason,
                    auditModParams, e.toString());
            throw e;
        }

        auditTokenStateChange(ILogger.SUCCESS, oldStatus, newStatus, oldReason, newReason, auditModParams, null);

    }

    public TokenData createTokenData(TokenRecord tokenRecord) throws Exception {

        org.dogtagpki.server.tps.TPSEngine engine = org.dogtagpki.server.tps.TPSEngine.getInstance();
        TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);

        ResourceBundle labels = getResourceBundle("token-states");

        TokenData tokenData = new TokenData();
        tokenData.setID(tokenRecord.getId());
        tokenData.setTokenID(tokenRecord.getId());
        tokenData.setUserID(tokenRecord.getUserID());
        tokenData.setType(tokenRecord.getType());

        TokenStatus status = tokenRecord.getTokenStatus();
        TokenStatusData statusData = new TokenStatusData();
        statusData.name = status;
        try {
            statusData.label = labels.getString(status.toString());
        } catch (MissingResourceException e) {
            statusData.label = status.toString();
        }
        tokenData.setStatus(statusData);

        Collection<TokenStatus> nextStates = subsystem.getUINextTokenStates(tokenRecord);
        if(nextStates != null) {
            Collection<TokenStatusData> nextStatesData = new ArrayList<>();
            for (TokenStatus nextState : nextStates) {
                TokenStatusData nextStateData = new TokenStatusData();
                nextStateData.name = nextState;
                try {
                    nextStateData.label = labels.getString(status + "." + nextState);
                } catch (MissingResourceException e) {
                    nextStateData.label = nextState.toString();
                }
                nextStatesData.add(nextStateData);
            }
            tokenData.setNextStates(nextStatesData);
        }

        tokenData.setAppletID(tokenRecord.getAppletID());
        tokenData.setKeyInfo(tokenRecord.getKeyInfo());
        tokenData.setPolicy(tokenRecord.getPolicy());
        tokenData.setCreateTimestamp(tokenRecord.getCreateTimestamp());
        tokenData.setModifyTimestamp(tokenRecord.getModifyTimestamp());

        String tokenID = tokenRecord.getId();
        try {
            tokenID = URLEncoder.encode(tokenID, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            logger.error("TokenService: " + e.getMessage(), e);
            throw new PKIException(e);
        }
        return tokenData;
    }

    /*
     * <restricted> records are records not permitted to be accessed
     * by the user per profile restrictions;  They are shown
     * on display when searched
     */
    public TokenData createRestrictedTokenData() throws Exception {

        TokenData tokenData = new TokenData();
        tokenData.setID("<restricted>");
        tokenData.setTokenID("<restricted>");
        tokenData.setUserID("<restricted>");
        tokenData.setType("<restricted>");

        TokenStatusData statusData = new TokenStatusData();
        statusData.name = TokenStatus.valueOf(null);
        statusData.label = "<restricted>";
        tokenData.setStatus(statusData);

        tokenData.setAppletID("<restricted>");
        tokenData.setKeyInfo("<restricted>");
        tokenData.setPolicy("<restricted>");
        tokenData.setCreateTimestamp(new Date(0L));
        tokenData.setModifyTimestamp(new Date(0L));

        return tokenData;
    }

    @Override
    public Response findTokens(
            String filter,
            String tokenID,
            String userID,
            String type,
            TokenStatus status,
            Integer start,
            Integer size) {

        logger.info("TokenService: Searching for tokens with filter " + filter);

        if (filter != null && filter.length() < MIN_FILTER_LENGTH) {
            throw new BadRequestException("Filter too short");
        }

        Map<String, String> attributes = new HashMap<>();

        if (StringUtils.isNotEmpty(tokenID)) {
            attributes.put("id", tokenID);
        }

        if (StringUtils.isNotEmpty(userID)) {
            attributes.put("userID", userID);
        }

        if (StringUtils.isNotEmpty(type)) {
            attributes.put("type", type);
        }

        if (status != null) {
            attributes.put("status", status.toString());
        }

        start = start == null ? 0 : start;
        size = size == null ? DEFAULT_SIZE : size;

        org.dogtagpki.server.tps.TPSEngine engine = org.dogtagpki.server.tps.TPSEngine.getInstance();
        try {
            TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
            TokenDatabase database = subsystem.getTokenDatabase();
            TokenCollection response = new TokenCollection();

            if (filter == null && attributes.isEmpty()) {
                retrieveTokensWithVLV(database, start, size, response);
            } else {
                retrieveTokensWithoutVLV(database, filter, attributes, start, size, response);
            }
            return createOKResponse(response);

        } catch (EDBException e) {
            Throwable t = e.getCause();
            if (t instanceof LDAPException) {
                throw LDAPExceptionConverter.toPKIException((LDAPException) t);
            }
            throw new PKIException(e);

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            logger.error("TokenService: " + e.getMessage(), e);
            throw new PKIException(e);
        }
    }

    protected void retrieveTokensWithVLV(
            TokenDatabase database,
            Integer start,
            Integer size,
            TokenCollection response) throws Exception {

        String method = "TokenService.retrieveTokensWithVLV: ";
        // search with VLV sorted by date in reverse order
        DBVirtualList<TokenRecord> list = database.findRecords(
                null, null, new String[] { "-modifyTimestamp", "-createTimestamp" }, size);

        List<String> authorizedProfiles = getAuthorizedProfiles();

        int total = list.getSize();
        int retTotal = 0; //debugging only

        // return entries in the requested page
        if (authorizedProfiles != null) {
            if (authorizedProfiles.contains(UserResource.ALL_PROFILES)) {
                for (int i = start; i < start + size && i < total; i++) {
                    TokenRecord record = list.getElementAt(i);

                    response.addEntry(createTokenData(record));
                    retTotal++;
                }
            } else { // not authorized for all profiles
                for (int i = start; i < start + size && i < total; i++) {
                    TokenRecord record = list.getElementAt(i);
                    //logger.debug(method + "record.ID="+ record.getId());

                    String type = record.getType();
                    //logger.debug(method + "record.tokenType="+ type;
                    if ((type == null) || type.isEmpty() || authorizedProfiles.contains(type)) {
                        //logger.debug(method + "token type allowed");
                        retTotal++;
                        response.addEntry(createTokenData(record));
                    } else {
                        //logger.debug(method + "token type restricted: " + type +
                        //        "; adding 'restricted' record");
                        response.addEntry(createRestrictedTokenData());
                    }
                } //for
            }
        } else { //authorizedProfiles null; no permission
            logger.debug(method + "authorized profiles is null");
        }

        logger.debug(method + "retTotal = " + retTotal);
        response.setTotal(total);
    }

    protected void retrieveTokensWithoutVLV(
            TokenDatabase database,
            String filter,
            Map<String, String> attributes,
            Integer start,
            Integer size,
            TokenCollection response) throws Exception {

        String method = "TokenService.retrieveTokensWithoutVLV: ";

        // search without VLV
        List<TokenRecord> tokens = (List<TokenRecord>) database.findRecords(filter);
        int total = tokens.size();
        logger.debug(method + "total: " + total);

        List<String> authorizedProfiles = getAuthorizedProfiles();

        int retTotal = 0; //debugging only
        int i = 0;

        // return entries in the requested page
        if (authorizedProfiles != null) {
            if (authorizedProfiles.contains(UserResource.ALL_PROFILES)) {
                for (i=start; i < start + size && i < total; i++) {
                    TokenRecord record = tokens.get(i);

                    //logger.debug(method + "record.tokenType="+ record.getType());
                    response.addEntry(createTokenData(record));
                    retTotal++;
                }
            } else { // not authorized for all profiles
                for (i=start; i < start + size && i < total; i++) {
                    TokenRecord record = tokens.get(i);
                    //logger.debug(method + "record.ID="+ record.getId());
                    String type = record.getType();
                    //logger.debug(method + "record.tokenType="+ type;
                    if ((type == null) || type.isEmpty() || authorizedProfiles.contains(type)) {
                        //logger.debug(method + "token type allowed");
                        retTotal++;
                        response.addEntry(createTokenData(record));
                    } else {
                        //logger.debug(method + "token type not allowed: " + type +
                        //        "; adding 'restricted' record");
                        response.addEntry(createRestrictedTokenData());
                    }
                }
            }
        } else { //authorizedProfiles null; no permission
            logger.debug(method + "authorized profiles is null");
        }

        logger.debug(method + "retTotal = " + retTotal);

        response.setTotal(total);
    }

    @Override
    public Response getToken(String tokenID) {

        String method = "TokenService.getToken: ";
        String msg = "";

        if (tokenID == null) {
            throw new BadRequestException(method + "Missing token ID");
        }
        logger.info(method + "Retrieving token " + tokenID);

        org.dogtagpki.server.tps.TPSEngine engine = org.dogtagpki.server.tps.TPSEngine.getInstance();
        try {
            List<String> authorizedProfiles = getAuthorizedProfiles();
            if (authorizedProfiles == null) {
                msg = "authorizedProfiles null";
                logger.debug(method + msg);
                throw new PKIException(method + msg);
            }

            TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
            TokenDatabase database = subsystem.getTokenDatabase();

            TokenRecord record = database.getRecord(tokenID);
            if (record == null) {
                msg = "Token record not found";
                logger.debug(method + msg);
                throw new PKIException(method + msg);
            }
            String type = record.getType();
            if ((type == null) || type.isEmpty() || authorizedProfiles.contains(UserResource.ALL_PROFILES) || authorizedProfiles.contains(type))

                return createOKResponse(createTokenData(record));
            else
                throw new PKIException(method + "Token record restricted");

        } catch (EDBException e) {
            Throwable t = e.getCause();
            if (t instanceof LDAPException) {
                throw LDAPExceptionConverter.toPKIException((LDAPException) t);
            }
            throw new PKIException(e);

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            logger.debug(method, e);
            throw new PKIException(e);
        }
    }

    @Override
    public Response addToken(TokenData tokenData) {

        String method = "TokenService.addToken: ";
        logger.info(method);

        Map<String, String> auditModParams = new HashMap<>();

        if (tokenData == null) {
            BadRequestException ex = new BadRequestException(method + "Missing token data");
            auditConfigTokenGeneral(ILogger.FAILURE, method, null,
                    ex.toString());
            throw ex;
        }

        String tokenID = tokenData.getTokenID();
        logger.info(method + "Token ID: " + tokenID);

        auditModParams.put("tokenID", tokenID);

        String remoteUser = servletRequest.getRemoteUser();
        String ipAddress = servletRequest.getRemoteAddr();

        org.dogtagpki.server.tps.TPSEngine engine = org.dogtagpki.server.tps.TPSEngine.getInstance();
        TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
        TokenRecord tokenRecord = null;
        String msg = "add token";

        try {
            TokenDatabase database = subsystem.getTokenDatabase();

            tokenRecord = new TokenRecord();
            tokenRecord.setId(tokenID);

            String userID = tokenData.getUserID();
            if (StringUtils.isNotEmpty(userID)) {
                tokenRecord.setUserID(userID);
                auditModParams.put("userID", userID);
            }

            String policy = tokenData.getPolicy();
            if (StringUtils.isNotEmpty(policy)) {
                tokenRecord.setPolicy(policy);
                auditModParams.put("Policy", policy);
            }

            // new tokens are UNFORMATTED when added via UI/CLI
            tokenRecord.setTokenStatus(TokenStatus.UNFORMATTED);
            auditModParams.put("Status", TokenStatus.UNFORMATTED.toString());

            database.addRecord(tokenID, tokenRecord);
            subsystem.tdb.tdbActivity(ActivityDatabase.OP_ADD, tokenRecord,
                    ipAddress, msg, "success", remoteUser);
            tokenData = createTokenData(database.getRecord(tokenID));
            auditConfigTokenRecord(ILogger.SUCCESS, method, tokenID,
                    auditModParams, null);

            String encodedTokenID = URLEncoder.encode(tokenID, "UTF-8");
            URI uri = uriInfo
                    .getBaseUriBuilder()
                    .path(TokenResource.class)
                    .path("{tokenID}")
                    .build(encodedTokenID);
            return createCreatedResponse(tokenData, uri);

        } catch (Exception e) {

            msg = msg + ": " + e.getMessage();
            logger.error(msg, e);

            subsystem.tdb.tdbActivity(ActivityDatabase.OP_ADD, tokenRecord,
                    ipAddress, msg, "failure", remoteUser);

            if (e instanceof EDBException) {
                Throwable t = e.getCause();
                if (t instanceof LDAPException) {
                    PKIException ex = LDAPExceptionConverter.toPKIException((LDAPException) t);
                    auditConfigTokenRecord(ILogger.FAILURE, method, tokenID,
                            auditModParams, ex.toString());
                    throw ex;
                }
            }

            if (e instanceof PKIException) {
                auditConfigTokenRecord(ILogger.FAILURE, method, tokenID,
                        auditModParams, e.toString());
                throw (PKIException) e;
            }

            auditConfigTokenRecord(ILogger.FAILURE, method, tokenID,
                    auditModParams, e.toString());
            throw new PKIException(e);
        }
    }

    @Override
    public Response replaceToken(String tokenID, TokenData tokenData) {

        String method = "TokenService.replaceToken: ";
        logger.info(method + "Replacing token " + tokenID);

        Map<String, String> auditModParams = new HashMap<>();

        if (tokenID == null) {
            auditConfigTokenGeneral(ILogger.FAILURE, method, null, "Missing token ID");
            throw new BadRequestException(method + "Missing token ID");
        }

        if (tokenData == null) {
            auditConfigTokenGeneral(ILogger.FAILURE, method, auditModParams, "Missing token data");
            throw new BadRequestException("Missing token data");
        }

        String remoteUser = servletRequest.getRemoteUser();
        String ipAddress = servletRequest.getRemoteAddr();

        org.dogtagpki.server.tps.TPSEngine engine = org.dogtagpki.server.tps.TPSEngine.getInstance();
        TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
        TokenRecord tokenRecord = null;
        String msg = "replace token";
        try {
            List<String> authorizedProfiles = getAuthorizedProfiles();
            if (authorizedProfiles == null) {
                msg = "authorizedProfiles null";
                logger.debug(method + msg);
                throw new PKIException(method + msg);
            }

            TokenDatabase database = subsystem.getTokenDatabase();

            tokenRecord = database.getRecord(tokenID);

            if (tokenRecord == null) {
                msg = "Token record not found";
                logger.debug(method + msg);
                throw new PKIException(method + msg);
            }

            String type = tokenRecord.getType();
            if ((type != null) && !type.isEmpty() && !authorizedProfiles.contains(UserResource.ALL_PROFILES) && !authorizedProfiles.contains(type))
                   throw new PKIException(method + "Token record restricted");

            tokenRecord.setUserID(remoteUser);
            auditModParams.put("userID", remoteUser);
            tokenRecord.setType(tokenData.getType());
            auditModParams.put("type", tokenData.getType());
            tokenRecord.setAppletID(tokenData.getAppletID());
            auditModParams.put("appletID", tokenData.getAppletID());
            tokenRecord.setKeyInfo(tokenData.getKeyInfo());
            auditModParams.put("keyInfo", tokenData.getKeyInfo());
            tokenRecord.setPolicy(tokenData.getPolicy());
            auditModParams.put("Policy", tokenData.getPolicy());
            database.updateRecord(tokenID, tokenRecord);
            subsystem.tdb.tdbActivity(ActivityDatabase.OP_TOKEN_MODIFY, tokenRecord,
                    ipAddress, msg, "success", remoteUser);

            tokenData = createTokenData(database.getRecord(tokenID));
            auditConfigTokenRecord(ILogger.SUCCESS, method, tokenID,
                    auditModParams, null);

            return createOKResponse(tokenData);

        } catch (Exception e) {

            msg = msg + ": " + e.getMessage();
            logger.error(msg, e);

            subsystem.tdb.tdbActivity(ActivityDatabase.OP_TOKEN_MODIFY, tokenRecord,
                    ipAddress, msg, "failure",
                    remoteUser);

            if (e instanceof EDBException) {
                Throwable t = e.getCause();
                if (t instanceof LDAPException) {
                    PKIException ex = LDAPExceptionConverter.toPKIException((LDAPException) t);
                    auditConfigTokenRecord(ILogger.FAILURE, method, tokenID,
                            auditModParams, ex.toString());
                    throw ex;
                }
            }

            if (e instanceof PKIException) {
                auditConfigTokenRecord(ILogger.FAILURE, method, tokenID,
                        auditModParams, e.toString());
                throw (PKIException) e;
            }

            auditConfigTokenRecord(ILogger.FAILURE, method, tokenID,
                    auditModParams, e.toString());
            throw new PKIException(e);
        }
    }

    @Override
    public Response modifyToken(String tokenID, TokenData tokenData) {

        String method = "TokenService.modifyToken: ";
        logger.info(method + "Modifying token " + tokenID);

        Map<String, String> auditModParams = new HashMap<>();

        if (tokenID == null) {
            BadRequestException e = new BadRequestException(method + "Missing token ID");
            auditConfigTokenRecord(ILogger.FAILURE, "modify", tokenID,
                    auditModParams, e.toString());
            throw e;
        }

        if (tokenData == null) {
            BadRequestException e = new BadRequestException("Missing token data");
            auditConfigTokenRecord(ILogger.FAILURE, "modify", tokenID,
                    auditModParams, e.toString());
            throw e;
        }

        String remoteUser = servletRequest.getRemoteUser();
        String ipAddress = servletRequest.getRemoteAddr();

        org.dogtagpki.server.tps.TPSEngine engine = org.dogtagpki.server.tps.TPSEngine.getInstance();
        TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
        TokenRecord tokenRecord = null;
        String msg = "modify token";
        try {
            List<String> authorizedProfiles = getAuthorizedProfiles();
            if (authorizedProfiles == null) {
                msg = "authorizedProfiles null";
                logger.debug(method + msg);
                throw new PKIException(method + msg);
            }

            TokenDatabase database = subsystem.getTokenDatabase();

            // get existing record
            tokenRecord = database.getRecord(tokenID);

            if (tokenRecord == null) {
                logger.debug(method + "Token record not found");
                throw new PKIException(method + "Token record not found");
            }
            String type = tokenRecord.getType();
            if ((type != null) && !type.isEmpty() && !authorizedProfiles.contains(UserResource.ALL_PROFILES) && !authorizedProfiles.contains(type)) {
                logger.debug(method + "token record restricted");

                throw new PKIException("token record restricted");
            }

            // update user ID if specified
            String userID = tokenData.getUserID();
            if (userID != null) {
                if (userID.equals("")) { // remove value if empty
                    tokenRecord.setUserID(null);
                } else { // otherwise replace value
                    tokenRecord.setUserID(userID);
                    auditModParams.put("userID", userID);
                }
            }

            // update policy if specified
            String policy = tokenData.getPolicy();
            if (policy != null) {
                if (policy.equals("")) { // remove value if empty
                    tokenRecord.setPolicy(null);
                } else { //otherwise replace value
                    tokenRecord.setPolicy(policy);
                    auditModParams.put("Policy", policy);
                }
            }

            database.updateRecord(tokenID, tokenRecord);
            subsystem.tdb.tdbActivity(ActivityDatabase.OP_TOKEN_MODIFY, tokenRecord,
                    ipAddress, msg, "success", remoteUser);

            tokenData = createTokenData(database.getRecord(tokenID));
            auditConfigTokenRecord(ILogger.SUCCESS, method, tokenID,
                    auditModParams, null);

            return createOKResponse(tokenData);

        } catch (Exception e) {

            msg = msg + ": " + e.getMessage();
            logger.error(msg, e);

            subsystem.tdb.tdbActivity(ActivityDatabase.OP_TOKEN_MODIFY, tokenRecord,
                    ipAddress, msg, "failure",
                    remoteUser);

            if (e instanceof EDBException) {
                Throwable t = e.getCause();
                if (t instanceof LDAPException) {
                    PKIException ex = LDAPExceptionConverter.toPKIException((LDAPException) t);
                    auditConfigTokenRecord(ILogger.FAILURE, method, tokenID,
                            auditModParams, ex.toString());
                    throw ex;
                }
            }

            if (e instanceof PKIException) {
                auditConfigTokenRecord(ILogger.FAILURE, method, tokenID,
                        auditModParams, e.toString());
                throw (PKIException) e;
            }

            auditConfigTokenRecord(ILogger.FAILURE, method, tokenID,
                    auditModParams, e.toString());
            throw new PKIException(e);
        }
    }

    @Override
    public Response changeTokenStatus(String tokenID, TokenStatus tokenStatus) {

        String method = "TokenService.changeTokenStatus: ";
        logger.debug(method + "begins: with tokenStatus=" + tokenStatus);
        if (tokenID == null) {
            auditConfigTokenGeneral(ILogger.FAILURE, method, null, "Missing token ID");
            throw new BadRequestException(method + "Missing token ID");
        }


        org.dogtagpki.server.tps.TPSEngine engine = org.dogtagpki.server.tps.TPSEngine.getInstance();
        TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);

        if (tokenStatus == null) {
            auditConfigTokenGeneral(ILogger.FAILURE, method, null, "Missing token status");
            throw new BadRequestException("Missing token status");
        }

        Map<String, String> auditModParams = new HashMap<>();
        auditModParams.put("tokenID", tokenID);
        auditModParams.put("tokenStatus", tokenStatus.toString());

        String remoteUser = servletRequest.getRemoteUser();
        String ipAddress = servletRequest.getRemoteAddr();

        // for auditing
        TokenStatus oldStatus = null;
        String oldReason = null;
        TokenStatus newStatus = null;
        String newReason = null;

        TokenRecord tokenRecord = null;
        String msg = "change token status";
        try {
            List<String> authorizedProfiles = getAuthorizedProfiles();
            if (authorizedProfiles == null) {
                msg = "authorizedProfiles null";
                logger.debug(method + msg);
                throw new PKIException(method + msg);
            }

            TokenDatabase database = subsystem.getTokenDatabase();
            database = subsystem.getTokenDatabase();
            tokenRecord = database.getRecord(tokenID);
            if (tokenRecord == null) {
                logger.debug(method + "Token record not found");
                throw new PKIException(method + "Token record not found");
            }
            String type = tokenRecord.getType();
            if ((type != null) && !type.isEmpty() && !authorizedProfiles.contains(UserResource.ALL_PROFILES) && !authorizedProfiles.contains(type)) {
                logger.debug(method + "token record restricted: " + type);

                throw new PKIException("token record restricted");
            }
            TokenStatus currentTokenStatus = tokenRecord.getTokenStatus();
            logger.debug(method + "current status: " + currentTokenStatus);

            oldStatus = tokenRecord.getTokenStatus();
            oldReason = tokenRecord.getReason();
            newStatus = tokenStatus;

            if (currentTokenStatus == tokenStatus) {
                logger.debug(method + "no status change, no activity log generated");

                TokenData tokenData = createTokenData(tokenRecord);
                return createOKResponse(tokenData);
            }

            msg = msg + " from " + currentTokenStatus + " to " + tokenStatus;
            logger.debug(method + msg);

            // Check for invalid current status
            if(!oldStatus.isValid()) {
                logger.debug(method + "current status is invalid: " + oldStatus);
                Exception ex = new BadRequestException("Cannot change status of token with current status: " + oldStatus);
                auditTokenStateChange(ILogger.FAILURE, oldStatus,
                        newStatus, oldReason, newReason,
                        auditModParams, ex.toString());
                throw ex;
            }

            // make sure transition is allowed
            if (!subsystem.isUITransitionAllowed(tokenRecord, tokenStatus)) {
                logger.error(method + "next status not allowed: " + tokenStatus);
                Exception ex = new BadRequestException("Invalid token status transition");
                auditTokenStateChange(ILogger.FAILURE, oldStatus,
                        newStatus, oldReason, newReason,
                        auditModParams, ex.toString());
                throw ex;
            }

            logger.debug(method + "next status allowed: " + tokenStatus);
            // audit in setTokenStatus()
            setTokenStatus(tokenRecord, tokenStatus, ipAddress, remoteUser, auditModParams);
            database.updateRecord(tokenID, tokenRecord);
            subsystem.tdb.tdbActivity(ActivityDatabase.OP_TOKEN_STATUS_CHANGE, tokenRecord,
                    ipAddress, msg, "success",
                    remoteUser);

            TokenData tokenData = createTokenData(database.getRecord(tokenID));

            return createOKResponse(tokenData);

        } catch (Exception e) {

            msg = msg + ": " + e.getMessage();
            logger.error(msg, e);

            subsystem.tdb.tdbActivity(ActivityDatabase.OP_TOKEN_STATUS_CHANGE, tokenRecord,
                    ipAddress, msg, "failure",
                    remoteUser);

            if (e instanceof EDBException) {
                Throwable t = e.getCause();
                if (t instanceof LDAPException) {
                    PKIException ex = LDAPExceptionConverter.toPKIException((LDAPException) t);
                    auditTokenStateChange(ILogger.FAILURE, oldStatus,
                            newStatus, oldReason, newReason,
                            auditModParams, ex.toString());
                    throw ex;
                }
            }

            if (e instanceof PKIException) {
                auditTokenStateChange(ILogger.FAILURE, oldStatus,
                        newStatus, oldReason, newReason,
                        auditModParams, e.toString());
                throw (PKIException) e;
            }

            auditTokenStateChange(ILogger.FAILURE, oldStatus,
                    newStatus, oldReason, newReason,
                    auditModParams, e.toString());
            throw new PKIException(e);
        }
    }

    @Override
    public Response removeToken(String tokenID) {

        String method = "TokenService.removeToken: ";

        Map<String, String> auditModParams = new HashMap<>();

        if (tokenID == null) {
            BadRequestException ex = new BadRequestException(method + "Missing token ID");
            auditConfigTokenRecord(ILogger.FAILURE, method, tokenID,
                    auditModParams, ex.toString());
            throw ex;
        }
        logger.info(method + "Removing token " + tokenID);

        String remoteUser = servletRequest.getRemoteUser();
        String ipAddress = servletRequest.getRemoteAddr();

        org.dogtagpki.server.tps.TPSEngine engine = org.dogtagpki.server.tps.TPSEngine.getInstance();
        TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
        TokenRecord tokenRecord = null;
        String msg = "remove token";
        try {

            List<String> authorizedProfiles = getAuthorizedProfiles();
            if (authorizedProfiles == null) {
                msg = "authorizedProfiles null";
                logger.debug(method + msg);
                throw new PKIException(method + msg);
            }

            TokenDatabase database = subsystem.getTokenDatabase();
            tokenRecord = database.getRecord(tokenID);
            if (tokenRecord == null) {
                msg = "Token record not found";
                logger.debug(method + msg);
                throw new PKIException(method + msg);
            }

            String type = tokenRecord.getType();
            if ((type != null) && !type.isEmpty() && !authorizedProfiles.contains(UserResource.ALL_PROFILES) && !authorizedProfiles.contains(type))
                  throw new PKIException(method + "Token record restricted");

            //delete all certs associated with this token
            logger.debug(method + "about to remove all certificates associated with the token first");
            subsystem.tdb.tdbRemoveCertificatesByCUID(tokenRecord.getId());

            database.removeRecord(tokenID);
            auditConfigTokenRecord(ILogger.SUCCESS, method, tokenID,
                    auditModParams, null);
            subsystem.tdb.tdbActivity(ActivityDatabase.OP_DELETE, tokenRecord,
                    ipAddress, msg, "success", remoteUser);

            return createNoContentResponse();

        } catch (Exception e) {

            msg = msg + ": " + e.getMessage();
            logger.error(msg, e);

            subsystem.tdb.tdbActivity(ActivityDatabase.OP_DELETE, tokenRecord,
                    ipAddress, msg, "failure",
                    remoteUser);

            if (e instanceof EDBException) {
                Throwable t = e.getCause();
                if (t instanceof LDAPException) {
                    PKIException ex = LDAPExceptionConverter.toPKIException((LDAPException) t);
                    auditConfigTokenRecord(ILogger.FAILURE, method, tokenID,
                            auditModParams, ex.toString());
                    throw ex;
                }
            }

            if (e instanceof PKIException) {
                auditConfigTokenRecord(ILogger.FAILURE, method, tokenID,
                        auditModParams, e.toString());
                throw (PKIException) e;
            }

            auditConfigTokenRecord(ILogger.FAILURE, method, tokenID,
                    auditModParams, e.toString());
            throw new PKIException(e);
        }
    }

    /*
     * returns a list of TPS profiles allowed for the current user
     */
    List<String> getAuthorizedProfiles()
           throws Exception {
        String method = "TokenService.getAuthorizedProfiles: ";

        PKIPrincipal pkiPrincipal = (PKIPrincipal) servletRequest.getUserPrincipal();
        if (pkiPrincipal == null) {
            logger.debug(method + "servletRequest.getUserPrincipal() returned null");
            return null;
        }
        User user = pkiPrincipal.getUser();

        return user.getTpsProfiles();
    }

    /*
     * Service can be any of the methods offered
     */
    public void auditConfigTokenRecord(String status, String service, String tokenID, Map<String, String> params,
            String info) {

        String msg = CMS.getLogMessage(
                AuditEvent.CONFIG_TOKEN_RECORD,
                servletRequest.getUserPrincipal().getName(),
                status,
                service,
                tokenID,
                auditor.getParamString(params),
                info);
        signedAuditLogger.log(msg);
    }

    /*
     *
     */
    public void auditTokenStateChange(String status, TokenStatus oldState, TokenStatus newState, String oldReason,
            String newReason, Map<String, String> params, String info) {

        String msg = CMS.getLogMessage(
                AuditEvent.TOKEN_STATE_CHANGE,
                servletRequest.getUserPrincipal().getName(),
                status,
                (oldState==null)? "":oldState.toString(),
                oldReason,
                (newState==null)? "":newState.toString(),
                newReason,
                auditor.getParamString(params),
                info);
        signedAuditLogger.log(msg);
    }
}
