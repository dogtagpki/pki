//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.quarkus;

import java.net.MalformedURLException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PATCH;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;

import org.apache.commons.lang3.StringUtils;
import org.dogtagpki.server.tps.TPSEngine;
import org.dogtagpki.server.tps.TPSEngineConfig;
import org.dogtagpki.server.tps.TPSSubsystem;
import org.dogtagpki.server.tps.dbs.ActivityDatabase;
import org.dogtagpki.server.tps.dbs.TokenDatabase;
import org.dogtagpki.server.tps.dbs.TokenRecord;
import org.dogtagpki.tps.main.TPSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.UnauthorizedException;
import com.netscape.certsrv.dbs.DBException;
import com.netscape.certsrv.ldap.LDAPExceptionConverter;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.tps.token.TokenCollection;
import com.netscape.certsrv.tps.token.TokenData;
import com.netscape.certsrv.tps.token.TokenData.TokenStatusData;
import com.netscape.certsrv.tps.token.TokenStatus;
import com.netscape.certsrv.user.UserResource;
import com.netscape.certsrv.util.JSONSerializer;

import io.quarkus.security.identity.SecurityIdentity;
import netscape.ldap.LDAPException;

/**
 * JAX-RS resource for TPS token operations.
 * Replaces TokenServlet.
 *
 * Implements the full token lifecycle state machine including
 * profile-based authorization, state transitions, certificate
 * revocation/unrevocation, and comprehensive audit logging.
 */
@Path("v2/tokens")
public class TPSTokenResource {

    private static final Logger logger = LoggerFactory.getLogger(TPSTokenResource.class);
    private static final int MIN_FILTER_LENGTH = 3;
    private static final int DEFAULT_SIZE = 20;

    @Inject
    TPSEngineQuarkus engineQuarkus;

    @Inject
    SecurityIdentity identity;

    @Context
    UriInfo uriInfo;

    private List<String> getAuthorizedProfiles() {
        return TPSEngineQuarkus.getAuthorizedProfiles(identity);
    }

    private String getUserID() {
        return TPSEngineQuarkus.getUserID(identity);
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response findTokens(
            @QueryParam("filter") String filter,
            @QueryParam("tokenID") String tokenID,
            @QueryParam("userID") String userID,
            @QueryParam("type") String type,
            @QueryParam("status") String status,
            @QueryParam("start") @DefaultValue("0") int start,
            @QueryParam("size") @DefaultValue("20") int size) throws Exception {

        TPSSubsystem subsystem = engineQuarkus.getSubsystem();
        TokenDatabase database = subsystem.getTokenDatabase();
        List<String> authorizedProfiles = getAuthorizedProfiles();
        if (authorizedProfiles.isEmpty()) {
            throw new UnauthorizedException("User not authorized");
        }

        if (filter != null && filter.length() < MIN_FILTER_LENGTH) {
            throw new BadRequestException("Filter is too short.");
        }

        Map<String, String> attributes = new HashMap<>();
        if (StringUtils.isNotEmpty(tokenID)) attributes.put("id", tokenID);
        if (StringUtils.isNotEmpty(userID)) attributes.put("userID", userID);
        if (StringUtils.isNotEmpty(type)) attributes.put("type", type);
        if (StringUtils.isNotEmpty(status)) attributes.put("status", status);

        TokenCollection tokens = retrieveTokens(database, authorizedProfiles,
                filter, attributes, start, size, Locale.getDefault());
        return Response.ok(tokens.toJSON()).build();
    }

    @GET
    @Path("{tokenId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getToken(@PathParam("tokenId") String tokenId) throws Exception {
        String method = "TPSTokenResource.getToken:";
        TPSSubsystem subsystem = engineQuarkus.getSubsystem();
        TokenDatabase database = subsystem.getTokenDatabase();
        List<String> authorizedProfiles = getAuthorizedProfiles();
        if (authorizedProfiles.isEmpty()) {
            throw new UnauthorizedException(method + " User not authorized");
        }

        TokenRecord trec;
        try {
            trec = database.getRecord(tokenId);
        } catch (DBException e) {
            Throwable t = e.getCause();
            if (t instanceof LDAPException ldape) {
                throw LDAPExceptionConverter.toPKIException(ldape);
            }
            throw new PKIException(e);
        }
        if (trec == null) {
            throw new PKIException(method + " Token record not found");
        }

        String type = trec.getType();
        if ((type == null) || type.isEmpty() ||
                authorizedProfiles.contains(UserResource.ALL_PROFILES) ||
                authorizedProfiles.contains(type)) {
            try {
                TokenData tData = createTokenData(trec, Locale.getDefault());
                return Response.ok(tData.toJSON()).build();
            } catch (MalformedURLException | TPSException e) {
                throw new PKIException(e);
            }
        }
        throw new UnauthorizedException(method + " Token record restricted");
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response addToken(String requestData) throws Exception {
        String method = "TPSTokenResource.addToken:";
        TokenData tokenData = JSONSerializer.fromJSON(requestData, TokenData.class);
        if (tokenData == null) {
            BadRequestException ex = new BadRequestException(method + "Missing token data");
            engineQuarkus.auditConfigTokenGeneral(ILogger.FAILURE, method, null, ex.toString(), getUserID());
            throw ex;
        }

        String tokenID = tokenData.getTokenID();
        Map<String, String> auditModParams = new HashMap<>();
        auditModParams.put("tokenID", tokenID);

        String remoteUser = getUserID();

        TPSEngine engine = engineQuarkus.getEngine();
        TPSSubsystem subsystem = engineQuarkus.getSubsystem();
        TokenRecord tokenRecord = null;
        String msg = "add token";

        try {
            TokenDatabase database = subsystem.getTokenDatabase();
            tokenRecord = new TokenRecord();
            tokenRecord.setId(tokenID);

            String uid = tokenData.getUserID();
            if (StringUtils.isNotEmpty(uid)) {
                tokenRecord.setUserID(uid);
                auditModParams.put("userID", uid);
            }

            String policy = tokenData.getPolicy();
            if (StringUtils.isNotEmpty(policy)) {
                tokenRecord.setPolicy(policy);
                auditModParams.put("Policy", policy);
            }

            tokenRecord.setTokenStatus(TokenStatus.UNFORMATTED);
            auditModParams.put("Status", TokenStatus.UNFORMATTED.toString());

            database.addRecord(tokenID, tokenRecord);
            subsystem.tdb.tdbActivity(ActivityDatabase.OP_ADD, tokenRecord,
                    "", msg, "success", remoteUser);

            TokenData newTokenData = createTokenData(database.getRecord(tokenID), Locale.getDefault());
            engineQuarkus.auditConfigTokenRecord(ILogger.SUCCESS, method, tokenID, auditModParams, null, remoteUser);

            String encodedTokenID = URLEncoder.encode(tokenID, "UTF-8");
            java.net.URI location = uriInfo.getAbsolutePathBuilder().path(encodedTokenID).build();
            return Response.created(location).entity(newTokenData.toJSON()).build();

        } catch (Exception e) {
            msg = msg + ": " + e.getMessage();
            logger.error(msg, e);
            subsystem.tdb.tdbActivity(ActivityDatabase.OP_ADD, tokenRecord, "", msg, "failure", remoteUser);
            handleException(e, method, tokenID, auditModParams, remoteUser);
            throw new PKIException(e);
        }
    }

    @POST
    @Path("{tokenId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response changeTokenStatus(
            @PathParam("tokenId") String tokenId,
            @QueryParam("status") String status) throws Exception {
        String method = "TPSTokenResource.changeTokenStatus:";
        if (StringUtils.isBlank(status)) {
            throw new BadRequestException(method + " New status not provided");
        }

        TokenStatus tStatus = TokenStatus.valueOf(status);
        if (tokenId == null) {
            engineQuarkus.auditConfigTokenGeneral(ILogger.FAILURE, method, null, "Missing token ID", getUserID());
            throw new BadRequestException(method + "Missing token ID");
        }

        TPSEngine engine = engineQuarkus.getEngine();
        TPSSubsystem subsystem = engineQuarkus.getSubsystem();
        TPSEngineConfig config = engine.getConfig();

        Map<String, String> auditModParams = new HashMap<>();
        auditModParams.put("tokenID", tokenId);
        auditModParams.put("tokenStatus", tStatus.toString());

        String remoteUser = getUserID();
        TokenStatus oldStatus = null;
        String oldReason = null;
        TokenStatus newStatus = tStatus;
        String newReason = null;
        TokenRecord tokenRecord = null;
        String msg = "change token status";

        try {
            List<String> authorizedProfiles = getAuthorizedProfiles();
            if (authorizedProfiles == null || authorizedProfiles.isEmpty()) {
                throw new PKIException(method + "authorizedProfiles null");
            }

            TokenDatabase database = subsystem.getTokenDatabase();
            tokenRecord = database.getRecord(tokenId);
            if (tokenRecord == null) {
                throw new PKIException(method + "Token record not found");
            }

            String type = tokenRecord.getType();
            if ((type != null) && !type.isEmpty() &&
                    !authorizedProfiles.contains(UserResource.ALL_PROFILES) &&
                    !authorizedProfiles.contains(type)) {
                throw new PKIException("token record restricted");
            }

            TokenStatus currentTokenStatus = tokenRecord.getTokenStatus();
            oldStatus = currentTokenStatus;
            oldReason = tokenRecord.getReason();

            if (currentTokenStatus == tStatus) {
                return Response.ok(createTokenData(tokenRecord, Locale.getDefault()).toJSON()).build();
            }

            msg = msg + " from " + currentTokenStatus + " to " + tStatus;

            if (!oldStatus.isValid()) {
                Exception ex = new BadRequestException("Cannot change status of token with current status: " + oldStatus);
                engineQuarkus.auditTokenStateChange(ILogger.FAILURE, oldStatus, newStatus, oldReason, newReason, auditModParams, ex.toString(), remoteUser);
                throw ex;
            }

            if (!subsystem.isUITransitionAllowed(tokenRecord, tStatus)) {
                Exception ex = new BadRequestException("Invalid token status transition");
                engineQuarkus.auditTokenStateChange(ILogger.FAILURE, oldStatus, newStatus, oldReason, newReason, auditModParams, ex.toString(), remoteUser);
                throw ex;
            }

            // Apply state-specific actions
            auditModParams.put("UserID", tokenRecord.getUserID());
            boolean clearOnUnformatUserID = config.getBoolean(TPSEngine.CFG_TOKENSERVICE_UNFORMATTED_CLEAR_USERID, true);
            boolean clearOnUnformatType = config.getBoolean(TPSEngine.CFG_TOKENSERVICE_UNFORMATTED_CLEAR_TYPE, true);
            boolean clearOnUnformatAppletID = config.getBoolean(TPSEngine.CFG_TOKENSERVICE_UNFORMATTED_CLEAR_APPLETID, true);
            boolean clearOnUnformatKeyInfo = config.getBoolean(TPSEngine.CFG_TOKENSERVICE_UNFORMATTED_CLEAR_KEYINFO, true);
            boolean clearOnUnformatPolicy = config.getBoolean(TPSEngine.CFG_TOKENSERVICE_UNFORMATTED_CLEAR_POLICY, true);

            switch (tStatus.getValue()) {
            case TokenStatus.TOKEN_UNFORMATTED:
                if (clearOnUnformatUserID) tokenRecord.setUserID(null);
                if (clearOnUnformatType) tokenRecord.setType(null);
                if (clearOnUnformatAppletID) tokenRecord.setAppletID(null);
                if (clearOnUnformatKeyInfo) tokenRecord.setKeyInfo(null);
                if (clearOnUnformatPolicy) tokenRecord.setPolicy(null);
                tokenRecord.setTokenStatus(tStatus);
                tokenRecord.setReason(null);
                break;
            case TokenStatus.TOKEN_FORMATTED:
                tokenRecord.setTokenStatus(tStatus);
                tokenRecord.setReason(null);
                break;
            case TokenStatus.TOKEN_ACTIVE:
                if (tokenRecord.getTokenStatus() == TokenStatus.SUSPENDED) {
                    subsystem.tdb.unRevokeCertsByCUID(tokenRecord.getId(), "", remoteUser);
                }
                tokenRecord.setTokenStatus(tStatus);
                tokenRecord.setReason(null);
                break;
            case TokenStatus.TOKEN_PERM_LOST:
            case TokenStatus.TOKEN_TEMP_LOST_PERM_LOST:
                tokenRecord.setTokenStatus(tStatus);
                tokenRecord.setReason("keyCompromise");
                newReason = "keyCompromise";
                subsystem.tdb.revokeCertsByCUID(tokenRecord.getId(), "keyCompromise", "", remoteUser);
                break;
            case TokenStatus.TOKEN_DAMAGED:
                tokenRecord.setTokenStatus(tStatus);
                tokenRecord.setReason("destroyed");
                newReason = "destroyed";
                subsystem.tdb.revokeCertsByCUID(tokenRecord.getId(), "destroyed", "", remoteUser);
                break;
            case TokenStatus.TOKEN_SUSPENDED:
                tokenRecord.setTokenStatus(tStatus);
                tokenRecord.setReason("onHold");
                newReason = "onHold";
                subsystem.tdb.revokeCertsByCUID(tokenRecord.getId(), "onHold", "", remoteUser);
                break;
            case TokenStatus.TOKEN_TERMINATED:
                tokenRecord.setTokenStatus(tStatus);
                tokenRecord.setReason("terminated");
                newReason = "terminated";
                subsystem.tdb.revokeCertsByCUID(tokenRecord.getId(), "terminated", "", remoteUser);
                break;
            default:
                PKIException pe = new PKIException("Unsupported token state: " + tStatus);
                engineQuarkus.auditTokenStateChange(ILogger.FAILURE, oldStatus, newStatus, oldReason, newReason, auditModParams, pe.toString(), remoteUser);
                throw pe;
            }

            engineQuarkus.auditTokenStateChange(ILogger.SUCCESS, oldStatus, newStatus, oldReason, newReason, auditModParams, null, remoteUser);
            database.updateRecord(tokenId, tokenRecord);
            subsystem.tdb.tdbActivity(ActivityDatabase.OP_TOKEN_STATUS_CHANGE, tokenRecord, "", msg, "success", remoteUser);
            return Response.ok(createTokenData(database.getRecord(tokenId), Locale.getDefault()).toJSON()).build();

        } catch (Exception e) {
            msg = msg + ": " + e.getMessage();
            logger.error(msg, e);
            subsystem.tdb.tdbActivity(ActivityDatabase.OP_TOKEN_STATUS_CHANGE, tokenRecord, "", msg, "failure", remoteUser);

            if (e instanceof DBException) {
                Throwable t = e.getCause();
                if (t instanceof LDAPException ldape) {
                    PKIException ex = LDAPExceptionConverter.toPKIException(ldape);
                    engineQuarkus.auditTokenStateChange(ILogger.FAILURE, oldStatus, newStatus, oldReason, newReason, auditModParams, ex.toString(), remoteUser);
                    throw ex;
                }
            }
            if (e instanceof PKIException pkie) {
                engineQuarkus.auditTokenStateChange(ILogger.FAILURE, oldStatus, newStatus, oldReason, newReason, auditModParams, pkie.toString(), remoteUser);
                throw pkie;
            }
            engineQuarkus.auditTokenStateChange(ILogger.FAILURE, oldStatus, newStatus, oldReason, newReason, auditModParams, e.toString(), remoteUser);
            throw new PKIException(e);
        }
    }

    @PUT
    @Path("{tokenId}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response replaceToken(@PathParam("tokenId") String tokenId, String requestData) throws Exception {
        String method = "TPSTokenResource.replaceToken:";
        TokenData tokenData = JSONSerializer.fromJSON(requestData, TokenData.class);
        Map<String, String> auditModParams = new HashMap<>();

        if (tokenId == null) {
            engineQuarkus.auditConfigTokenGeneral(ILogger.FAILURE, method, null, "Missing token ID", getUserID());
            throw new BadRequestException(method + "Missing token ID");
        }
        if (tokenData == null) {
            engineQuarkus.auditConfigTokenGeneral(ILogger.FAILURE, method, auditModParams, "Missing token data", getUserID());
            throw new BadRequestException("Missing token data");
        }

        String remoteUser = getUserID();
        TPSSubsystem subsystem = engineQuarkus.getSubsystem();
        TokenRecord tokenRecord = null;
        String msg = "replace token";

        try {
            List<String> authorizedProfiles = getAuthorizedProfiles();
            TokenDatabase database = subsystem.getTokenDatabase();
            tokenRecord = database.getRecord(tokenId);
            if (tokenRecord == null) throw new PKIException(method + "Token record not found");

            String type = tokenRecord.getType();
            if ((type != null) && !type.isEmpty() &&
                    !authorizedProfiles.contains(UserResource.ALL_PROFILES) &&
                    !authorizedProfiles.contains(type)) {
                throw new PKIException(method + "Token record restricted");
            }

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
            database.updateRecord(tokenId, tokenRecord);
            subsystem.tdb.tdbActivity(ActivityDatabase.OP_TOKEN_MODIFY, tokenRecord, "", msg, "success", remoteUser);

            TokenData result = createTokenData(database.getRecord(tokenId), Locale.getDefault());
            engineQuarkus.auditConfigTokenRecord(ILogger.SUCCESS, method, tokenId, auditModParams, null, remoteUser);
            return Response.ok(result.toJSON()).build();
        } catch (Exception e) {
            msg = msg + ": " + e.getMessage();
            logger.error(msg, e);
            subsystem.tdb.tdbActivity(ActivityDatabase.OP_TOKEN_MODIFY, tokenRecord, "", msg, "failure", remoteUser);
            handleException(e, method, tokenId, auditModParams, remoteUser);
            throw new PKIException(e);
        }
    }

    @PATCH
    @Path("{tokenId}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response modifyToken(@PathParam("tokenId") String tokenId, String requestData) throws Exception {
        String method = "TPSTokenResource.modifyToken:";
        TokenData tokenData = JSONSerializer.fromJSON(requestData, TokenData.class);
        Map<String, String> auditModParams = new HashMap<>();

        if (tokenId == null) {
            BadRequestException e = new BadRequestException(method + "Missing token ID");
            engineQuarkus.auditConfigTokenRecord(ILogger.FAILURE, "modify", tokenId, auditModParams, e.toString(), getUserID());
            throw e;
        }
        if (tokenData == null) {
            BadRequestException e = new BadRequestException("Missing token data");
            engineQuarkus.auditConfigTokenRecord(ILogger.FAILURE, "modify", tokenId, auditModParams, e.toString(), getUserID());
            throw e;
        }

        String remoteUser = getUserID();
        TPSSubsystem subsystem = engineQuarkus.getSubsystem();
        TokenRecord tokenRecord = null;
        String msg = "modify token";

        try {
            List<String> authorizedProfiles = getAuthorizedProfiles();
            TokenDatabase database = subsystem.getTokenDatabase();
            tokenRecord = database.getRecord(tokenId);
            if (tokenRecord == null) throw new PKIException(method + "Token record not found");

            String type = tokenRecord.getType();
            if ((type != null) && !type.isEmpty() &&
                    !authorizedProfiles.contains(UserResource.ALL_PROFILES) &&
                    !authorizedProfiles.contains(type)) {
                throw new PKIException("token record restricted");
            }

            String userID = tokenData.getUserID();
            if (userID != null) {
                if (userID.isEmpty()) {
                    tokenRecord.setUserID(null);
                } else {
                    tokenRecord.setUserID(userID);
                    auditModParams.put("userID", userID);
                }
            }

            String policy = tokenData.getPolicy();
            if (policy != null) {
                if (policy.isEmpty()) {
                    tokenRecord.setPolicy(null);
                } else {
                    tokenRecord.setPolicy(policy);
                    auditModParams.put("Policy", policy);
                }
            }

            database.updateRecord(tokenId, tokenRecord);
            subsystem.tdb.tdbActivity(ActivityDatabase.OP_TOKEN_MODIFY, tokenRecord, "", msg, "success", remoteUser);

            TokenData result = createTokenData(database.getRecord(tokenId), Locale.getDefault());
            engineQuarkus.auditConfigTokenRecord(ILogger.SUCCESS, method, tokenId, auditModParams, null, remoteUser);
            return Response.ok(result.toJSON()).build();
        } catch (Exception e) {
            msg = msg + ": " + e.getMessage();
            logger.error(msg, e);
            subsystem.tdb.tdbActivity(ActivityDatabase.OP_TOKEN_MODIFY, tokenRecord, "", msg, "failure", remoteUser);
            handleException(e, method, tokenId, auditModParams, remoteUser);
            throw new PKIException(e);
        }
    }

    @DELETE
    @Path("{tokenId}")
    public Response removeToken(@PathParam("tokenId") String tokenId) throws Exception {
        String method = "TPSTokenResource.removeToken:";
        Map<String, String> auditModParams = new HashMap<>();

        if (tokenId == null) {
            BadRequestException ex = new BadRequestException(method + "Missing token ID");
            engineQuarkus.auditConfigTokenRecord(ILogger.FAILURE, method, tokenId, auditModParams, ex.toString(), getUserID());
            throw ex;
        }

        String remoteUser = getUserID();
        TPSSubsystem subsystem = engineQuarkus.getSubsystem();
        TokenRecord tokenRecord = null;
        String msg = "remove token";

        try {
            List<String> authorizedProfiles = getAuthorizedProfiles();
            TokenDatabase database = subsystem.getTokenDatabase();
            tokenRecord = database.getRecord(tokenId);
            if (tokenRecord == null) throw new PKIException(method + "Token record not found");

            String type = tokenRecord.getType();
            if ((type != null) && !type.isEmpty() &&
                    !authorizedProfiles.contains(UserResource.ALL_PROFILES) &&
                    !authorizedProfiles.contains(type)) {
                throw new PKIException(method + "Token record restricted");
            }

            subsystem.tdb.tdbRemoveCertificatesByCUID(tokenRecord.getId());
            database.removeRecord(tokenId);
            engineQuarkus.auditConfigTokenRecord(ILogger.SUCCESS, method, tokenId, auditModParams, null, remoteUser);
            subsystem.tdb.tdbActivity(ActivityDatabase.OP_DELETE, tokenRecord, "", msg, "success", remoteUser);
            return Response.noContent().build();
        } catch (Exception e) {
            msg = msg + ": " + e.getMessage();
            logger.error(msg, e);
            subsystem.tdb.tdbActivity(ActivityDatabase.OP_DELETE, tokenRecord, "", msg, "failure", remoteUser);
            handleException(e, method, tokenId, auditModParams, remoteUser);
            throw new PKIException(e);
        }
    }

    // Helper methods

    private TokenCollection retrieveTokens(TokenDatabase database, List<String> authorizedProfiles,
            String filter, Map<String, String> attributes, int start, int size, Locale loc) throws Exception {

        TokenCollection tokens = new TokenCollection();
        List<TokenRecord> tokenList = (List<TokenRecord>) database.findRecords(
                filter, attributes, null, start, size);

        if (authorizedProfiles.contains(UserResource.ALL_PROFILES)) {
            for (TokenRecord tRec : tokenList) {
                tokens.addEntry(createTokenData(tRec, loc));
            }
        } else {
            for (TokenRecord tRec : tokenList) {
                String type = tRec.getType();
                if ((type == null) || type.isEmpty() || authorizedProfiles.contains(type)) {
                    tokens.addEntry(createTokenData(tRec, loc));
                } else {
                    tokens.addEntry(createRestrictedTokenData());
                }
            }
        }
        tokens.setTotal(tokenList.size());
        return tokens;
    }

    private TokenData createTokenData(TokenRecord tokenRecord, Locale loc) throws MalformedURLException, TPSException {
        TPSSubsystem subsystem = engineQuarkus.getSubsystem();
        ResourceBundle labels;
        try {
            labels = ResourceBundle.getBundle("token-states", loc);
        } catch (MissingResourceException e) {
            labels = null;
        }

        TokenData tokenData = new TokenData();
        tokenData.setID(tokenRecord.getId());
        tokenData.setTokenID(tokenRecord.getId());
        tokenData.setUserID(tokenRecord.getUserID());
        tokenData.setType(tokenRecord.getType());

        TokenStatus status = tokenRecord.getTokenStatus();
        TokenStatusData statusData = new TokenStatusData();
        statusData.name = status;
        try {
            statusData.label = labels != null ? labels.getString(status.toString()) : status.toString();
        } catch (MissingResourceException e) {
            statusData.label = status.toString();
        }
        tokenData.setStatus(statusData);

        Collection<TokenStatus> nextStates = subsystem.getUINextTokenStates(tokenRecord);
        if (nextStates != null) {
            Collection<TokenStatusData> nextStatesData = new ArrayList<>();
            for (TokenStatus nextState : nextStates) {
                TokenStatusData nextStateData = new TokenStatusData();
                nextStateData.name = nextState;
                try {
                    nextStateData.label = labels != null ? labels.getString(status + "." + nextState) : nextState.toString();
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
        return tokenData;
    }

    private TokenData createRestrictedTokenData() {
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

    private void handleException(Exception e, String method, String tokenID,
            Map<String, String> auditModParams, String remoteUser) {
        if (e instanceof DBException) {
            Throwable t = e.getCause();
            if (t instanceof LDAPException ldape) {
                PKIException ex = LDAPExceptionConverter.toPKIException(ldape);
                engineQuarkus.auditConfigTokenRecord(ILogger.FAILURE, method, tokenID, auditModParams, ex.toString(), remoteUser);
                throw ex;
            }
        }
        if (e instanceof PKIException pkie) {
            engineQuarkus.auditConfigTokenRecord(ILogger.FAILURE, method, tokenID, auditModParams, e.toString(), remoteUser);
            throw pkie;
        }
        engineQuarkus.auditConfigTokenRecord(ILogger.FAILURE, method, tokenID, auditModParams, e.toString(), remoteUser);
    }
}
