//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.rest.v2;

import java.io.PrintWriter;
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
import java.util.Objects;
import java.util.ResourceBundle;
import java.util.stream.Collectors;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

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

import com.netscape.certsrv.base.BadRequestDataException;
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

import netscape.ldap.LDAPException;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "token",
        urlPatterns = "/v2/tokens/*")
public class TokenServlet extends TPSServlet {
    private static final long serialVersionUID = 1L;
    private static final Logger logger = LoggerFactory.getLogger(TokenServlet.class);

    @Override
    public void get(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String method = "TokenServlet.get:";
        TPSSubsystem subsystem = getTPSSubsystem();
        TokenDatabase database = subsystem.getTokenDatabase();
        List<String> authorizedProfiles = getAuthorizedProfiles(request);
        if (authorizedProfiles.isEmpty()) {
            throw new UnauthorizedException(method + " User not authorized");
        }

        PrintWriter out = response.getWriter();

        if (request.getPathInfo() != null) {
            String id = request.getPathInfo().substring(1);
            if(id.isBlank()) {
                throw new BadRequestException(method + " tokenID is empty");
            }
            logger.debug("{} (\"{}\")", method, id);

            TokenRecord trec;
            try {
                trec = database.getRecord(id);
            } catch (DBException e) {
                Throwable t = e.getCause();
                if (t instanceof LDAPException ldape) {
                    throw LDAPExceptionConverter.toPKIException(ldape);
                }
                throw new PKIException(e);
            }
            if (trec == null) {
                logger.debug("{} Token record not found", method);
                throw new PKIException(method + " Token record not found");
            }
            String type = trec.getType();
            if ((type == null) || type.isEmpty() ||
                    authorizedProfiles.contains(UserResource.ALL_PROFILES) ||
                    authorizedProfiles.contains(type)) {
                try {
                    TokenData tData = createTokenData(trec, request.getLocale());
                    out.println(tData.toJSON());
                    return;
                } catch (MalformedURLException | TPSException e) {
                    throw new PKIException(e);                }
            }
            throw new UnauthorizedException(method + " Token record restricted");
        }

        String filter = request.getParameter("filter");
        if (filter != null && filter.length() < MIN_FILTER_LENGTH) {
            throw new BadRequestException("Filter is too short.");
        }
        Map<String, String> attributes = new HashMap<>();
        String tokenID = request.getParameter("tokenID");
        if (StringUtils.isNotEmpty(tokenID)) {
            attributes.put("id", tokenID);
        }
        String userID = request.getParameter("userID");
        if (StringUtils.isNotEmpty(userID)) {
            attributes.put("userID", userID);
        }
        String type = request.getParameter("type");
        if (StringUtils.isNotEmpty(type)) {
            attributes.put("type", type);
        }
        String status = request.getParameter("status");
        if (StringUtils.isNotEmpty(status)) {
            attributes.put("status", status);
        }

        int size = request.getParameter("size") == null ?
                DEFAULT_SIZE : Integer.parseInt(request.getParameter("size"));
        int start = request.getParameter("start") == null ? 0 : Integer.parseInt(request.getParameter("start"));
        TokenCollection tokens = retrieveTokens(database, authorizedProfiles, filter, attributes, start, size, request.getLocale());
        out.println(tokens.toJSON());
    }

    @Override
    public void post(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String method = "TokenServlet.post:";
        PrintWriter out = response.getWriter();

        if (request.getPathInfo() != null) {
            String id = request.getPathInfo().substring(1);
            if(id.isBlank()) {
                throw new BadRequestDataException(method + " tokenID is empty");
            }
            String status = request.getParameter("status");
            if (StringUtils.isBlank(status)) {
                throw new BadRequestDataException(method + " New status not provided");
            }
            TokenStatus tStatus = TokenStatus.valueOf(status);
            TokenData token = changeTokenStatus(request, id, tStatus);
            out.println(token.toJSON());
            return;
        }
        String contentType = request.getContentType();
        if (Objects.nonNull(contentType) && !contentType.equals("application/json")) {
            throw new BadRequestDataException(method + " not handling " + contentType);
        }
        String requestData = request.getReader().lines().collect(Collectors.joining());
        TokenData tokenData = JSONSerializer.fromJSON(requestData, TokenData.class);
        TokenData token = addToken(request, tokenData);
        String encodedTokenID = URLEncoder.encode(token.getTokenID(), "UTF-8");
        StringBuffer uri = request.getRequestURL();
        uri.append("/" + encodedTokenID);
        response.setStatus(HttpServletResponse.SC_CREATED);
        response.setHeader("Location", uri.toString());
        out.println(token.toJSON());
    }


    @Override
    public void put(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String method = "TokenServlet.put:";
        PrintWriter out = response.getWriter();

        if (request.getPathInfo() == null) {
            throw new BadRequestDataException(method + " tokenID not provided");
        }
        String id = request.getPathInfo().substring(1);
        if(id.isBlank()) {
            throw new BadRequestDataException(method + " tokenID is empty");
        }
        String contentType = request.getContentType();
        if (Objects.nonNull(contentType) && !contentType.equals("application/json")) {
            throw new BadRequestDataException(method + " not handling " + contentType);
        }
        String requestData = request.getReader().lines().collect(Collectors.joining());
        TokenData tokenData = JSONSerializer.fromJSON(requestData, TokenData.class);
        TokenData token = replaceToken(request, id, tokenData);
        out.println(token.toJSON());
    }

    @Override
    public void patch(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String method = "TokenServlet.patch:";
        PrintWriter out = response.getWriter();

        if (request.getPathInfo() == null) {
            throw new BadRequestDataException(method + " tokenID not provided");
        }
        String id = request.getPathInfo().substring(1);
        if(id.isBlank()) {
            throw new BadRequestDataException(method + " tokenID is empty");
        }
        String contentType = request.getContentType();
        if (Objects.nonNull(contentType) && !contentType.equals("application/json")) {
            throw new BadRequestDataException(method + " not handling " + contentType);
        }
        String requestData = request.getReader().lines().collect(Collectors.joining());
        TokenData tokenData = JSONSerializer.fromJSON(requestData, TokenData.class);
        TokenData token = modifyToken(request, id, tokenData);
        out.println(token.toJSON());
    }

    @Override
    public void delete(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String method = "TokenServlet.delete:";
        if (request.getPathInfo() == null) {
            throw new BadRequestDataException(method + " tokenID not provided");
        }
        String id = request.getPathInfo().substring(1);
        if(id.isBlank()) {
            throw new BadRequestDataException(method + " tokenID is empty");
        }
        removeToken(request, id);
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    private TokenCollection retrieveTokens(
            TokenDatabase database,
            List<String> authorizedProfiles,
            String filter,
            Map<String, String> attributes,
            int start, int size,
            Locale loc) throws Exception {

        String method = "ActivityServlet.retrieveActivities:";
        logger.debug(method);
        TokenCollection tokens = new TokenCollection();

        List<TokenRecord> tokenList = (List<TokenRecord>) database.findRecords(
                filter, attributes, null, start, size);

        if (authorizedProfiles.contains(UserResource.ALL_PROFILES)) {
            for (TokenRecord tRec: tokenList) {
                tokens.addEntry(createTokenData(tRec, loc));
            }
        } else { // not authorized for all profiles
            for (TokenRecord tRec: tokenList) {
                logger.debug("{} record.Id= {}", method, tRec.getId());
                String type = tRec.getType();
                logger.debug("{} type={}", method, type);
                if ((type == null) || type.isEmpty() || authorizedProfiles.contains(type)) {
                    logger.debug("{} token type allowed", method);
                    tokens.addEntry(createTokenData(tRec, loc));
                } else {
                    logger.debug("{} token type restricted; adding 'restricted' record", method);
                    tokens.addEntry(createRestrictedTokenData());
                }
            } //for
        }
        tokens.setTotal(tokenList.size());
        return tokens;
    }


    private TokenData createTokenData(TokenRecord tokenRecord, Locale loc) throws MalformedURLException, TPSException {

        TPSSubsystem subsystem = getTPSSubsystem();

        ResourceBundle labels = getResourceBundle("token-states", loc);

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

        return tokenData;
    }

    /*
     * <restricted> records are records not permitted to be accessed
     * by the user per profile restrictions;  They are shown
     * on display when searched
     */
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

    private TokenData addToken(HttpServletRequest request, TokenData tokenData) {
        String method = "TokenServlet.addToken:";
        if (tokenData == null) {
            BadRequestException ex = new BadRequestException(method + "Missing token data");
            auditConfigTokenGeneral(ILogger.FAILURE, method, null,
                    ex.toString());
            throw ex;
        }
        logger.info("{} {}", method, tokenData.getTokenID());

        Map<String, String> auditModParams = new HashMap<>();


        String tokenID = tokenData.getTokenID();
        logger.info("{} Token ID: {}", method, tokenID);

        auditModParams.put("tokenID", tokenID);

        String remoteUser = request.getRemoteUser();
        String ipAddress = request.getRemoteAddr();

        TPSEngine engine = TPSEngine.getInstance();
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
            TokenData newTokenData = createTokenData(database.getRecord(tokenID), request.getLocale());
            auditConfigTokenRecord(ILogger.SUCCESS, method, tokenID,
                    auditModParams, null);

            return newTokenData;

        } catch (Exception e) {

            msg = msg + ": " + e.getMessage();
            logger.error(msg, e);

            subsystem.tdb.tdbActivity(ActivityDatabase.OP_ADD, tokenRecord,
                    ipAddress, msg, "failure", remoteUser);

            if (e instanceof DBException) {
                Throwable t = e.getCause();
                if (t instanceof LDAPException ldape) {
                    PKIException ex = LDAPExceptionConverter.toPKIException(ldape);
                    auditConfigTokenRecord(ILogger.FAILURE, method, tokenID,
                            auditModParams, ex.toString());
                    throw ex;
                }
            }

            if (e instanceof PKIException pkie) {
                auditConfigTokenRecord(ILogger.FAILURE, method, tokenID,
                        auditModParams, e.toString());
                throw pkie;
            }

            auditConfigTokenRecord(ILogger.FAILURE, method, tokenID,
                    auditModParams, e.toString());
            throw new PKIException(e);
        }
    }

    private TokenData changeTokenStatus(HttpServletRequest request, String tokenID, TokenStatus tokenStatus) {

        String method = "TokenServlet.changeTokenStatus:";
        logger.debug("{} begins: with tokenStatus={}", method, tokenStatus);
        if (tokenID == null) {
            auditConfigTokenGeneral(ILogger.FAILURE, method, null, "Missing token ID");
            throw new BadRequestException(method + "Missing token ID");
        }


        TPSEngine engine = TPSEngine.getInstance();
        TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);

        if (tokenStatus == null) {
            auditConfigTokenGeneral(ILogger.FAILURE, method, null, "Missing token status");
            throw new BadRequestException("Missing token status");
        }

        Map<String, String> auditModParams = new HashMap<>();
        auditModParams.put("tokenID", tokenID);
        auditModParams.put("tokenStatus", tokenStatus.toString());

        String remoteUser = request.getRemoteUser();
        String ipAddress = request.getRemoteAddr();

        // for auditing
        TokenStatus oldStatus = null;
        String oldReason = null;
        TokenStatus newStatus = null;
        String newReason = null;

        TokenRecord tokenRecord = null;
        String msg = "change token status";
        try {
            List<String> authorizedProfiles = getAuthorizedProfiles(request);
            if (authorizedProfiles == null) {
                msg = "authorizedProfiles null";
                logger.debug("{} {}", method, msg);
                throw new PKIException(method + msg);
            }

            TokenDatabase database = subsystem.getTokenDatabase();
            database = subsystem.getTokenDatabase();
            tokenRecord = database.getRecord(tokenID);
            if (tokenRecord == null) {
                logger.debug("{} Token record not found", method);
                throw new PKIException(method + "Token record not found");
            }
            String type = tokenRecord.getType();
            if ((type != null) && !type.isEmpty() && !authorizedProfiles.contains(UserResource.ALL_PROFILES) && !authorizedProfiles.contains(type)) {
                logger.debug("{} token record restricted: {}", method, type);

                throw new PKIException("token record restricted");
            }
            TokenStatus currentTokenStatus = tokenRecord.getTokenStatus();
            logger.debug("{} current status: {}", method, currentTokenStatus);

            oldStatus = tokenRecord.getTokenStatus();
            oldReason = tokenRecord.getReason();
            newStatus = tokenStatus;

            if (currentTokenStatus == tokenStatus) {
                logger.debug("{} no status change, no activity log generated", method);

                return createTokenData(tokenRecord, request.getLocale());
            }

            msg = msg + " from " + currentTokenStatus + " to " + tokenStatus;
            logger.debug("{} {}", method, msg);

            // Check for invalid current status
            if(!oldStatus.isValid()) {
                logger.debug("{} current status is invalid: {}", method, oldStatus);
                Exception ex = new BadRequestException("Cannot change status of token with current status: " + oldStatus);
                auditTokenStateChange(ILogger.FAILURE, oldStatus,
                        newStatus, oldReason, newReason,
                        auditModParams, ex.toString());
                throw ex;
            }

            // make sure transition is allowed
            if (!subsystem.isUITransitionAllowed(tokenRecord, tokenStatus)) {
                logger.error("{} next status not allowed: {}", method, tokenStatus);
                Exception ex = new BadRequestException("Invalid token status transition");
                auditTokenStateChange(ILogger.FAILURE, oldStatus,
                        newStatus, oldReason, newReason,
                        auditModParams, ex.toString());
                throw ex;
            }

            logger.debug("{} next status allowed: {}", method, tokenStatus);
            // audit in setTokenStatus()
            setTokenStatus(authorizedProfiles, tokenRecord, tokenStatus, ipAddress, remoteUser, auditModParams);
            database.updateRecord(tokenID, tokenRecord);
            subsystem.tdb.tdbActivity(ActivityDatabase.OP_TOKEN_STATUS_CHANGE, tokenRecord,
                    ipAddress, msg, "success",
                    remoteUser);

            return createTokenData(database.getRecord(tokenID), request.getLocale());
        } catch (Exception e) {

            msg = msg + ": " + e.getMessage();
            logger.error(msg, e);

            subsystem.tdb.tdbActivity(ActivityDatabase.OP_TOKEN_STATUS_CHANGE, tokenRecord,
                    ipAddress, msg, "failure",
                    remoteUser);

            if (e instanceof DBException) {
                Throwable t = e.getCause();
                if (t instanceof LDAPException ldape) {
                    PKIException ex = LDAPExceptionConverter.toPKIException(ldape);
                    auditTokenStateChange(ILogger.FAILURE, oldStatus,
                            newStatus, oldReason, newReason,
                            auditModParams, ex.toString());
                    throw ex;
                }
            }

            if (e instanceof PKIException pkie) {
                auditTokenStateChange(ILogger.FAILURE, oldStatus,
                        newStatus, oldReason, newReason,
                        auditModParams, pkie.toString());
                throw pkie;
            }

            auditTokenStateChange(ILogger.FAILURE, oldStatus,
                    newStatus, oldReason, newReason,
                    auditModParams, e.toString());
            throw new PKIException(e);
        }
    }

    private void setTokenStatus(List<String> authorizedProfiles, TokenRecord tokenRecord, TokenStatus tokenState, String ipAddress, String remoteUser,
            Map<String, String> auditModParams)
                    throws Exception {

        String method = "TokenServlet.setTokenStatus: ";
        String msg = "";

        if (authorizedProfiles == null) {
            msg = "authorizedProfiles null";
            logger.debug(method + msg);
            throw new PKIException(method + msg);
        }
        String type = tokenRecord.getType();
        // if token not associated with any keyType/profile, disallow access,
        // unless the user has the "ALL_PROFILES" privilege
        if (!authorizedProfiles.contains(UserResource.ALL_PROFILES) &&
                (((type == null) || type.isEmpty()) || !authorizedProfiles.contains(type))) {
               throw new PKIException(method + "Token record restricted");
        }

        TPSEngine engine = getTPSEngine();
        TPSEngineConfig config = engine.getConfig();

        TPSSubsystem tps = getTPSSubsystem();

        TokenStatus oldStatus = tokenRecord.getTokenStatus();
        String oldReason = tokenRecord.getReason();
        TokenStatus newStatus = tokenState;
        String newReason = null;

        boolean clearOnUnformatUserID = config.getBoolean(TPSEngine.CFG_TOKENSERVICE_UNFORMATTED_CLEAR_USERID, true);
        boolean clearOnUnformatType = config.getBoolean(TPSEngine.CFG_TOKENSERVICE_UNFORMATTED_CLEAR_TYPE, true);
        boolean clearOnUnformatAppletID = config.getBoolean(TPSEngine.CFG_TOKENSERVICE_UNFORMATTED_CLEAR_APPLETID, true);
        boolean clearOnUnformatKeyInfo = config.getBoolean(TPSEngine.CFG_TOKENSERVICE_UNFORMATTED_CLEAR_KEYINFO, true);
        boolean clearOnUnformatPolicy = config.getBoolean(TPSEngine.CFG_TOKENSERVICE_UNFORMATTED_CLEAR_POLICY, true);

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

        case TokenStatus.TOKEN_PERM_LOST, TokenStatus.TOKEN_TEMP_LOST_PERM_LOST:
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

    private TokenData replaceToken(HttpServletRequest request, String tokenID, TokenData tokenData) {

        String method = "TokenServlet.replaceToken:";
        logger.info("{} Replacing token {}", method, tokenID);

        Map<String, String> auditModParams = new HashMap<>();

        if (tokenID == null) {
            auditConfigTokenGeneral(ILogger.FAILURE, method, null, "Missing token ID");
            throw new BadRequestException(method + "Missing token ID");
        }

        if (tokenData == null) {
            auditConfigTokenGeneral(ILogger.FAILURE, method, auditModParams, "Missing token data");
            throw new BadRequestException("Missing token data");
        }

        String remoteUser = request.getRemoteUser();
        String ipAddress = request.getRemoteAddr();

        TPSEngine engine = TPSEngine.getInstance();
        TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
        TokenRecord tokenRecord = null;
        String msg = "replace token";
        try {
            List<String> authorizedProfiles = getAuthorizedProfiles(request);
            if (authorizedProfiles == null) {
                msg = "authorizedProfiles null";
                logger.debug("{} {}", method, msg);
                throw new PKIException(method + msg);
            }

            TokenDatabase database = subsystem.getTokenDatabase();

            tokenRecord = database.getRecord(tokenID);

            if (tokenRecord == null) {
                msg = "Token record not found";
                logger.debug("{} {}", method, msg);
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

            tokenData = createTokenData(database.getRecord(tokenID), request.getLocale());
            auditConfigTokenRecord(ILogger.SUCCESS, method, tokenID,
                    auditModParams, null);

            return tokenData;

        } catch (Exception e) {

            msg = msg + ": " + e.getMessage();
            logger.error(msg, e);

            subsystem.tdb.tdbActivity(ActivityDatabase.OP_TOKEN_MODIFY, tokenRecord,
                    ipAddress, msg, "failure",
                    remoteUser);

            if (e instanceof DBException) {
                Throwable t = e.getCause();
                if (t instanceof LDAPException ldape) {
                    PKIException ex = LDAPExceptionConverter.toPKIException(ldape);
                    auditConfigTokenRecord(ILogger.FAILURE, method, tokenID,
                            auditModParams, ex.toString());
                    throw ex;
                }
            }

            if (e instanceof PKIException pkie) {
                auditConfigTokenRecord(ILogger.FAILURE, method, tokenID,
                        auditModParams, e.toString());
                throw pkie;
            }

            auditConfigTokenRecord(ILogger.FAILURE, method, tokenID,
                    auditModParams, e.toString());
            throw new PKIException(e);
        }
    }

    private TokenData modifyToken(HttpServletRequest request, String tokenID, TokenData tokenData) {

        String method = "TokenServlet.modifyToken:";
        logger.info("{} Modifying token {}", method, tokenID);

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

        String remoteUser = request.getRemoteUser();
        String ipAddress = request.getRemoteAddr();

        TPSEngine engine = TPSEngine.getInstance();
        TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
        TokenRecord tokenRecord = null;
        String msg = "modify token";
        try {
            List<String> authorizedProfiles = getAuthorizedProfiles(request);
            if (authorizedProfiles == null) {
                msg = "authorizedProfiles null";
                logger.debug("{} {}", method, msg);
                throw new PKIException(method + msg);
            }

            TokenDatabase database = subsystem.getTokenDatabase();

            // get existing record
            tokenRecord = database.getRecord(tokenID);

            if (tokenRecord == null) {
                logger.debug("{} Token record not found", method);
                throw new PKIException(method + "Token record not found");
            }
            String type = tokenRecord.getType();
            if ((type != null) && !type.isEmpty() && !authorizedProfiles.contains(UserResource.ALL_PROFILES) && !authorizedProfiles.contains(type)) {
                logger.debug("{} token record restricted", method);

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

            tokenData = createTokenData(database.getRecord(tokenID), request.getLocale());
            auditConfigTokenRecord(ILogger.SUCCESS, method, tokenID,
                    auditModParams, null);

            return tokenData;

        } catch (Exception e) {

            msg = msg + ": " + e.getMessage();
            logger.error(msg, e);

            subsystem.tdb.tdbActivity(ActivityDatabase.OP_TOKEN_MODIFY, tokenRecord,
                    ipAddress, msg, "failure",
                    remoteUser);

            if (e instanceof DBException) {
                Throwable t = e.getCause();
                if (t instanceof LDAPException ldape) {
                    PKIException ex = LDAPExceptionConverter.toPKIException(ldape);
                    auditConfigTokenRecord(ILogger.FAILURE, method, tokenID,
                            auditModParams, ex.toString());
                    throw ex;
                }
            }

            if (e instanceof PKIException pkie) {
                auditConfigTokenRecord(ILogger.FAILURE, method, tokenID,
                        auditModParams, e.toString());
                throw pkie;
            }

            auditConfigTokenRecord(ILogger.FAILURE, method, tokenID,
                    auditModParams, e.toString());
            throw new PKIException(e);
        }
    }

    private void removeToken(HttpServletRequest request, String tokenID) {

        String method = "TokenServlet.removeToken:";

        Map<String, String> auditModParams = new HashMap<>();

        if (tokenID == null) {
            BadRequestException ex = new BadRequestException(method + "Missing token ID");
            auditConfigTokenRecord(ILogger.FAILURE, method, tokenID,
                    auditModParams, ex.toString());
            throw ex;
        }
        logger.info("{} Removing token {}", method, tokenID);

        String remoteUser = request.getRemoteUser();
        String ipAddress = request.getRemoteAddr();

        TPSEngine engine = TPSEngine.getInstance();
        TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
        TokenRecord tokenRecord = null;
        String msg = "remove token";
        try {

            List<String> authorizedProfiles = getAuthorizedProfiles(request);
            if (authorizedProfiles == null) {
                msg = "authorizedProfiles null";
                logger.debug("{} {}", method, msg);
                throw new PKIException(method + msg);
            }

            TokenDatabase database = subsystem.getTokenDatabase();
            tokenRecord = database.getRecord(tokenID);
            if (tokenRecord == null) {
                msg = "Token record not found";
                logger.debug("{} {}", method, msg);
                throw new PKIException(method + msg);
            }

            String type = tokenRecord.getType();
            if ((type != null) && !type.isEmpty() && !authorizedProfiles.contains(UserResource.ALL_PROFILES) && !authorizedProfiles.contains(type))
                  throw new PKIException(method + "Token record restricted");

            //delete all certs associated with this token
            logger.debug("{} about to remove all certificates associated with the token first", method);
            subsystem.tdb.tdbRemoveCertificatesByCUID(tokenRecord.getId());

            database.removeRecord(tokenID);
            auditConfigTokenRecord(ILogger.SUCCESS, method, tokenID,
                    auditModParams, null);
            subsystem.tdb.tdbActivity(ActivityDatabase.OP_DELETE, tokenRecord,
                    ipAddress, msg, "success", remoteUser);

        } catch (Exception e) {

            msg = msg + ": " + e.getMessage();
            logger.error(msg, e);

            subsystem.tdb.tdbActivity(ActivityDatabase.OP_DELETE, tokenRecord,
                    ipAddress, msg, "failure",
                    remoteUser);

            if (e instanceof DBException) {
                Throwable t = e.getCause();
                if (t instanceof LDAPException ldape) {
                    PKIException ex = LDAPExceptionConverter.toPKIException(ldape);
                    auditConfigTokenRecord(ILogger.FAILURE, method, tokenID,
                            auditModParams, ex.toString());
                    throw ex;
                }
            }

            if (e instanceof PKIException pkie) {
                auditConfigTokenRecord(ILogger.FAILURE, method, tokenID,
                        auditModParams, e.toString());
                throw pkie;
            }

            auditConfigTokenRecord(ILogger.FAILURE, method, tokenID,
                    auditModParams, e.toString());
            throw new PKIException(e);
        }
    }
}
