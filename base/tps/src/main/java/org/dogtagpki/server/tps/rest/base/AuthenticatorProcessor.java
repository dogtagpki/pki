//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.rest.base;

import java.security.Principal;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.dogtagpki.server.rest.v2.PKIServlet;
import org.dogtagpki.server.tps.TPSEngine;
import org.dogtagpki.server.tps.TPSSubsystem;
import org.dogtagpki.server.tps.config.AuthenticatorDatabase;
import org.dogtagpki.server.tps.config.AuthenticatorRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.tps.authenticator.AuthenticatorCollection;
import com.netscape.certsrv.tps.authenticator.AuthenticatorData;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.logging.Auditor;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 * @author Endi S. Dewata
 */
public class AuthenticatorProcessor {
    private static final Logger logger = LoggerFactory.getLogger(AuthenticatorProcessor.class);

    private TPSSubsystem subsystem;
    private AuthenticatorDatabase database;
    private Auditor auditor;

    public AuthenticatorProcessor(TPSEngine engine) {
        subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
        database = subsystem.getAuthenticatorDatabase();
        auditor = engine.getAuditor();
    }

    public AuthenticatorCollection findAuthenticators(String filter, int start, int size) {
        logger.debug("AuthenticatorProcessor.findAuthenticators()");

        if (filter != null && filter.length() < PKIServlet.MIN_FILTER_LENGTH) {
            throw new BadRequestException("Filter is too short.");
        }
        try {
            Iterator<AuthenticatorRecord> authenticators = database.findRecords(filter).iterator();

            AuthenticatorCollection response = new AuthenticatorCollection();
            int i = 0;

            // skip to the start of the page
            for (; i < start && authenticators.hasNext(); i++)
                authenticators.next();

            // return entries up to the page size
            for (; i < start + size && authenticators.hasNext(); i++) {
                response.addEntry(createAuthenticatorData(authenticators.next()));
            }

            // count the total entries
            for (; authenticators.hasNext(); i++)
                authenticators.next();
            response.setTotal(i);

            return response;

        } catch (PKIException e) {
            logger.error("AuthenticatorProcessor: " + e.getMessage(), e);
            throw e;

        } catch (Exception e) {
            logger.error("AuthenticatorProcessor: " + e.getMessage(), e);
            throw new PKIException(e);
        }
    }

    public AuthenticatorData addAuthenticator(Principal principal, AuthenticatorData authenticatorData) {
        String method = "AuthenticatorProcessor.addAuthenticator";

        if (authenticatorData == null) {
            auditConfigTokenGeneral(principal, ILogger.FAILURE, method, null,
                    "Authenticator data is null.");
            throw new BadRequestException("Authenticator data is null.");
        }

        logger.debug("AuthenticatorProcessor.addAuthenticator(\"{}\")", authenticatorData.getID());

        try {
            String status = authenticatorData.getStatus();

            boolean statusChanged = false;
            if (StringUtils.isEmpty(status) || database.requiresApproval() && !database.canApprove(principal)) {
                // if status is unspecified or user doesn't have rights to approve, the entry is disabled
                status = Constants.CFG_DISABLED;
                authenticatorData.setStatus(status);
                statusChanged = true;
            }

            database.addRecord(authenticatorData.getID(), createAuthenticatorRecord(authenticatorData));
            authenticatorData = createAuthenticatorData(database.getRecord(authenticatorData.getID()));
            Map<String, String> properties = authenticatorData.getProperties();
            if (statusChanged) {
                properties.put("Status", status);
            }
            auditTPSAuthenticatorChange(principal, ILogger.SUCCESS, method, authenticatorData.getID(), properties, null);

            return authenticatorData;

        } catch (PKIException e) {
            logger.error("AuthenticatorProcessor: " + e.getMessage(), e);
            auditTPSAuthenticatorChange(principal, ILogger.FAILURE, method,
                    authenticatorData.getID(), authenticatorData.getProperties(), e.toString());

            throw e;

        } catch (Exception e) {
            logger.error("AuthenticatorProcessor: " + e.getMessage(), e);
            auditTPSAuthenticatorChange(principal, ILogger.FAILURE, method,
                    authenticatorData.getID(), authenticatorData.getProperties(), e.toString());
            throw new PKIException(e);
        }
    }

    public AuthenticatorData getAuthenticator(String authenticatorID) {
        if (authenticatorID == null)
            throw new BadRequestException("Authenticator ID is null.");

        logger.debug("AuthenticatorProcessor.getAuthenticator(\"{}\")", authenticatorID);
        try {
            return createAuthenticatorData(database.getRecord(authenticatorID));

        } catch (PKIException e) {
            logger.error("AuthenticatorProcessor: " + e.getMessage(), e);
            throw e;

        } catch (Exception e) {
            logger.error("AuthenticatorProcessor: " + e.getMessage(), e);
            throw new PKIException(e);
        }
    }

    public AuthenticatorData updateAuthenticator(Principal principal, String authenticatorID, AuthenticatorData authenticatorData) {
        String method = "AuthenticatorProcessor.updateAuthenticator";

        if (authenticatorID == null) {
            auditConfigTokenGeneral(principal, ILogger.FAILURE, method, null,
                    "Authenticator ID is null.");
            throw new BadRequestException("Authenticator ID is null.");
        }
        if (authenticatorData == null) {
            auditConfigTokenGeneral(principal, ILogger.FAILURE, method, null,
                    "Authenticator data is null.");
            throw new BadRequestException("Authenticator data is null.");
        }

        logger.debug("AuthenticatorProcessor.updateAuthenticator(\"{}\")", authenticatorID);

        try {
            AuthenticatorRecord authRecord = database.getRecord(authenticatorID);

            // only disabled authenticator can be updated
            if (!Constants.CFG_DISABLED.equals(authRecord.getStatus())) {
                Exception e = new ForbiddenException("Unable to update authenticator "
                        + authenticatorID
                        + "; authenticator not disabled");
                auditTPSAuthenticatorChange(principal, ILogger.FAILURE, method,
                        authenticatorID, authenticatorData.getProperties(), e.toString());
                throw e;
            }

            // update status if specified
            String status = authenticatorData.getStatus();
            boolean statusChanged = false;
            if (status != null && !Constants.CFG_DISABLED.equals(status)) {
                if (!Constants.CFG_ENABLED.equals(status)) {
                    ForbiddenException e = new ForbiddenException("Invalid authenticator status: " + status);
                    auditTPSAuthenticatorChange(principal, ILogger.FAILURE, method,
                            authenticatorID, authenticatorData.getProperties(), e.toString());
                    throw e;
                }

                // if user doesn't have rights, set to pending
                if (database.requiresApproval() && !database.canApprove(principal)) {
                    status = Constants.CFG_PENDING_APPROVAL;
                    statusChanged = true;
                }

                // enable authenticator
                authRecord.setStatus(status);
            }

            // update properties if specified
            Map<String, String> properties = authenticatorData.getProperties();
            if (properties != null) {
                authRecord.setProperties(authenticatorData.getProperties());
                if (statusChanged) {
                    properties.put("Status", status);
                }
            }

            database.updateRecord(authenticatorID, authRecord);

            authenticatorData = createAuthenticatorData(database.getRecord(authenticatorID));
            auditTPSAuthenticatorChange(principal, ILogger.SUCCESS, method, authenticatorData.getID(), properties, null);

            return authenticatorData;

        } catch (PKIException e) {
            logger.error("AuthenticatorProcessor: " + e.getMessage(), e);
            auditTPSAuthenticatorChange(principal, ILogger.FAILURE, method,
                    authenticatorID, authenticatorData.getProperties(), e.toString());
            throw e;

        } catch (Exception e) {
            logger.error("AuthenticatorProcessor: " + e.getMessage(), e);
            auditTPSAuthenticatorChange(principal, ILogger.FAILURE, method,
                    authenticatorID, authenticatorData.getProperties(), e.toString());
            throw new PKIException(e);
        }
    }

    public AuthenticatorData changeStatus(Principal principal, String authenticatorID, String action) {
        String method = "AuthenticatorProcessor.changeStatus";
        Map<String, String> auditModParams = new HashMap<>();

        if (authenticatorID == null) {
            auditConfigTokenGeneral(principal, ILogger.FAILURE, method, null,
                    "authenticator id is null.");
            throw new BadRequestException("Authenticator ID is null.");
        }
        auditModParams.put("authenticatorID", authenticatorID);
        if (action == null) {
            auditConfigTokenGeneral(principal, ILogger.FAILURE, method, auditModParams,
                    "action is null.");
            throw new BadRequestException("Action is null.");
        }
        auditModParams.put("Action", action);

        logger.debug("AuthenticatorProcessor.changeStatus(\"{}\", \"{}\")", authenticatorID, action);

        try {
            AuthenticatorRecord authRecord = database.getRecord(authenticatorID);
            String status = authRecord.getStatus();

            boolean canApprove = database.canApprove(principal);

            if (Constants.CFG_DISABLED.equals(status)) {

                if (database.requiresApproval()) {

                    if ("submit".equals(action) && !canApprove) {
                        status = Constants.CFG_PENDING_APPROVAL;

                    } else if ("enable".equals(action) && canApprove) {
                        status = Constants.CFG_ENABLED;

                    } else {
                        Exception e = new BadRequestException("Invalid action: " + action);
                        auditTPSAuthenticatorChange(principal, ILogger.FAILURE, method,
                                authenticatorID, auditModParams, e.toString());
                        throw e;
                    }

                } else {
                    if ("enable".equals(action)) {
                        status = Constants.CFG_ENABLED;

                    } else {
                        Exception e = new BadRequestException("Invalid action: " + action);
                        auditTPSAuthenticatorChange(principal, ILogger.FAILURE, method,
                                authenticatorID, auditModParams, e.toString());
                        throw e;
                    }
                }

            } else if (Constants.CFG_ENABLED.equals(status)) {

                if ("disable".equals(action)) {
                    status = Constants.CFG_DISABLED;

                } else {
                    Exception e = new BadRequestException("Invalid action: " + action);
                    auditTPSAuthenticatorChange(principal, ILogger.FAILURE, method,
                            authenticatorID, auditModParams, e.toString());
                    throw e;
                }

            } else if (Constants.CFG_PENDING_APPROVAL.equals(status)) {

                if ("approve".equals(action) && canApprove) {
                    status = Constants.CFG_ENABLED;

                } else if ("reject".equals(action) && canApprove) {
                    status = Constants.CFG_DISABLED;

                } else if ("cancel".equals(action) && !canApprove) {
                    status = Constants.CFG_DISABLED;

                } else {
                    Exception e = new BadRequestException("Invalid action: " + action);
                    auditTPSAuthenticatorChange(principal, ILogger.FAILURE, method,
                            authenticatorID, auditModParams, e.toString());
                }

            } else {
                PKIException e = new PKIException("Invalid status: " + status);
                auditTPSAuthenticatorChange(principal, ILogger.FAILURE, method,
                        authenticatorID, auditModParams, e.toString());
                throw e;
            }

            authRecord.setStatus(status);
            database.updateRecord(authenticatorID, authRecord);

            AuthenticatorData authenticatorData = createAuthenticatorData(database.getRecord(authenticatorID));
            auditModParams.put("Status", status);
            auditTPSAuthenticatorChange(principal, ILogger.SUCCESS, method, authenticatorID, auditModParams, null);

            return authenticatorData;

        } catch (PKIException e) {
            logger.error("AuthenticatorProcessor: " + e.getMessage(), e);
            auditTPSAuthenticatorChange(principal, ILogger.FAILURE, method,
                    authenticatorID, auditModParams, e.toString());
            throw e;

        } catch (Exception e) {
            logger.error("AuthenticatorProcessor: " + e.getMessage(), e);
            auditTPSAuthenticatorChange(principal, ILogger.FAILURE, method,
                    authenticatorID, auditModParams, e.toString());
            throw new PKIException(e);
        }
    }

    public void removeAuthenticator(Principal principal, String authenticatorID) {
        String method = "AuthenticatorProcessor.removeAuthenticator";
        Map<String, String> auditModParams = new HashMap<>();

        if (authenticatorID == null) {
            auditConfigTokenGeneral(principal, ILogger.FAILURE, method, null,
                    "Authenticator ID is null.");
            throw new BadRequestException("Authenticator ID is null.");
        }
        auditModParams.put("authenticatorID", authenticatorID);

        logger.debug("AuthenticatorProcessor.removeAuthenticator(\"{}\")", authenticatorID);
        try {
            AuthenticatorRecord authRecord = database.getRecord(authenticatorID);
            String status = authRecord.getStatus();

            if (!Constants.CFG_DISABLED.equals(status)) {
                Exception e = new ForbiddenException("Unable to remove authenticator "
                        + authenticatorID
                        + "; authenticator not disabled");
                auditTPSAuthenticatorChange(principal, ILogger.FAILURE, method,
                        authenticatorID, auditModParams, e.toString());
                throw e;
            }

            database.removeRecord(authenticatorID);
            auditTPSAuthenticatorChange(principal, ILogger.SUCCESS, method, authenticatorID, null, null);

        } catch (PKIException e) {
            logger.error("AuthenticatorProcessor: " + e.getMessage(), e);
            auditTPSAuthenticatorChange(principal, ILogger.FAILURE, method,
                    authenticatorID, auditModParams, e.toString());
            throw e;

        } catch (Exception e) {
            logger.error("AuthenticatorProcessor: " + e.getMessage(), e);
            auditTPSAuthenticatorChange(principal, ILogger.FAILURE, method,
                    authenticatorID, auditModParams, e.toString());
            throw new PKIException(e);
        }
    }

    private AuthenticatorData createAuthenticatorData(AuthenticatorRecord authenticatorRecord) {
        String authenticatorID = authenticatorRecord.getID();

        AuthenticatorData authenticatorData = new AuthenticatorData();
        authenticatorData.setID(authenticatorID);
        authenticatorData.setStatus(authenticatorRecord.getStatus());
        authenticatorData.setProperties(authenticatorRecord.getProperties());

        return authenticatorData;
    }

    private AuthenticatorRecord createAuthenticatorRecord(AuthenticatorData authenticatorData) {
        AuthenticatorRecord authenticatorRecord = new AuthenticatorRecord();
        authenticatorRecord.setID(authenticatorData.getID());
        authenticatorRecord.setStatus(authenticatorData.getStatus());
        authenticatorRecord.setProperties(authenticatorData.getProperties());

        return authenticatorRecord;
    }

    private void auditTPSAuthenticatorChange(Principal principal, String status, String service, String authenticatorID,
            Map<String, String> params, String info) {

        String msg = CMS.getLogMessage(
                AuditEvent.CONFIG_TOKEN_AUTHENTICATOR,
                principal.getName(),
                status,
                service,
                authenticatorID,
                auditor.getParamString(params),
                info);
        auditor.log(msg);
    }

    private void auditConfigTokenGeneral(Principal principal, String status, String service, Map<String, String> params, String info) {

        String msg = CMS.getLogMessage(
                AuditEvent.CONFIG_TOKEN_GENERAL,
                principal.getName(),
                status,
                service,
                auditor.getParamString(params),
                info);
        auditor.log(msg);
    }
}
