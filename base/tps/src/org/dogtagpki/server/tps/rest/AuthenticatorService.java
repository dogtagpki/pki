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
import java.security.Principal;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

import org.apache.commons.lang.StringUtils;
import org.dogtagpki.server.tps.TPSSubsystem;
import org.dogtagpki.server.tps.config.AuthenticatorDatabase;
import org.dogtagpki.server.tps.config.AuthenticatorRecord;
import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.tps.authenticator.AuthenticatorCollection;
import com.netscape.certsrv.tps.authenticator.AuthenticatorData;
import com.netscape.certsrv.tps.authenticator.AuthenticatorResource;
import com.netscape.cms.servlet.base.SubsystemService;

/**
 * @author Endi S. Dewata
 */
public class AuthenticatorService extends SubsystemService implements AuthenticatorResource {

    @Context
    private UriInfo uriInfo;

    @Context
    private HttpHeaders headers;

    @Context
    private Request request;

    @Context
    private HttpServletRequest servletRequest;

    public AuthenticatorService() {
        CMS.debug("AuthenticatorService.<init>()");
    }

    public AuthenticatorData createAuthenticatorData(AuthenticatorRecord authenticatorRecord)
            throws UnsupportedEncodingException {

        String authenticatorID = authenticatorRecord.getID();

        AuthenticatorData authenticatorData = new AuthenticatorData();
        authenticatorData.setID(authenticatorID);
        authenticatorData.setStatus(authenticatorRecord.getStatus());
        authenticatorData.setProperties(authenticatorRecord.getProperties());

        authenticatorID = URLEncoder.encode(authenticatorID, "UTF-8");
        URI uri = uriInfo.getBaseUriBuilder().path(AuthenticatorResource.class).path("{authenticatorID}")
                .build(authenticatorID);
        authenticatorData.setLink(new Link("self", uri));

        return authenticatorData;
    }

    public AuthenticatorRecord createAuthenticatorRecord(AuthenticatorData authenticatorData) {

        AuthenticatorRecord authenticatorRecord = new AuthenticatorRecord();
        authenticatorRecord.setID(authenticatorData.getID());
        authenticatorRecord.setStatus(authenticatorData.getStatus());
        authenticatorRecord.setProperties(authenticatorData.getProperties());

        return authenticatorRecord;
    }

    @Override
    public Response findAuthenticators(String filter, Integer start, Integer size) {

        CMS.debug("AuthenticatorService.findAuthenticators()");

        if (filter != null && filter.length() < MIN_FILTER_LENGTH) {
            throw new BadRequestException("Filter is too short.");
        }

        start = start == null ? 0 : start;
        size = size == null ? DEFAULT_SIZE : size;

        try {
            TPSSubsystem subsystem = (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);
            AuthenticatorDatabase database = subsystem.getAuthenticatorDatabase();

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

            if (start > 0) {
                URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", Math.max(start - size, 0)).build();
                response.addLink(new Link("prev", uri));
            }

            if (start + size < i) {
                URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", start + size).build();
                response.addLink(new Link("next", uri));
            }

            return createOKResponse(response);

        } catch (PKIException e) {
            CMS.debug("AuthenticatorService: " + e);
            throw e;

        } catch (Exception e) {
            CMS.debug(e);
            throw new PKIException(e);
        }
    }

    @Override
    public Response getAuthenticator(String authenticatorID) {

        if (authenticatorID == null)
            throw new BadRequestException("Authenticator ID is null.");

        CMS.debug("AuthenticatorService.getAuthenticator(\"" + authenticatorID + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);
            AuthenticatorDatabase database = subsystem.getAuthenticatorDatabase();

            return createOKResponse(createAuthenticatorData(database.getRecord(authenticatorID)));

        } catch (PKIException e) {
            CMS.debug("AuthenticatorService: " + e);
            throw e;

        } catch (Exception e) {
            CMS.debug(e);
            throw new PKIException(e);
        }
    }

    @Override
    public Response addAuthenticator(AuthenticatorData authenticatorData) {
        String method = "AuthenticatorService.addAuthenticator";

        if (authenticatorData == null) {
            auditConfigTokenGeneral(ILogger.FAILURE, method, null,
                    "Authenticator data is null.");
            throw new BadRequestException("Authenticator data is null.");
        }

        CMS.debug("AuthenticatorService.addAuthenticator(\"" + authenticatorData.getID() + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);
            AuthenticatorDatabase database = subsystem.getAuthenticatorDatabase();

            String status = authenticatorData.getStatus();
            Principal principal = servletRequest.getUserPrincipal();

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
            auditTPSAuthenticatorChange(ILogger.SUCCESS, method, authenticatorData.getID(), properties, null);

            return createCreatedResponse(authenticatorData, authenticatorData.getLink().getHref());

        } catch (PKIException e) {
            CMS.debug("AuthenticatorService: " + e);
            auditTPSAuthenticatorChange(ILogger.FAILURE, method,
                    authenticatorData.getID(), authenticatorData.getProperties(), e.toString());

            throw e;

        } catch (Exception e) {
            CMS.debug("AuthenticatorService: " + e);
            auditTPSAuthenticatorChange(ILogger.FAILURE, method,
                    authenticatorData.getID(), authenticatorData.getProperties(), e.toString());
            throw new PKIException(e);
        }
    }

    @Override
    public Response updateAuthenticator(String authenticatorID, AuthenticatorData authenticatorData) {
        String method = "uthenticatorService.updateAuthenticator";

        if (authenticatorID == null) {
            auditConfigTokenGeneral(ILogger.FAILURE, method, null,
                    "Authenticator ID is null.");
            throw new BadRequestException("Authenticator ID is null.");
        }
        if (authenticatorData == null) {
            auditConfigTokenGeneral(ILogger.FAILURE, method, null,
                    "Authenticator data is null.");
            throw new BadRequestException("Authenticator data is null.");
        }

        CMS.debug("AuthenticatorService.updateAuthenticator(\"" + authenticatorID + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);
            AuthenticatorDatabase database = subsystem.getAuthenticatorDatabase();

            AuthenticatorRecord record = database.getRecord(authenticatorID);

            // only disabled authenticator can be updated
            if (!Constants.CFG_DISABLED.equals(record.getStatus())) {
                Exception e = new ForbiddenException("Unable to update authenticator "
                        + authenticatorID
                        + "; authenticator not disabled");
                auditTPSAuthenticatorChange(ILogger.FAILURE, method,
                        authenticatorID, authenticatorData.getProperties(), e.toString());
                throw e;
            }

            // update status if specified
            String status = authenticatorData.getStatus();
            boolean statusChanged = false;
            if (status != null && !Constants.CFG_DISABLED.equals(status)) {
                if (!Constants.CFG_ENABLED.equals(status)) {
                    ForbiddenException e = new ForbiddenException("Invalid authenticator status: " + status);
                    auditTPSAuthenticatorChange(ILogger.FAILURE, method,
                            authenticatorID, authenticatorData.getProperties(), e.toString());
                    throw e;
                }

                // if user doesn't have rights, set to pending
                Principal principal = servletRequest.getUserPrincipal();
                if (database.requiresApproval() && !database.canApprove(principal)) {
                    status = Constants.CFG_PENDING_APPROVAL;
                    statusChanged = true;
                }

                // enable authenticator
                record.setStatus(status);
            }

            // update properties if specified
            Map<String, String> properties = authenticatorData.getProperties();
            if (properties != null) {
                record.setProperties(authenticatorData.getProperties());
                if (statusChanged) {
                    properties.put("Status", status);
                }
            }

            database.updateRecord(authenticatorID, record);

            authenticatorData = createAuthenticatorData(database.getRecord(authenticatorID));
            auditTPSAuthenticatorChange(ILogger.SUCCESS, method, authenticatorData.getID(), properties, null);

            return createOKResponse(authenticatorData);

        } catch (PKIException e) {
            CMS.debug("AuthenticatorService: " + e);
            auditTPSAuthenticatorChange(ILogger.FAILURE, method,
                    authenticatorID, authenticatorData.getProperties(), e.toString());
            throw e;

        } catch (Exception e) {
            CMS.debug("AuthenticatorService: " + e);
            auditTPSAuthenticatorChange(ILogger.FAILURE, method,
                    authenticatorID, authenticatorData.getProperties(), e.toString());
            throw new PKIException(e);
        }
    }

    @Override
    public Response changeStatus(String authenticatorID, String action) {
        String method = "AuthenticatorService.changeStatus";
        Map<String, String> auditModParams = new HashMap<String, String>();

        if (authenticatorID == null) {
            auditConfigTokenGeneral(ILogger.FAILURE, method, null,
                    "authenticator id is null.");
            throw new BadRequestException("Authenticator ID is null.");
        }
        auditModParams.put("authenticatorID", authenticatorID);
        if (action == null) {
            auditConfigTokenGeneral(ILogger.FAILURE, method, auditModParams,
                    "action is null.");
            throw new BadRequestException("Action is null.");
        }
        auditModParams.put("Action", action);

        CMS.debug("AuthenticatorService.changeStatus(\"" + authenticatorID + "\", \"" + action + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);
            AuthenticatorDatabase database = subsystem.getAuthenticatorDatabase();

            AuthenticatorRecord record = database.getRecord(authenticatorID);
            String status = record.getStatus();

            Principal principal = servletRequest.getUserPrincipal();
            boolean canApprove = database.canApprove(principal);

            if (Constants.CFG_DISABLED.equals(status)) {

                if (database.requiresApproval()) {

                    if ("submit".equals(action) && !canApprove) {
                        status = Constants.CFG_PENDING_APPROVAL;

                    } else if ("enable".equals(action) && canApprove) {
                        status = Constants.CFG_ENABLED;

                    } else {
                        Exception e = new BadRequestException("Invalid action: " + action);
                        auditTPSAuthenticatorChange(ILogger.FAILURE, method,
                                authenticatorID, auditModParams, e.toString());
                        throw e;
                    }

                } else {
                    if ("enable".equals(action)) {
                        status = Constants.CFG_ENABLED;

                    } else {
                        Exception e = new BadRequestException("Invalid action: " + action);
                        auditTPSAuthenticatorChange(ILogger.FAILURE, method,
                                authenticatorID, auditModParams, e.toString());
                        throw e;
                    }
                }

            } else if (Constants.CFG_ENABLED.equals(status)) {

                if ("disable".equals(action)) {
                    status = Constants.CFG_DISABLED;

                } else {
                    Exception e = new BadRequestException("Invalid action: " + action);
                    auditTPSAuthenticatorChange(ILogger.FAILURE, method,
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
                    auditTPSAuthenticatorChange(ILogger.FAILURE, method,
                            authenticatorID, auditModParams, e.toString());
                }

            } else {
                PKIException e = new PKIException("Invalid status: " + status);
                auditTPSAuthenticatorChange(ILogger.FAILURE, method,
                        authenticatorID, auditModParams, e.toString());
                throw e;
            }

            record.setStatus(status);
            database.updateRecord(authenticatorID, record);

            AuthenticatorData authenticatorData = createAuthenticatorData(database.getRecord(authenticatorID));
            auditModParams.put("Status", status);
            auditTPSAuthenticatorChange(ILogger.SUCCESS, method, authenticatorID, auditModParams, null);

            return createOKResponse(authenticatorData);

        } catch (PKIException e) {
            CMS.debug("AuthenticatorService: " + e);
            auditTPSAuthenticatorChange(ILogger.FAILURE, method,
                    authenticatorID, auditModParams, e.toString());
            throw e;

        } catch (Exception e) {
            CMS.debug("AuthenticatorService: " + e);
            auditTPSAuthenticatorChange(ILogger.FAILURE, method,
                    authenticatorID, auditModParams, e.toString());
            throw new PKIException(e);
        }
    }

    @Override
    public Response removeAuthenticator(String authenticatorID) {
        String method = "AuthenticatorService.removeAuthenticator";
        Map<String, String> auditModParams = new HashMap<String, String>();

        if (authenticatorID == null) {
            auditConfigTokenGeneral(ILogger.FAILURE, method, null,
                    "Authenticator ID is null.");
            throw new BadRequestException("Authenticator ID is null.");
        }
        auditModParams.put("authenticatorID", authenticatorID);

        CMS.debug("AuthenticatorService.removeAuthenticator(\"" + authenticatorID + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);
            AuthenticatorDatabase database = subsystem.getAuthenticatorDatabase();

            AuthenticatorRecord record = database.getRecord(authenticatorID);
            String status = record.getStatus();

            if (!Constants.CFG_DISABLED.equals(status)) {
                Exception e = new ForbiddenException("Unable to remove authenticator "
                        + authenticatorID
                        + "; authenticator not disabled");
                auditTPSAuthenticatorChange(ILogger.FAILURE, method,
                        authenticatorID, auditModParams, e.toString());
                throw e;
            }

            database.removeRecord(authenticatorID);
            auditTPSAuthenticatorChange(ILogger.SUCCESS, method, authenticatorID, null, null);

            return createNoContentResponse();

        } catch (PKIException e) {
            CMS.debug("AuthenticatorService: " + e);
            auditTPSAuthenticatorChange(ILogger.FAILURE, method,
                    authenticatorID, auditModParams, e.toString());
            throw e;

        } catch (Exception e) {
            CMS.debug("AuthenticatorService: " + e);
            auditTPSAuthenticatorChange(ILogger.FAILURE, method,
                    authenticatorID, auditModParams, e.toString());
            throw new PKIException(e);
        }
    }

    /*
     * service can be any of the methods offered
     */
    public void auditTPSAuthenticatorChange(String status, String service, String authenticatorID,
            Map<String, String> params, String info) {

        String msg = CMS.getLogMessage(
                "LOGGING_SIGNED_AUDIT_CONFIG_TOKEN_AUTHENTICATOR_6",
                servletRequest.getUserPrincipal().getName(),
                status,
                service,
                authenticatorID,
                auditor.getParamString(null, params),
                info);
        auditor.log(msg);

    }
}
