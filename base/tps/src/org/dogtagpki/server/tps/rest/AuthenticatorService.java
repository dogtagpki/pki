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
import java.util.Iterator;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

import org.dogtagpki.server.tps.TPSSubsystem;
import org.dogtagpki.server.tps.config.AuthenticatorDatabase;
import org.dogtagpki.server.tps.config.AuthenticatorRecord;
import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.tps.authenticator.AuthenticatorCollection;
import com.netscape.certsrv.tps.authenticator.AuthenticatorData;
import com.netscape.certsrv.tps.authenticator.AuthenticatorResource;
import com.netscape.cms.servlet.base.PKIService;

/**
 * @author Endi S. Dewata
 */
public class AuthenticatorService extends PKIService implements AuthenticatorResource {

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

    public AuthenticatorData createAuthenticatorData(AuthenticatorRecord authenticatorRecord) throws UnsupportedEncodingException {

        String authenticatorID = authenticatorRecord.getID();

        AuthenticatorData authenticatorData = new AuthenticatorData();
        authenticatorData.setID(authenticatorID);
        authenticatorData.setStatus(authenticatorRecord.getStatus());
        authenticatorData.setProperties(authenticatorRecord.getProperties());

        authenticatorID = URLEncoder.encode(authenticatorID, "UTF-8");
        URI uri = uriInfo.getBaseUriBuilder().path(AuthenticatorResource.class).path("{authenticatorID}").build(authenticatorID);
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
            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            AuthenticatorDatabase database = subsystem.getAuthenticatorDatabase();

            Iterator<AuthenticatorRecord> authenticators = database.findRecords(filter).iterator();

            AuthenticatorCollection response = new AuthenticatorCollection();
            int i = 0;

            // skip to the start of the page
            for ( ; i<start && authenticators.hasNext(); i++) authenticators.next();

            // return entries up to the page size
            for ( ; i<start+size && authenticators.hasNext(); i++) {
                response.addEntry(createAuthenticatorData(authenticators.next()));
            }

            // count the total entries
            for ( ; authenticators.hasNext(); i++) authenticators.next();
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

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public Response getAuthenticator(String authenticatorID) {

        if (authenticatorID == null) throw new BadRequestException("Authenticator ID is null.");

        CMS.debug("AuthenticatorService.getAuthenticator(\"" + authenticatorID + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            AuthenticatorDatabase database = subsystem.getAuthenticatorDatabase();

            return createOKResponse(createAuthenticatorData(database.getRecord(authenticatorID)));

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public Response addAuthenticator(AuthenticatorData authenticatorData) {

        if (authenticatorData == null) throw new BadRequestException("Authenticator data is null.");

        CMS.debug("AuthenticatorService.addAuthenticator(\"" + authenticatorData.getID() + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            AuthenticatorDatabase database = subsystem.getAuthenticatorDatabase();

            String status = authenticatorData.getStatus();
            Principal principal = servletRequest.getUserPrincipal();

            if (status == null || database.requiresApproval() && !database.canApprove(principal)) {
                // if status is unspecified or user doesn't have rights to approve, the entry is disabled
                authenticatorData.setStatus("Disabled");
            }

            database.addRecord(authenticatorData.getID(), createAuthenticatorRecord(authenticatorData));
            authenticatorData = createAuthenticatorData(database.getRecord(authenticatorData.getID()));

            return createCreatedResponse(authenticatorData, authenticatorData.getLink().getHref());

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public Response updateAuthenticator(String authenticatorID, AuthenticatorData authenticatorData) {

        if (authenticatorID == null) throw new BadRequestException("Authenticator ID is null.");
        if (authenticatorData == null) throw new BadRequestException("Authenticator data is null.");

        CMS.debug("AuthenticatorService.updateAuthenticator(\"" + authenticatorID + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            AuthenticatorDatabase database = subsystem.getAuthenticatorDatabase();

            AuthenticatorRecord record = database.getRecord(authenticatorID);

            // only disabled authenticator can be updated
            if (!"Disabled".equals(record.getStatus())) {
                throw new ForbiddenException("Unable to update authenticator " + authenticatorID);
            }

            // update status if specified
            String status = authenticatorData.getStatus();
            if (status != null && !"Disabled".equals(status)) {
                if (!"Enabled".equals(status)) {
                    throw new ForbiddenException("Invalid authenticator status: " + status);
                }

                // if user doesn't have rights, set to pending
                Principal principal = servletRequest.getUserPrincipal();
                if (database.requiresApproval() && !database.canApprove(principal)) {
                    status = "Pending_Approval";
                }

                // enable authenticator
                record.setStatus(status);
            }

            // update properties if specified
            Map<String, String> properties = authenticatorData.getProperties();
            if (properties != null) {
                record.setProperties(authenticatorData.getProperties());
            }

            database.updateRecord(authenticatorID, record);

            authenticatorData = createAuthenticatorData(database.getRecord(authenticatorID));

            return createOKResponse(authenticatorData);

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public Response changeAuthenticatorStatus(String authenticatorID, String action) {

        if (authenticatorID == null) throw new BadRequestException("Authenticator ID is null.");
        if (action == null) throw new BadRequestException("Action is null.");

        CMS.debug("AuthenticatorService.changeAuthenticatorStatus(\"" + authenticatorID + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            AuthenticatorDatabase database = subsystem.getAuthenticatorDatabase();

            AuthenticatorRecord record = database.getRecord(authenticatorID);
            String status = record.getStatus();

            if ("Disabled".equals(status)) {
                if ("enable".equals(action)) {
                    status = "Enabled";
                } else {
                    throw new BadRequestException("Invalid action: " + action);
                }

            } else if ("Enabled".equals(status)) {
                if ("disable".equals(action)) {
                    status = "Disabled";
                } else {
                    throw new BadRequestException("Invalid action: " + action);
                }

            } else if ("Pending_Approval".equals(status)) {
                if ("approve".equals(action)) {
                    status = "Enabled";
                } else if ("reject".equals(action)) {
                    status = "Disabled";
                } else {
                    throw new BadRequestException("Invalid action: " + action);
                }

            } else {
                throw new PKIException("Invalid authenticator status: " + status);
            }

            record.setStatus(status);
            database.updateRecord(authenticatorID, record);

            AuthenticatorData authenticatorData = createAuthenticatorData(database.getRecord(authenticatorID));

            return createOKResponse(authenticatorData);

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public Response removeAuthenticator(String authenticatorID) {

        if (authenticatorID == null) throw new BadRequestException("Authenticator ID is null.");

        CMS.debug("AuthenticatorService.removeAuthenticator(\"" + authenticatorID + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            AuthenticatorDatabase database = subsystem.getAuthenticatorDatabase();

            AuthenticatorRecord record = database.getRecord(authenticatorID);
            String status = record.getStatus();

            if (!"Disabled".equals(status)) {
                throw new ForbiddenException("Unable to delete authenticator " + authenticatorID);
            }

            database.removeRecord(authenticatorID);

            return createNoContentResponse();

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }
}
