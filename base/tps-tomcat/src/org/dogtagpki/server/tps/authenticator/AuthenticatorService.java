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

package org.dogtagpki.server.tps.authenticator;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.util.Iterator;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.dogtagpki.server.tps.TPSSubsystem;
import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.tps.authenticator.AuthenticatorCollection;
import com.netscape.certsrv.tps.authenticator.AuthenticatorData;
import com.netscape.certsrv.tps.authenticator.AuthenticatorInfo;
import com.netscape.certsrv.tps.authenticator.AuthenticatorModification;
import com.netscape.certsrv.tps.authenticator.AuthenticatorResource;
import com.netscape.cms.servlet.base.PKIService;

/**
 * @author Endi S. Dewata
 */
public class AuthenticatorService extends PKIService implements AuthenticatorResource {

    public final static int DEFAULT_SIZE = 20;

    public AuthenticatorService() {
        CMS.debug("AuthenticatorService.<init>()");
    }

    public AuthenticatorInfo createAuthenticatorInfo(AuthenticatorRecord authenticatorRecord) {

        AuthenticatorInfo authenticatorInfo = new AuthenticatorInfo();
        authenticatorInfo.setID(authenticatorRecord.getID());
        authenticatorInfo.setStatus(authenticatorRecord.getStatus());

        String authenticatorID = authenticatorRecord.getID();
        try {
            authenticatorID = URLEncoder.encode(authenticatorID, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }

        URI uri = uriInfo.getBaseUriBuilder().path(AuthenticatorResource.class).path("{authenticatorID}").build(authenticatorID);
        authenticatorInfo.setLink(new Link("self", uri));

        return authenticatorInfo;
    }

    public AuthenticatorData createAuthenticatorData(AuthenticatorRecord authenticatorRecord) {

        AuthenticatorData authenticatorData = new AuthenticatorData();
        authenticatorData.setID(authenticatorRecord.getID());
        authenticatorData.setStatus(authenticatorRecord.getStatus());
        authenticatorData.setContents(authenticatorRecord.getContents());

        String authenticatorID = authenticatorRecord.getID();
        try {
            authenticatorID = URLEncoder.encode(authenticatorID, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }

        URI uri = uriInfo.getBaseUriBuilder().path(AuthenticatorResource.class).path("{authenticatorID}").build(authenticatorID);
        authenticatorData.setLink(new Link("self", uri));

        return authenticatorData;
    }

    public AuthenticatorRecord createAuthenticatorRecord(AuthenticatorData authenticatorData) {

        AuthenticatorRecord authenticatorRecord = new AuthenticatorRecord();
        authenticatorRecord.setID(authenticatorData.getID());
        authenticatorRecord.setStatus(authenticatorData.getStatus());
        authenticatorRecord.setContents(authenticatorData.getContents());

        return authenticatorRecord;
    }

    @Override
    public AuthenticatorCollection findAuthenticators(Integer start, Integer size) {

        CMS.debug("AuthenticatorService.findAuthenticators()");

        try {
            start = start == null ? 0 : start;
            size = size == null ? DEFAULT_SIZE : size;

            TPSSubsystem subsystem = TPSSubsystem.getInstance();
            AuthenticatorDatabase database = subsystem.getAuthenticatorDatabase();

            Iterator<AuthenticatorRecord> authenticators = database.getRecords().iterator();

            AuthenticatorCollection response = new AuthenticatorCollection();

            int i = 0;

            // skip to the start of the page
            for ( ; i<start && authenticators.hasNext(); i++) authenticators.next();

            // return entries up to the page size
            for ( ; i<start+size && authenticators.hasNext(); i++) {
                response.addEntry(createAuthenticatorInfo(authenticators.next()));
            }

            // count the total entries
            for ( ; authenticators.hasNext(); i++) authenticators.next();

            if (start > 0) {
                URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", Math.max(start-size, 0)).build();
                response.addLink(new Link("prev", uri));
            }

            if (start+size < i) {
                URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", start+size).build();
                response.addLink(new Link("next", uri));
            }

            return response;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public AuthenticatorData getAuthenticator(String authenticatorID) {

        CMS.debug("AuthenticatorService.getAuthenticator(\"" + authenticatorID + "\")");

        try {
            TPSSubsystem subsystem = TPSSubsystem.getInstance();
            AuthenticatorDatabase database = subsystem.getAuthenticatorDatabase();

            return createAuthenticatorData(database.getRecord(authenticatorID));

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public Response addAuthenticator(AuthenticatorData authenticatorData) {

        CMS.debug("AuthenticatorService.addAuthenticator(\"" + authenticatorData.getID() + "\")");

        try {
            TPSSubsystem subsystem = TPSSubsystem.getInstance();
            AuthenticatorDatabase database = subsystem.getAuthenticatorDatabase();

            database.addRecord(createAuthenticatorRecord(authenticatorData));
            authenticatorData = createAuthenticatorData(database.getRecord(authenticatorData.getID()));

            return Response
                    .created(authenticatorData.getLink().getHref())
                    .entity(authenticatorData)
                    .type(MediaType.APPLICATION_XML)
                    .build();

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public Response updateAuthenticator(String authenticatorID, AuthenticatorData authenticatorData) {

        CMS.debug("AuthenticatorService.updateAuthenticator(\"" + authenticatorID + "\")");

        try {
            TPSSubsystem subsystem = TPSSubsystem.getInstance();
            AuthenticatorDatabase database = subsystem.getAuthenticatorDatabase();

            database.updateRecord(createAuthenticatorRecord(authenticatorData));
            authenticatorData = createAuthenticatorData(database.getRecord(authenticatorID));

            return Response
                    .ok(authenticatorData)
                    .type(MediaType.APPLICATION_XML)
                    .build();

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public Response modifyAuthenticator(String authenticatorID, AuthenticatorModification request) {

        CMS.debug("AuthenticatorService.modifyAuthenticator(\"" + authenticatorID + "\", request");

        try {
            TPSSubsystem subsystem = TPSSubsystem.getInstance();
            AuthenticatorDatabase database = subsystem.getAuthenticatorDatabase();

            AuthenticatorRecord authenticatorRecord = database.getRecord(authenticatorID);

            String status = request.getStatus();
            if (status != null) {
                authenticatorRecord.setStatus(status);
            }

            String contents = request.getContents();
            if (contents != null) {
                authenticatorRecord.setContents(contents);
            }

            database.updateRecord(authenticatorRecord);
            AuthenticatorData authenticatorData = createAuthenticatorData(database.getRecord(authenticatorID));

            return Response
                    .ok(authenticatorData)
                    .type(MediaType.APPLICATION_XML)
                    .build();

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public void removeAuthenticator(String authenticatorID) {

        CMS.debug("AuthenticatorService.removeAuthenticator(\"" + authenticatorID + "\")");

        try {
            TPSSubsystem subsystem = TPSSubsystem.getInstance();
            AuthenticatorDatabase database = subsystem.getAuthenticatorDatabase();
            database.removeRecord(authenticatorID);

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }
}
