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

package org.dogtagpki.server.tps.profile;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.security.Principal;
import java.util.Iterator;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

import org.dogtagpki.server.tps.TPSSubsystem;
import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.tps.profile.ProfileCollection;
import com.netscape.certsrv.tps.profile.ProfileData;
import com.netscape.certsrv.tps.profile.ProfileResource;
import com.netscape.cms.servlet.base.PKIService;

/**
 * @author Endi S. Dewata
 */
public class ProfileService extends PKIService implements ProfileResource {

    @Context
    private UriInfo uriInfo;

    @Context
    private HttpHeaders headers;

    @Context
    private Request request;

    @Context
    private HttpServletRequest servletRequest;

    public final static int DEFAULT_SIZE = 20;

    public ProfileService() {
        CMS.debug("ProfileService.<init>()");
    }

    public ProfileData createProfileData(ProfileRecord profileRecord) throws UnsupportedEncodingException {

        String profileID = profileRecord.getID();

        ProfileData profileData = new ProfileData();
        profileData.setID(profileID);
        profileData.setStatus(profileRecord.getStatus());
        profileData.setProperties(profileRecord.getProperties());

        profileID = URLEncoder.encode(profileID, "UTF-8");
        URI uri = uriInfo.getBaseUriBuilder().path(ProfileResource.class).path("{profileID}").build(profileID);
        profileData.setLink(new Link("self", uri));

        return profileData;
    }

    public ProfileRecord createProfileRecord(ProfileData profileData) {

        ProfileRecord profileRecord = new ProfileRecord();
        profileRecord.setID(profileData.getID());
        profileRecord.setStatus(profileData.getStatus());
        profileRecord.setProperties(profileData.getProperties());

        return profileRecord;
    }

    @Override
    public ProfileCollection findProfiles(Integer start, Integer size) {

        CMS.debug("ProfileService.findProfiles()");

        try {
            start = start == null ? 0 : start;
            size = size == null ? DEFAULT_SIZE : size;

            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            ProfileDatabase database = subsystem.getProfileDatabase();

            Iterator<ProfileRecord> profiles = database.getRecords().iterator();

            ProfileCollection response = new ProfileCollection();
            int i = 0;

            // skip to the start of the page
            for ( ; i<start && profiles.hasNext(); i++) profiles.next();

            // return entries up to the page size
            for ( ; i<start+size && profiles.hasNext(); i++) {
                response.addEntry(createProfileData(profiles.next()));
            }

            // count the total entries
            for ( ; profiles.hasNext(); i++) profiles.next();
            response.setTotal(i);

            if (start > 0) {
                URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", Math.max(start-size, 0)).build();
                response.addLink(new Link("prev", uri));
            }

            if (start+size < i) {
                URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", start+size).build();
                response.addLink(new Link("next", uri));
            }

            return response;

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public ProfileData getProfile(String profileID) {

        if (profileID == null) throw new BadRequestException("Profile ID is null.");

        CMS.debug("ProfileService.getProfile(\"" + profileID + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            ProfileDatabase database = subsystem.getProfileDatabase();

            return createProfileData(database.getRecord(profileID));

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public Response addProfile(ProfileData profileData) {

        if (profileData == null) throw new BadRequestException("Profile data is null.");

        CMS.debug("ProfileService.addProfile(\"" + profileData.getID() + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            ProfileDatabase database = subsystem.getProfileDatabase();

            database.addRecord(profileData.getID(), createProfileRecord(profileData));

            profileData = createProfileData(database.getRecord(profileData.getID()));

            return Response
                    .created(profileData.getLink().getHref())
                    .entity(profileData)
                    .type(MediaType.APPLICATION_XML)
                    .build();

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public Response updateProfile(String profileID, ProfileData profileData) {

        if (profileID == null) throw new BadRequestException("Profile ID is null.");
        if (profileData == null) throw new BadRequestException("Profile data is null.");

        CMS.debug("ProfileService.updateProfile(\"" + profileID + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            ProfileDatabase database = subsystem.getProfileDatabase();

            ProfileRecord record = database.getRecord(profileID);
            String status = record.getStatus();

            if (!"Disabled".equals(status)) {
                throw new ForbiddenException("Unable to update profile " + profileID);
            }

            status = profileData.getStatus();
            if ("Enabled".equals(status)) {
                Principal principal = servletRequest.getUserPrincipal();
                if (database.requiresApproval() && !database.canApprove(principal)) {
                    status = "Pending_Approval";
                }
                record.setStatus(status);;

            } else {
                throw new ForbiddenException("Invalid profile status: " + status);
            }

            record.setProperties(profileData.getProperties());
            database.updateRecord(profileID, record);

            profileData = createProfileData(database.getRecord(profileID));

            return Response
                    .ok(profileData)
                    .type(MediaType.APPLICATION_XML)
                    .build();

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public Response changeProfileStatus(String profileID, String action) {

        if (profileID == null) throw new BadRequestException("Profile ID is null.");
        if (action == null) throw new BadRequestException("Action is null.");

        CMS.debug("ProfileService.changeProfileStatus(\"" + profileID + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            ProfileDatabase database = subsystem.getProfileDatabase();

            ProfileRecord record = database.getRecord(profileID);
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
                throw new PKIException("Invalid profile status: " + status);
            }

            record.setStatus(status);
            database.updateRecord(profileID, record);

            ProfileData profileData = createProfileData(database.getRecord(profileID));

            return Response
                    .ok(profileData)
                    .type(MediaType.APPLICATION_XML)
                    .build();

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public void removeProfile(String profileID) {

        if (profileID == null) throw new BadRequestException("Profile ID is null.");

        CMS.debug("ProfileService.removeProfile(\"" + profileID + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            ProfileDatabase database = subsystem.getProfileDatabase();

            ProfileRecord record = database.getRecord(profileID);
            String status = record.getStatus();

            if (!"Disabled".equals(status)) {
                throw new ForbiddenException("Unable to delete profile " + profileID);
            }

            database.removeRecord(profileID);

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }
}
