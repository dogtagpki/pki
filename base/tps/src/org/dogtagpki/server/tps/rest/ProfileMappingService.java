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

import org.apache.commons.lang.StringUtils;
import org.dogtagpki.server.tps.TPSSubsystem;
import org.dogtagpki.server.tps.config.ProfileMappingDatabase;
import org.dogtagpki.server.tps.config.ProfileMappingRecord;
import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.tps.profile.ProfileMappingCollection;
import com.netscape.certsrv.tps.profile.ProfileMappingData;
import com.netscape.certsrv.tps.profile.ProfileMappingResource;
import com.netscape.cms.servlet.base.PKIService;

/**
 * @author Endi S. Dewata
 */
public class ProfileMappingService extends PKIService implements ProfileMappingResource {

    @Context
    private UriInfo uriInfo;

    @Context
    private HttpHeaders headers;

    @Context
    private Request request;

    @Context
    private HttpServletRequest servletRequest;

    public ProfileMappingService() {
        CMS.debug("ProfileMappingService.<init>()");
    }

    public ProfileMappingData createProfileMappingData(ProfileMappingRecord profileMappingRecord) throws UnsupportedEncodingException {

        String profileMappingID = profileMappingRecord.getID();

        ProfileMappingData profileMappingData = new ProfileMappingData();
        profileMappingData.setID(profileMappingID);
        profileMappingData.setStatus(profileMappingRecord.getStatus());
        profileMappingData.setProperties(profileMappingRecord.getProperties());

        profileMappingID = URLEncoder.encode(profileMappingID, "UTF-8");
        URI uri = uriInfo.getBaseUriBuilder().path(ProfileMappingResource.class).path("{profileMappingID}").build(profileMappingID);
        profileMappingData.setLink(new Link("self", uri));

        return profileMappingData;
    }

    public ProfileMappingRecord createProfileMappingRecord(ProfileMappingData profileMappingData) {

        ProfileMappingRecord profileMappingRecord = new ProfileMappingRecord();
        profileMappingRecord.setID(profileMappingData.getID());
        profileMappingRecord.setStatus(profileMappingData.getStatus());
        profileMappingRecord.setProperties(profileMappingData.getProperties());

        return profileMappingRecord;
    }

    @Override
    public Response findProfileMappings(String filter, Integer start, Integer size) {

        CMS.debug("ProfileMappingService.findProfileMappings()");

        if (filter != null && filter.length() < MIN_FILTER_LENGTH) {
            throw new BadRequestException("Filter is too short.");
        }

        start = start == null ? 0 : start;
        size = size == null ? DEFAULT_SIZE : size;

        try {
            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            ProfileMappingDatabase database = subsystem.getProfileMappingDatabase();

            Iterator<ProfileMappingRecord> profileMappings = database.findRecords(filter).iterator();

            ProfileMappingCollection response = new ProfileMappingCollection();
            int i = 0;

            // skip to the start of the page
            for ( ; i<start && profileMappings.hasNext(); i++) profileMappings.next();

            // return entries up to the page size
            for ( ; i<start+size && profileMappings.hasNext(); i++) {
                response.addEntry(createProfileMappingData(profileMappings.next()));
            }

            // count the total entries
            for ( ; profileMappings.hasNext(); i++) profileMappings.next();
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
            CMS.debug("ProfileMappingService: " + e);
            throw e;

        } catch (Exception e) {
            CMS.debug(e);
            throw new PKIException(e);
        }
    }

    @Override
    public Response getProfileMapping(String profileMappingID) {

        CMS.debug("ProfileMappingService.getProfileMapping(\"" + profileMappingID + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            ProfileMappingDatabase database = subsystem.getProfileMappingDatabase();

            return createOKResponse(createProfileMappingData(database.getRecord(profileMappingID)));

        } catch (PKIException e) {
            CMS.debug("ProfileMappingService: " + e);
            throw e;

        } catch (Exception e) {
            CMS.debug(e);
            throw new PKIException(e);
        }
    }

    @Override
    public Response addProfileMapping(ProfileMappingData profileMappingData) {

        CMS.debug("ProfileMappingService.addProfileMapping(\"" + profileMappingData.getID() + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            ProfileMappingDatabase database = subsystem.getProfileMappingDatabase();

            String status = profileMappingData.getStatus();
            Principal principal = servletRequest.getUserPrincipal();

            if (StringUtils.isEmpty(status) || database.requiresApproval() && !database.canApprove(principal)) {
                // if status is unspecified or user doesn't have rights to approve, the entry is disabled
                profileMappingData.setStatus(Constants.CFG_DISABLED);
            }

            database.addRecord(profileMappingData.getID(), createProfileMappingRecord(profileMappingData));
            profileMappingData = createProfileMappingData(database.getRecord(profileMappingData.getID()));

            return createCreatedResponse(profileMappingData, profileMappingData.getLink().getHref());

        } catch (PKIException e) {
            CMS.debug("ProfileMappingService: " + e);
            throw e;

        } catch (Exception e) {
            CMS.debug(e);
            throw new PKIException(e);
        }
    }

    @Override
    public Response updateProfileMapping(String profileMappingID, ProfileMappingData profileMappingData) {

        CMS.debug("ProfileMappingService.updateProfileMapping(\"" + profileMappingID + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            ProfileMappingDatabase database = subsystem.getProfileMappingDatabase();

            ProfileMappingRecord record = database.getRecord(profileMappingID);

            // only disabled profile mapping can be updated
            if (!Constants.CFG_DISABLED.equals(record.getStatus())) {
                throw new ForbiddenException("Unable to update profile mapping " + profileMappingID);
            }

            // update status if specified
            String status = profileMappingData.getStatus();
            if (status != null && !Constants.CFG_DISABLED.equals(status)) {
                if (!Constants.CFG_ENABLED.equals(status)) {
                    throw new ForbiddenException("Invalid profile mapping status: " + status);
                }

                // if user doesn't have rights, set to pending
                Principal principal = servletRequest.getUserPrincipal();
                if (database.requiresApproval() && !database.canApprove(principal)) {
                    status = Constants.CFG_PENDING_APPROVAL;
                }

                // enable profile mapping
                record.setStatus(status);
            }

            // update properties if specified
            Map<String, String> properties = profileMappingData.getProperties();
            if (properties != null) {
                record.setProperties(properties);
            }

            database.updateRecord(profileMappingID, record);

            profileMappingData = createProfileMappingData(database.getRecord(profileMappingID));

            return createOKResponse(profileMappingData);

        } catch (PKIException e) {
            CMS.debug("ProfileMappingService: " + e);
            throw e;

        } catch (Exception e) {
            CMS.debug(e);
            throw new PKIException(e);
        }
    }

    @Override
    public Response changeStatus(String profileMappingID, String action) {

        if (profileMappingID == null) throw new BadRequestException("Profile mapping ID is null.");
        if (action == null) throw new BadRequestException("Action is null.");

        CMS.debug("ProfileMappingService.changeStatus(\"" + profileMappingID + "\", \"" + action + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            ProfileMappingDatabase database = subsystem.getProfileMappingDatabase();

            ProfileMappingRecord record = database.getRecord(profileMappingID);
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
                        throw new BadRequestException("Invalid action: " + action);
                    }

                } else {
                    if ("enable".equals(action)) {
                        status = Constants.CFG_ENABLED;

                    } else {
                        throw new BadRequestException("Invalid action: " + action);
                    }
                }

            } else if (Constants.CFG_ENABLED.equals(status)) {

                if ("disable".equals(action)) {
                    status = Constants.CFG_DISABLED;

                } else {
                    throw new BadRequestException("Invalid action: " + action);
                }

            } else if (Constants.CFG_PENDING_APPROVAL.equals(status)) {

                if ("approve".equals(action) && canApprove) {
                    status = Constants.CFG_ENABLED;

                } else if ("reject".equals(action) && canApprove) {
                    status = Constants.CFG_DISABLED;

                } else if ("cancel".equals(action) && !canApprove) {
                    status = Constants.CFG_DISABLED;

                } else {
                    throw new BadRequestException("Invalid action: " + action);
                }

            } else {
                throw new PKIException("Invalid profile mapping status: " + status);
            }

            record.setStatus(status);
            database.updateRecord(profileMappingID, record);

            ProfileMappingData profileMappingData = createProfileMappingData(database.getRecord(profileMappingID));

            return createOKResponse(profileMappingData);

        } catch (PKIException e) {
            CMS.debug("ProfileMappingService: " + e);
            throw e;

        } catch (Exception e) {
            CMS.debug(e);
            throw new PKIException(e);
        }
    }

    @Override
    public Response removeProfileMapping(String profileMappingID) {

        CMS.debug("ProfileMappingService.removeProfileMapping(\"" + profileMappingID + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            ProfileMappingDatabase database = subsystem.getProfileMappingDatabase();

            ProfileMappingRecord record = database.getRecord(profileMappingID);
            String status = record.getStatus();

            if (!Constants.CFG_DISABLED.equals(status)) {
                throw new ForbiddenException("Unable to delete profile mapping " + profileMappingID);
            }

            database.removeRecord(profileMappingID);

            return createNoContentResponse();

        } catch (PKIException e) {
            CMS.debug("ProfileMappingService: " + e);
            throw e;

        } catch (Exception e) {
            CMS.debug(e);
            throw new PKIException(e);
        }
    }
}
