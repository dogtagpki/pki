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
import org.dogtagpki.server.tps.config.ProfileMappingDatabase;
import org.dogtagpki.server.tps.config.ProfileMappingRecord;
import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.tps.profile.ProfileMappingCollection;
import com.netscape.certsrv.tps.profile.ProfileMappingData;
import com.netscape.certsrv.tps.profile.ProfileMappingResource;
import com.netscape.cms.servlet.base.SubsystemService;

/**
 * @author Endi S. Dewata
 */
public class ProfileMappingService extends SubsystemService implements ProfileMappingResource {

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

    public ProfileMappingData createProfileMappingData(ProfileMappingRecord profileMappingRecord)
            throws UnsupportedEncodingException {

        String profileMappingID = profileMappingRecord.getID();

        ProfileMappingData profileMappingData = new ProfileMappingData();
        profileMappingData.setID(profileMappingID);
        profileMappingData.setStatus(profileMappingRecord.getStatus());
        profileMappingData.setProperties(profileMappingRecord.getProperties());

        profileMappingID = URLEncoder.encode(profileMappingID, "UTF-8");
        URI uri = uriInfo.getBaseUriBuilder().path(ProfileMappingResource.class).path("{profileMappingID}")
                .build(profileMappingID);
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
            TPSSubsystem subsystem = (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);
            ProfileMappingDatabase database = subsystem.getProfileMappingDatabase();

            Iterator<ProfileMappingRecord> profileMappings = database.findRecords(filter).iterator();

            ProfileMappingCollection response = new ProfileMappingCollection();
            int i = 0;

            // skip to the start of the page
            for (; i < start && profileMappings.hasNext(); i++)
                profileMappings.next();

            // return entries up to the page size
            for (; i < start + size && profileMappings.hasNext(); i++) {
                response.addEntry(createProfileMappingData(profileMappings.next()));
            }

            // count the total entries
            for (; profileMappings.hasNext(); i++)
                profileMappings.next();
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
            TPSSubsystem subsystem = (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);
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
        String method = "ProfileMappingService.addProfileMapping";

        CMS.debug("ProfileMappingService.addProfileMapping(\"" + profileMappingData.getID() + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);
            ProfileMappingDatabase database = subsystem.getProfileMappingDatabase();

            String status = profileMappingData.getStatus();
            Principal principal = servletRequest.getUserPrincipal();

            if (StringUtils.isEmpty(status) || database.requiresApproval() && !database.canApprove(principal)) {
                // if status is unspecified or user doesn't have rights to approve, the entry is disabled
                profileMappingData.setStatus(Constants.CFG_DISABLED);
            }

            database.addRecord(profileMappingData.getID(), createProfileMappingRecord(profileMappingData));
            profileMappingData = createProfileMappingData(database.getRecord(profileMappingData.getID()));
            auditMappingResolverChange(ILogger.SUCCESS, method, profileMappingData.getID(),
                    profileMappingData.getProperties(), null);

            return createCreatedResponse(profileMappingData, profileMappingData.getLink().getHref());

        } catch (PKIException e) {
            CMS.debug("ProfileMappingService: " + e);
            auditMappingResolverChange(ILogger.FAILURE, method, profileMappingData.getID(),
                    profileMappingData.getProperties(), e.toString());
            throw e;

        } catch (Exception e) {
            CMS.debug(e);
            auditMappingResolverChange(ILogger.FAILURE, method, profileMappingData.getID(),
                    profileMappingData.getProperties(), e.toString());
            throw new PKIException(e);
        }
    }

    @Override
    public Response updateProfileMapping(String profileMappingID, ProfileMappingData profileMappingData) {
        String method = "ProfileMappingService.updateProfileMapping";

        CMS.debug("ProfileMappingService.updateProfileMapping(\"" + profileMappingID + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);
            ProfileMappingDatabase database = subsystem.getProfileMappingDatabase();

            ProfileMappingRecord record = database.getRecord(profileMappingID);

            // only disabled profile mapping can be updated
            if (!Constants.CFG_DISABLED.equals(record.getStatus())) {
                Exception e = new ForbiddenException("Unable to update profile mapping " + profileMappingID);
                auditMappingResolverChange(ILogger.FAILURE, method, profileMappingData.getID(),
                        profileMappingData.getProperties(), e.toString());
                throw e;
            }

            // update status if specified
            String status = profileMappingData.getStatus();
            boolean statusChanged = false;
            if (status != null && !Constants.CFG_DISABLED.equals(status)) {
                if (!Constants.CFG_ENABLED.equals(status)) {
                    Exception e = new ForbiddenException("Invalid profile mapping status: " + status);
                    auditMappingResolverChange(ILogger.FAILURE, method, profileMappingData.getID(),
                            profileMappingData.getProperties(), e.toString());
                    throw e;
                }

                // if user doesn't have rights, set to pending
                Principal principal = servletRequest.getUserPrincipal();
                if (database.requiresApproval() && !database.canApprove(principal)) {
                    status = Constants.CFG_PENDING_APPROVAL;
                }

                // enable profile mapping
                record.setStatus(status);
                statusChanged = true;
            }

            // update properties if specified
            Map<String, String> properties = profileMappingData.getProperties();
            if (properties != null) {
                record.setProperties(properties);
            }

            database.updateRecord(profileMappingID, record);

            profileMappingData = createProfileMappingData(database.getRecord(profileMappingID));
            if (statusChanged) {
                properties.put("Status", status);
            }
            auditMappingResolverChange(ILogger.SUCCESS, method, profileMappingData.getID(), properties, null);

            return createOKResponse(profileMappingData);

        } catch (PKIException e) {
            CMS.debug("ProfileMappingService: " + e);
            auditMappingResolverChange(ILogger.FAILURE, method, profileMappingData.getID(),
                    profileMappingData.getProperties(), e.toString());
            throw e;

        } catch (Exception e) {
            CMS.debug("ProfileMappingService: " + e);
            auditMappingResolverChange(ILogger.FAILURE, method, profileMappingData.getID(),
                    profileMappingData.getProperties(), e.toString());
            throw new PKIException(e);
        }
    }

    @Override
    public Response changeStatus(String profileMappingID, String action) {
        String method = "ProfileMappingService.changeStatus";

        Map<String, String> auditModParams = new HashMap<String, String>();

        if (profileMappingID == null) {
            auditConfigTokenGeneral(ILogger.FAILURE, method, null,
                    "Profile mapper ID is null.");
            throw new BadRequestException("Profile mapper ID is null.");
        }

        if (action == null) {
            auditConfigTokenGeneral(ILogger.FAILURE, method, auditModParams,
                    "action is null.");
            throw new BadRequestException("Action is null.");
        }
        auditModParams.put("Action", action);

        CMS.debug("ProfileMappingService.changeStatus(\"" + profileMappingID + "\", \"" + action + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);
            ProfileMappingDatabase database = subsystem.getProfileMappingDatabase();

            ProfileMappingRecord record = database.getRecord(profileMappingID);
            boolean statusChanged = false;
            String status = record.getStatus();

            Principal principal = servletRequest.getUserPrincipal();
            boolean canApprove = database.canApprove(principal);

            if (Constants.CFG_DISABLED.equals(status)) {

                if (database.requiresApproval()) {

                    if ("submit".equals(action) && !canApprove) {
                        status = Constants.CFG_PENDING_APPROVAL;
                        statusChanged = true;

                    } else if ("enable".equals(action) && canApprove) {
                        status = Constants.CFG_ENABLED;
                        statusChanged = true;

                    } else {
                        Exception e = new BadRequestException("Invalid action: " + action);
                        auditMappingResolverChange(ILogger.FAILURE, method, profileMappingID,
                                auditModParams, e.toString());
                        throw e;
                    }

                } else {
                    if ("enable".equals(action)) {
                        status = Constants.CFG_ENABLED;
                        statusChanged = true;

                    } else {
                        Exception e = new BadRequestException("Invalid action: " + action);
                        auditMappingResolverChange(ILogger.FAILURE, method, profileMappingID,
                                auditModParams, e.toString());
                        throw e;
                    }
                }

            } else if (Constants.CFG_ENABLED.equals(status)) {

                if ("disable".equals(action)) {
                    status = Constants.CFG_DISABLED;
                    statusChanged = true;

                } else {
                    Exception e = new BadRequestException("Invalid action: " + action);
                    auditMappingResolverChange(ILogger.FAILURE, method, profileMappingID,
                            auditModParams, e.toString());
                    throw e;
                }

            } else if (Constants.CFG_PENDING_APPROVAL.equals(status)) {

                if ("approve".equals(action) && canApprove) {
                    status = Constants.CFG_ENABLED;
                    statusChanged = true;

                } else if ("reject".equals(action) && canApprove) {
                    status = Constants.CFG_DISABLED;
                    statusChanged = true;

                } else if ("cancel".equals(action) && !canApprove) {
                    status = Constants.CFG_DISABLED;
                    statusChanged = true;

                } else {
                    Exception e = new BadRequestException("Invalid action: " + action);
                    auditMappingResolverChange(ILogger.FAILURE, method, profileMappingID,
                            auditModParams, e.toString());
                    throw e;
                }

            } else {
                Exception e = new PKIException("Invalid profile mapping status: " + status);
                auditMappingResolverChange(ILogger.FAILURE, method, profileMappingID,
                        auditModParams, e.toString());
                throw e;
            }

            record.setStatus(status);
            database.updateRecord(profileMappingID, record);

            ProfileMappingData profileMappingData = createProfileMappingData(database.getRecord(profileMappingID));

            if (statusChanged) {
                auditModParams.put("Status", status);
            }
            auditMappingResolverChange(ILogger.SUCCESS, method, profileMappingData.getID(), auditModParams, null);

            return createOKResponse(profileMappingData);

        } catch (PKIException e) {
            CMS.debug("ProfileMappingService: " + e);
            auditMappingResolverChange(ILogger.FAILURE, method, profileMappingID,
                    auditModParams, e.toString());
            throw e;

        } catch (Exception e) {
            CMS.debug("ProfileMappingService: " + e);
            auditMappingResolverChange(ILogger.FAILURE, method, profileMappingID,
                    auditModParams, e.toString());
            throw new PKIException(e);
        }
    }

    @Override
    public Response removeProfileMapping(String profileMappingID) {
        String method = "ProfileMappingService.removeProfileMapping";
        Map<String, String> auditModParams = new HashMap<String, String>();

        CMS.debug("ProfileMappingService.removeProfileMapping(\"" + profileMappingID + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);
            ProfileMappingDatabase database = subsystem.getProfileMappingDatabase();

            ProfileMappingRecord record = database.getRecord(profileMappingID);
            String status = record.getStatus();

            if (!Constants.CFG_DISABLED.equals(status)) {
                Exception e = new ForbiddenException("Unable to delete profile mapping " + profileMappingID);
                auditMappingResolverChange(ILogger.FAILURE, method, profileMappingID,
                        auditModParams, e.toString());
                throw e;
            }

            database.removeRecord(profileMappingID);
            auditMappingResolverChange(ILogger.SUCCESS, method, profileMappingID, null, null);

            return createNoContentResponse();

        } catch (PKIException e) {
            CMS.debug("ProfileMappingService: " + e);
            auditMappingResolverChange(ILogger.FAILURE, method, profileMappingID,
                    auditModParams, e.toString());
            throw e;

        } catch (Exception e) {
            CMS.debug("ProfileMappingService: " + e);
            auditMappingResolverChange(ILogger.FAILURE, method, profileMappingID,
                    auditModParams, e.toString());
            throw new PKIException(e);
        }
    }

    /*
     * Service can be any of the methods offered
     */
    public void auditMappingResolverChange(String status, String service, String resolverID, Map<String, String> params,
            String info) {
        String msg = CMS.getLogMessage(
                "LOGGING_SIGNED_AUDIT_CONFIG_TOKEN_MAPPING_RESOLVER_6",
                servletRequest.getUserPrincipal().getName(),
                status,
                service,
                resolverID,
                auditor.getParamString(null, params),
                info);
        auditor.log(msg);

    }

}
