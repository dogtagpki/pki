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
import java.util.regex.Pattern;

import javax.ws.rs.core.Response;

import org.apache.commons.lang3.StringUtils;
import org.dogtagpki.server.tps.TPSSubsystem;
import org.dogtagpki.server.tps.config.ProfileDatabase;
import org.dogtagpki.server.tps.config.ProfileRecord;

import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.certsrv.base.Link;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.tps.profile.ProfileCollection;
import com.netscape.certsrv.tps.profile.ProfileData;
import com.netscape.certsrv.tps.profile.ProfileResource;
import com.netscape.cms.servlet.base.SubsystemService;
import com.netscape.cmscore.apps.CMS;

/**
 * @author Endi S. Dewata
 */
public class TPSProfileService extends SubsystemService implements ProfileResource {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(TPSProfileService.class);

    public static Pattern PROFILE_ID_PATTERN = Pattern.compile("^[a-zA-Z0-9_]+$");
    public static Pattern PROPERTY_NAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_\\.]+$");

    public ProfileData createProfileData(ProfileRecord profileRecord) throws UnsupportedEncodingException {

        String profileID = profileRecord.getID();

        ProfileData profileData = new ProfileData();
        profileData.setID(profileID);
        profileData.setProfileID(profileID);
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
    public Response findProfiles(String filter, Integer start, Integer size) {

        logger.info("TPSProfileService: Searching for profiles with filter " + filter);

        if (filter != null && filter.length() < MIN_FILTER_LENGTH) {
            throw new BadRequestException("Filter is too short.");
        }

        start = start == null ? 0 : start;
        size = size == null ? DEFAULT_SIZE : size;

        org.dogtagpki.server.tps.TPSEngine engine = org.dogtagpki.server.tps.TPSEngine.getInstance();
        try {
            TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
            ProfileDatabase database = subsystem.getProfileDatabase();

            Iterator<ProfileRecord> profiles = database.findRecords(filter).iterator();

            ProfileCollection response = new ProfileCollection();
            int i = 0;

            // skip to the start of the page
            for (; i < start && profiles.hasNext(); i++)
                profiles.next();

            // return entries up to the page size
            for (; i < start + size && profiles.hasNext(); i++) {
                response.addEntry(createProfileData(profiles.next()));
            }

            // count the total entries
            for (; profiles.hasNext(); i++)
                profiles.next();
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
            logger.error("TPSProfileService: " + e.getMessage(), e);
            throw e;

        } catch (Exception e) {
            logger.error("TPSProfileService: " + e.getMessage(), e);
            throw new PKIException(e);
        }
    }

    @Override
    public Response getProfile(String profileID) {

        logger.info("TPSProfileService: Retrieving profile " + profileID);

        if (profileID == null) {
            throw new BadRequestException("Missing profile ID");
        }

        org.dogtagpki.server.tps.TPSEngine engine = org.dogtagpki.server.tps.TPSEngine.getInstance();
        try {
            TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
            ProfileDatabase database = subsystem.getProfileDatabase();

            return createOKResponse(createProfileData(database.getRecord(profileID)));

        } catch (PKIException e) {
            logger.error("TPSProfileService: " + e.getMessage(), e);
            throw e;

        } catch (Exception e) {
            logger.error("TPSProfileService: " + e.getMessage(), e);
            throw new PKIException(e);
        }
    }

    @Override
    public Response addProfile(ProfileData profileData) {

        String method = "TPSProfileService.addProfile";

        if (profileData == null) {
            auditConfigTokenGeneral(ILogger.FAILURE, method, null, "Missing profile data");
            throw new BadRequestException("Missing profile data");
        }

        String id = profileData.getID();
        if (id == null) {
            id = profileData.getProfileID();
        }

        logger.info("TPSProfileService: Adding profile " + id);

        if (!PROFILE_ID_PATTERN.matcher(id).matches()) {
            throw new BadRequestException("Invalid profile ID: " + id);
        }

        Map<String, String> properties = profileData.getProperties();
        for (String name : properties.keySet()) {
            if (!PROPERTY_NAME_PATTERN.matcher(name).matches()) {
                throw new BadRequestException("Invalid profile property: " + name);
            }
        }

        org.dogtagpki.server.tps.TPSEngine engine = org.dogtagpki.server.tps.TPSEngine.getInstance();
        try {
            TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
            ProfileDatabase database = subsystem.getProfileDatabase();

            String status = profileData.getStatus();
            Principal principal = servletRequest.getUserPrincipal();

            boolean statusChanged = false;
            if (StringUtils.isEmpty(status) || database.requiresApproval() && !database.canApprove(principal)) {
                // if status is unspecified or user doesn't have rights to approve, the entry is disabled
                status = Constants.CFG_DISABLED;
                profileData.setStatus(status);
                statusChanged = true;
            }

            database.addRecord(id, createProfileRecord(profileData));

            profileData = createProfileData(database.getRecord(id));

            //Map<String, String> properties = database.getRecord(profileData.getID()).getProperties();
            if (statusChanged) {
                properties.put("Status", status);
            }
            auditTPSProfileChange(ILogger.SUCCESS, method, id, properties, null);

            String profileID = URLEncoder.encode(profileData.getID(), "UTF-8");
            URI uri = uriInfo
                    .getBaseUriBuilder()
                    .path(ProfileResource.class)
                    .path("{profileID}")
                    .build(profileID);
            return createCreatedResponse(profileData, uri);

        } catch (PKIException e) {
            logger.error("TPSProfileService: " + e.getMessage(), e);
            auditTPSProfileChange(ILogger.FAILURE, method, id, null, e.toString());
            throw e;

        } catch (Exception e) {
            logger.error("TPSProfileService: " + e.getMessage(), e);
            auditTPSProfileChange(ILogger.FAILURE, method, id, null, e.toString());
            throw new PKIException(e);
        }
    }

    @Override
    public Response updateProfile(String profileID, ProfileData profileData) {

        logger.info("TPSProfileService: Updating profile " + profileID);
        String method = "TPSProfileService.updateProfile";

        if (profileID == null) {
            auditConfigTokenGeneral(ILogger.FAILURE, method, null, "Missing profile ID");
            throw new BadRequestException("Missing profile ID");
        }

        if (profileData == null) {
            auditConfigTokenGeneral(ILogger.FAILURE, method, null, "Missing profile data");
            throw new BadRequestException("Missing profile data");
        }

        Map<String, String> properties = profileData.getProperties();
        for (String name : properties.keySet()) {
            if (!PROPERTY_NAME_PATTERN.matcher(name).matches()) {
                throw new BadRequestException("Invalid profile property: " + name);
            }
        }

        org.dogtagpki.server.tps.TPSEngine engine = org.dogtagpki.server.tps.TPSEngine.getInstance();
        try {
            TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
            ProfileDatabase database = subsystem.getProfileDatabase();

            ProfileRecord record = database.getRecord(profileID);

            // only disabled profile can be updated
            if (!Constants.CFG_DISABLED.equals(record.getStatus())) {
                Exception e = new ForbiddenException("Unable to update profile " + profileID);
                auditTPSProfileChange(ILogger.FAILURE, method, profileID,
                        profileData.getProperties(), e.toString());
                throw e;
            }

            // update status if specified
            String status = profileData.getStatus();
            boolean statusChanged = false;
            if (status != null && !Constants.CFG_DISABLED.equals(status)) {
                if (!Constants.CFG_ENABLED.equals(status)) {
                    Exception e = new ForbiddenException("Invalid profile status: " + status);
                    auditTPSProfileChange(ILogger.FAILURE, method, profileID,
                            profileData.getProperties(), e.toString());
                    throw e;
                }

                // if user doesn't have rights, set to pending
                Principal principal = servletRequest.getUserPrincipal();
                if (database.requiresApproval() && !database.canApprove(principal)) {
                    status = Constants.CFG_PENDING_APPROVAL;
                }

                // enable profile
                record.setStatus(status);
                statusChanged = true;
            }

            // update properties if specified
            if (properties != null) {
                record.setProperties(properties);
                if (statusChanged) {
                    properties.put("Status", status);
                }
            }

            database.updateRecord(profileID, record);

            profileData = createProfileData(database.getRecord(profileID));

            auditTPSProfileChange(ILogger.SUCCESS, method, profileData.getID(), properties, null);

            return createOKResponse(profileData);

        } catch (PKIException e) {
            logger.error("TPSProfileService: " + e.getMessage(), e);
            auditTPSProfileChange(ILogger.FAILURE, method, profileID, profileData.getProperties(), e.toString());
            throw e;

        } catch (Exception e) {
            logger.error("TPSProfileService: " + e.getMessage(), e);
            auditTPSProfileChange(ILogger.FAILURE, method, profileID, profileData.getProperties(), e.toString());
            throw new PKIException(e);
        }
    }

    @Override
    public Response changeStatus(String profileID, String action) {

        logger.info("TPSProfileService: Changing profile " + profileID + " status: " + action);
        String method = "TPSProfileService.changeStatus";

        Map<String, String> auditModParams = new HashMap<>();

        if (profileID == null) {
            auditConfigTokenGeneral(ILogger.FAILURE, method, null, "Missin profile ID");
            throw new BadRequestException("Missing profile ID");
        }
        auditModParams.put("profileID", profileID);

        if (action == null) {
            auditConfigTokenGeneral(ILogger.FAILURE, method, auditModParams, "Missing action");
            throw new BadRequestException("Missing action");
        }
        auditModParams.put("Action", action);

        org.dogtagpki.server.tps.TPSEngine engine = org.dogtagpki.server.tps.TPSEngine.getInstance();
        try {
            TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
            ProfileDatabase database = subsystem.getProfileDatabase();

            ProfileRecord record = database.getRecord(profileID);
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
                        auditTPSProfileChange(ILogger.FAILURE, method, profileID,
                                auditModParams, e.toString());
                        throw e;
                    }

                } else {
                    if ("enable".equals(action)) {
                        status = Constants.CFG_ENABLED;

                    } else {
                        Exception e = new BadRequestException("Invalid action: " + action);
                        auditTPSProfileChange(ILogger.FAILURE, method, profileID,
                                auditModParams, e.toString());
                        throw e;
                    }
                }

            } else if (Constants.CFG_ENABLED.equals(status)) {

                if ("disable".equals(action)) {
                    status = Constants.CFG_DISABLED;

                } else {
                    Exception e = new BadRequestException("Invalid action: " + action);
                    auditTPSProfileChange(ILogger.FAILURE, method, profileID,
                            auditModParams, e.toString());
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
                    auditTPSProfileChange(ILogger.FAILURE, method, profileID,
                            auditModParams, e.toString());
                    throw e;
                }

            } else {
                Exception e = new PKIException("Invalid profile status: " + status);
                auditTPSProfileChange(ILogger.FAILURE, method, profileID,
                        auditModParams, e.toString());
                throw e;
            }

            record.setStatus(status);
            database.updateRecord(profileID, record);

            ProfileData profileData = createProfileData(database.getRecord(profileID));
            auditModParams.put("Status", status);
            auditTPSProfileChange(ILogger.SUCCESS, method, profileID, auditModParams, null);

            return createOKResponse(profileData);

        } catch (PKIException e) {
            logger.error("TPSProfileService: " + e.getMessage(), e);
            auditConfigTokenGeneral(ILogger.FAILURE, method,
                    auditModParams, e.toString());
            throw e;

        } catch (Exception e) {
            logger.error("TPSProfileService: " + e.getMessage(), e);
            auditConfigTokenGeneral(ILogger.FAILURE, method,
                    auditModParams, e.toString());
            throw new PKIException(e);
        }
    }

    @Override
    public Response removeProfile(String profileID) {

        logger.info("TPSProfileService: Removing profile " + profileID);
        String method = "TPSProfileService.removeProfile";

        Map<String, String> auditModParams = new HashMap<>();

        if (profileID == null) {
            auditConfigTokenGeneral(ILogger.FAILURE, method, null,
                    "Profile ID is null.");
            throw new BadRequestException("Profile ID is null.");
        }
        auditModParams.put("profileID", profileID);

        org.dogtagpki.server.tps.TPSEngine engine = org.dogtagpki.server.tps.TPSEngine.getInstance();
        try {
            TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
            ProfileDatabase database = subsystem.getProfileDatabase();

            ProfileRecord record = database.getRecord(profileID);
            String status = record.getStatus();

            if (!Constants.CFG_DISABLED.equals(status)) {
                Exception e = new ForbiddenException("Profile " + profileID + " is not disabled");
                auditTPSProfileChange(ILogger.FAILURE, method, profileID,
                        auditModParams, e.toString());
                throw e;
            }

            database.removeRecord(profileID);
            auditTPSProfileChange(ILogger.SUCCESS, method, profileID, null, null);

            return createNoContentResponse();

        } catch (PKIException e) {
            logger.error("TPSProfileService: " + e.getMessage(), e);
            auditTPSProfileChange(ILogger.FAILURE, method, profileID,
                    auditModParams, e.toString());
            throw e;

        } catch (Exception e) {
            logger.error("TPSProfileService: " + e.getMessage(), e);
            auditTPSProfileChange(ILogger.FAILURE, method, profileID,
                    auditModParams, e.toString());
            throw new PKIException(e);
        }
    }

    /**
     * Service can be any of the methods offered
     */
    public void auditTPSProfileChange(String status, String service, String profileID, Map<String, String> params,
            String info) {

        String msg = CMS.getLogMessage(
                AuditEvent.CONFIG_TOKEN_PROFILE,
                servletRequest.getUserPrincipal().getName(),
                status,
                service,
                profileID,
                auditor.getParamString(params),
                info);
        signedAuditLogger.log(msg);
    }
}
