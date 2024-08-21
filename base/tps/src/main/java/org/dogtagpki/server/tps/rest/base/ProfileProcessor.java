//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.rest.base;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;
import org.dogtagpki.server.rest.v2.PKIServlet;
import org.dogtagpki.server.tps.TPSEngine;
import org.dogtagpki.server.tps.TPSSubsystem;
import org.dogtagpki.server.tps.config.ProfileDatabase;
import org.dogtagpki.server.tps.config.ProfileRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.tps.profile.ProfileCollection;
import com.netscape.certsrv.tps.profile.ProfileData;
import com.netscape.certsrv.user.UserResource;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.logging.Auditor;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 * @author Endi S. Dewata
 */
public class ProfileProcessor {
    private static final Logger logger = LoggerFactory.getLogger(ProfileProcessor.class);
    private static final Pattern PROFILE_ID_PATTERN = Pattern.compile("^[a-zA-Z0-9_]+$");
    private static final Pattern PROPERTY_NAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_\\.]+$");

    private TPSSubsystem subsystem;
    private ProfileDatabase database;
    private Auditor auditor;

    public ProfileProcessor(TPSEngine engine) {
        subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
        database = subsystem.getProfileDatabase();
        auditor = engine.getAuditor();
    }

    public ProfileCollection findProfiles(List<String> authorizedProfiles, String filter, int start, int size) {
        String method = "ProfileProcessor.findProfiles:";

        if (filter != null && filter.length() < PKIServlet.MIN_FILTER_LENGTH) {
            throw new BadRequestException(method + "Filter is too short.");
        }
        logger.info("{} Searching for profiles with filter {}", method, filter);

        try {

            Collection<ProfileRecord> profiles = new ArrayList<>();
            if (authorizedProfiles != null) {

                Collection<ProfileRecord> filteredProfiles = database.findRecords(filter);

                if (authorizedProfiles.contains(UserResource.ALL_PROFILES)) {
                    logger.debug("{} User allowed to access all profiles", method);
                    profiles.addAll(filteredProfiles);

                } else {
                    for (ProfileRecord profile : filteredProfiles) {
                        if (authorizedProfiles.contains(profile.getID())) {
                            logger.debug("{} User allowed to access profile {}", method, profile.getID());
                            profiles.add(profile);
                        }
                    }
                }
            }
            Iterator<ProfileRecord> profileIterator = profiles.iterator();

            ProfileCollection response = new ProfileCollection();
            int i = 0;

            // skip to the start of the page
            for (; i < start && profileIterator.hasNext(); i++)
                profileIterator.next();

            // return entries up to the page size
            for (; i < start + size && profileIterator.hasNext(); i++) {
                response.addEntry(createProfileData(profileIterator.next()));
            }

            // count the total entries
            for (; profileIterator.hasNext(); i++)
                profileIterator.next();
            response.setTotal(i);

            return response;

        } catch (PKIException e) {
            logger.error(method + e.getMessage(), e);
            throw e;

        } catch (Exception e) {
            logger.error(method + e.getMessage(), e);
            throw new PKIException(e);
        }
    }

    public ProfileData addProfile(Principal principal, ProfileData profileData) {
        String method = "ProfileProcessor.addProfile:";

        if (profileData == null) {
            auditConfigTokenGeneral(principal, ILogger.FAILURE, method, null, "Missing profile data");
            throw new BadRequestException(method + "Missing profile data");
        }

        String id = profileData.getID();
        if (id == null) {
            id = profileData.getProfileID();
        }

        logger.info("{} Adding profile {}", method, id);

        if (!PROFILE_ID_PATTERN.matcher(id).matches()) {
            throw new BadRequestException("Invalid profile ID: " + id);
        }

        Map<String, String> properties = profileData.getProperties();
        for (String name : properties.keySet()) {
            if (!PROPERTY_NAME_PATTERN.matcher(name).matches()) {
                throw new BadRequestException(method + "Invalid profile property: " + name);
            }
        }
        try {
            String status = profileData.getStatus();
            boolean statusChanged = false;
            if (StringUtils.isEmpty(status) || database.requiresApproval() && !database.canApprove(principal)) {
                // if status is unspecified or user doesn't have rights to approve, the entry is disabled
                status = Constants.CFG_DISABLED;
                profileData.setStatus(status);
                statusChanged = true;
            }
            database.addRecord(id, createProfileRecord(profileData));

            profileData = createProfileData(database.getRecord(id));

            if (statusChanged) {
                properties.put("Status", status);
            }
            auditTPSProfileChange(principal, ILogger.SUCCESS, method, id, properties, null);

            return profileData;

        } catch (PKIException e) {
            logger.error(method + e.getMessage(), e);
            auditTPSProfileChange(principal, ILogger.FAILURE, method, id, null, e.toString());
            throw e;

        } catch (Exception e) {
            logger.error(method + e.getMessage(), e);
            auditTPSProfileChange(principal, ILogger.FAILURE, method, id, null, e.toString());
            throw new PKIException(e);
        }
    }

    public ProfileData getProfile(List<String> authorizedProfiles, String profileID) {
        String method = "ProfileProcessor.getProfile:";
        String msg = "";
        logger.info("{} Retrieving profile {}", method, profileID);

        if (profileID == null) {
            throw new BadRequestException(method + "Missing profile ID");
        }
        try {
           if ((authorizedProfiles== null) || (!authorizedProfiles.contains(UserResource.ALL_PROFILES) && !authorizedProfiles.contains(profileID))) {
                msg = "profile record restricted for profileID:" + profileID;
                logger.debug("{} {}", method, msg);
                throw new PKIException(msg);
            }
            ProfileRecord profileRecord = database.getRecord(profileID);
            return createProfileData(profileRecord);

        } catch (PKIException e) {
            logger.error(method + e.getMessage(), e);
            throw e;

        } catch (Exception e) {
            logger.error(method + e.getMessage(), e);
            throw new PKIException(e);
        }
    }

    public ProfileData updateProfile(Principal principal, List<String> authorizedProfiles, String profileID, ProfileData profileData) {
        String method = "ProfileProcessor.updateProfile:";
        String msg = "";

        if (profileID == null) {
            auditConfigTokenGeneral(principal, ILogger.FAILURE, method, null, "Missing profile ID");
            throw new BadRequestException("Missing profile ID");
        }
        logger.info("{} Updating profile {}", method, profileID);

        if (profileData == null) {
            auditConfigTokenGeneral(principal, ILogger.FAILURE, method, null, "Missing profile data");
            throw new BadRequestException("Missing profile data");
        }

        Map<String, String> properties = profileData.getProperties();
        for (String name : properties.keySet()) {
            if (!PROPERTY_NAME_PATTERN.matcher(name).matches()) {
                throw new BadRequestException("Invalid profile property: " + name);
            }
        }
        try {
            if ((authorizedProfiles== null) || (!authorizedProfiles.contains(UserResource.ALL_PROFILES) && !authorizedProfiles.contains(profileID))) {
                msg = "profile record restricted for profileID:" + profileID;
                logger.debug("{} {}", method,  msg);

                throw new PKIException(msg);
            }
            ProfileRecord pRecord = database.getRecord(profileID);

            // only disabled profile can be updated
            if (!Constants.CFG_DISABLED.equals(pRecord.getStatus())) {
                Exception e = new ForbiddenException("Unable to update profile " + profileID);
                auditTPSProfileChange(principal, ILogger.FAILURE, method, profileID,
                        profileData.getProperties(), e.toString());
                throw e;
            }

            // update status if specified
            String status = profileData.getStatus();
            boolean statusChanged = false;
            if (status != null && !Constants.CFG_DISABLED.equals(status)) {
                if (!Constants.CFG_ENABLED.equals(status)) {
                    Exception e = new ForbiddenException(method + "Invalid profile status: " + status);
                    auditTPSProfileChange(principal, ILogger.FAILURE, method, profileID,
                            profileData.getProperties(), e.toString());
                    throw e;
                }

                // if user doesn't have rights, set to pending
                if (database.requiresApproval() && !database.canApprove(principal)) {
                    status = Constants.CFG_PENDING_APPROVAL;
                }

                // enable profile
                pRecord.setStatus(status);
                statusChanged = true;
            }

            // update properties if specified
            if (properties != null) {
                pRecord.setProperties(properties);
                if (statusChanged) {
                    properties.put("Status", status);
                }
            }

            database.updateRecord(profileID, pRecord);

            profileData = createProfileData(database.getRecord(profileID));

            auditTPSProfileChange(principal, ILogger.SUCCESS, method, profileData.getID(), properties, null);

            return profileData;

        } catch (PKIException e) {
            logger.error(method + e.getMessage(), e);
            auditTPSProfileChange(principal, ILogger.FAILURE, method, profileID, profileData.getProperties(), e.toString());
            throw e;

        } catch (Exception e) {
            logger.error(method + e.getMessage(), e);
            auditTPSProfileChange(principal, ILogger.FAILURE, method, profileID, profileData.getProperties(), e.toString());
            throw new PKIException(e);
        }
    }

    public ProfileData changeStatus(Principal principal, List<String> authorizedProfiles, String profileID, String action) {
        String method = "ProfileProcessor.changeStatus:";
        String msg = "";

        Map<String, String> auditModParams = new HashMap<>();

        if (profileID == null) {
            auditConfigTokenGeneral(principal, ILogger.FAILURE, method, null, "Missin profile ID");
            throw new BadRequestException("Missing profile ID");
        }
        auditModParams.put("profileID", profileID);

        if (action == null) {
            auditConfigTokenGeneral(principal, ILogger.FAILURE, method, auditModParams, "Missing action");
            throw new BadRequestException("Missing action");
        }
        auditModParams.put("Action", action);
        logger.info("{} Changing profile {} status: {}", method, profileID, action);

        try {
            if ((authorizedProfiles== null) || (!authorizedProfiles.contains(UserResource.ALL_PROFILES) && !authorizedProfiles.contains(profileID))) {
                msg = "profile record restricted for profileID:" + profileID;
                logger.debug("{} {}", method, msg);

                throw new PKIException(msg);
            }

            ProfileRecord pRecord = database.getRecord(profileID);
            String status = pRecord.getStatus();

            boolean canApprove = database.canApprove(principal);

            if (Constants.CFG_DISABLED.equals(status)) {

                if (database.requiresApproval()) {

                    if ("submit".equals(action) && !canApprove) {
                        status = Constants.CFG_PENDING_APPROVAL;

                    } else if ("enable".equals(action) && canApprove) {
                        status = Constants.CFG_ENABLED;

                    } else {
                        Exception e = new BadRequestException(method + "Invalid action: " + action);
                        auditTPSProfileChange(principal, ILogger.FAILURE, method, profileID,
                                auditModParams, e.toString());
                        throw e;
                    }

                } else {
                    if ("enable".equals(action)) {
                        status = Constants.CFG_ENABLED;

                    } else {
                        Exception e = new BadRequestException(method + "Invalid action: " + action);
                        auditTPSProfileChange(principal, ILogger.FAILURE, method, profileID,
                                auditModParams, e.toString());
                        throw e;
                    }
                }

            } else if (Constants.CFG_ENABLED.equals(status)) {

                if ("disable".equals(action)) {
                    status = Constants.CFG_DISABLED;

                } else {
                    Exception e = new BadRequestException(method + "Invalid action: " + action);
                    auditTPSProfileChange(principal, ILogger.FAILURE, method, profileID,
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
                    Exception e = new BadRequestException(method + "Invalid action: " + action);
                    auditTPSProfileChange(principal, ILogger.FAILURE, method, profileID,
                            auditModParams, e.toString());
                    throw e;
                }

            } else {
                Exception e = new PKIException(method + "Invalid profile status: " + status);
                auditTPSProfileChange(principal, ILogger.FAILURE, method, profileID,
                        auditModParams, e.toString());
                throw e;
            }

            pRecord.setStatus(status);
            database.updateRecord(profileID, pRecord);

            ProfileData profileData = createProfileData(database.getRecord(profileID));
            auditModParams.put("Status", status);
            auditTPSProfileChange(principal, ILogger.SUCCESS, method, profileID, auditModParams, null);

            return profileData;

        } catch (PKIException e) {
            logger.error(method + e.getMessage(), e);
            auditConfigTokenGeneral(principal, ILogger.FAILURE, method,
                    auditModParams, e.toString());
            throw e;

        } catch (Exception e) {
            logger.error(method + e.getMessage(), e);
            auditConfigTokenGeneral(principal, ILogger.FAILURE, method,
                    auditModParams, e.toString());
            throw new PKIException(e);
        }
    }

    public void removeProfile(Principal principal, String profileID) {
        String method = "ProfileProcessor.removeProfile:";

        Map<String, String> auditModParams = new HashMap<>();

        if (profileID == null) {
            auditConfigTokenGeneral(principal, ILogger.FAILURE, method, null,
                    "Profile ID is null.");
            throw new BadRequestException("Profile ID is null.");
        }
        auditModParams.put("profileID", profileID);
        logger.info("{} Removing profile {}", method, profileID);

        try {
            ProfileRecord pRecord = database.getRecord(profileID);
            String status = pRecord.getStatus();

            if (!Constants.CFG_DISABLED.equals(status)) {
                Exception e = new ForbiddenException("Profile " + profileID + " is not disabled");
                auditTPSProfileChange(principal, ILogger.FAILURE, method, profileID,
                        auditModParams, e.toString());
                throw e;
            }

            database.removeRecord(profileID);
            auditTPSProfileChange(principal, ILogger.SUCCESS, method, profileID, null, null);

        } catch (PKIException e) {
            logger.error(method + e.getMessage(), e);
            auditTPSProfileChange(principal, ILogger.FAILURE, method, profileID,
                    auditModParams, e.toString());
            throw e;

        } catch (Exception e) {
            logger.error(method + e.getMessage(), e);
            auditTPSProfileChange(principal, ILogger.FAILURE, method, profileID,
                    auditModParams, e.toString());
            throw new PKIException(e);
        }
    }

    private ProfileData createProfileData(ProfileRecord profileRecord) {

        String profileID = profileRecord.getID();

        ProfileData profileData = new ProfileData();
        profileData.setID(profileID);
        profileData.setProfileID(profileID);
        profileData.setStatus(profileRecord.getStatus());
        profileData.setProperties(profileRecord.getProperties());

        return profileData;
    }

    private ProfileRecord createProfileRecord(ProfileData profileData) {

        ProfileRecord profileRecord = new ProfileRecord();
        profileRecord.setID(profileData.getID());
        profileRecord.setStatus(profileData.getStatus());
        profileRecord.setProperties(profileData.getProperties());

        return profileRecord;
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

    private void auditTPSProfileChange(Principal principal, String status, String service, String profileID, Map<String, String> params,
            String info) {
        String msg = CMS.getLogMessage(
                AuditEvent.CONFIG_TOKEN_PROFILE,
                principal.getName(),
                status,
                service,
                profileID,
                auditor.getParamString(params),
                info);
        auditor.log(msg);
    }
}
