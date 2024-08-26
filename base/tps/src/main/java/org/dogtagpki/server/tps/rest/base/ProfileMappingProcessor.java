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
import org.dogtagpki.server.tps.config.ProfileMappingDatabase;
import org.dogtagpki.server.tps.config.ProfileMappingRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.tps.profile.ProfileMappingCollection;
import com.netscape.certsrv.tps.profile.ProfileMappingData;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.logging.Auditor;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 * @author Endi S. Dewata
 */
public class ProfileMappingProcessor {
    private static final Logger logger = LoggerFactory.getLogger(ProfileMappingProcessor.class);

    private TPSSubsystem subsystem;
    private ProfileMappingDatabase database;
    private Auditor auditor;

    public ProfileMappingProcessor(TPSEngine engine) {
        subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
        database = subsystem.getProfileMappingDatabase();
        auditor = engine.getAuditor();
    }

    public ProfileMappingCollection findProfileMappings(String filter, int start, int size) {
        logger.debug("ProfileMappingProcessor.findProfileMappings()");

        if (filter != null && filter.length() < PKIServlet.MIN_FILTER_LENGTH) {
            throw new BadRequestException("Filter is too short.");
        }
        try {
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

            return response;

        } catch (PKIException e) {
            logger.error("ProfileMappingProcessor: " + e.getMessage(), e);
            throw e;

        } catch (Exception e) {
            logger.error("ProfileMappingProcessor: " + e.getMessage(), e);
            throw new PKIException(e);
        }
    }

    public ProfileMappingData addProfileMapping(Principal principal, ProfileMappingData profileMappingData) {
        String method = "ProfileMappingProcessor.addProfileMapping";

        logger.debug("ProfileMappingProcessor.addProfileMapping(\"{}\")", profileMappingData.getProfileMappingID());
        ProfileMappingData pmd = null;

        try {
            String status = profileMappingData.getStatus();

            if (StringUtils.isEmpty(status) || database.requiresApproval() && !database.canApprove(principal)) {
                // if status is unspecified or user doesn't have rights to approve, the entry is disabled
                profileMappingData.setStatus(Constants.CFG_DISABLED);
            }
            String id = profileMappingData.getProfileMappingID();
            database.addRecord(id, createProfileMappingRecord(profileMappingData));
            pmd = createProfileMappingData(database.getRecord(id));
            auditMappingResolverChange(principal, ILogger.SUCCESS, method, pmd.getID(),
                    profileMappingData.getProperties(), null);

            return pmd;

        } catch (PKIException e) {
            logger.error("ProfileMappingProcessor: " + e.getMessage(), e);
            auditMappingResolverChange(principal, ILogger.FAILURE, method, profileMappingData.getID(),
                    profileMappingData.getProperties(), e.toString());
            throw e;

        } catch (Exception e) {
            logger.error("ProfileMappingProcessor: " + e.getMessage(), e);
            auditMappingResolverChange(principal, ILogger.FAILURE, method, profileMappingData.getID(),
                    profileMappingData.getProperties(), e.toString());
            throw new PKIException(e);
        }
    }

    public ProfileMappingData getProfileMapping(String profileMappingID) {
        logger.debug("ProfileMappingProcessor.getProfileMapping(\"{}\")", profileMappingID);

        try {
            return createProfileMappingData(database.getRecord(profileMappingID));
        } catch (PKIException e) {
            logger.error("ProfileMappingProcessor: " + e.getMessage(), e);
            throw e;

        } catch (Exception e) {
            logger.error("ProfileMappingProcessor: " + e.getMessage(), e);
            throw new PKIException(e);
        }
    }

    public ProfileMappingData updateProfileMapping(Principal principal, String profileMappingID, ProfileMappingData profileMappingData) {
        String method = "ProfileMappingProcessor.updateProfileMapping";

        logger.debug("ProfileMappingProcessor.updateProfileMapping(\"{}\")", profileMappingID);

        try {
            ProfileMappingRecord pmRecord = database.getRecord(profileMappingID);
            // only disabled profile mapping can be updated
            if (!Constants.CFG_DISABLED.equals(pmRecord.getStatus())) {
                Exception e = new ForbiddenException("Unable to update profile mapping " + profileMappingID);
                auditMappingResolverChange(principal, ILogger.FAILURE, method, profileMappingData.getID(),
                        profileMappingData.getProperties(), e.toString());
                throw e;
            }
            // update status if specified
            String status = profileMappingData.getStatus();
            boolean statusChanged = false;
            if (status != null && !Constants.CFG_DISABLED.equals(status)) {
                if (!Constants.CFG_ENABLED.equals(status)) {
                    Exception e = new ForbiddenException("Invalid profile mapping status: " + status);
                    auditMappingResolverChange(principal, ILogger.FAILURE, method, profileMappingData.getID(),
                            profileMappingData.getProperties(), e.toString());
                    throw e;
                }
                // if user doesn't have rights, set to pending
                if (database.requiresApproval() && !database.canApprove(principal)) {
                    status = Constants.CFG_PENDING_APPROVAL;
                }
                // enable profile mapping
                pmRecord.setStatus(status);
                statusChanged = true;
            }
            // update properties if specified
            Map<String, String> properties = profileMappingData.getProperties();
            if (properties != null) {
                pmRecord.setProperties(properties);
            }

            database.updateRecord(profileMappingID, pmRecord);

            profileMappingData = createProfileMappingData(database.getRecord(profileMappingID));
            if (statusChanged) {
                if (properties == null) {
                    properties = new HashMap<>();
                }
                properties.put("Status", status);
            }
            auditMappingResolverChange(principal, ILogger.SUCCESS, method, profileMappingData.getID(), properties, null);

            return profileMappingData;

        } catch (PKIException e) {
            logger.error("ProfileMappingProcessor: " + e.getMessage(), e);
            auditMappingResolverChange(principal, ILogger.FAILURE, method, profileMappingData.getID(),
                    profileMappingData.getProperties(), e.toString());
            throw e;

        } catch (Exception e) {
            logger.error("ProfileMappingProcessor: " + e.getMessage(), e);
            auditMappingResolverChange(principal, ILogger.FAILURE, method, profileMappingData.getID(),
                    profileMappingData.getProperties(), e.toString());
            throw new PKIException(e);
        }
    }

    public ProfileMappingData changeStatus(Principal principal, String profileMappingID, String action) {
        String method = "ProfileMappingProcessor.changeStatus";

        Map<String, String> auditModParams = new HashMap<>();

        if (profileMappingID == null) {
            auditConfigTokenGeneral(principal, ILogger.FAILURE, method, null,
                    "Profile mapper ID is null.");
            throw new BadRequestException("Profile mapper ID is null.");
        }

        if (action == null) {
            auditConfigTokenGeneral(principal, ILogger.FAILURE, method, auditModParams,
                    "action is null.");
            throw new BadRequestException("Action is null.");
        }
        auditModParams.put("Action", action);

        logger.debug("ProfileMappingProcessor.changeStatus(\"{}\", \"{}\")", profileMappingID, action);
        try {
            ProfileMappingRecord pmRecord = database.getRecord(profileMappingID);
            boolean statusChanged = false;
            String status = pmRecord.getStatus();

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
                        auditMappingResolverChange(principal, ILogger.FAILURE, method, profileMappingID,
                                auditModParams, e.toString());
                        throw e;
                    }

                } else {
                    if ("enable".equals(action)) {
                        status = Constants.CFG_ENABLED;
                        statusChanged = true;

                    } else {
                        Exception e = new BadRequestException("Invalid action: " + action);
                        auditMappingResolverChange(principal, ILogger.FAILURE, method, profileMappingID,
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
                    auditMappingResolverChange(principal, ILogger.FAILURE, method, profileMappingID,
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
                    auditMappingResolverChange(principal, ILogger.FAILURE, method, profileMappingID,
                            auditModParams, e.toString());
                    throw e;
                }

            } else {
                Exception e = new PKIException("Invalid profile mapping status: " + status);
                auditMappingResolverChange(principal, ILogger.FAILURE, method, profileMappingID,
                        auditModParams, e.toString());
                throw e;
            }

            pmRecord.setStatus(status);
            database.updateRecord(profileMappingID, pmRecord);

            ProfileMappingData profileMappingData = createProfileMappingData(database.getRecord(profileMappingID));

            if (statusChanged) {
                auditModParams.put("Status", status);
            }
            auditMappingResolverChange(principal, ILogger.SUCCESS, method, profileMappingData.getID(), auditModParams, null);

            return profileMappingData;

        } catch (PKIException e) {
            logger.error("ProfileMappingProcessor: " + e.getMessage(), e);
            auditMappingResolverChange(principal, ILogger.FAILURE, method, profileMappingID,
                    auditModParams, e.toString());
            throw e;

        } catch (Exception e) {
            logger.error("ProfileMappingProcessor: " + e.getMessage(), e);
            auditMappingResolverChange(principal, ILogger.FAILURE, method, profileMappingID,
                    auditModParams, e.toString());
            throw new PKIException(e);
        }
    }

    public void removeProfileMapping(Principal principal, String profileMappingID) {
        String method = "ProfileMappingProcessor.removeProfileMapping";
        Map<String, String> auditModParams = new HashMap<>();

        logger.debug("ProfileMappingProcessor.removeProfileMapping(\"{}\")", profileMappingID);

        try {
            ProfileMappingRecord pmRecord = database.getRecord(profileMappingID);
            String status = pmRecord.getStatus();

            if (!Constants.CFG_DISABLED.equals(status)) {
                Exception e = new ForbiddenException("Unable to delete profile mapping " + profileMappingID);
                auditMappingResolverChange(principal, ILogger.FAILURE, method, profileMappingID,
                        auditModParams, e.toString());
                throw e;
            }
            database.removeRecord(profileMappingID);
            auditMappingResolverChange(principal, ILogger.SUCCESS, method, profileMappingID, null, null);
        } catch (PKIException e) {
            logger.error("ProfileMappingProcessor: " + e.getMessage(), e);
            auditMappingResolverChange(principal, ILogger.FAILURE, method, profileMappingID,
                    auditModParams, e.toString());
            throw e;

        } catch (Exception e) {
            logger.error("ProfileMappingProcessor: " + e.getMessage(), e);
            auditMappingResolverChange(principal, ILogger.FAILURE, method, profileMappingID,
                    auditModParams, e.toString());
            throw new PKIException(e);
        }
    }

    private ProfileMappingData createProfileMappingData(ProfileMappingRecord profileMappingRecord) {

        ProfileMappingData profileMappingData = new ProfileMappingData();
        profileMappingData.setID(profileMappingRecord.getID());
        profileMappingData.setProfileMappingID(profileMappingRecord.getID());
        profileMappingData.setStatus(profileMappingRecord.getStatus());
        profileMappingData.setProperties(profileMappingRecord.getProperties());
        return profileMappingData;
    }

    private ProfileMappingRecord createProfileMappingRecord(ProfileMappingData profileMappingData) {

        String id = profileMappingData.getID();
        ProfileMappingRecord profileMappingRecord = new ProfileMappingRecord();
        profileMappingRecord.setID(id == null ? profileMappingData.getProfileMappingID() : id);
        profileMappingRecord.setStatus(profileMappingData.getStatus());
        profileMappingRecord.setProperties(profileMappingData.getProperties());
        return profileMappingRecord;
    }

    private void auditMappingResolverChange(Principal principal, String status, String service, String resolverID, Map<String, String> params,
            String info) {

        String msg = CMS.getLogMessage(
                AuditEvent.CONFIG_TOKEN_MAPPING_RESOLVER,
                principal.getName(),
                status,
                service,
                resolverID,
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
