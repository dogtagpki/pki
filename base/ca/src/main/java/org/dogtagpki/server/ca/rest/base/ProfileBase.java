//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.rest.base;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Vector;

import javax.servlet.http.HttpServletRequest;

import org.apache.catalina.realm.GenericPrincipal;
import org.apache.commons.lang3.StringUtils;
import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.authorization.AuthzToken;
import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.CAEngineConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.authentication.ExternalAuthToken;
import com.netscape.certsrv.authorization.EAuthzUnknownRealm;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.ConflictingOperationException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.base.UnauthorizedException;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.common.OpDef;
import com.netscape.certsrv.common.ScopeDef;
import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.PolicyConstraint;
import com.netscape.certsrv.profile.PolicyConstraintValue;
import com.netscape.certsrv.profile.PolicyDefault;
import com.netscape.certsrv.profile.ProfileAttribute;
import com.netscape.certsrv.profile.ProfileData;
import com.netscape.certsrv.profile.ProfileDataInfo;
import com.netscape.certsrv.profile.ProfileDataInfos;
import com.netscape.certsrv.profile.ProfileInput;
import com.netscape.certsrv.profile.ProfileNotFoundException;
import com.netscape.certsrv.profile.ProfileOutput;
import com.netscape.certsrv.profile.ProfileParameter;
import com.netscape.certsrv.profile.ProfilePolicy;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.cms.profile.common.CAEnrollProfile;
import com.netscape.cms.profile.common.PolicyConstraintConfig;
import com.netscape.cms.profile.common.PolicyDefaultConfig;
import com.netscape.cms.profile.common.Profile;
import com.netscape.cms.profile.common.ProfileConfig;
import com.netscape.cms.profile.common.ProfileInputConfig;
import com.netscape.cms.profile.common.ProfileInputsConfig;
import com.netscape.cms.profile.common.ProfileOutputConfig;
import com.netscape.cms.profile.common.ProfileOutputsConfig;
import com.netscape.cms.profile.common.ProfilePolicyConfig;
import com.netscape.cms.profile.common.ProfilePolicySetConfig;
import com.netscape.cms.profile.common.ProfilePolicySetsConfig;
import com.netscape.cms.realm.PKIPrincipal;
import com.netscape.cms.servlet.profile.PolicyConstraintFactory;
import com.netscape.cms.servlet.profile.PolicyDefaultFactory;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.authorization.AuthzSubsystem;
import com.netscape.cmscore.base.SimpleProperties;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.cmscore.profile.ProfileSubsystem;
import com.netscape.cmscore.registry.PluginInfo;
import com.netscape.cmscore.registry.PluginRegistry;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 * @author alee
 */
public class ProfileBase {
    private static Logger logger = LoggerFactory.getLogger(ProfileBase.class);

    private CAEngine engine;
    private CAEngineConfig engineConfig;
    private PluginRegistry registry;
    private ProfileSubsystem ps;

    public ProfileBase(CAEngine engine) {
        this.engine = engine;
        this.engineConfig = engine.getConfig();
        this.registry = engine.getPluginRegistry();
        this.ps = engine.getProfileSubsystem();
    }

    public ProfileDataInfos listProfiles(HttpServletRequest servletRequest, int start, int size, Boolean visible, Boolean enable, String enableBy) {
        ProfileDataInfos infos = new ProfileDataInfos();
        boolean visibleOnly = isProfileAccessLimited(servletRequest.getUserPrincipal());

        if (ps == null) {
            logger.error("ProfileBase.listProfiles: ps is null");
            throw new PKIException("Error listing profiles.  Profile subsystem not available");
        }

        if (visibleOnly && visible != null && !visible.booleanValue()) {
            return infos;
        }

        Enumeration<String> e = ps.getProfileIds();
        if (e == null) {
            return infos;
        }

        List<ProfileDataInfo> results = new ArrayList<>();
        while (e.hasMoreElements()) {
            String id = e.nextElement();
            StringBuffer uri = servletRequest.getRequestURL();
            String encodedID;
            try {
                encodedID = URLEncoder.encode(id, "UTF-8");
                uri.append("/" + encodedID);
            } catch (UnsupportedEncodingException e1) {
                logger.error("ProfileBase.listProfiles: Problem to enconding profile {}", id);
            }
            try {
                ProfileDataInfo info = createProfileDataInfo(id, uri.toString(), servletRequest.getLocale());
                if (info == null ||
                        (visibleOnly && !info.getProfileVisible().booleanValue()) ||
                        (visible != null && !visible.equals(info.getProfileVisible())) ||
                        (enable != null && !enable.equals(info.getProfileEnable())) ||
                        (enableBy != null && !enableBy.equals(info.getProfileEnableBy())))
                    continue;
                results.add(info);
            } catch (EBaseException ex) {
                logger.warn("Profile: {}", ex.getMessage());
            }
        }
        int total = results.size();
        infos.setTotal(total);

        for (int i = start; i < start + size && i < total; i++) {
            infos.addEntry(results.get(i));
        }
        return infos;
    }

    public ProfileData retrieveProfile(HttpServletRequest servletRequest, String profileId) {
        boolean visibleOnly = isProfileAccessLimited(servletRequest.getUserPrincipal());
        try {
            return createProfileData(profileId, visibleOnly, servletRequest.getLocale());
        } catch (EBaseException e) {
            throw new ResourceNotFoundException("Profile not found: " + profileId);
        }
    }

    public byte[] retrieveRawProfile(HttpServletRequest servletRequest, String profileId) {
        boolean visibleOnly = isProfileAccessLimited(servletRequest.getUserPrincipal());
        Profile profile = getProfile(profileId, visibleOnly);
        ByteArrayOutputStream data = new ByteArrayOutputStream();
        // add profileId and classId "virtual" properties
        profile.getConfigStore().put("profileId", profileId);
        profile.getConfigStore().put("classId", ps.getProfileClassId(profileId));
        try {
            profile.getConfigStore().store(data);
        } catch (Exception e) {
            logger.error("ProfileBase.retrieveRawProfile: impossible to get raw data for for profile {}", profileId);
            throw new PKIException("Error getting raw profile " + profileId);
        }
        return data.toByteArray();
    }

    public String createProfile(HttpServletRequest servletRequest, ProfileData data) {

        if (data == null) {
            logger.error("createProfile: profile data is null");
            throw new BadRequestException("Unable to create profile: Invalid profile data.");
        }

        if (ps == null) {
            logger.error("createProfile: ps is null");
            throw new PKIException("Error creating profile.  Profile Service not available");
        }

        Profile profile = null;
        String profileId = data.getId();
        Map<String, String> auditParams = new LinkedHashMap<>();
        try {
            profile = ps.getProfile(profileId);
            if (profile != null) {
                throw new ConflictingOperationException("Profile already exists");
            }

            auditParams.put("class_id", data.getClassId());
            auditParams.put("name", data.getName());
            auditParams.put("description", data.getDescription());
            auditParams.put("visible", Boolean.toString(data.isVisible()));

            PluginInfo info = registry.getPluginInfo("profile", data.getClassId());

            profile = ps.createProfile(profileId, data.getClassId(), info.getClassName());
            profile.setName(servletRequest.getLocale(), data.getName());
            profile.setDescription(servletRequest.getLocale(), data.getDescription());
            profile.setVisible(data.isVisible());
            ps.commitProfile(profileId);

            if (profile instanceof CAEnrollProfile) {
                // populates profile specific plugins such as
                // policies, inputs and outputs with defaults
                ((CAEnrollProfile) profile).populate();
            }

            auditProfileChange(
                    ScopeDef.SC_PROFILE_RULES,
                    OpDef.OP_ADD,
                    profileId,
                    ILogger.SUCCESS,
                    auditParams);

            changeProfileData(data, profile, servletRequest.getLocale());

            return profileId;

        } catch (EBaseException e) {
            logger.error("createProfile: error creating profile: " + e.getMessage(), e);

            auditProfileChange(
                    ScopeDef.SC_PROFILE_RULES,
                    OpDef.OP_ADD,
                    profileId,
                    ILogger.FAILURE,
                    auditParams);

            throw new PKIException("Error in creating profile", e);
        }
    }

    public String createProfile(byte[] data) {
        if (data == null) {
            String message = "Unable to create profile: Missing profile data";
            logger.error(message);
            throw new BadRequestException(message);
        }

        if (ps == null) {
            String message = "Unable to create profile: Profile service not available";
            logger.error(message);
            throw new PKIException(message);
        }

        logger.info("ProfileBase: Creating profile from raw data");

        Map<String, String> auditParams = new LinkedHashMap<>();
        String profileId;
        String classId;

        SimpleProperties properties = new SimpleProperties();
        try {
            // load data and read profileId and classId
            properties.load(new ByteArrayInputStream(data));
            profileId = properties.remove("profileId");
            classId = properties.remove("classId");

        } catch (IOException e) {
            String message = "Unable to create profile: " + e.getMessage();
            logger.error(message, e);
            throw new BadRequestException(message, e);
        }

        if (profileId == null) {
            String message = "Unable to create profile: Missing profile ID";
            logger.error(message);
            throw new BadRequestException(message);
        }

        if (classId == null) {
            String message = "Unable to create profile: Missing class ID";
            logger.error(message);
            throw new BadRequestException(message);
        }

        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            properties.store(out, null);
            data = out.toByteArray();  // original data sans profileId, classId

            Profile profile = ps.getProfile(profileId);
            if (profile != null) {
                String message = "Unable to create profile: Profile already exists";
                logger.error(message);
                throw new ConflictingOperationException(message);
            }

            auditParams.put("class_id", classId);

            PluginInfo info = registry.getPluginInfo("profile", classId);
            String className = info.getClassName();

            // create temporary profile to verify profile configuration
            Profile tempProfile;
            try {
                tempProfile = (Profile) Class.forName(className).getDeclaredConstructor().newInstance();
            } catch (Exception e) {
                String message = "Unable to create profile: " + e.getMessage();
                logger.error(message, e);
                throw new PKIException(message, e);
            }

            tempProfile.setId(profileId);

            try {
                ProfileConfig profileConfig = new ProfileConfig();
                profileConfig.load(new ByteArrayInputStream(data));
                tempProfile.init(engineConfig, registry, profileConfig);

            } catch (Exception e) {
                String message = "Unable to create profile: " + e.getMessage();
                logger.error(message, e);
                throw new BadRequestException(message, e);
            }

            // no error thrown, proceed with profile creation
            profile = ps.createProfile(profileId, classId, className);
            profile.getConfigStore().load(new ByteArrayInputStream(data));
            ps.disableProfile(profileId);
            ps.commitProfile(profileId);

            auditProfileChange(
                    ScopeDef.SC_PROFILE_RULES,
                    OpDef.OP_ADD,
                    profileId,
                    ILogger.SUCCESS,
                    auditParams);

            return profileId;

        } catch (EBaseException | IOException e) {

            String message = "Unable to create profile: " + e.getMessage();
            logger.error(message, e);

            auditProfileChange(
                    ScopeDef.SC_PROFILE_RULES,
                    OpDef.OP_ADD,
                    profileId,
                    ILogger.FAILURE,
                    auditParams);

            throw new PKIException(message, e);
        }
    }

    public void modifyProfileState(Principal principal, String profileId, String action) throws EBaseException {
        if (profileId == null) {
            logger.error("modifyProfileState: invalid request. profileId is null");
            throw new BadRequestException("Unable to modify profile state: Invalid Profile Id");
        }

        if (action == null) {
            logger.error("modifyProfileState: invalid request. action is null");
            throw new BadRequestException("Unable to modify profile state: Missing action");
        }

        if (ps == null) {
            logger.error("modifyProfileState: ps is null");
            throw new PKIException("Error modifying profile state.  Profile Service not available");
        }

        try {
            Profile profile = ps.getProfile(profileId);
            if (profile == null) {
                logger.error("Trying to modify profile: {}.  Profile not found.", profileId);
                throw new ProfileNotFoundException(profileId);
            }
        } catch (EProfileException e1) {
            e1.printStackTrace();
            throw new PKIException("Error modifying profile state: unable to get profile");
        }

        switch (action) {
        case "enable":
            if (ps.isProfileEnable(profileId)) {
                throw new ConflictingOperationException("Profile already enabled");
            }
            try {
                ps.enableProfile(profileId, principal.getName());
                ps.commitProfile(profileId);
                auditProfileChangeState(profileId, "approve", ILogger.SUCCESS);
            } catch (EProfileException e) {
                logger.error("modifyProfileState: error enabling profile: " + e.getMessage(), e);
                auditProfileChangeState(profileId, "approve", ILogger.FAILURE);
                throw new PKIException("Error enabling profile");
            }
            break;
        case "disable":
            if (!ps.isProfileEnable(profileId)) {
                throw new ConflictingOperationException("Profile already disabled");
            }
            String userid = principal.getName();
            try {
                if (ps.checkOwner()) {
                    if (ps.getProfileEnableBy(profileId).equals(userid)) {
                        ps.disableProfile(profileId);
                        ps.commitProfile(profileId);
                        auditProfileChangeState(profileId, "disapprove", ILogger.SUCCESS);
                    } else {
                        auditProfileChangeState(profileId, "disapprove", ILogger.FAILURE);
                        throw new UnauthorizedException(
                                "Profile can only be disabled by the agent that enabled it");
                    }
                } else {
                    ps.disableProfile(profileId);
                    ps.commitProfile(profileId);
                    auditProfileChangeState(profileId, "disapprove", ILogger.SUCCESS);
                }
            } catch (EProfileException e) {
                logger.error("modifyProfileState: Error disabling profile: " + e.getMessage(), e);
                auditProfileChangeState(profileId, "disapprove", ILogger.FAILURE);
                throw new PKIException("Error disabling profile");
            }
            break;
        default:
            auditProfileChangeState(profileId, "invalid", ILogger.FAILURE);
            throw new BadRequestException("Invalid operation");
        }
    }

    public ProfileData modifyProfile(HttpServletRequest servletRequest, String profileId, ProfileData data) throws EBaseException {
        logger.info("ProfileBase: Modifying certificate profile");


        if (profileId == null) {
            logger.error("modifyProfile: invalid request. profileId is null");
            throw new BadRequestException("Unable to modify profile: Invalid Profile Id");
        }

        if (data == null) {
            logger.error("modifyProfile: invalid request. data is null");
            throw new BadRequestException("Unable to modify profile: Invalid profile data");
        }

        if (ps == null) {
            logger.error("modifyProfile: ps is null");
            throw new PKIException("Error modifying profile. Profile Service not available");
        }

        if (ps.isProfileEnable(profileId)) {
            throw new ConflictingOperationException("Cannot change profile data. Profile must be disabled");
        }

        Profile profile = null;
        try {
            profile = ps.getProfile(profileId);
            if (profile == null) {
                throw new ProfileNotFoundException(profileId);
            }

            changeProfileData(data, profile, servletRequest.getLocale());

            return  createProfileData(profileId, false, servletRequest.getLocale());

        } catch (EBaseException e) {
            logger.error("modifyProfile: error obtaining profile `" + profileId + "`: " + e.getMessage(), e);
            throw new PKIException("Error modifying profile.  Cannot obtain profile.");
        }
    }

    public byte[] modifyProfile(String profileId, byte[] data) throws EBaseException {
        if (profileId == null) {
            logger.error("modifyProfile: invalid request. profileId is null");
            throw new BadRequestException("Unable to modify profile: Invalid Profile Id");
        }

        if (data == null) {
            logger.error("modifyProfile: invalid request. data is null");
            throw new BadRequestException("Unable to modify profile: Invalid profile data");
        }

        if (ps == null) {
            logger.error("modifyProfile: ps is null");
            throw new PKIException("Error modifying profile. Profile Service not available");
        }

        if (ps.isProfileEnable(profileId)) {
            throw new ConflictingOperationException("Cannot change profile data. Profile must be disabled");
        }

        SimpleProperties properties = new SimpleProperties();
        try {
            properties.load(new ByteArrayInputStream(data));
        } catch (IOException e) {
            throw new BadRequestException("Could not parse raw profile data.", e);
        }
        properties.remove("profileId");
        properties.remove("classId");

        try {
            Profile profile = ps.getProfile(profileId);
            if (profile == null) {
                throw new ProfileNotFoundException(profileId);
            }

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            properties.store(out, null);
            data = out.toByteArray();  // original data sans profileId, classId

            // create temporary profile to verify profile configuration
            String classId = ps.getProfileClassId(profileId);
            String className =
                registry.getPluginInfo("profile", classId).getClassName();
            Profile tempProfile;
            try {
                tempProfile = (Profile) Class.forName(className).getDeclaredConstructor().newInstance();
            } catch (Exception e) {
                throw new PKIException(
                    "Error instantiating profile class: " + className);
            }
            tempProfile.setId(profileId);
            try {
                ProfileConfig profileConfig = new ProfileConfig();
                profileConfig.load(new ByteArrayInputStream(data));
                tempProfile.init(engineConfig, registry, profileConfig);
            } catch (Exception e) {
                throw new BadRequestException("Invalid profile data", e);
            }

            // no error thrown, so commit updated profile config
            profile.getConfigStore().clear();
            profile.getConfigStore().load(new ByteArrayInputStream(data));
            ps.disableProfile(profileId);
            ps.commitProfile(profileId);

            return data;
        } catch (EBaseException | IOException e) {
            logger.error("modifyProfile: error modifying profile " + profileId + ": " + e.getMessage(), e);
            throw new PKIException("Error modifying profile.", e);
        }
    }

    public void deleteProfile(String profileId) {
        if (profileId == null) {
            logger.error("deleteProfile: invalid request. profileId is null");
            throw new BadRequestException("Unable to delete profile: Invalid Profile Id");
        }

        if (ps == null) {
            logger.error("deleteProfile: ps is null");
            throw new PKIException("Error deleting profile. Profile Service not available");
        }

        try {
            Profile profile = ps.getProfile(profileId);
            if (profile == null) {
                logger.error("Trying to delete profile: {}. Profile already deleted.", profileId);
                throw new ProfileNotFoundException(profileId);
            }

            if (ps.isProfileEnable(profileId)) {
                logger.error("Delete profile not permitted.  Profile must be disabled first.");
                auditProfileChange(
                        ScopeDef.SC_PROFILE_RULES,
                        OpDef.OP_DELETE,
                        profileId,
                        ILogger.FAILURE,
                        null);

                throw new ConflictingOperationException("Cannot delete profile `" + profileId +
                        "`.  Profile must be disabled first.");
            }

            ps.deleteProfile(profileId);

            auditProfileChange(
                    ScopeDef.SC_PROFILE_RULES,
                    OpDef.OP_DELETE,
                    profileId,
                    ILogger.FAILURE,
                    null);

        } catch (EBaseException e) {
            logger.error("deleteProfile: error in deleting profile `" + profileId + "`: " + e.getMessage(), e);

            auditProfileChange(
                    ScopeDef.SC_PROFILE_RULES,
                    OpDef.OP_DELETE,
                    profileId,
                    ILogger.FAILURE,
                    null);

            throw new PKIException("Error deleting profile.");
        }
    }

    private ProfileDataInfo createProfileDataInfo(String profileId, String uri,
            Locale locale) throws EBaseException {

        if (profileId == null) {
            throw new EBaseException("Error creating ProfileDataInfo.");
        }
        ProfileDataInfo ret = null;

        com.netscape.cms.profile.common.Profile profile = null;

        profile = ps.getProfile(profileId);
        if (profile == null) {
            return null;
        }

        ret = new ProfileDataInfo();

        ret.setProfileId(profileId);
        ret.setProfileName(profile.getName(locale));
        ret.setProfileDescription(profile.getDescription(locale));

        ret.setProfileVisible(profile.isVisible());
        ret.setProfileEnable(profile.isEnable());
        ret.setProfileEnableBy(profile.getApprovedBy());

        ret.setProfileURL(uri);

        return ret;
    }

    private ProfileData createProfileData(String profileId, boolean visibleOnly, Locale loc) throws EBaseException {
        Profile profile = getProfile(profileId, visibleOnly);

        ProfileData data = new ProfileData();

        data.setAuthenticatorId(profile.getAuthenticatorId());
        data.setAuthzAcl(profile.getAuthzAcl());
        data.setClassId(ps.getProfileClassId(profileId));
        data.setDescription(profile.getDescription(loc));
        data.setEnabled(ps.isProfileEnable(profileId));
        data.setEnabledBy(ps.getProfileEnableBy(profileId));
        data.setId(profileId);
        data.setName(profile.getName(loc));
        data.setRenewal(Boolean.getBoolean(profile.isRenewal()));
        data.setVisible(profile.isVisible());
        data.setXMLOutput(Boolean.getBoolean(profile.isXmlOutput()));

        Enumeration<String> inputIds = profile.getProfileInputIds();
        if (inputIds != null) {
            while (inputIds.hasMoreElements()) {
                ProfileInput input = createProfileInput(profile, inputIds.nextElement(), loc);
                if (input == null)
                    continue;
                data.addProfileInput(input);
            }
        }

        // profile outputs
        Enumeration<String> outputIds = profile.getProfileOutputIds();
        if (outputIds != null) {
            while (outputIds.hasMoreElements()) {
                ProfileOutput output = createProfileOutput(profile, outputIds.nextElement(), loc);
                if (output == null)
                    continue;
                data.addProfileOutput(output);
            }
        }

        // profile policies
        Enumeration<String> policySetIds = profile.getProfilePolicySetIds();
        if (policySetIds != null) {
            while (policySetIds.hasMoreElements()) {
                Vector<ProfilePolicy> pset = new Vector<>();
                String policySetId = policySetIds.nextElement();
                Enumeration<String> policyIds = profile.getProfilePolicyIds(policySetId);
                while (policyIds.hasMoreElements()) {
                    String policyId = policyIds.nextElement();
                    pset.add(createProfilePolicy(profile, policySetId, policyId, loc));
                }

                if (!pset.isEmpty()) {
                    data.addProfilePolicySet(policySetId, pset);
                }
            }
        }
        return data;
    }


    private Profile getProfile(String profileId, boolean visibleOnly) throws ProfileNotFoundException {
        if (profileId == null) {
            logger.error("retrieveProfile: profileID is null");
            throw new BadRequestException("Unable to retrieve profile: invalid profile ID");
        }

        if (ps == null) {
            logger.error("retrieveProfile: ps is null");
            throw new PKIException("Error retrieving profile.  Profile Service not available");
        }

        Profile profile;
        try {
            profile = ps.getProfile(profileId);
        } catch (EProfileException e) {
            throw new ProfileNotFoundException(profileId, "Profile not found", e);
        }

        if (profile == null) {
            throw new ProfileNotFoundException(profileId);
        }

        if (visibleOnly && !profile.isVisible()) {
            throw new ProfileNotFoundException(profileId);
        }

        return profile;
    }

    private ProfileInput createProfileInput(Profile profile, String inputId, Locale locale) throws EBaseException {
        com.netscape.cms.profile.common.ProfileInput profileInput = profile.getProfileInput(inputId);
        if (profileInput == null)
            return null;

        ProfileConfig profileConfig = profile.getConfigStore();
        ProfileInputsConfig inputStore = profileConfig.getProfileInputsConfig();
        String name = profileInput.getName(locale);
        ProfileInputConfig inputConfig = inputStore.getProfileInputConfig(inputId);
        String classId = inputConfig.getString("class_id");

        ProfileInput input = new ProfileInput(inputId, name, classId);

        Enumeration<String> attrNames = profileInput.getValueNames();
        while (attrNames.hasMoreElements()) {
            String attrName = attrNames.nextElement();

            Descriptor descriptor = (Descriptor) profileInput.getValueDescriptor(locale, attrName);

            ProfileAttribute attr = new ProfileAttribute(attrName, null, descriptor);
            input.addAttribute(attr);
        }

        return input;
    }

    private ProfileOutput createProfileOutput(Profile profile, String outputId, Locale locale) throws EBaseException {
        com.netscape.cms.profile.common.ProfileOutput profileOutput = profile.getProfileOutput(outputId);
        if (profileOutput == null)
            return null;

        ProfileConfig profileConfig = profile.getConfigStore();
        ProfileOutputsConfig outputStore = profileConfig.getProfileOutputsConfig();
        String name = profileOutput.getName(locale);
        ProfileOutputConfig outputConfig = outputStore.getProfileOutputConfig(outputId);
        String classId = outputConfig.getString("class_id");

        ProfileOutput output = new ProfileOutput(outputId, name, classId);

        Enumeration<String> attrNames = profileOutput.getValueNames();
        while (attrNames.hasMoreElements()) {
            String attrName = attrNames.nextElement();

            Descriptor descriptor = (Descriptor) profileOutput.getValueDescriptor(locale, attrName);

            ProfileAttribute attr = new ProfileAttribute(attrName, null, descriptor);
            output.addAttribute(attr);
        }

        return output;
    }

    private ProfilePolicy createProfilePolicy(Profile profile, String setId, String policyId, Locale locale) throws EBaseException {
        com.netscape.cms.profile.common.ProfilePolicy policy = profile.getProfilePolicy(setId, policyId);
        ProfilePolicySetsConfig policiesConfig = profile.getConfigStore().getPolicySetsConfig();
        ProfilePolicySetConfig policySetConfig = policiesConfig.getPolicySetConfig(setId);
        ProfilePolicyConfig policyStore = policySetConfig.getPolicyConfig(policy.getId());

        ProfilePolicy p = new ProfilePolicy();
        p.setId(policy.getId());

        PolicyConstraintConfig constraintConfig = policyStore.getPolicyConstraintConfig();
        String constraintClassId = constraintConfig.getClassID();
        p.setConstraint(PolicyConstraintFactory.create(locale, policy.getConstraint(), constraintClassId));

        PolicyDefaultConfig defaultConfig = policyStore.getPolicyDefaultConfig();
        String defaultClassId = defaultConfig.getClassID();
        p.setDef(PolicyDefaultFactory.create(locale, policy.getDefault(), defaultClassId));

        return p;
    }

    private void changeProfileData(ProfileData data, Profile profile, Locale locale) throws EBaseException {
        String profileId = data.getId();
        if (profile == null) {
            logger.error("changeProfileData - profile is null");
            throw new PKIException("Error changing profile data. Profile not available.");
        }
        if (ps.isProfileEnable(profileId)) {
            throw new ConflictingOperationException("Cannot change profile data.  Profile must be disabled");
        }

        Map<String, String> auditParams = new LinkedHashMap<>();

        if (differs(profile.getAuthenticatorId(), data.getAuthenticatorId())) {
            profile.setAuthenticatorId(data.getAuthenticatorId());
            auditParams.put("authenticatorId", data.getAuthenticatorId());
        }

        if (differs(profile.getAuthzAcl(), data.getAuthzAcl())) {
            profile.setAuthzAcl(data.getAuthzAcl());
            auditParams.put("authzAcl", data.getAuthzAcl());
        }

        if (differs(profile.getDescription(locale), data.getDescription())) {
            profile.setDescription(locale, data.getDescription());
            auditParams.put("description", data.getDescription());
        }

        if (differs(profile.getId(), data.getId())) {
            profile.setId(data.getId());
            auditParams.put("id", data.getId());
        }

        if (differs(profile.getName(locale), data.getName())) {
            profile.setName(locale, data.getName());
            auditParams.put("name", data.getName());
        }

        // TODO renewal is a string in Profile, should be changed
        if (differs(profile.isRenewal(), Boolean.toString(data.isRenewal()))) {
            profile.setRenewal(data.isRenewal());
            auditParams.put("renewal", Boolean.toString(data.isRenewal()));
        }

        if (!profile.isVisible() == data.isVisible()) {
            profile.setVisible(data.isVisible());
            auditParams.put("visible", Boolean.toString(data.isVisible()));
        }

        // TODO xmloutput is a string in Profile, should be changed
        if (differs(profile.isXmlOutput(), Boolean.toString(data.isXMLOutput()))) {
            profile.setXMLOutput(data.isXMLOutput());
            auditParams.put("xmloutput", Boolean.toString(data.isXMLOutput()));
        }

        if (!auditParams.isEmpty()) {
            auditProfileChange(
                    ScopeDef.SC_PROFILE_RULES,
                    OpDef.OP_MODIFY,
                    profileId,
                    ILogger.SUCCESS,
                    auditParams);
        }

        try {
            populateProfileInputs(data, profile, locale);
            populateProfileOutputs(data, profile, locale);
            populateProfilePolicies(data, profile, locale);
            ps.commitProfile(profileId);

        } catch (EBaseException e) {
            logger.error("ProfileBase: Unable to update profile: " + e.getMessage(), e);
            throw new PKIException("Unable to update profile: " + e.getMessage(), e);
        }
    }

    private boolean differs(String v1, String v2) {
        if (v1 != null) {
            if (!v1.equals(v2)) {
                return true;
            }
        } else {
            if (v2 != null) {
                return true;
            }
        }
        return false;
    }

    private void populateProfilePolicies(ProfileData data, Profile profile, Locale locale) throws EBaseException {
        // get list of changes for auditing
        List<String> auditAdd = new ArrayList<>();
        List<String> auditModify = new ArrayList<>();

        Enumeration<String> existingSetIds = profile.getProfilePolicySetIds();
        Map<String, ProfilePolicy> existingPolicies = new LinkedHashMap<>();
        while (existingSetIds.hasMoreElements()) {
            String setId = existingSetIds.nextElement();
            Enumeration<String> policyIds = profile.getProfilePolicyIds(setId);
            while (policyIds.hasMoreElements()) {
                String policyId = policyIds.nextElement();
                existingPolicies.put(
                        setId + ":" + policyId,
                        createProfilePolicy(profile, setId, policyId, locale));
            }
        }

        for (Map.Entry<String, List<ProfilePolicy>> policySet : data.getPolicySets().entrySet()) {
            String setId = policySet.getKey();
            for (ProfilePolicy policy : policySet.getValue()) {
                String id = setId + ":" + policy.getId();
                if (!existingPolicies.containsKey(id)) {
                    auditAdd.add(id);
                } else {
                    if (!policy.equals(existingPolicies.get(id))) {
                        auditModify.add(id);
                    }
                }
                existingPolicies.remove(id);
            }
        }

        List<String> auditDelete = new ArrayList<>(existingPolicies.keySet());

        //perform actions
        try {
            profile.deleteAllProfilePolicies();
            for (Map.Entry<String, List<ProfilePolicy>> policySet : data.getPolicySets().entrySet()) {
                String setId = policySet.getKey();
                for (ProfilePolicy policy : policySet.getValue()) {
                    PolicyDefault def = policy.getDef();
                    PolicyConstraint con = policy.getConstraint();

                    // create policy using defaults for PolicyDefault and PolicyConstraint
                    com.netscape.cms.profile.common.ProfilePolicy p = profile.createProfilePolicy(setId, policy.getId(),
                            def.getClassId(), con.getClassId());

                    // change specific elements to match incoming data for PolicyDefault
                    ProfilePolicySetsConfig policiesConfig = profile.getConfigStore().getPolicySetsConfig();
                    ProfilePolicySetConfig policySetConfig = policiesConfig.getPolicySetConfig(setId);
                    ProfilePolicyConfig pstore = policySetConfig.getPolicyConfig(policy.getId());
                    PolicyDefaultConfig defaultConfig = pstore.getPolicyDefaultConfig();
                    PolicyConstraintConfig constraintConfig = pstore.getPolicyConstraintConfig();

                    if (!def.getName().isEmpty()) {
                        defaultConfig.setDefaultName(def.getName());
                    }
                    /*if (!def.getText().isEmpty()) {
                        defaultConfig.setDescription(def.getText());
                    }*/
                    for (ProfileParameter param : def.getParams()) {
                        if (!param.getValue().isEmpty()) {
                            p.getDefault().setConfig(param.getName(), param.getValue());
                        }
                    }

                    // change specific elements to match incoming data for PolicyConstraint
                    if (!con.getName().isEmpty()) {
                        constraintConfig.setConstraintName(con.getName());
                    }
                    /*if (!con.getText().isEmpty()) {
                        constraintConfig.setDescription(con.getText());
                    }*/
                    for (PolicyConstraintValue pcv : con.getConstraints()) {
                        if (!pcv.getValue().isEmpty()) {
                            p.getConstraint().setConfig(pcv.getName(), pcv.getValue());
                        }
                    }
                }
            }

            if (!auditDelete.isEmpty()) {
                Map<String, String> auditParams = new LinkedHashMap<>();
                auditParams.put("inputs", StringUtils.join(auditDelete, ","));
                auditProfileChange(
                        ScopeDef.SC_PROFILE_POLICIES,
                        OpDef.OP_DELETE,
                        profile.getId(),
                        ILogger.SUCCESS,
                        auditParams);
            }

            if (!auditAdd.isEmpty()) {
                Map<String, String> auditParams = new LinkedHashMap<>();
                auditParams.put("inputs", StringUtils.join(auditAdd, ","));
                auditProfileChange(
                        ScopeDef.SC_PROFILE_POLICIES,
                        OpDef.OP_ADD,
                        profile.getId(),
                        ILogger.SUCCESS,
                        auditParams);
            }

            if (!auditModify.isEmpty()) {
                Map<String, String> auditParams = new LinkedHashMap<>();
                auditParams.put("inputs", StringUtils.join(auditModify, ","));
                auditProfileChange(
                        ScopeDef.SC_PROFILE_POLICIES,
                        OpDef.OP_MODIFY,
                        profile.getId(),
                        ILogger.SUCCESS,
                        auditParams);
            }
        } catch (EProfileException | EPropertyException e) {
            Map<String, String> auditParams = new LinkedHashMap<>();
            auditParams.put("added", StringUtils.join(auditAdd, ","));
            auditParams.put("deleted", StringUtils.join(auditDelete, ","));
            auditParams.put("modified", StringUtils.join(auditModify, ","));
            auditProfileChange(
                    ScopeDef.SC_PROFILE_POLICIES,
                    OpDef.OP_MODIFY,
                    profile.getId(),
                    ILogger.FAILURE,
                    auditParams);
            throw e;
        }
    }

    private void populateProfileOutputs(ProfileData data, Profile profile, Locale locale) throws EBaseException {
        // get list of changes for auditing
        List<String> auditAdd = new ArrayList<>();
        List<String> auditModify = new ArrayList<>();

        Enumeration<String> existingIds = profile.getProfileOutputIds();
        Map<String, ProfileOutput> existingOutputs = new LinkedHashMap<>();
        while (existingIds.hasMoreElements()) {
            String id = existingIds.nextElement();
            ProfileOutput output = createProfileOutput(profile, id, locale);
            if (output == null)
                continue;
            existingOutputs.put(id, output);
        }

        List<ProfileOutput> outputs = data.getOutputs();
        for (ProfileOutput output : outputs) {
            String id = output.getId();
            if (!existingOutputs.containsKey(id)) {
                auditAdd.add(id);
            } else {
                if (!output.equals(existingOutputs.get(id))) {
                    auditModify.add(id);
                }
                existingOutputs.remove(id);
            }
        }
        List<String> auditDelete = new ArrayList<>(existingOutputs.keySet());

        // perform operations

        try {
            profile.deleteAllProfileOutputs();
            for (ProfileOutput output : outputs) {
                String id = output.getId();
                String classId = output.getClassId();

                NameValuePairs nvp = new NameValuePairs();
                // TODO - add a field for params in ProfileOuput
                // No current examples
                profile.createProfileOutput(id, classId, nvp);
            }

            if (!auditDelete.isEmpty()) {
                Map<String, String> auditParams = new LinkedHashMap<>();
                auditParams.put("outputs", StringUtils.join(auditDelete, ","));
                auditProfileChange(
                        ScopeDef.SC_PROFILE_OUTPUT,
                        OpDef.OP_DELETE,
                        profile.getId(),
                        ILogger.SUCCESS,
                        auditParams);
            }

            if (!auditAdd.isEmpty()) {
                Map<String, String> auditParams = new LinkedHashMap<>();
                auditParams.put("outputs", StringUtils.join(auditAdd, ","));
                auditProfileChange(
                        ScopeDef.SC_PROFILE_OUTPUT,
                        OpDef.OP_ADD,
                        profile.getId(),
                        ILogger.SUCCESS,
                        auditParams);
            }

            if (!auditModify.isEmpty()) {
                Map<String, String> auditParams = new LinkedHashMap<>();
                auditParams.put("outputs", StringUtils.join(auditModify, ","));
                auditProfileChange(
                        ScopeDef.SC_PROFILE_OUTPUT,
                        OpDef.OP_MODIFY,
                        profile.getId(),
                        ILogger.SUCCESS,
                        auditParams);
            }
        } catch (EProfileException e) {
            Map<String, String> auditParams = new LinkedHashMap<>();

            auditParams.put("added", StringUtils.join(auditAdd, ","));
            auditParams.put("deleted", StringUtils.join(auditDelete, ","));
            auditParams.put("modified", StringUtils.join(auditModify, ","));
            auditProfileChange(
                    ScopeDef.SC_PROFILE_OUTPUT,
                    OpDef.OP_MODIFY,
                    profile.getId(),
                    ILogger.FAILURE,
                    auditParams);
            throw e;
        }
    }

    private void populateProfileInputs(ProfileData data, Profile profile, Locale locale) throws EBaseException {
        // get list of changes for auditing
        List<String> auditAdd = new ArrayList<>();
        List<String> auditModify = new ArrayList<>();
        Enumeration<String> existingIds = profile.getProfileInputIds();
        Map<String, ProfileInput> existingInputs = new LinkedHashMap<>();

        while (existingIds.hasMoreElements()) {
            String id = existingIds.nextElement();
            ProfileInput input = createProfileInput(profile, id, locale);
            if (input == null)
                continue;
            existingInputs.put(id, input);
        }

        List<ProfileInput> inputs = data.getInputs();
        for (ProfileInput input : inputs) {
            String id = input.getId();
            if (!existingInputs.containsKey(id)) {
                auditAdd.add(id);
            } else {
                if (!input.equals(existingInputs.get(id))) {
                    auditModify.add(id);
                }
                existingInputs.remove(id);
            }
        }
        List<String> auditDelete = new ArrayList<>(existingInputs.keySet());

        try {
            // perform the operations
            profile.deleteAllProfileInputs();

            for (ProfileInput input : inputs) {
                String id = input.getId();
                String classId = input.getClassId();

                NameValuePairs nvp = new NameValuePairs();
                // TODO - add a field for params in ProfileInput.
                // an example of this is DomainController.cfg
                profile.createProfileInput(id, classId, nvp);
            }

            if (!auditDelete.isEmpty()) {
                Map<String, String> auditParams = new LinkedHashMap<>();
                auditParams.put("inputs", StringUtils.join(auditDelete, ","));
                auditProfileChange(
                        ScopeDef.SC_PROFILE_INPUT,
                        OpDef.OP_DELETE,
                        profile.getId(),
                        ILogger.SUCCESS,
                        auditParams);
            }

            if (!auditAdd.isEmpty()) {
                Map<String, String> auditParams = new LinkedHashMap<>();
                auditParams.put("inputs", StringUtils.join(auditAdd, ","));
                auditProfileChange(
                        ScopeDef.SC_PROFILE_INPUT,
                        OpDef.OP_ADD,
                        profile.getId(),
                        ILogger.SUCCESS,
                        auditParams);
            }

            if (!auditModify.isEmpty()) {
                Map<String, String> auditParams = new LinkedHashMap<>();
                auditParams.put("inputs", StringUtils.join(auditModify, ","));
                auditProfileChange(
                        ScopeDef.SC_PROFILE_INPUT,
                        OpDef.OP_MODIFY,
                        profile.getId(),
                        ILogger.SUCCESS,
                        auditParams);
            }
        } catch (EProfileException e) {
            Map<String, String> auditParams = new LinkedHashMap<>();

            auditParams.put("added", StringUtils.join(auditAdd, ","));
            auditParams.put("deleted", StringUtils.join(auditDelete, ","));
            auditParams.put("modified", StringUtils.join(auditModify, ","));
            auditProfileChange(
                    ScopeDef.SC_PROFILE_INPUT,
                    OpDef.OP_MODIFY,
                    profile.getId(),
                    ILogger.FAILURE,
                    auditParams);
            throw e;
        }
    }

    private boolean isProfileAccessLimited(Principal principal) {
        AuthzSubsystem authzSubsystem = engine.getAuthzSubsystem();
        if (principal == null)
            return true;
        AuthToken authToken = null;
        String authzMgrName = null;
        if (principal instanceof PKIPrincipal pkiPrincipal) {
            authzMgrName = "DirAclAuthz";
            authToken = pkiPrincipal.getAuthToken();
            if (authToken == null)
                return true;
        } else {
            String realm = null;
            String[] parts = principal.getName().split("@", 2);
            if (parts.length == 2) {
                realm = parts[1];
            }
            try {
                authzMgrName = authzSubsystem.getAuthzManagerNameByRealm(realm);
            } catch (EAuthzUnknownRealm e) {
                logger.error("Cannot find AuthzManager for external principal {}", principal.getName());
                return true;
            }
            authToken = new ExternalAuthToken((GenericPrincipal) principal);
        }
        try {
            AuthzToken authzToken = authzSubsystem.authorize(
                    authzMgrName,
                    authToken,
                    "certServer.profile.configuration",
                    "read");

            if (authzToken != null)
                return false;
        } catch (EBaseException e) {
            logger.error("Cannot check authorization for principal {}", principal.getName());
            return true;
        }
        return true;
    }

    private void auditProfileChangeState(String profileId, String op, String status) {

        Auditor auditor = engine.getAuditor();
        String msg = CMS.getLogMessage(
                AuditEvent.CERT_PROFILE_APPROVAL,
                auditor.getSubjectID(),
                status,
                profileId,
                op);
        auditor.log(msg);
    }

    private void auditProfileChange(String scope, String type, String id, String status, Map<String, String> params) {

        Auditor auditor = engine.getAuditor();
        String msg = CMS.getLogMessage(
                AuditEvent.CONFIG_CERT_PROFILE,
                auditor.getSubjectID(),
                status,
                auditor.getParamString(scope, type, id, params));
        auditor.log(msg);
    }
}
