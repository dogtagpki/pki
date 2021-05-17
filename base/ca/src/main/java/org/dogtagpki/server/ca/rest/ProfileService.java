//--- BEGIN COPYRIGHT BLOCK ---
//This program is free software; you can redistribute it and/or modify
//it under the terms of the GNU General Public License as published by
//the Free Software Foundation; version 2 of the License.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License along
//with this program; if not, write to the Free Software Foundation, Inc.,
//51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
//(C) 2011 Red Hat, Inc.
//All rights reserved.
//--- END COPYRIGHT BLOCK ---

package org.dogtagpki.server.ca.rest;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Vector;

import javax.ws.rs.PathParam;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;

import org.apache.catalina.realm.GenericPrincipal;
import org.apache.commons.lang3.StringUtils;
import org.dogtagpki.server.ca.CAEngine;
import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.ConflictingOperationException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.PKIException;
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
import com.netscape.certsrv.profile.ProfileResource;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.registry.IPluginInfo;
import com.netscape.cms.profile.common.CAEnrollProfile;
import com.netscape.cms.profile.common.Profile;
import com.netscape.cms.servlet.base.SubsystemService;
import com.netscape.cms.servlet.profile.PolicyConstraintFactory;
import com.netscape.cms.servlet.profile.PolicyDefaultFactory;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.PropConfigStore;
import com.netscape.cmscore.base.SimpleProperties;
import com.netscape.cmscore.profile.ProfileSubsystem;
import com.netscape.cmscore.registry.PluginRegistry;

/**
 * @author alee
 *
 */
public class ProfileService extends SubsystemService implements ProfileResource {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ProfileService.class);

    private PluginRegistry registry;
    private ProfileSubsystem ps;

    public ProfileService() {
        CAEngine engine = CAEngine.getInstance();
        registry = engine.getPluginRegistry();
        ps = engine.getProfileSubsystem();
    }

    @Override
    public Response listProfiles(Integer start, Integer size) {

        start = start == null ? 0 : start;
        size = size == null ? DEFAULT_SIZE : size;

        ProfileDataInfos infos = new ProfileDataInfos();
        boolean visibleOnly = true;

        if (ps == null) {
            logger.error("listProfiles: ps is null");
            throw new PKIException("Error listing profiles.  Profile Service not available");
        }

        // TODO remove hardcoded role names and consult authzmgr
        // (so that we can handle externally-authenticated principals)
        Principal principal = servletRequest.getUserPrincipal();
        if (principal != null && principal instanceof GenericPrincipal) {
            GenericPrincipal genPrincipal = (GenericPrincipal) principal;
            if (genPrincipal.hasRole("Certificate Manager Agents") ||
                genPrincipal.hasRole("Certificate Manager Administrators"))
                    visibleOnly = false;
        }

        Enumeration<String> e = ps.getProfileIds();
        if (e == null) return createOKResponse(infos);

        // store non-null results in a list
        List<ProfileDataInfo> results = new ArrayList<ProfileDataInfo>();
        while (e.hasMoreElements()) {
            try {
                String id = e.nextElement();
                ProfileDataInfo info = createProfileDataInfo(id, visibleOnly, uriInfo, getLocale(headers));
                if (info == null) continue;
                results.add(info);
            } catch (EBaseException ex) {
                continue;
            }
        }

        int total = results.size();
        infos.setTotal(total);

        // return entries in the requested page
        for (int i = start; i < start + size && i < total; i++) {
            infos.addEntry(results.get(i));
        }

        if (start > 0) {
            URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", Math.max(start-size, 0)).build();
            infos.addLink(new Link("prev", uri));
        }

        if (start + size < total) {
            URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", start+size).build();
            infos.addLink(new Link("next", uri));
        }

        return createOKResponse(infos);
    }

    private Profile getProfile(String profileId) throws ProfileNotFoundException {
        boolean visibleOnly = true;

        if (profileId == null) {
            logger.error("retrieveProfile: profileID is null");
            throw new BadRequestException("Unable to retrieve profile: invalid profile ID");
        }

        if (ps == null) {
            logger.error("retrieveProfile: ps is null");
            throw new PKIException("Error retrieving profile.  Profile Service not available");
        }

        // TODO remove hardcoded role names and consult authzmgr
        // (so that we can handle externally-authenticated principals)
        Principal principal = servletRequest.getUserPrincipal();
        if (principal != null && principal instanceof GenericPrincipal) {
            GenericPrincipal genPrincipal = (GenericPrincipal) principal;
            if (genPrincipal.hasRole("Certificate Manager Agents") ||
                genPrincipal.hasRole("Certificate Manager Administrators"))
                    visibleOnly = false;
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

    @Override
    public Response retrieveProfile(String profileId) throws ProfileNotFoundException {
        ProfileData data = null;
        try {
            data = createProfileData(profileId);
        } catch (EBaseException e) {
            e.printStackTrace();
            throw new ProfileNotFoundException(profileId);
        }

        UriBuilder profileBuilder = uriInfo.getBaseUriBuilder();
        URI uri = profileBuilder.path(ProfileResource.class).path("{id}").
                build(profileId);
        data.setLink(new Link("self", uri));

        return createOKResponse(data);
    }

    @Override
    public Response retrieveProfileRaw(String profileId) throws Exception {
        Profile profile = getProfile(profileId);
        ByteArrayOutputStream data = new ByteArrayOutputStream();
        // add profileId and classId "virtual" properties
        profile.getConfigStore().put("profileId", profileId);
        profile.getConfigStore().put("classId", ps.getProfileClassId(profileId));
        profile.getConfigStore().store(data);
        return createOKResponse(data.toByteArray());
    }


    public ProfileData createProfileData(String profileId) throws EBaseException {
        Profile profile = getProfile(profileId);

        ProfileData data = new ProfileData();

        data.setAuthenticatorId(profile.getAuthenticatorId());
        data.setAuthzAcl(profile.getAuthzAcl());
        data.setClassId(ps.getProfileClassId(profileId));
        data.setDescription(profile.getDescription(getLocale(headers)));
        data.setEnabled(ps.isProfileEnable(profileId));
        data.setEnabledBy(ps.getProfileEnableBy(profileId));
        data.setId(profileId);
        data.setName(profile.getName(getLocale(headers)));
        data.setRenewal(Boolean.getBoolean(profile.isRenewal()));
        data.setVisible(profile.isVisible());
        data.setXMLOutput(Boolean.getBoolean(profile.isXmlOutput()));

        Enumeration<String> inputIds = profile.getProfileInputIds();
        if (inputIds != null) {
            while (inputIds.hasMoreElements()) {
                ProfileInput input = createProfileInput(profile, inputIds.nextElement(), getLocale(headers));
                if (input == null)
                    continue;
                data.addProfileInput(input);
            }
        }

        // profile outputs
        Enumeration<String> outputIds = profile.getProfileOutputIds();
        if (outputIds != null) {
            while (outputIds.hasMoreElements()) {
                ProfileOutput output = createProfileOutput(profile, outputIds.nextElement(), getLocale(headers));
                if (output == null)
                    continue;
                data.addProfileOutput(output);
            }
        }

        // profile policies
        Enumeration<String> policySetIds = profile.getProfilePolicySetIds();
        if (policySetIds != null) {
            while (policySetIds.hasMoreElements()) {
                Vector<ProfilePolicy> pset = new Vector<ProfilePolicy>();
                String policySetId = policySetIds.nextElement();
                Enumeration<String> policyIds = profile.getProfilePolicyIds(policySetId);
                while (policyIds.hasMoreElements()) {
                    String policyId = policyIds.nextElement();
                    pset.add(createProfilePolicy(profile, policySetId, policyId));
                }

                if (!pset.isEmpty()) {
                    data.addProfilePolicySet(policySetId, pset);
                }
            }
        }

        UriBuilder profileBuilder = uriInfo.getBaseUriBuilder();
        URI uri = profileBuilder.path(ProfileResource.class).path("{id}").
                build(profileId);
        data.setLink(new Link("self", uri));

        return data;
    }

    public ProfilePolicy createProfilePolicy(Profile profile, String setId, String policyId) throws EBaseException {
        com.netscape.cms.profile.common.ProfilePolicy policy = profile.getProfilePolicy(setId, policyId);
        IConfigStore policyStore = profile.getConfigStore().getSubStore(
                "policyset." + setId + "." + policy.getId());

        ProfilePolicy p = new ProfilePolicy();
        String constraintClassId = policyStore.getString("constraint.class_id");
        p.setConstraint(PolicyConstraintFactory.create(getLocale(headers), policy.getConstraint(), constraintClassId));
        String defaultClassId = policyStore.getString("default.class_id");
        p.setDef(PolicyDefaultFactory.create(getLocale(headers), policy.getDefault(), defaultClassId));
        p.setId(policy.getId());
        return p;
    }

    public static ProfileInput createProfileInput(Profile profile, String inputId, Locale locale) throws EBaseException {
        com.netscape.cms.profile.common.ProfileInput profileInput = profile.getProfileInput(inputId);
        if (profileInput == null)
            return null;

        IConfigStore inputStore = profile.getConfigStore().getSubStore("input");
        String name = profileInput.getName(locale);
        String classId = inputStore.getString(inputId + ".class_id");

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

    public static ProfileOutput createProfileOutput(Profile profile, String outputId, Locale locale) throws EBaseException {
        com.netscape.cms.profile.common.ProfileOutput profileOutput = profile.getProfileOutput(outputId);
        if (profileOutput == null)
            return null;

        IConfigStore outputStore = profile.getConfigStore().getSubStore("output");
        String name = profileOutput.getName(locale);
        String classId = outputStore.getString(outputId + ".class_id");

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

    public static ProfileDataInfo createProfileDataInfo(String profileId, boolean visibleOnly, UriInfo uriInfo,
            Locale locale) throws EBaseException {

        CAEngine engine = CAEngine.getInstance();
        ProfileSubsystem ps = engine.getProfileSubsystem();

        if (profileId == null) {
            throw new EBaseException("Error creating ProfileDataInfo.");
        }
        ProfileDataInfo ret = null;

        Profile profile = null;

        profile = ps.getProfile(profileId);
        if (profile == null) {
            return null;
        }

        if (visibleOnly && !profile.isVisible()) {
            return null;
        }

        ret = new ProfileDataInfo();

        ret.setProfileId(profileId);
        ret.setProfileName(profile.getName(locale));
        ret.setProfileDescription(profile.getDescription(locale));

        UriBuilder profileBuilder = uriInfo.getBaseUriBuilder();
        URI uri = profileBuilder.path(ProfileResource.class).path("{id}").
                build(profileId);

        ret.setProfileURL(uri.toString());

        return ret;
    }

    @Override
    public Response modifyProfileState(String profileId, String action) throws Exception {
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
                logger.error("Trying to modify profile: " + profileId + ".  Profile not found.");
                throw new ProfileNotFoundException(profileId);
            }
        } catch (EProfileException e1) {
            e1.printStackTrace();
            throw new PKIException("Error modifying profile state: unable to get profile");
        }

        Principal principal = servletRequest.getUserPrincipal();

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

        return createNoContentResponse();
    }

    @Override
    public Response createProfile(ProfileData data) throws Exception {
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
        Map<String, String> auditParams = new LinkedHashMap<String, String>();
        try {
            profile = ps.getProfile(profileId);
            if (profile != null) {
                throw new ConflictingOperationException("Profile already exists");
            }

            auditParams.put("class_id", data.getClassId());
            auditParams.put("name", data.getName());
            auditParams.put("description", data.getDescription());
            auditParams.put("visible", Boolean.toString(data.isVisible()));

            IPluginInfo info = registry.getPluginInfo("profile", data.getClassId());

            profile = ps.createProfile(profileId, data.getClassId(), info.getClassName());
            profile.setName(getLocale(headers), data.getName());
            profile.setDescription(getLocale(headers), data.getDescription());
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

            changeProfileData(data, profile);

            ProfileData profileData = createProfileData(profileId);

            URI uri = uriInfo
                    .getBaseUriBuilder()
                    .path(ProfileResource.class)
                    .path("{id}")
                    .build(profileId);
            return createCreatedResponse(profileData, uri);

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

    @Override
    public Response createProfileRaw(byte[] data) {

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

        logger.info("ProfileService: Creating profile from raw data");

        Map<String, String> auditParams = new LinkedHashMap<String, String>();
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

            IPluginInfo info = registry.getPluginInfo("profile", classId);
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
                PropConfigStore tempConfig = new PropConfigStore();
                tempConfig.load(new ByteArrayInputStream(data));
                tempProfile.init(tempConfig);

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

            return createCreatedResponse(data, uriInfo.getAbsolutePath());

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

    @Override
    public Response modifyProfile(String profileId, ProfileData data) throws Exception {
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
            throw new PKIException("Error modifying profile.  Profile Service not available");
        }

        Profile profile = null;
        try {
            profile = ps.getProfile(profileId);
            if (profile == null) {
                throw new ProfileNotFoundException(profileId);
            }

            changeProfileData(data, profile);

            ProfileData profileData = createProfileData(profileId);

            return createOKResponse(profileData);

        } catch (EBaseException e) {
            logger.error("modifyProfile: error obtaining profile `" + profileId + "`: " + e.getMessage(), e);
            throw new PKIException("Error modifying profile.  Cannot obtain profile.");
        }
    }

    @Override
    public Response modifyProfileRaw(String profileId, byte[] data) throws Exception {
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
            throw new PKIException("Error modifying profile.  Profile Service not available");
        }

        if (ps.isProfileEnable(profileId)) {
            throw new ConflictingOperationException("Cannot change profile data.  Profile must be disabled");
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
                PropConfigStore tempConfig = new PropConfigStore();
                tempConfig.load(new ByteArrayInputStream(data));
                tempProfile.init(tempConfig);
            } catch (Exception e) {
                throw new BadRequestException("Invalid profile data", e);
            }

            // no error thrown, so commit updated profile config
            profile.getConfigStore().clear();
            profile.getConfigStore().load(new ByteArrayInputStream(data));
            ps.disableProfile(profileId);
            ps.commitProfile(profileId);

            return createOKResponse(data);
        } catch (EBaseException | IOException e) {
            logger.error("modifyProfile: error modifying profile " + profileId + ": " + e.getMessage(), e);
            throw new PKIException("Error modifying profile.", e);
        }
    }

    private void changeProfileData(ProfileData data, Profile profile) throws Exception {
        String profileId = data.getId();
        if (profile == null) {
            logger.error("changeProfileData - profile is null");
            throw new PKIException("Error changing profile data. Profile not available.");
        }
        if (ps.isProfileEnable(profileId)) {
            throw new ConflictingOperationException("Cannot change profile data.  Profile must be disabled");
        }

        Map<String, String> auditParams = new LinkedHashMap<String, String>();

        if (differs(profile.getAuthenticatorId(), data.getAuthenticatorId())) {
            profile.setAuthenticatorId(data.getAuthenticatorId());
            auditParams.put("authenticatorId", data.getAuthenticatorId());
        }

        if (differs(profile.getAuthzAcl(), data.getAuthzAcl())) {
            profile.setAuthzAcl(data.getAuthzAcl());
            auditParams.put("authzAcl", data.getAuthzAcl());
        }

        if (differs(profile.getDescription(getLocale(headers)), data.getDescription())) {
            profile.setDescription(getLocale(headers), data.getDescription());
            auditParams.put("description", data.getDescription());
        }

        if (differs(profile.getId(), data.getId())) {
            profile.setId(data.getId());
            auditParams.put("id", data.getId());
        }

        if (differs(profile.getName(getLocale(headers)), data.getName())) {
            profile.setName(getLocale(headers), data.getName());
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
            populateProfileInputs(data, profile);
            populateProfileOutputs(data, profile);
            populateProfilePolicies(data, profile);
            ps.commitProfile(profileId);
        } catch (EBaseException e) {
            logger.error("changeProfileData: Error changing profile inputs/outputs/policies: " + e.getMessage(), e);
            throw new PKIException("Error changing profile data");
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

    private void populateProfilePolicies(ProfileData data, Profile profile) throws EBaseException {
        // get list of changes for auditing
        List<String> auditAdd = new ArrayList<String>();
        List<String> auditModify = new ArrayList<String>();

        Enumeration<String> existingSetIds = profile.getProfilePolicySetIds();
        Map<String, ProfilePolicy> existingPolicies = new LinkedHashMap<String, ProfilePolicy>();
        while (existingSetIds.hasMoreElements()) {
            String setId = existingSetIds.nextElement();
            Enumeration<String> policyIds = profile.getProfilePolicyIds(setId);
            while (policyIds.hasMoreElements()) {
                String policyId = policyIds.nextElement();
                existingPolicies.put(
                        setId + ":" + policyId,
                        createProfilePolicy(profile, setId, policyId));
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

        List<String> auditDelete = new ArrayList<String>(existingPolicies.keySet());

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
                    IConfigStore pstore = profile.getConfigStore().getSubStore(
                            "policyset." + setId + "." + policy.getId());
                    if (!def.getName().isEmpty()) {
                        pstore.putString("default.name", def.getName());
                    }
                    /*if (!def.getText().isEmpty()) {
                        pstore.putString("default.description", def.getText());
                    }*/
                    for (ProfileParameter param : def.getParams()) {
                        if (!param.getValue().isEmpty()) {
                            p.getDefault().setConfig(param.getName(), param.getValue());
                        }
                    }

                    // change specific elements to match incoming data for PolicyConstraint
                    if (!con.getName().isEmpty()) {
                        pstore.putString("constraint.name", con.getName());
                    }
                    /*if (!con.getText().isEmpty()) {
                        pstore.putString("constraint.description", con.getText());
                    }*/
                    for (PolicyConstraintValue pcv : con.getConstraints()) {
                        if (!pcv.getValue().isEmpty()) {
                            p.getConstraint().setConfig(pcv.getName(), pcv.getValue());
                        }
                    }
                }
            }

            if (!auditDelete.isEmpty()) {
                Map<String, String> auditParams = new LinkedHashMap<String, String>();
                auditParams.put("inputs", StringUtils.join(auditDelete, ","));
                auditProfileChange(
                        ScopeDef.SC_PROFILE_POLICIES,
                        OpDef.OP_DELETE,
                        profile.getId(),
                        ILogger.SUCCESS,
                        auditParams);
            }

            if (!auditAdd.isEmpty()) {
                Map<String, String> auditParams = new LinkedHashMap<String, String>();
                auditParams.put("inputs", StringUtils.join(auditAdd, ","));
                auditProfileChange(
                        ScopeDef.SC_PROFILE_POLICIES,
                        OpDef.OP_ADD,
                        profile.getId(),
                        ILogger.SUCCESS,
                        auditParams);
            }

            if (!auditModify.isEmpty()) {
                Map<String, String> auditParams = new LinkedHashMap<String, String>();
                auditParams.put("inputs", StringUtils.join(auditModify, ","));
                auditProfileChange(
                        ScopeDef.SC_PROFILE_POLICIES,
                        OpDef.OP_MODIFY,
                        profile.getId(),
                        ILogger.SUCCESS,
                        auditParams);
            }
        } catch (EProfileException | EPropertyException e) {
            Map<String, String> auditParams = new LinkedHashMap<String, String>();
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

    private void populateProfileOutputs(ProfileData data, Profile profile) throws EBaseException {
        // get list of changes for auditing
        List<String> auditAdd = new ArrayList<String>();
        List<String> auditModify = new ArrayList<String>();

        Enumeration<String> existingIds = profile.getProfileOutputIds();
        Map<String, ProfileOutput> existingOutputs = new LinkedHashMap<String, ProfileOutput>();
        while (existingIds.hasMoreElements()) {
            String id = existingIds.nextElement();
            ProfileOutput output = createProfileOutput(profile, id, getLocale(headers));
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
        List<String> auditDelete = new ArrayList<String>(existingOutputs.keySet());

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
                Map<String, String> auditParams = new LinkedHashMap<String, String>();
                auditParams.put("outputs", StringUtils.join(auditDelete, ","));
                auditProfileChange(
                        ScopeDef.SC_PROFILE_OUTPUT,
                        OpDef.OP_DELETE,
                        profile.getId(),
                        ILogger.SUCCESS,
                        auditParams);
            }

            if (!auditAdd.isEmpty()) {
                Map<String, String> auditParams = new LinkedHashMap<String, String>();
                auditParams.put("outputs", StringUtils.join(auditAdd, ","));
                auditProfileChange(
                        ScopeDef.SC_PROFILE_OUTPUT,
                        OpDef.OP_ADD,
                        profile.getId(),
                        ILogger.SUCCESS,
                        auditParams);
            }

            if (!auditModify.isEmpty()) {
                Map<String, String> auditParams = new LinkedHashMap<String, String>();
                auditParams.put("outputs", StringUtils.join(auditModify, ","));
                auditProfileChange(
                        ScopeDef.SC_PROFILE_OUTPUT,
                        OpDef.OP_MODIFY,
                        profile.getId(),
                        ILogger.SUCCESS,
                        auditParams);
            }
        } catch (EProfileException e) {
            Map<String, String> auditParams = new LinkedHashMap<String, String>();

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

    private void populateProfileInputs(ProfileData data, Profile profile) throws EBaseException {
        // get list of changes for auditing
        List<String> auditAdd = new ArrayList<String>();
        List<String> auditModify = new ArrayList<String>();
        Enumeration<String> existingIds = profile.getProfileInputIds();
        Map<String, ProfileInput> existingInputs = new LinkedHashMap<String, ProfileInput>();

        while (existingIds.hasMoreElements()) {
            String id = existingIds.nextElement();
            ProfileInput input = createProfileInput(profile, id, getLocale(headers));
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
        List<String> auditDelete = new ArrayList<String>(existingInputs.keySet());

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
                Map<String, String> auditParams = new LinkedHashMap<String, String>();
                auditParams.put("inputs", StringUtils.join(auditDelete, ","));
                auditProfileChange(
                        ScopeDef.SC_PROFILE_INPUT,
                        OpDef.OP_DELETE,
                        profile.getId(),
                        ILogger.SUCCESS,
                        auditParams);
            }

            if (!auditAdd.isEmpty()) {
                Map<String, String> auditParams = new LinkedHashMap<String, String>();
                auditParams.put("inputs", StringUtils.join(auditAdd, ","));
                auditProfileChange(
                        ScopeDef.SC_PROFILE_INPUT,
                        OpDef.OP_ADD,
                        profile.getId(),
                        ILogger.SUCCESS,
                        auditParams);
            }

            if (!auditModify.isEmpty()) {
                Map<String, String> auditParams = new LinkedHashMap<String, String>();
                auditParams.put("inputs", StringUtils.join(auditModify, ","));
                auditProfileChange(
                        ScopeDef.SC_PROFILE_INPUT,
                        OpDef.OP_MODIFY,
                        profile.getId(),
                        ILogger.SUCCESS,
                        auditParams);
            }
        } catch (EProfileException e) {
            Map<String, String> auditParams = new LinkedHashMap<String, String>();

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

    @Override
    public Response deleteProfile(@PathParam("id") String profileId) {
        if (profileId == null) {
            logger.error("deleteProfile: invalid request. profileId is null");
            throw new BadRequestException("Unable to delete profile: Invalid Profile Id");
        }

        if (ps == null) {
            logger.error("deleteProfile: ps is null");
            throw new PKIException("Error deleting profile.  Profile Service not available");
        }

        try {
            Profile profile = ps.getProfile(profileId);
            if (profile == null) {
                logger.error("Trying to delete profile: " + profileId + ".  Profile already deleted.");
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

            return createNoContentResponse();

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

    public void auditProfileChangeState(String profileId, String op, String status) {
        String msg = CMS.getLogMessage(
                AuditEvent.CERT_PROFILE_APPROVAL,
                auditor.getSubjectID(),
                status,
                profileId,
                op);
        signedAuditLogger.log(msg);
    }

    public void auditProfileChange(String scope, String type, String id, String status, Map<String, String> params) {
        String msg = CMS.getLogMessage(
                AuditEvent.CONFIG_CERT_PROFILE,
                auditor.getSubjectID(),
                status,
                auditor.getParamString(scope, type, id, params));
        signedAuditLogger.log(msg);
    }

}
