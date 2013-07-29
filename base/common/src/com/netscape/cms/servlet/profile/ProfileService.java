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

package com.netscape.cms.servlet.profile;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Vector;

import javax.ws.rs.PathParam;
import javax.ws.rs.core.UriBuilder;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.profile.IProfileEx;
import com.netscape.certsrv.profile.IProfileInput;
import com.netscape.certsrv.profile.IProfileOutput;
import com.netscape.certsrv.profile.IProfilePolicy;
import com.netscape.certsrv.profile.IProfileSubsystem;
import com.netscape.certsrv.profile.PolicyConstraint;
import com.netscape.certsrv.profile.PolicyConstraintValue;
import com.netscape.certsrv.profile.PolicyDefault;
import com.netscape.certsrv.profile.ProfileData;
import com.netscape.certsrv.profile.ProfileDataInfo;
import com.netscape.certsrv.profile.ProfileDataInfos;
import com.netscape.certsrv.profile.ProfileInput;
import com.netscape.certsrv.profile.ProfileNotFoundException;
import com.netscape.certsrv.profile.ProfileOutput;
import com.netscape.certsrv.profile.ProfileParameter;
import com.netscape.certsrv.profile.ProfilePolicy;
import com.netscape.certsrv.profile.ProfileResource;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.registry.IPluginInfo;
import com.netscape.certsrv.registry.IPluginRegistry;
import com.netscape.cms.servlet.base.PKIService;
import com.netscape.cmscore.realm.PKIPrincipal;

/**
 * @author alee
 *
 */
public class ProfileService extends PKIService implements ProfileResource {

    private IProfileSubsystem ps = (IProfileSubsystem) CMS.getSubsystem(IProfileSubsystem.ID);
    private IPluginRegistry registry = (IPluginRegistry) CMS.getSubsystem(CMS.SUBSYSTEM_REGISTRY);
    private IConfigStore cs = CMS.getConfigStore().getSubStore("profile");

    public ProfileDataInfos listProfiles() {
        List<ProfileDataInfo> list = new ArrayList<ProfileDataInfo>();
        ProfileDataInfos infos = new ProfileDataInfos();
        boolean visibleOnly = true;

        if (ps == null) {
            return null;
        }

        PKIPrincipal principal = (PKIPrincipal)servletRequest.getUserPrincipal();
        if ((principal != null) &&
            (principal.hasRole("Certificate Manager Agents") ||
             principal.hasRole("Certificate Manager Administrators"))) {
            visibleOnly = false;
        }
        Enumeration<String> profileIds = ps.getProfileIds();
        if (profileIds != null) {
            while (profileIds.hasMoreElements()) {
                String id = profileIds.nextElement();
                ProfileDataInfo info = null;
                try {
                    info = createProfileDataInfo(id, visibleOnly);
                } catch (EBaseException e) {
                    continue;
                }

                if (info != null) {
                    list.add(info);
                }
            }
        }

        infos.setProfileInfos(list);
        return infos;
    }

    public ProfileData retrieveProfile(String profileId) throws ProfileNotFoundException {
        ProfileData data = null;
        boolean visibleOnly = false;

        if (ps == null) {
            return null;
        }

        PKIPrincipal principal = (PKIPrincipal)servletRequest.getUserPrincipal();
        if ((principal != null) &&
            (principal.hasRole("Certificate Manager Agents") ||
             principal.hasRole("Certificate Manager Administrators"))) {
            visibleOnly = true;
        }

        Enumeration<String> profileIds = ps.getProfileIds();

        IProfile profile = null;
        if (profileIds != null) {
            while (profileIds.hasMoreElements()) {
                String id = profileIds.nextElement();

                if (id.equals(profileId)) {

                    try {
                        profile = ps.getProfile(profileId);
                    } catch (EProfileException e) {
                        e.printStackTrace();
                        throw new ProfileNotFoundException(profileId);
                    }
                    break;
                }
            }
        }

        if (profile == null) {
            throw new ProfileNotFoundException(profileId);
        }

        if (visibleOnly && !profile.isVisible()) {
            throw new ProfileNotFoundException(profileId);
        }

        try {
            data = createProfileData(profileId);
        } catch (EBaseException e) {
            e.printStackTrace();
            throw new ProfileNotFoundException(profileId);
        }

        return data;
    }

    public ProfileData createProfileData(String profileId) throws EBaseException {

        IProfile profile;

        try {
            profile = ps.getProfile(profileId);
        } catch (EProfileException e) {
            e.printStackTrace();
            throw new ProfileNotFoundException(profileId);
        }

        ProfileData data = new ProfileData();

        data.setAuthenticatorId(profile.getAuthenticatorId());
        data.setAuthzAcl(profile.getAuthzAcl());
        data.setClassId(cs.getString(profileId + ".class_id"));
        data.setDescription(profile.getDescription(getLocale()));
        data.setEnabled(ps.isProfileEnable(profileId));
        data.setEnabledBy(ps.getProfileEnableBy(profileId));
        data.setId(profileId);
        data.setName(profile.getName(getLocale()));
        data.setRenewal(Boolean.getBoolean(profile.isRenewal()));
        data.setVisible(profile.isVisible());
        data.setXMLOutput(Boolean.getBoolean(profile.isXmlOutput()));

        Enumeration<String> inputIds = profile.getProfileInputIds();
        if (inputIds != null) {
            IConfigStore inputStore = profile.getConfigStore().getSubStore("input");
            while (inputIds.hasMoreElements()) {
                String inputId = inputIds.nextElement();
                IProfileInput profileInput = profile.getProfileInput(inputId);

                if (profileInput == null) {
                    continue;
                }

                String classId = inputStore.getString(inputId + ".class_id");

                ProfileInput input = new ProfileInput(profileInput, classId, getLocale());
                data.addProfileInput(inputId, input);
            }
        }

        // profile outputs
        Enumeration<String> outputIds = profile.getProfileOutputIds();
        if (outputIds != null) {
            IConfigStore outputStore = profile.getConfigStore().getSubStore("output");
            while (outputIds.hasMoreElements()) {
                String outputId = outputIds.nextElement();
                IProfileOutput profileOutput = profile.getProfileOutput(outputId);

                if (profileOutput == null) {
                    continue;
                }

                String classId = outputStore.getString(outputId + ".class_id");

                ProfileOutput output = new ProfileOutput(profileOutput, classId, getLocale());
                data.addProfileOutput(outputId, output);
            }
        }

        // profile policies
        Enumeration<String> policySetIds = profile.getProfilePolicySetIds();
        if (policySetIds != null) {
            while (policySetIds.hasMoreElements()) {
                Vector<ProfilePolicy> pset = new Vector<ProfilePolicy>();
                String policySetId = policySetIds.nextElement();
                Enumeration<com.netscape.cms.profile.common.ProfilePolicy> policies =
                        profile.getProfilePolicies(policySetId);
                if (policies != null) {
                    while (policies.hasMoreElements()) {
                        com.netscape.cms.profile.common.ProfilePolicy policy = policies.nextElement();
                        IConfigStore policyStore = profile.getConfigStore().getSubStore(
                                "policyset." + policySetId + "." + policy.getId());
                        ProfilePolicy p = new ProfilePolicy();
                        String constraintClassId = policyStore.getString("constraint.class_id");
                        p.setConstraint(PolicyConstraintFactory.create(getLocale(), policy.getConstraint(), constraintClassId));
                        String defaultClassId = policyStore.getString("default.class_id");
                        p.setDef(PolicyDefaultFactory.create(getLocale(), policy.getDefault(), defaultClassId));
                        p.setId(policy.getId());
                        pset.add(p);
                    }
                }
                if (!pset.isEmpty()) {
                    data.addProfilePolicySet(policySetId, pset);
                }
            }
        }

        return data;
    }

    public ProfileDataInfo createProfileDataInfo(String profileId, boolean visibleOnly) throws EBaseException {

        if (profileId == null) {
            throw new EBaseException("Error creating ProfileDataInfo.");
        }
        ProfileDataInfo ret = null;

        IProfile profile = null;

        profile = ps.getProfile(profileId);
        if (profile == null) {
            return null;
        }

        if (visibleOnly && !profile.isVisible()) {
            return null;
        }

        ret = new ProfileDataInfo();

        ret.setProfileId(profileId);
        ret.setProfileName(profile.getName(getLocale()));
        ret.setProfileDescription(profile.getDescription(getLocale()));

        UriBuilder profileBuilder = uriInfo.getBaseUriBuilder();
        URI uri = profileBuilder.path(ProfileResource.class).path("{id}").
                build(profileId);

        /*
        URI uri = null;
        if (visibleOnly) {
            uri = profileBuilder.path(ProfileResource.class).path("profiles").path("{id}")
                    .build(profileId);
        } else {
            uri = profileBuilder.path(ProfileResource.class).path("agent").path("profiles")
                    .path("{id}").build(profileId);
        }*/

        ret.setProfileURL(uri.toString());

        return ret;
    }

    public void modifyProfileState(String profileId, String action) {
        if (ps == null) {
            // throw internal error exception;
        }

        Principal principal = servletRequest.getUserPrincipal();

        switch (action) {
        case "enable":
            if (ps.isProfileEnable(profileId)) {
                // throw new ProfileAlreadyEnabled exception
            }
            try {
                ps.enableProfile(profileId, principal.getName());
            } catch (EProfileException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            break;
        case "disable":
            if (!ps.isProfileEnable(profileId)) {
                // throw new ProfileAlreadyDisabled exception
            }
            String userid = principal.getName();
            try {
                if (ps.checkOwner()) {
                    if (ps.getProfileEnableBy(profileId).equals(userid)) {
                        ps.disableProfile(profileId);
                    } else {
                        // audit log messages
                        // throw Unauthorized exception
                    }
                } else {
                    ps.disableProfile(profileId);
                }
            } catch (EProfileException e) {
                e.printStackTrace();
                // throw internal error exception
            }
            break;
        default:
            // throw Bad Request exception
        }
    }

    public void createProfile(ProfileData data){
        if (ps == null) {
            // throw internal error exception;
        }

        IProfile profile = null;
        String profileId = data.getId();
        try {
            profile = ps.getProfile(profileId);
            if (profile != null) {
                // throw Profile Already Exists Exception
            }
            String config = CMS.getConfigStore().getString("instanceRoot") + "/ca/profiles/ca/" +
                    profileId + ".cfg";
            File configFile = new File(config);
            configFile.createNewFile();
            IPluginInfo info = registry.getPluginInfo("profile", data.getClassId());

            profile = ps.createProfile(profileId, data.getClassId(), info.getClassName(), config);
            profile.setName(getLocale(),data.getName());
            profile.setDescription(getLocale(), data.getDescription());
            profile.setVisible(data.isVisible());
            profile.getConfigStore().commit(false);
            ps.createProfileConfig(profileId, data.getClassId(), config);

            if (profile instanceof IProfileEx) {
                // populates profile specific plugins such as
                // policies, inputs and outputs with defaults
                ((IProfileEx) profile).populate();
            }
        } catch (EBaseException | IOException e) {
            e.printStackTrace();
            // throw internal error exception
        }

        changeProfileData(data, profile);
    }

    public void modifyProfile(String profileId, ProfileData data){
        if (ps == null) {
            // throw internal error exception;
        }

        IProfile profile = null;
        try {
            profile = ps.getProfile(profileId);
            if (profile == null) {
                // throw ProfileNotExist Exception
            }
        } catch (EBaseException e) {
            e.printStackTrace();
            // throw internal error exception
        }

        changeProfileData(data, profile);
    }

    private void changeProfileData(ProfileData data, IProfile profile) {
        String profileId = data.getId();
        if (profile == null) {
            // throw internal error exception
        }
        if (ps.isProfileEnable(profileId)) {
            // throw bad request - profile must be disabled
        }

        Map<String, String> auditParams = new LinkedHashMap<String, String>();

        if (differs(profile.getAuthenticatorId(), data.getAuthenticatorId())) {
            profile.setAuthenticatorId(data.getAuthenticatorId());
            auditParams.put("authenticatorId", data.getAuthenticatorId());
        }

        if (differs(profile.getAuthzAcl(),data.getAuthzAcl())) {
            profile.setAuthzAcl(data.getAuthzAcl());
            auditParams.put("authzAcl", data.getAuthzAcl());
        }

        if (differs(profile.getDescription(getLocale()), data.getDescription())) {
            profile.setDescription(getLocale(), data.getDescription());
            auditParams.put("description", data.getDescription());
        }

        if (differs(profile.getId(),data.getId())) {
            profile.setId(data.getId());
            auditParams.put("id", data.getId());
        }

        if (differs(profile.getName(getLocale()),data.getName())) {
            profile.setName(getLocale(),data.getName());
            auditParams.put("name", data.getName());
        }

        // TODO renewal is a string in Profile, should be changed
        if (differs(profile.isRenewal(),Boolean.toString(data.isRenewal()))) {
            profile.setRenewal(data.isRenewal());
            auditParams.put("renewal", Boolean.toString(data.isRenewal()));
        }

        if (! profile.isVisible() == data.isVisible()) {
            profile.setVisible(data.isVisible());
            auditParams.put("visible", Boolean.toString(data.isVisible()));
        }

        // TODO xmloutput is a string in Profile, should be changed
        if (differs(profile.isXmlOutput(),Boolean.toString(data.isXMLOutput()))) {
            profile.setXMLOutput(data.isXMLOutput());
            auditParams.put("xmloutput", Boolean.toString(data.isXMLOutput()));
        }

        // add audit log for auditParams

        try {
            populateProfileInputs(data, profile);

            // add audit log for profile inputs

            populateProfileOutputs(data, profile);

            // add audit log for profile outputs

            populateProfilePolicies(data, profile);

            // add audit log for profile policies

            profile.getConfigStore().commit(false);
        } catch (EPropertyException e) {
            e.printStackTrace();
            // throw bad request exception
        } catch (EBaseException e) {
            e.printStackTrace();
            // throw internal error exception
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

    private void populateProfilePolicies(ProfileData data, IProfile profile) throws EProfileException, EPropertyException {
        profile.deleteAllProfilePolicies();
        for (Map.Entry<String,List<ProfilePolicy>> policySet:
            data.getPolicySets().entrySet()) {
            String setId = policySet.getKey();
            for (ProfilePolicy policy: policySet.getValue()) {
                PolicyDefault def = policy.getDef();
                PolicyConstraint con = policy.getConstraint();

                // create policy using defaults for PolicyDefault and PolicyConstraint
                IProfilePolicy p = profile.createProfilePolicy(setId, policy.getId(),
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
                for (ProfileParameter param: def.getParams()) {
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
    }

    private void populateProfileOutputs(ProfileData data, IProfile profile) throws EProfileException {
        profile.deleteAllProfileOutputs();
        Map<String, ProfileOutput> outputs = data.getOutputs();
        for (Entry<String, ProfileOutput> entry: outputs.entrySet()) {
            String id = entry.getKey();
            String classId = entry.getValue().getClassId();

            NameValuePairs nvp = new NameValuePairs();
            // TODO - add a field for params in ProfileOuput
            // No current examples
            profile.createProfileOutput(id, classId, nvp);
        }
    }

    private void populateProfileInputs(ProfileData data, IProfile profile) throws EProfileException {
        profile.deleteAllProfileInputs();
       Map<String, ProfileInput> inputs = data.getInputs();
        for (Entry<String, ProfileInput> entry: inputs.entrySet()) {
            String id = entry.getKey();
            String classId = entry.getValue().getClassId();

            NameValuePairs nvp = new NameValuePairs();
            // TODO - add a field for params in ProfileInput.
            // an example of this is DomainController.cfg
            profile.createProfileInput(id, classId, nvp);
        }
    }

    public void deleteProfile(@PathParam("id") String profileId) {
        if (ps == null) {
            // throw internal error exception;
        }

        try {
            IProfile profile = ps.getProfile(profileId);
            if (profile == null) {
                // log already deleted
                return;
            }

            if (ps.isProfileEnable(profileId)) {
                // log attempt to delete profile when enabled
                // throw unauthorized exception
            }

            String configFile = CMS.getConfigStore().getString("profile." + profileId + ".config");

            ps.deleteProfile(profileId, configFile);
        } catch (EBaseException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }


    }
}
