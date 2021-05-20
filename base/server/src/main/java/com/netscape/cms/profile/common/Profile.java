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
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.profile.common;

import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Locale;
import java.util.Map;
import java.util.StringTokenizer;
import java.util.Vector;

import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.profile.EDeferException;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.ERejectException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.registry.IPluginInfo;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.logging.Logger;
import com.netscape.cms.logging.SignedAuditLogger;
import com.netscape.cms.profile.constraint.PolicyConstraint;
import com.netscape.cms.profile.def.PolicyDefault;
import com.netscape.cms.profile.input.EnrollInput;
import com.netscape.cms.profile.updater.IProfileUpdater;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.registry.PluginRegistry;

/**
 * This class implements a basic profile. A profile contains
 * a list of input policies, default policies, constraint
 * policies and output policies.
 * <p>
 *
 * The input policy is for building the enrollment page.
 * <p>
 *
 * The default policy is for populating user-supplied and system-supplied values into the request.
 * <p>
 *
 * The constraint policy is for validating the request before processing.
 * <p>
 *
 * The output policy is for building the result page.
 * <p>
 *
 * Each profile can have multiple policy set. Each set is composed of zero or more default policies and zero or more
 * constraint policies.
 * <p>
 */
public abstract class Profile {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(Profile.class);
    protected static Logger signedAuditLogger = SignedAuditLogger.getLogger();

    public static final String PROP_ENABLE = "enable";
    public static final String PROP_ENABLE_BY = "enableBy";
    public static final String PROP_IS_RENEWAL = "renewal";
    public static final String PROP_XML_OUTPUT = "xmlOutput";
    public static final String PROP_VISIBLE = "visible";
    public static final String PROP_INPUT_LIST = "list";
    public static final String PROP_OUTPUT_LIST = "list";
    public static final String PROP_UPDATER_LIST = "list";
    public static final String PROP_POLICY_LIST = "list";
    public static final String PROP_DEFAULT = "default";
    public static final String PROP_CONSTRAINT = "constraint";
    public static final String PROP_INPUT = "input";
    public static final String PROP_OUTPUT = "output";
    public static final String PROP_CLASS_ID = "class_id";
    public static final String PROP_INSTANCE_ID = "instance_id";
    public static final String PROP_PARAMS = "params";
    public static final String PROP_NAME = "name";
    public static final String PROP_DESC = "desc";
    public static final String PROP_NO_DEFAULT = "noDefaultImpl";
    public static final String PROP_NO_CONSTRAINT = "noConstraintImpl";
    public static final String PROP_GENERIC_EXT_DEFAULT = "genericExtDefaultImpl";

    protected IConfigStore mConfig = null;
    protected PluginRegistry registry;

    protected Vector<String> mInputNames = new Vector<>();
    protected Hashtable<String, ProfileInput> mInputs = new Hashtable<>();
    protected Vector<String> mInputIds = new Vector<>();
    protected Hashtable<String, ProfileOutput> mOutputs = new Hashtable<>();
    protected Vector<String> mOutputIds = new Vector<>();
    protected Hashtable<String, IProfileUpdater> mUpdaters = new Hashtable<>();
    protected Vector<String> mUpdaterIds = new Vector<>();
    protected String mAuthInstanceId = null;
    protected String mId = null;
    protected String mAuthzAcl = "";

    protected Hashtable<String, Vector<ProfilePolicy>> mPolicySet = new Hashtable<>();

    public Profile() {
    }

    public boolean isEnable() {
        try {
            return mConfig.getBoolean(PROP_ENABLE, false);
        } catch (EBaseException e) {
            return false;
        }
    }

    /**
     * Is this a renewal profile
     */
    public String isRenewal() {
        try {
            return mConfig.getString(PROP_IS_RENEWAL, "false");
        } catch (EBaseException e) {
            return "false";
        }
    }

    public void setRenewal(boolean renewal) {
        mConfig.putBoolean(PROP_IS_RENEWAL, renewal);
    }

    /**
     * is output going to be in xml?
     */
    public String isXmlOutput() {
        try {
            return mConfig.getString(PROP_XML_OUTPUT, "false");
        } catch (EBaseException e) {
            return "false";
        }
    }

    public void setXMLOutput(boolean xmlOutput) {
        mConfig.putBoolean(PROP_XML_OUTPUT, xmlOutput);
    }

    /**
     * Retrieves the user id of the person who
     * approves this profile.
     *
     * @return user id of the approver of this profile
     */
    public String getApprovedBy() {
        try {
            return mConfig.getString(PROP_ENABLE_BY, "");
        } catch (EBaseException e) {
            return "";
        }
    }

    /**
     * Sets id of this profile.
     *
     * @param id profile identifier
     */
    public void setId(String id) {
        mId = id;
    }

    /**
     * Returns the identifier of this profile.
     *
     * @return profile id
     */
    public String getId() {
        return mId;
    }

    /**
     * Retrieves a localized string that represents
     * requestor's distinguished name. This string
     * displayed in the request listing user interface.
     *
     * @param request request
     * @return distringuished name of the request owner
     */
    public String getRequestorDN(IRequest request) {
        return null;
    }

    /**
     * Retrieves the instance id of the authenticator for this profile.
     *
     * @return authenticator instance id
     */
    public String getAuthenticatorId() {
        return mAuthInstanceId;
    }

    /**
     * Sets the instance id of the authenticator for this profile.
     *
     * @param id authenticator instance id
     */
    public void setAuthenticatorId(String id) {
        mAuthInstanceId = id;
        mConfig.putString("auth." + PROP_INSTANCE_ID, id);
    }

    public void setAuthzAcl(String id) {
        mAuthzAcl = id;
        mConfig.putString("authz.acl", id);
    }

    public String getAuthzAcl() {
        return mAuthzAcl;
    }

    /**
     * Initializes this profile.
     * @param config configuration store for this profile
     *
     * @exception EBaseException failed to initialize
     */
    public void init(IConfigStore config) throws EBaseException {

        logger.debug("Profile: start init");
        mConfig = config;

        CMSEngine engine = CMS.getCMSEngine();
        registry = engine.getPluginRegistry();

        // Configure File Formats:
        // visible
        // auth.class_id=NoAuthImpl
        // auth.params.x1=x1
        // input.list=i1,i2,...
        // input.i1.class=com.netscape.cms.profile.input.CertReqInput
        // input.i1.params.x1=x1
        // policy.list=p1,p2,...
        // policy.p1.enable=true
        // policy.p1.default.class=com.netscape.cms.profile.defaults.SubjectName
        // policy.p1.default.params.x1=x1
        // policy.p1.default.params.x2=x2
        // policy.p1.constraint.class= ... .cms.profile.constraints.ValidityRange
        // policy.p1.constraint.params.x1=x1
        // policy.p1.constraint.params.x2=x2

        // handle profile authentication plugins
        try {
            mAuthInstanceId = config.getString("auth." + PROP_INSTANCE_ID, null);
            mAuthzAcl = config.getString("authz.acl", "");
        } catch (EBaseException e) {
            logger.warn("Profile: authentication class not found " + e.getMessage(), e);
        }

        // handle profile input plugins
        IConfigStore inputStore = config.getSubStore("input");
        String input_list = inputStore.getString(PROP_INPUT_LIST, "");
        StringTokenizer input_st = new StringTokenizer(input_list, ",");

        while (input_st.hasMoreTokens()) {
            String input_id = input_st.nextToken();
            String inputClassId = inputStore.getString(input_id + "." +
                    PROP_CLASS_ID);
            IPluginInfo inputInfo = registry.getPluginInfo("profileInput",
                    inputClassId);
            String inputClass = inputInfo.getClassName();

            EnrollInput input = null;
            try {
                input = (EnrollInput) Class.forName(inputClass).getDeclaredConstructor().newInstance();
            } catch (Exception e) {
                // throw Exception
                logger.error("Profile: input plugin Class.forName " + inputClass + " " + e.getMessage(), e);
                throw new EBaseException(e.toString());
            }

            IConfigStore inputConfig = inputStore.getSubStore(input_id);
            input.init(this, inputConfig);
            mInputs.put(input_id, input);
            mInputIds.addElement(input_id);
        }

        // handle profile output plugins
        IConfigStore outputStore = config.getSubStore("output");
        String output_list = outputStore.getString(PROP_OUTPUT_LIST, "");
        StringTokenizer output_st = new StringTokenizer(output_list, ",");

        while (output_st.hasMoreTokens()) {
            String output_id = output_st.nextToken();

            String outputClassId = outputStore.getString(output_id + "." +
                    PROP_CLASS_ID);
            IPluginInfo outputInfo = registry.getPluginInfo("profileOutput",
                    outputClassId);
            String outputClass = outputInfo.getClassName();

            ProfileOutput output = null;

            try {
                output = (ProfileOutput) Class.forName(outputClass).getDeclaredConstructor().newInstance();
            } catch (Exception e) {
                // throw Exception
                logger.error("Profile: output plugin Class.forName " +
                        outputClass + " " + e.getMessage(), e);
                throw new EBaseException(e.toString());
            }
            IConfigStore outputConfig = outputStore.getSubStore(output_id);
            output.init(outputConfig);
            mOutputs.put(output_id, output);
            mOutputIds.addElement(output_id);
        }

        // handle profile output plugins
        IConfigStore updaterStore = config.getSubStore("updater");
        String updater_list = updaterStore.getString(PROP_UPDATER_LIST, "");
        StringTokenizer updater_st = new StringTokenizer(updater_list, ",");

        while (updater_st.hasMoreTokens()) {
            String updater_id = updater_st.nextToken();

            String updaterClassId = updaterStore.getString(updater_id + "." +
                    PROP_CLASS_ID);
            IPluginInfo updaterInfo = registry.getPluginInfo("profileUpdater",
                     updaterClassId);
            String updaterClass = updaterInfo.getClassName();

            IProfileUpdater updater = null;

            try {
                updater = (IProfileUpdater) Class.forName(updaterClass).getDeclaredConstructor().newInstance();
            } catch (Exception e) {
                // throw Exception
                logger.error("Profile: updater plugin Class.forName " +
                        updaterClass + " " + e.getMessage(), e);
                throw new EBaseException(e.toString());
            }
            IConfigStore updaterConfig = updaterStore.getSubStore(updater_id);
            updater.init(this, updaterConfig);
            mUpdaters.put(updater_id, updater);
            mUpdaterIds.addElement(updater_id);
        }

        // handle profile policy plugins
        IConfigStore policySetStore = config.getSubStore("policyset");
        String setlist = policySetStore.getString("list", "");
        StringTokenizer st = new StringTokenizer(setlist, ",");

        while (st.hasMoreTokens()) {
            String setId = st.nextToken();

            IConfigStore policyStore = policySetStore.getSubStore(setId);
            String list = policyStore.getString(PROP_POLICY_LIST, "");
            StringTokenizer st1 = new StringTokenizer(list, ",");

            while (st1.hasMoreTokens()) {
                String id = st1.nextToken();

                String defaultRoot = id + "." + PROP_DEFAULT;
                String defaultClassId = policyStore.getString(defaultRoot + "." +
                        PROP_CLASS_ID);

                String constraintRoot = id + "." + PROP_CONSTRAINT;
                String constraintClassId =
                        policyStore.getString(constraintRoot + "." + PROP_CLASS_ID);

                createProfilePolicy(setId, id, defaultClassId,
                        constraintClassId, false);
            }
        }
        logger.debug("Profile: done init");
    }

    /**
     * Retrieves the configuration store of this profile.
     *
     * @return configuration store
     */
    public IConfigStore getConfigStore() {
        return mConfig;
    }

    public Enumeration<String> getInputNames() {
        return mInputNames.elements();
    }

    public Enumeration<String> getProfileUpdaterIds() {
        return mUpdaterIds.elements(); // ordered list
    }

    public IProfileUpdater getProfileUpdater(String name) {
        return mUpdaters.get(name);
    }

    /**
     * Retrieves a list of output policy IDs.
     *
     * @return output policy id list
     */
    public Enumeration<String> getProfileOutputIds() {
        return mOutputIds.elements(); // ordered list
    }

    /**
     * Retrieves output policy by id.
     *
     * @param id output policy id
     * @return output policy instance
     */
    public ProfileOutput getProfileOutput(String id) {
        return mOutputs.get(id);
    }

    /**
     * Retrieves a list of input policy IDs.
     *
     * @return input policy id list
     */
    public Enumeration<String> getProfileInputIds() {
        return mInputIds.elements(); // ordered list
    }

    /**
     * Retrieves input policy by id.
     *
     * @param id input policy id
     * @return input policy instance
     */
    public ProfileInput getProfileInput(String id) {
        return mInputs.get(id);
    }

    public void addInputName(String name) {
        mInputNames.addElement(name);
    }

    public IDescriptor getInputDescriptor(String name) {
        return null;
    }

    public String getInput(String name, Locale locale, IRequest request)
            throws EProfileException {
        return null;
    }

    public void setInput(String name, Locale locale, IRequest request,
            String value) throws EProfileException {
    }

    /**
     * Returns the profile policy set identifiers.
     *
     * @return a list of policy set id
     */
    public Enumeration<String> getProfilePolicySetIds() {
        return mPolicySet.keys();
    }

    /**
     * Deletes a policy.
     *
     * @param setId id of the policy set
     * @param policyId id of policy to delete
     * @exception EProfileException failed to delete
     */
    public void deleteProfilePolicy(String setId, String policyId)
            throws EProfileException {
        Vector<ProfilePolicy> policies = mPolicySet.get(setId);

        if (policies == null) {
            return;
        }
        try {
            IConfigStore policySetSubStore = mConfig.getSubStore("policyset");
            IConfigStore policySubStore = policySetSubStore.getSubStore(setId);

            policySubStore.removeSubStore(policyId);
            String list = policySubStore.getString(PROP_POLICY_LIST, null);
            StringTokenizer st = new StringTokenizer(list, ",");
            String newlist = "";
            StringBuffer sb = new StringBuffer();

            while (st.hasMoreTokens()) {
                String e = st.nextToken();

                if (!e.equals(policyId)) {
                    sb.append(e);
                    sb.append(",");
                }
            }
            newlist = sb.toString();
            if (!newlist.equals("")) {
                newlist = newlist.substring(0, newlist.length() - 1);
                policySubStore.putString(PROP_POLICY_LIST, newlist);
            } else {
                policySetSubStore.removeSubStore(setId);
            }

            int size = policies.size();

            for (int i = 0; i < size; i++) {
                ProfilePolicy policy = policies.elementAt(i);
                String id = policy.getId();

                if (id.equals(policyId)) {
                    policies.removeElementAt(i);
                    if (size == 1) {
                        mPolicySet.remove(setId);
                        String setlist = policySetSubStore.getString(PROP_POLICY_LIST, null);
                        StringTokenizer st1 = new StringTokenizer(setlist, ",");
                        String newlist1 = "";

                        while (st1.hasMoreTokens()) {
                            String e = st1.nextToken();

                            if (!e.equals(setId))
                                newlist1 = newlist1 + e + ",";
                        }
                        if (!newlist1.equals(""))
                            newlist1 = newlist1.substring(0, newlist1.length() - 1);
                        policySetSubStore.putString(PROP_POLICY_LIST, newlist1);
                    }
                    break;
                }
            }

            mConfig.putString("lastModified",
                    Long.toString(new Date().getTime()));
            mConfig.commit(false);
        } catch (Exception e) {
        }

    }

    /**
     * Delete all profile policies
     * @exception EProfileException
     */
    public void deleteAllProfilePolicies() throws EProfileException {
        for (Map.Entry<String, Vector<ProfilePolicy>> entry : mPolicySet.entrySet()) {
            String setId = entry.getKey();
            Vector<ProfilePolicy> pList = new Vector<>(entry.getValue());
            for (ProfilePolicy policy: pList) {
                deleteProfilePolicy(setId, policy.getId());
            }
        }

        mPolicySet.clear();
    }

    /**
     * Deletes input policy by id.
     *
     * @param inputId id of the input policy
     * @exception EProfileException failed to delete
     */
    public void deleteProfileInput(String inputId) throws EProfileException {
        try {
            mConfig.removeSubStore("input." + inputId);
            String list = mConfig.getString("input." + PROP_INPUT_LIST, null);
            StringTokenizer st = new StringTokenizer(list, ",");
            String newlist = "";
            StringBuffer sb = new StringBuffer();

            while (st.hasMoreTokens()) {
                String e = st.nextToken();

                if (!e.equals(inputId)) {
                    sb.append(e);
                    sb.append(",");
                }
            }
            newlist = sb.toString();
            if (!newlist.equals(""))
                newlist = newlist.substring(0, newlist.length() - 1);

            int size = mInputIds.size();

            for (int i = 0; i < size; i++) {
                String id = mInputIds.elementAt(i);

                if (id.equals(inputId)) {
                    mInputIds.removeElementAt(i);
                    break;
                }
            }

            mInputs.remove(inputId);
            mConfig.putString("input." + PROP_INPUT_LIST, newlist);
            mConfig.putString("lastModified",
                    Long.toString(new Date().getTime()));
            mConfig.commit(false);
        } catch (Exception e) {
        }
    }

    /**
     * Delete all profile inputs
     * @throws EProfileException
     */
    public void deleteAllProfileInputs() throws EProfileException {
        // need to use a copy here because we are removing elements from the vector
        Vector<String> inputs = new Vector<>(mInputIds);
        for (String id: inputs) {
            deleteProfileInput(id);
        }
    }

    /**
     * Deletes output policy by id.
     *
     * @param outputId id of the output policy
     * @exception EProfileException failed to delete
     */
    public void deleteProfileOutput(String outputId) throws EProfileException {
        try {
            mConfig.removeSubStore("output." + outputId);
            String list = mConfig.getString("output." + PROP_OUTPUT_LIST, null);
            StringTokenizer st = new StringTokenizer(list, ",");
            String newlist = "";
            StringBuffer sb = new StringBuffer();

            while (st.hasMoreTokens()) {
                String e = st.nextToken();

                if (!e.equals(outputId)) {
                    sb.append(e);
                    sb.append(",");
                }
            }
            newlist = sb.toString();
            if (!newlist.equals(""))
                newlist = newlist.substring(0, newlist.length() - 1);

            int size = mOutputIds.size();

            for (int i = 0; i < size; i++) {
                String id = mOutputIds.elementAt(i);

                if (id.equals(outputId)) {
                    mOutputIds.removeElementAt(i);
                    break;
                }
            }

            mOutputs.remove(outputId);
            mConfig.putString("output." + PROP_OUTPUT_LIST, newlist);
            mConfig.putString("lastModified",
                    Long.toString(new Date().getTime()));
            mConfig.commit(false);
        } catch (Exception e) {
        }
    }

    /**
     * Delete all profile inputs
     * @exception EProfileException
     */
    public void deleteAllProfileOutputs() throws EProfileException {
     // need to use a copy here because we are removing elements from the vector
        Vector<String> outputs = new Vector<>(mOutputIds);
        for (String id: outputs) {
            deleteProfileOutput(id);
        }
    }

    /**
     * Creates a output policy.
     *
     * @param id output policy id
     * @param outputID id of the registered output implementation
     * @param nvps default parameters
     * @return output policy
     * @exception EProfileException failed to create
     */
    public ProfileOutput createProfileOutput(String id, String outputID,
            NameValuePairs nvps)
            throws EProfileException {
        return createProfileOutput(id, outputID, nvps, true);
    }

    public ProfileOutput createProfileOutput(String id, String outputId,
            NameValuePairs nvps, boolean createConfig)

    throws EProfileException {
        IConfigStore outputStore = mConfig.getSubStore("output");

        IPluginInfo outputInfo = registry.getPluginInfo("profileOutput",
                outputId);

        if (outputInfo == null) {
            logger.error("Cannot find " + outputId);
            throw new EProfileException("Cannot find " + outputId);
        }
        String outputClass = outputInfo.getClassName();

        logger.debug("Profile: loading output class " + outputClass);
        ProfileOutput output = null;

        try {
            output = (ProfileOutput) Class.forName(outputClass).getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            // throw Exception
            logger.warn(e.getMessage(), e);
        }
        if (output == null) {
            logger.warn("Profile: failed to create " + outputClass);
        } else {
            logger.debug("Profile: initing " + id + " output");

            logger.debug("Profile: outputStore " + outputStore);
            output.init(outputStore);

            mOutputs.put(id, output);
            mOutputIds.addElement(id);
        }

        if (createConfig) {
            String list = null;

            try {
                list = outputStore.getString(PROP_OUTPUT_LIST, null);
            } catch (EBaseException e) {
            }
            if (list == null || list.equals("")) {
                outputStore.putString(PROP_OUTPUT_LIST, id);
            } else {
                StringTokenizer st1 = new StringTokenizer(list, ",");

                while (st1.hasMoreTokens()) {
                    String pid = st1.nextToken();

                    if (pid.equals(id)) {
                        throw new EProfileException("Duplicate output id: " + id);
                    }
                }
                outputStore.putString(PROP_OUTPUT_LIST, list + "," + id);
            }
            String prefix = id + ".";

            outputStore.putString(prefix + "name",
                    outputInfo.getName(Locale.getDefault()));
            outputStore.putString(prefix + "class_id", outputId);

            for (String name : nvps.keySet()) {

                outputStore.putString(prefix + "params." + name, nvps.get(name));
                try {
                    if (output != null) {
                        output.setConfig(name, nvps.get(name));
                    }
                } catch (EBaseException e) {
                    logger.warn(e.getMessage(), e);
                }
            }

            try {
                mConfig.putString("lastModified",
                        Long.toString(new Date().getTime()));
                mConfig.commit(false);
            } catch (EBaseException e) {
                logger.warn(e.getMessage(), e);
            }
        }

        return output;
    }

    /**
     * Creates a input policy.
     *
     * @param id input policy id
     * @param inputID id of the registered input implementation
     * @param nvps default parameters
     * @return input policy
     * @exception EProfileException failed to create
     */
    public ProfileInput createProfileInput(String id, String inputID,
            NameValuePairs nvps)
            throws EProfileException {
        return createProfileInput(id, inputID, nvps, true);
    }

    public ProfileInput createProfileInput(String id, String inputId,
            NameValuePairs nvps, boolean createConfig)
            throws EProfileException {
        IConfigStore inputStore = mConfig.getSubStore("input");

        IPluginInfo inputInfo = registry.getPluginInfo("profileInput",
                inputId);

        if (inputInfo == null) {
            logger.error("Cannot find " + inputId);
            throw new EProfileException("Cannot find " + inputId);
        }

        String inputClass = inputInfo.getClassName();
        logger.debug("Profile: loading input class " + inputClass);

        EnrollInput input = null;
        try {
            input = (EnrollInput) Class.forName(inputClass).getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            // throw Exception
            logger.warn(e.getMessage(), e);
        }

        if (input == null) {
            logger.warn("Profile: failed to create " + inputClass);
        } else {
            logger.debug("Profile: initing " + id + " input");

            logger.debug("Profile: inputStore " + inputStore);
            input.init(this, inputStore);

            mInputs.put(id, input);
            mInputIds.addElement(id);
        }

        if (createConfig) {
            String list = null;

            try {
                list = inputStore.getString(PROP_INPUT_LIST, null);
            } catch (EBaseException e) {
            }
            if (list == null || list.equals("")) {
                inputStore.putString(PROP_INPUT_LIST, id);
            } else {
                StringTokenizer st1 = new StringTokenizer(list, ",");

                while (st1.hasMoreTokens()) {
                    String pid = st1.nextToken();

                    if (pid.equals(id)) {
                        throw new EProfileException("Duplicate input id: " + id);
                    }
                }
                inputStore.putString(PROP_INPUT_LIST, list + "," + id);
            }
            String prefix = id + ".";

            inputStore.putString(prefix + "name",
                    inputInfo.getName(Locale.getDefault()));
            inputStore.putString(prefix + "class_id", inputId);

            for (String name : nvps.keySet()) {

                inputStore.putString(prefix + "params." + name, nvps.get(name));
                try {
                    if (input != null) {
                        input.setConfig(name, nvps.get(name));
                    }
                } catch (EBaseException e) {
                    logger.warn(e.getMessage(), e);
                }
            }

            try {
                mConfig.putString("lastModified",
                        Long.toString(new Date().getTime()));
                mConfig.commit(false);
            } catch (EBaseException e) {
                logger.warn(e.getMessage(), e);
            }
        }

        return input;
    }

    /**
     * Creates a profile policy.
     *
     * @param setId id of the policy set that owns this policy
     * @param id policy id
     * @param defaultClassId id of the registered default implementation
     * @param constraintClassId id of the registered constraint implementation
     * @exception EProfileException failed to create policy
     * @return profile policy instance
     */
    public ProfilePolicy createProfilePolicy(String setId, String id,
            String defaultClassId, String constraintClassId)
            throws EProfileException {
        return createProfilePolicy(setId, id, defaultClassId,
                constraintClassId, true);
    }

    public ProfilePolicy createProfilePolicy(String setId, String id,
            String defaultClassId, String constraintClassId,
            boolean createConfig)
            throws EProfileException {

        String method = "Profile: createProfilePolicy: ";
        logger.debug(method + "begins");
        // String setId ex: policyset.set1
        // String id    Id of policy : examples: p1,p2,p3
        // String defaultClassId : id of the default plugin ex: validityDefaultImpl
        // String constraintClassId : if of the constraint plugin ex: basicConstraintsExtConstraintImpl
        // boolean createConfig : true : being called from the console. false: being called from server startup code

        Vector<ProfilePolicy> policies = mPolicySet.get(setId);

        IConfigStore policyStore = mConfig.getSubStore("policyset." + setId);
        if (policies == null) {
            policies = new Vector<>();
            mPolicySet.put(setId, policies);
            if (createConfig) {
                // re-create policyset.list
                StringBuffer setlist = new StringBuffer();
                Enumeration<String> keys = mPolicySet.keys();

                while (keys.hasMoreElements()) {
                    String k = keys.nextElement();

                    if (!(setlist.toString()).equals("")) {
                        setlist.append(",");
                    }
                    setlist.append(k);
                }
                mConfig.putString("policyset.list", setlist.toString());
            }
        } else {
            String ids = null;

            try {
                ids = policyStore.getString(PROP_POLICY_LIST, "");
            } catch (Exception ee) {
            }

            if (ids == null) {
                logger.warn("Profile: createProfilePolicy() - ids is null!");
                return null;
            }

            StringTokenizer st1 = new StringTokenizer(ids, ",");
            int appearances = 0;
            int appearancesTooMany = 0;
            if (createConfig)
                appearancesTooMany = 1;
            else
                appearancesTooMany = 2;

            while (st1.hasMoreTokens()) {
                String pid = st1.nextToken();
                if (pid.equals(id)) {
                    appearances++;
                    if (appearances >= appearancesTooMany) {
                        logger.warn("detected duplicate policy id:   " + id + " Profile: " + mId);
                        if (createConfig) {
                            throw new EProfileException("Duplicate policy id: " + id);
                        }
                    }
                }
            }
        }

        // Now make sure we aren't trying to add a policy that already exists
        IConfigStore policySetStore = mConfig.getSubStore("policyset");
        String setlist = null;
        try {
            setlist = policySetStore.getString("list", "");
        } catch (Exception e) {
        }
        StringTokenizer st = new StringTokenizer(setlist, ",");

        int matches = 0;
        while (st.hasMoreTokens()) {
            String sId = st.nextToken();

            //Only search the setId set. Ex: encryptionCertSet
            if (!sId.equals(setId)) {
                continue;
            }
            IConfigStore pStore = policySetStore.getSubStore(sId);

            String list = null;
            try {
                list = pStore.getString(PROP_POLICY_LIST, "");
            } catch (Exception e) {
                logger.warn("can't get policy id list!");
            }

            StringTokenizer st1 = new StringTokenizer(list, ",");

            while (st1.hasMoreTokens()) {
                String curId = st1.nextToken();

                String defaultRoot = curId + "." + PROP_DEFAULT;
                String curDefaultClassId = null;
                try {
                    curDefaultClassId = pStore.getString(defaultRoot + "." +
                            PROP_CLASS_ID);
                } catch (Exception e) {
                    logger.warn("can't get default plugin id!");
                }

                //Disallow duplicate defaults  with the following exceptions:
                // noDefaultImpl, genericExtDefaultImpl

                if ((curDefaultClassId.equals(defaultClassId) &&
                        !curDefaultClassId.equals(PROP_NO_DEFAULT) &&
                        !curDefaultClassId.equals(PROP_GENERIC_EXT_DEFAULT))) {

                    matches++;
                    if (createConfig) {
                        if (matches == 1) {
                            logger.warn("attempt to add duplicate Policy "
                                    + defaultClassId + ":" + constraintClassId +
                                    " Contact System Administrator.");
                            throw new EProfileException("Attempt to add duplicate Policy : "
                                    + defaultClassId + ":" + constraintClassId);
                        }
                    } else {
                        if (matches > 1) {
                            logger.warn("attempt to add duplicate Policy "
                                    + defaultClassId + ":" + constraintClassId +
                                    " Contact System Administrator.");
                        }
                    }
                }
            }
        }
        String defaultRoot = id + "." + PROP_DEFAULT;
        String constraintRoot = id + "." + PROP_CONSTRAINT;
        IPluginInfo defInfo = registry.getPluginInfo("defaultPolicy",
                defaultClassId);

        if (defInfo == null) {
            logger.error(method + " Cannot find " + defaultClassId);
            throw new EProfileException("Cannot find " + defaultClassId);
        }
        String defaultClass = defInfo.getClassName();

        logger.debug(method + " loading default class " + defaultClass);
        PolicyDefault def = null;

        try {
            def = (PolicyDefault) Class.forName(defaultClass).getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            // throw Exception
            logger.warn(method + " default policy " +
                    defaultClass + " " + e.getMessage(), e);
        }
        if (def == null) {
            logger.warn("Profile: failed to create " + defaultClass);
        } else {
            IConfigStore defStore = null;

            defStore = policyStore.getSubStore(defaultRoot);
            def.init(defStore);
            logger.debug(method + " default class initialized.");
        }

        IPluginInfo conInfo = registry.getPluginInfo("constraintPolicy",
                constraintClassId);
        if (conInfo == null) {
            logger.error(method + " Cannot find " + constraintClassId);
            throw new EProfileException("Cannot find " + constraintClassId);
        }
        String constraintClass = conInfo.getClassName();

        logger.debug(method + " loading constraint class " + constraintClass);
        PolicyConstraint constraint = null;
        try {
            constraint = (PolicyConstraint) Class.forName(constraintClass).getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            // throw Exception
            logger.warn(method + " constraint policy " +
                    constraintClass + " " + e.getMessage(), e);
        }
        ProfilePolicy policy = null;
        if (constraint == null) {
            logger.warn(method + " failed to create " + constraintClass);
        } else {
            IConfigStore conStore = null;

            conStore = policyStore.getSubStore(constraintRoot);
            constraint.init(conStore);
            policy = new ProfilePolicy(id, def, constraint);
            policies.addElement(policy);
            logger.debug(method + " constraint class initialized.");
        }

        if (createConfig) {
            logger.debug(method + " createConfig true; creating...");
            String list = null;

            try {
                list = policyStore.getString(PROP_POLICY_LIST, null);
            } catch (EBaseException e) {
            }
            if (list == null || list.equals("")) {
                policyStore.putString(PROP_POLICY_LIST, id);
            } else {
                policyStore.putString(PROP_POLICY_LIST, list + "," + id);
            }
            policyStore.putString(id + ".default.name",
                    defInfo.getName(Locale.getDefault()));
            policyStore.putString(id + ".default.class_id",
                    defaultClassId);
            policyStore.putString(id + ".constraint.name",
                    conInfo.getName(Locale.getDefault()));
            policyStore.putString(id + ".constraint.class_id",
                    constraintClassId);
            try {
                mConfig.putString("lastModified",
                        Long.toString(new Date().getTime()));
                policyStore.commit(false);
            } catch (EBaseException e) {
                logger.warn("Profile: commiting config store " +
                        e.getMessage(), e);
            }
            logger.debug(method + " config created.");
        }

        logger.debug(method + "ends");
        return policy;
    }

    /**
     * Retrieves a policy.
     *
     * @param setId set id
     * @param id policy id
     * @return profile policy
     */
    public ProfilePolicy getProfilePolicy(String setId, String id) {
        Vector<ProfilePolicy> policies = mPolicySet.get(setId);

        if (policies == null)
            return null;

        for (int i = 0; i < policies.size(); i++) {
            ProfilePolicy policy = policies.elementAt(i);

            if (policy.getId().equals(id)) {
                return policy;
            }
        }
        return null;
    }

    /**
     * Checks if this profile is end-user profile or not.
     * End-user profile will be displayed to the end user.
     * Non end-user profile mainly is for registration
     * manager.
     *
     * @return end-user profile or not
     */
    public boolean isVisible() {
        try {
            return mConfig.getBoolean(PROP_VISIBLE, false);
        } catch (EBaseException e) {
            return false;
        }
    }

    /**
     * Sets this profile end-user profile or not.
     *
     * @param v end-user profile or not
     */
    public void setVisible(boolean v) {
        mConfig.putBoolean(PROP_VISIBLE, v);
    }

    /**
     * Returns the profile name.
     *
     * @param locale end-user locale
     * @return localized profile name
     */
    public String getName(Locale locale) {
        try {
            return mConfig.getString(PROP_NAME, "");
        } catch (EBaseException e) {
            return "";
        }
    }

    /**
     * Returns the profile name.
     *
     * @param locale end-user locale
     * @param name profile name
     */
    public void setName(Locale locale, String name) {
        mConfig.putString(PROP_NAME, name);
    }

    /**
     * Creates one or more requests. Normally, only one request will
     * be created. In case of CRMF request, multiple requests may be
     * created for one submission.
     *
     * @param ctx profile context
     * @param locale user locale
     * @return a list of requests
     * @exception Exception failed to create requests
     */
    public abstract IRequest[] createRequests(Map<String, String> ctx, Locale locale) throws Exception;

    /**
     * Returns the profile description.
     *
     * @param locale end-user locale
     * @return localized profile description
     */
    public String getDescription(Locale locale) {
        try {
            return mConfig.getString(PROP_DESC, "");
        } catch (EBaseException e) {
            return "";
        }
    }

    /**
     * Returns the profile description.
     *
     * @param locale end-user locale
     * @param desc profile description
     */
    public void setDescription(Locale locale, String desc) {
        mConfig.putString(PROP_DESC, desc);
    }

    /**
     * Populates user-supplied input values into the requests.
     *
     * @param ctx profile context
     * @param request request
     * @exception Exception failed to populate
     */
    public void populateInput(Map<String, String> ctx, IRequest request) throws Exception {

        Enumeration<String> ids = getProfileInputIds();

        while (ids.hasMoreElements()) {
            String id = ids.nextElement();
            ProfileInput input = getProfileInput(id);

            input.populate(ctx, request);
        }
    }

    public Vector<ProfilePolicy> getPolicies(String setId) {
        return mPolicySet.get(setId);
    }

    /**
     * Retrieves a default set id for the given request.
     * It is the profile's responsibility to return
     * an appropriate set id for the request.
     *
     * @param req request
     * @return policy set id
     */
    public abstract String getPolicySetId(IRequest req);

    /**
     * Passes the request to the set of default policies that
     * populate the profile information against the profile.
     *
     * @param request request
     * @exception EProfileException failed to populate default values
     */
    public void populate(IRequest request)
            throws EProfileException {
        String method = "Profile: populate: ";
        String setId = getPolicySetId(request);
        Vector<ProfilePolicy> policies = getPolicies(setId);
        logger.debug(method + "policy setid =" + setId);

        for (int i = 0; i < policies.size(); i++) {
            ProfilePolicy policy = policies.elementAt(i);

            policy.getDefault().populate(request);
        }
    }

    /**
     * Passes the request to the set of constraint policies
     * that validate the request against the profile.
     *
     * @param request request
     * @exception ERejectException validation violation
     */
    public void validate(IRequest request)
            throws ERejectException {
        String setId = getPolicySetId(request);
        logger.debug("Profile: validate start on setId=" + setId);
        Vector<ProfilePolicy> policies = getPolicies(setId);

        for (int i = 0; i < policies.size(); i++) {
            ProfilePolicy policy = policies.elementAt(i);

            policy.getConstraint().validate(request);
        }
        logger.debug("Profile: change to pending state");
        request.setRequestStatus(RequestStatus.PENDING);
        logger.debug("Profile: validate end");
    }

    /**
     * Returns a list of profile policies.
     *
     * @param setId set id
     * @return a list of policies
     */
    public Enumeration<ProfilePolicy> getProfilePolicies(String setId) {
        Vector<ProfilePolicy> policies = mPolicySet.get(setId);

        if (policies == null)
            return null;
        return policies.elements();
    }

    /**
     * Retrieves all the policy id within a set.
     *
     * @param setId set id
     * @return a list of policy id
     */
    public Enumeration<String> getProfilePolicyIds(String setId) {
        Vector<ProfilePolicy> policies = mPolicySet.get(setId);

        if (policies == null)
            return null;

        Vector<String> v = new Vector<>();

        for (int i = 0; i < policies.size(); i++) {
            ProfilePolicy policy = policies.elementAt(i);

            v.addElement(policy.getId());
        }
        return v.elements();
    }

    /**
     * Process a request after validation.
     *
     * @param request request to be processed
     * @exception EProfileException failed to process
     */
    public void execute(IRequest request)
            throws EProfileException {
    }

    /**
     * Handles end-user request submission.
     *
     * @param token authentication token
     * @param request request to be processed
     * @exception EDeferException defer request
     * @exception EProfileException failed to submit
     */
    public abstract void submit(IAuthToken token, IRequest request)
            throws EDeferException, EProfileException;

    /**
     * Signed Audit Log Subject ID
     *
     * This method is used to obtain the "SubjectID" for
     * a signed audit log message.
     * <P>
     *
     * @return id string containing the signed audit log message SubjectID
     */
    protected String auditSubjectID() {

        String subjectID = null;

        // Initialize subjectID
        SessionContext auditContext = SessionContext.getExistingContext();

        if (auditContext != null) {
            subjectID = (String)
                    auditContext.get(SessionContext.USER_ID);

            if (subjectID != null) {
                subjectID = subjectID.trim();
            } else {
                subjectID = ILogger.NONROLEUSER;
            }
        } else {
            subjectID = ILogger.UNIDENTIFIED;
        }

        return subjectID;
    }
}
