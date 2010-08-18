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


import java.util.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.common.*;
import com.netscape.certsrv.profile.*;
import com.netscape.certsrv.authority.*;
import com.netscape.certsrv.registry.*;
import com.netscape.certsrv.request.*;
import com.netscape.certsrv.authentication.*;
import com.netscape.certsrv.property.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.logging.*;


/**
 * This class implements a basic profile.
 *
 * @version $Revision$, $Date$
 */
public abstract class BasicProfile implements IProfile {

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

    protected IProfileSubsystem mOwner = null;
    protected IConfigStore mConfig = null;
    protected IPluginRegistry mRegistry = null;

    protected Vector mInputNames = new Vector();
    protected Hashtable mInputs = new Hashtable();
    protected Vector mInputIds = new Vector();
    protected Hashtable mOutputs = new Hashtable();
    protected Vector mOutputIds = new Vector();
    protected Hashtable mUpdaters = new Hashtable();
    protected Vector mUpdaterIds = new Vector();
    protected IProfileAuthenticator mAuthenticator = null;
    protected String mAuthInstanceId = null;
    protected String mId = null;
    protected String mAuthzAcl = "";

    protected Hashtable mPolicySet = new Hashtable();

    protected ILogger mSignedAuditLogger = CMS.getSignedAuditLogger();

    public BasicProfile() {
    }

    public boolean isEnable() {
        try {
            return mConfig.getBoolean(PROP_ENABLE, false);
        } catch (EBaseException e) {
            return false;
        }
    }

    public String isRenewal() {
        try {
            return mConfig.getString(PROP_IS_RENEWAL, "false");
        } catch (EBaseException e) {
            return "false";
        }
    }

    public String isXmlOutput() {
        try {
            return mConfig.getString(PROP_XML_OUTPUT, "false");
        } catch (EBaseException e) {
            return "false";
        }
    }

    public String getApprovedBy() {
        try {
            return mConfig.getString(PROP_ENABLE_BY, "");
        } catch (EBaseException e) {
            return "";
        }
    }

    public void setId(String id) {
        mId = id;
    }

    public String getId() {
        return mId;
    }

    public IProfileAuthenticator getAuthenticator() throws EProfileException {
        try {
            IAuthSubsystem authSub = (IAuthSubsystem)
                CMS.getSubsystem(CMS.SUBSYSTEM_AUTH);
            IProfileAuthenticator auth = (IProfileAuthenticator)
                authSub.get(mAuthInstanceId);

            if (mAuthInstanceId != null && mAuthInstanceId.length() > 0 
                && auth == null) {
                throw new EProfileException("Cannot load " + 
                        mAuthInstanceId);
            }
            return auth;
        } catch (Exception e) {
            if (mAuthInstanceId != null) {
                throw new EProfileException("Cannot load " + 
                        mAuthInstanceId);
            }
            return null;
        }
    }

    public String getRequestorDN(IRequest request) {
        return null;
    }
  
    public String getAuthenticatorId() {
        return mAuthInstanceId;
    }

    public void setAuthenticatorId(String id) {
        mAuthInstanceId = id;
        mConfig.putString("auth." + PROP_INSTANCE_ID, id);
    }

    public String getAuthzAcl() {
        return mAuthzAcl;
    }

    /**
     * Initializes this profile.
     */
    public void init(IProfileSubsystem owner, IConfigStore config)
        throws EBaseException { 
        CMS.debug("BasicProfile: start init");
        mOwner = owner;
        mConfig = config;

        mRegistry = (IPluginRegistry) CMS.getSubsystem(CMS.SUBSYSTEM_REGISTRY);

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
            CMS.debug("BasicProfile: authentication class not found " +
                e.toString());
        }

        // handle profile input plugins
        IConfigStore inputStore = config.getSubStore("input");
        String input_list = inputStore.getString(PROP_INPUT_LIST, "");
        StringTokenizer input_st = new StringTokenizer(input_list, ",");

        while (input_st.hasMoreTokens()) {
            String input_id = (String) input_st.nextToken();
            String inputClassId = inputStore.getString(input_id + "." + 
                    PROP_CLASS_ID);
            IPluginInfo inputInfo = mRegistry.getPluginInfo("profileInput",
                    inputClassId);
            String inputClass = inputInfo.getClassName();

            IProfileInput input = null;

            try {
                input = (IProfileInput)
                        Class.forName(inputClass).newInstance(); 
            } catch (Exception e) {
                // throw Exception
                CMS.debug("BasicProfile: input plugin Class.forName " + 
                    inputClass + " " + e.toString());
                throw new EBaseException( e.toString() );
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
            String output_id = (String) output_st.nextToken();

            String outputClassId = outputStore.getString(output_id + "." + 
                    PROP_CLASS_ID);
            IPluginInfo outputInfo = mRegistry.getPluginInfo("profileOutput",
                    outputClassId);
            String outputClass = outputInfo.getClassName();

            IProfileOutput output = null;

            try {
                output = (IProfileOutput)
                        Class.forName(outputClass).newInstance(); 
            } catch (Exception e) {
                // throw Exception
                CMS.debug("BasicProfile: output plugin Class.forName " + 
                    outputClass + " " + e.toString());
                throw new EBaseException( e.toString() );
            }
            IConfigStore outputConfig = outputStore.getSubStore(output_id);
            output.init(this, outputConfig);
            mOutputs.put(output_id, output);
            mOutputIds.addElement(output_id);
        }

        // handle profile output plugins
        IConfigStore updaterStore = config.getSubStore("updater");
        String updater_list = updaterStore.getString(PROP_UPDATER_LIST, "");
        StringTokenizer updater_st = new StringTokenizer(updater_list, ",");

        while (updater_st.hasMoreTokens()) {
            String updater_id = (String) updater_st.nextToken();

            String updaterClassId = updaterStore.getString(updater_id + "." + 
                    PROP_CLASS_ID);
            IPluginInfo updaterInfo = mRegistry.getPluginInfo("profileUpdater",
                     updaterClassId);
            String updaterClass = updaterInfo.getClassName();

            IProfileUpdater updater = null;

            try {
                updater = (IProfileUpdater)
                        Class.forName(updaterClass).newInstance(); 
            } catch (Exception e) {
                // throw Exception
                CMS.debug("BasicProfile: updater plugin Class.forName " + 
                    updaterClass + " " + e.toString());
                throw new EBaseException( e.toString() );
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
            String setId = (String) st.nextToken();

            IConfigStore policyStore = policySetStore.getSubStore(setId);
            String list = policyStore.getString(PROP_POLICY_LIST, "");
            StringTokenizer st1 = new StringTokenizer(list, ",");

            while (st1.hasMoreTokens()) {
                String id = (String) st1.nextToken();

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
        CMS.debug("BasicProfile: done init");
    }

    public IConfigStore getConfigStore() {
        return mConfig;
    }

    public Enumeration getInputNames() {
        return mInputNames.elements();
    }

    public Enumeration getProfileUpdaterIds() {
        return mUpdaterIds.elements(); // ordered list
    }

    public IProfileUpdater getProfileUpdater(String name) {
        return (IProfileUpdater) mUpdaters.get(name);
    }

    public Enumeration getProfileOutputIds() {
        return mOutputIds.elements(); // ordered list
    }

    public IProfileOutput getProfileOutput(String name) {
        return (IProfileOutput) mOutputs.get(name);
    }

    public Enumeration getProfileInputIds() {
        return mInputIds.elements(); // ordered list
    }

    public IProfileInput getProfileInput(String name) {
        return (IProfileInput) mInputs.get(name);
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

    public Enumeration getProfilePolicySetIds() {
        return mPolicySet.keys();
    }

    public void deleteProfilePolicy(String setId, String policyId) 
        throws EProfileException {
        Vector policies = (Vector) mPolicySet.get(setId);

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
            boolean found = false;

            for (int i = 0; i < size; i++) {
                ProfilePolicy policy = (ProfilePolicy) policies.elementAt(i);
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
               Long.toString(CMS.getCurrentDate().getTime()));
            mConfig.commit(false);
        } catch (Exception e) {
        }

    }

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
            boolean found = false;

            for (int i = 0; i < size; i++) {
                String id = (String) mInputIds.elementAt(i);

                if (id.equals(inputId)) {
                    mInputIds.removeElementAt(i);
                    break;
                }
            }

            mInputs.remove(inputId);
            mConfig.putString("input." + PROP_INPUT_LIST, newlist);
            mConfig.putString("lastModified", 
               Long.toString(CMS.getCurrentDate().getTime()));
            mConfig.commit(false);
        } catch (Exception e) {
        }
    }

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
            boolean found = false;

            for (int i = 0; i < size; i++) {
                String id = (String) mOutputIds.elementAt(i);

                if (id.equals(outputId)) {
                    mOutputIds.removeElementAt(i);
                    break;
                }
            }

            mOutputs.remove(outputId);
            mConfig.putString("output." + PROP_OUTPUT_LIST, newlist);
            mConfig.putString("lastModified", 
               Long.toString(CMS.getCurrentDate().getTime()));
            mConfig.commit(false);
        } catch (Exception e) {
        }
    }

    public IProfileOutput createProfileOutput(String id, String outputId, 
        NameValuePairs nvps)
        throws EProfileException {
        return createProfileOutput(id, outputId, nvps, true); 
    }

    public IProfileOutput createProfileOutput(String id, String outputId,
        NameValuePairs nvps, boolean createConfig)
        throws EProfileException {
        IConfigStore outputStore = mConfig.getSubStore("output");
        String output_list = null;

        try {
            output_list = outputStore.getString(PROP_OUTPUT_LIST, "");
        } catch (Exception ee) {
        }

        IPluginInfo outputInfo = mRegistry.getPluginInfo("profileOutput",
                outputId);

        if (outputInfo == null) {
            CMS.debug("Cannot find " + outputId);
            throw new EProfileException("Cannot find " + outputId);
        }
        String outputClass = outputInfo.getClassName();

        CMS.debug("BasicProfile: loading output class " + outputClass);
        IProfileOutput output = null;

        try {
            output = (IProfileOutput)
                    Class.forName(outputClass).newInstance();
        } catch (Exception e) {
            // throw Exception
            CMS.debug(e.toString());
        }
        if (output == null) {
            CMS.debug("BasicProfile: failed to create " + outputClass);
        } else {
            CMS.debug("BasicProfile: initing " + id + " output");

            CMS.debug("BasicProfile: outputStore " + outputStore);
            output.init(this, outputStore);

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

            Enumeration enum1 = nvps.getNames();

            while (enum1.hasMoreElements()) {
                String name = (String) enum1.nextElement();

                outputStore.putString(prefix + "params." + name, nvps.getValue(name));
                try {
                   if (output != null) {
                       output.setConfig(name, nvps.getValue(name));
                   }
                } catch (EBaseException e) {
                   CMS.debug(e.toString());
                }
            }

            try {
            mConfig.putString("lastModified", 
               Long.toString(CMS.getCurrentDate().getTime()));
                mConfig.commit(false);
            } catch (EBaseException e) {
                CMS.debug(e.toString());
            }
        }

        return output;
    }

    public IProfileInput createProfileInput(String id, String inputId, 
        NameValuePairs nvps)
        throws EProfileException {
        return createProfileInput(id, inputId, nvps, true); 
    }

    public IProfileInput createProfileInput(String id, String inputId,
        NameValuePairs nvps, boolean createConfig)
        throws EProfileException {
        IConfigStore inputStore = mConfig.getSubStore("input");

        String input_list = null;

        try {
            input_list = inputStore.getString(PROP_INPUT_LIST, "");
        } catch (Exception ee) {
        }

        IPluginInfo inputInfo = mRegistry.getPluginInfo("profileInput",
                inputId);

        if (inputInfo == null) {
            CMS.debug("Cannot find " + inputId);
            throw new EProfileException("Cannot find " + inputId);
        }
        String inputClass = inputInfo.getClassName();

        CMS.debug("BasicProfile: loading input class " + inputClass);
        IProfileInput input = null;

        try {
            input = (IProfileInput)
                    Class.forName(inputClass).newInstance();
        } catch (Exception e) {
            // throw Exception
            CMS.debug(e.toString());
        }
        if (input == null) {
            CMS.debug("BasicProfile: failed to create " + inputClass);
        } else {
            CMS.debug("BasicProfile: initing " + id + " input");

            CMS.debug("BasicProfile: inputStore " + inputStore);
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
            
            Enumeration enum1 = nvps.getNames();

            while (enum1.hasMoreElements()) {
                String name = (String) enum1.nextElement();

                inputStore.putString(prefix + "params." + name, nvps.getValue(name));
                try {
                   if (input != null) {
                       input.setConfig(name, nvps.getValue(name));
                   }
                } catch (EBaseException e) {
                   CMS.debug(e.toString());
                }
            }

            try {
                mConfig.putString("lastModified", 
                  Long.toString(CMS.getCurrentDate().getTime()));
                mConfig.commit(false);
            } catch (EBaseException e) {
                CMS.debug(e.toString());
            }
        }

        return input;
    }

    /**
     * Creates a profile policy
     */
    public IProfilePolicy createProfilePolicy(String setId, String id, 
        String defaultClassId, String constraintClassId)
        throws EProfileException {
        return createProfilePolicy(setId, id, defaultClassId, 
                constraintClassId, true);
    }

    public IProfilePolicy createProfilePolicy(String setId, String id, 
        String defaultClassId, String constraintClassId,
        boolean createConfig)
        throws EProfileException {
        Vector policies = (Vector) mPolicySet.get(setId);

        IConfigStore policyStore = mConfig.getSubStore("policyset." + setId);

        if (policies == null) {
            policies = new Vector();
            mPolicySet.put(setId, policies);
            if (createConfig) {	
                // re-create policyset.list
                StringBuffer setlist =new StringBuffer();
                Enumeration keys = mPolicySet.keys();

                while (keys.hasMoreElements()) {
                    String k = (String) keys.nextElement();

                    if (!(setlist.toString()).equals("")) {
                        setlist.append(",");
                    }
                    setlist.append(k);
                }
                mConfig.putString("policyset.list", setlist.toString());
            }
        } else {
            if (createConfig) {
                String ids = null;

                try {
                    ids = policyStore.getString(PROP_POLICY_LIST, "");
                } catch (Exception ee) {
                }

                if( ids == null ) {
                    CMS.debug("BasicProfile::createProfilePolicy() - ids is null!" );
                    return null;
                }

                StringTokenizer st1 = new StringTokenizer(ids, ",");

                while (st1.hasMoreTokens()) {
                    String pid = st1.nextToken();

                    if (pid.equals(id)) {
                        throw new EProfileException("Duplicate policy id: " + id);
                    }
                }
            }
        }
        
        String defaultRoot = id + "." + PROP_DEFAULT;
        String constraintRoot = id + "." + PROP_CONSTRAINT;
        IPluginInfo defInfo = mRegistry.getPluginInfo("defaultPolicy",
                defaultClassId);

        if (defInfo == null) {
            CMS.debug("BasicProfile: Cannot find " + defaultClassId);
            throw new EProfileException("Cannot find " + defaultClassId);
        }
        String defaultClass = defInfo.getClassName();

        CMS.debug("BasicProfile: loading default class " + defaultClass);
        IPolicyDefault def = null;

        try {
            def = (IPolicyDefault)
                    Class.forName(defaultClass).newInstance();
        } catch (Exception e) {
            // throw Exception
            CMS.debug("BasicProfile: default policy " + 
                defaultClass + " " + e.toString());
        }
        if (def == null) {
            CMS.debug("BasicProfile: failed to create " + defaultClass);
        } else {
            IConfigStore defStore = null;

            defStore = policyStore.getSubStore(defaultRoot);
            def.init(this, defStore);
        }

        IPluginInfo conInfo = mRegistry.getPluginInfo("constraintPolicy", 
                constraintClassId);
        String constraintClass = conInfo.getClassName();
        IPolicyConstraint constraint = null;

        try {
            constraint = (IPolicyConstraint)
                    Class.forName(constraintClass).newInstance();
        } catch (Exception e) {
            // throw Exception
            CMS.debug("BasicProfile: constraint policy " + 
                constraintClass + " " + e.toString());
        }
        ProfilePolicy policy = null;
        if (constraint == null) {
            CMS.debug("BasicProfile: failed to create " + constraintClass);
        } else {
            IConfigStore conStore = null;

            conStore = policyStore.getSubStore(constraintRoot);
            constraint.init(this, conStore);
            policy = new ProfilePolicy(id, def, constraint);

            policies.addElement(policy);
        }

        if (createConfig) {
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
                  Long.toString(CMS.getCurrentDate().getTime()));
                policyStore.commit(false);
            } catch (EBaseException e) {
                CMS.debug("BasicProfile: commiting config store " + 
                    e.toString());
            }
        }

        return policy;
    }

    public IProfilePolicy getProfilePolicy(String setId, String id) {
        Vector policies = (Vector) mPolicySet.get(setId);

        if (policies == null)
            return null;

        for (int i = 0; i < policies.size(); i++) {
            ProfilePolicy policy = (ProfilePolicy) policies.elementAt(i);

            if (policy.getId().equals(id)) {
                return policy;
            }
        }
        return null;
    }

    public boolean isVisible() {
        try {
            return mConfig.getBoolean(PROP_VISIBLE, false);
        } catch (EBaseException e) {
            return false;
        }
    }

    public void setVisible(boolean v) {
        mConfig.putBoolean(PROP_VISIBLE, v);
    }

    /**
     * Returns the profile name.
     */
    public String getName(Locale locale) {
        try {
            return mConfig.getString(PROP_NAME, "");
        } catch (EBaseException e) {
            return "";
        }
    }

    public void setName(Locale locale, String name) {
        mConfig.putString(PROP_NAME, name);
    }

    public abstract IProfileContext createContext();

    /**
     * Creates request.
     */
    public abstract IRequest[] createRequests(IProfileContext ctx, Locale locale)
        throws EProfileException;

    /**
     * Returns the profile description.
     */
    public String getDescription(Locale locale) {
        try {
            return mConfig.getString(PROP_DESC, "");
        } catch (EBaseException e) {
            return "";
        }
    }

    public void setDescription(Locale locale, String desc) {
        mConfig.putString(PROP_DESC, desc);
    }

    public void populateInput(IProfileContext ctx, IRequest request)
        throws EProfileException {
        Enumeration ids = getProfileInputIds();

        while (ids.hasMoreElements()) {
            String id = (String) ids.nextElement();
            IProfileInput input = getProfileInput(id); 

            input.populate(ctx, request);
        }
    }

    public Vector getPolicies(String setId) {
        Vector policies = (Vector) mPolicySet.get(setId);

        return policies;
    }

    /**
     * Passes the request to the set of default policies that
     * populate the profile information against the profile.
     */ 
    public void populate(IRequest request)
        throws EProfileException {
        String setId = getPolicySetId(request);
        Vector policies = getPolicies(setId);
        CMS.debug("BasicProfile: populate() policy setid ="+ setId);

        for (int i = 0; i < policies.size(); i++) {
            ProfilePolicy policy = (ProfilePolicy)
                policies.elementAt(i);

            policy.getDefault().populate(request);
        }
    }

    /**
     * Passes the request to the set of constraint policies 
     * that validate the request against the profile.
     */ 
    public void validate(IRequest request)
        throws ERejectException {
        String setId = getPolicySetId(request);
        CMS.debug("BasicProfile: validate start on setId="+ setId);
        Vector policies = getPolicies(setId);

        for (int i = 0; i < policies.size(); i++) {
            ProfilePolicy policy = (ProfilePolicy)
                policies.elementAt(i);

            policy.getConstraint().validate(request);
        }
        CMS.debug("BasicProfile: change to pending state");
        request.setRequestStatus(RequestStatus.PENDING);
        CMS.debug("BasicProfile: validate end");
    }

    public Enumeration getProfilePolicies(String setId) {
        Vector policies = (Vector) mPolicySet.get(setId);

        if (policies == null)
            return null;
        return policies.elements();
    }

    public Enumeration getProfilePolicyIds(String setId) {
        Vector policies = (Vector) mPolicySet.get(setId);

        if (policies == null)
            return null;

        Vector v = new Vector();

        for (int i = 0; i < policies.size(); i++) {
            ProfilePolicy policy = (ProfilePolicy)
                policies.elementAt(i);

            v.addElement(policy.getId());	
        }
        return v.elements();
    }

    public void execute(IRequest request)
        throws EProfileException {
    }

    /**
     * Signed Audit Log
     *
     * This method is inherited by all extended "BasicProfile"s,
     * and is called to store messages to the signed audit log.
     * <P>
     *
     * @param msg signed audit log message
     */
    protected void audit(String msg) {
        // in this case, do NOT strip preceding/trailing whitespace
        // from passed-in String parameters

        if (mSignedAuditLogger == null) {
            return;
        }

        mSignedAuditLogger.log(ILogger.EV_SIGNED_AUDIT,
            null,
            ILogger.S_SIGNED_AUDIT,
            ILogger.LL_SECURITY,
            msg);
    }

    /**
     * Signed Audit Log Subject ID
     *
     * This method is inherited by all extended "BasicProfile"s,
     * and is called to obtain the "SubjectID" for
     * a signed audit log message.
     * <P>
     *
     * @return id string containing the signed audit log message SubjectID
     */
    protected String auditSubjectID() {
        // if no signed audit object exists, bail
        if (mSignedAuditLogger == null) {
            return null;
        }

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

