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
package com.netscape.cms.servlet.admin;

import java.io.IOException;
import java.util.Enumeration;
import java.util.Locale;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.DestDef;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.common.OpDef;
import com.netscape.certsrv.common.ScopeDef;
import com.netscape.certsrv.jobs.EJobsException;
import com.netscape.certsrv.jobs.IJob;
import com.netscape.certsrv.jobs.IJobsScheduler;
import com.netscape.certsrv.jobs.JobPlugin;
import com.netscape.certsrv.logging.ILogger;

/**
 * A class representing an administration servlet for the
 * Jobs Scheduler and it's scheduled jobs.
 *
 * @version $Revision$, $Date$
 */
public class JobsAdminServlet extends AdminServlet {
    /**
     *
     */
    private static final long serialVersionUID = 561767449283982015L;
    // ... remove later
    private final static String VISIBLE = ";visible";
    private final static String ENABLED = ";enabled";
    private final static String DISABLED = ";disabled";

    private final static String INFO = "JobsAdminServlet";
    private IJobsScheduler mJobsSched = null;

    /**
     * Constructs JobsAdminServlet.
     */
    public JobsAdminServlet() {
        super();
    }

    /**
     * Initializes this servlet.
     */
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        mJobsSched = (IJobsScheduler)
                CMS.getSubsystem(CMS.SUBSYSTEM_JOBS);
    }

    /**
     * Returns serlvet information.
     */
    public String getServletInfo() {
        return INFO;
    }

    /**
     * retrieve extended plugin info such as brief description, type info
     * from jobs
     */
    private void getExtendedPluginInfo(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        String id = req.getParameter(Constants.RS_ID);

        int colon = id.indexOf(':');

        String implType = id.substring(0, colon);
        String implName = id.substring(colon + 1);

        NameValuePairs params =
                getExtendedPluginInfo(getLocale(req), implType, implName);

        sendResponse(SUCCESS, null, params, resp);
    }

    private NameValuePairs getExtendedPluginInfo(Locale locale, String implType, String implName) {
        IExtendedPluginInfo ext_info = null;
        Object impl = null;

        JobPlugin jp =
                mJobsSched.getPlugins().get(implName);

        if (jp != null)
            impl = getClassByNameAsExtendedPluginInfo(jp.getClassPath());
        if (impl != null) {
            if (impl instanceof IExtendedPluginInfo) {
                ext_info = (IExtendedPluginInfo) impl;
            }
        }

        NameValuePairs nvps = null;

        if (ext_info == null) {
            nvps = new NameValuePairs();
        } else {
            nvps = convertStringArrayToNVPairs(ext_info.getExtendedPluginInfo(locale));
        }

        return nvps;

    }

    /**
     * Serves HTTP admin request.
     */
    public void service(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        super.service(req, resp);

        String scope = req.getParameter(Constants.OP_SCOPE);
        String op = req.getParameter(Constants.OP_TYPE);

        if (op == null) {
            //System.out.println("SRVLT_INVALID_PROTOCOL");
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_INVALID_PROTOCOL"),
                    null, resp);
            return;
        }

        try {
            super.authenticate(req);
        } catch (IOException e) {
            sendResponse(ERROR, CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHS_FAILED"),
                    null, resp);
            return;
        }

        try {
            AUTHZ_RES_NAME = "certServer.job.configuration";
            if (op.equals(OpDef.OP_READ)) {
                mOp = "read";
                if ((mToken = super.authorize(req)) == null) {
                    sendResponse(ERROR,
                            CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHZ_FAILED"),
                            null, resp);
                    return;
                }
                if (scope.equals(ScopeDef.SC_JOBS))
                    getSettings(req, resp);
                else if (scope.equals(ScopeDef.SC_JOBS_IMPLS))
                    getConfig(req, resp);
                else if (scope.equals(ScopeDef.SC_JOBS_INSTANCE))
                    getInstConfig(req, resp);
                else if (scope.equals(ScopeDef.SC_EXTENDED_PLUGIN_INFO)) {
                    try {
                        getExtendedPluginInfo(req, resp);
                    } catch (EBaseException e) {
                        sendResponse(ERROR, e.toString(getLocale(req)), null, resp);
                        return;
                    }
                } else {
                    //System.out.println("SRVLT_INVALID_OP_SCOPE");
                    sendResponse(ERROR,
                            CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_INVALID_OP_SCOPE"),
                            null, resp);
                    return;
                }
            } else if (op.equals(OpDef.OP_MODIFY)) {
                mOp = "modify";
                if ((mToken = super.authorize(req)) == null) {
                    sendResponse(ERROR,
                            CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHZ_FAILED"),
                            null, resp);
                    return;
                }
                if (scope.equals(ScopeDef.SC_JOBS)) {
                    setSettings(req, resp);
                } else if (scope.equals(ScopeDef.SC_JOBS_INSTANCE)) {
                    modJobsInst(req, resp, scope);
                } else {
                    sendResponse(ERROR,
                            CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_INVALID_OP_SCOPE"),
                            null, resp);
                    return;
                }
            } else if (op.equals(OpDef.OP_SEARCH)) {
                mOp = "read";
                if ((mToken = super.authorize(req)) == null) {
                    sendResponse(ERROR,
                            CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHZ_FAILED"),
                            null, resp);
                    return;
                }
                if (scope.equals(ScopeDef.SC_JOBS_IMPLS))
                    listJobPlugins(req, resp);
                else if (scope.equals(ScopeDef.SC_JOBS_INSTANCE))
                    listJobsInsts(req, resp);
                else {
                    //System.out.println("SRVLT_INVALID_OP_SCOPE");
                    sendResponse(ERROR,
                            CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_INVALID_OP_SCOPE"),
                            null, resp);
                    return;
                }
            } else if (op.equals(OpDef.OP_ADD)) {
                mOp = "modify";
                if ((mToken = super.authorize(req)) == null) {
                    sendResponse(ERROR,
                            CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHZ_FAILED"),
                            null, resp);
                    return;
                }
                if (scope.equals(ScopeDef.SC_JOBS_IMPLS))
                    addJobPlugin(req, resp, scope);
                else if (scope.equals(ScopeDef.SC_JOBS_INSTANCE))
                    addJobsInst(req, resp, scope);
                else {
                    //System.out.println("SRVLT_INVALID_OP_SCOPE");
                    sendResponse(ERROR,
                            CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_INVALID_OP_SCOPE"),
                            null, resp);
                    return;
                }
            } else if (op.equals(OpDef.OP_DELETE)) {
                mOp = "modify";
                if ((mToken = super.authorize(req)) == null) {
                    sendResponse(ERROR,
                            CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHZ_FAILED"),
                            null, resp);
                    return;
                }
                if (scope.equals(ScopeDef.SC_JOBS_IMPLS))
                    delJobPlugin(req, resp, scope);
                else if (scope.equals(ScopeDef.SC_JOBS_INSTANCE))
                    delJobsInst(req, resp, scope);
                else {
                    //System.out.println("SRVLT_INVALID_OP_SCOPE");
                    sendResponse(ERROR,
                            CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_INVALID_OP_SCOPE"),
                            null, resp);
                    return;
                }
            } else {
                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_INVALID_OP_TYPE", op),
                        null, resp);
                return;
            }
        } catch (EBaseException e) {
            sendResponse(ERROR, e.toString(getLocale(req)), null, resp);
            return;
        }
    }

    private synchronized void addJobPlugin(HttpServletRequest req,
            HttpServletResponse resp, String scope)
            throws ServletException, IOException, EBaseException {

        String id = req.getParameter(Constants.RS_ID);

        if (id == null) {
            //System.out.println("SRVLT_NULL_RS_ID");
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                    null, resp);
            return;
        }
        // is the job plugin id unique?
        if (mJobsSched.getPlugins().containsKey(id)) {
            sendResponse(ERROR,
                    new EJobsException(CMS.getUserMessage(getLocale(req), "CMS_JOB_SRVLT_ILL_JOB_PLUGIN_ID", id))
                            .toString(),
                    null, resp);
            return;
        }

        String classPath = req.getParameter(Constants.PR_JOBS_CLASS);

        if (classPath == null) {
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_JOB_SRVLT_NULL_CLASS"),
                    null, resp);
            return;
        }

        IConfigStore destStore =
                mConfig.getSubStore(DestDef.DEST_JOBS_ADMIN);
        IConfigStore instancesConfig =
                destStore.getSubStore(scope);

        // Does the class exist?
        Class<?> newImpl = null;

        try {
            newImpl = Class.forName(classPath);
        } catch (ClassNotFoundException e) {
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_JOB_SRVLT_NO_CLASS"),
                    null, resp);
            return;
        } catch (IllegalArgumentException e) {
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_JOB_SRVLT_NO_CLASS"),
                    null, resp);
            return;
        }

        // is the class an IJob?
        try {
            if (IJob.class.isAssignableFrom(newImpl) == false) {
                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_JOB_SRVLT_ILL_CLASS"),
                        null, resp);
                return;
            }
        } catch (NullPointerException e) { // unlikely, only if newImpl null.
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_JOB_SRVLT_ILL_CLASS"),
                    null, resp);
            return;
        }

        IConfigStore substore = instancesConfig.makeSubStore(id);

        substore.put(Constants.PR_JOBS_CLASS, classPath);

        // commiting
        try {
            mConfig.commit(true);
        } catch (EBaseException e) {
            //System.out.println("SRVLT_FAIL_COMMIT");
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_COMMIT_FAILED"),
                    null, resp);
            return;
        }

        // add manager to registry.
        JobPlugin plugin = new JobPlugin(id, classPath);

        mJobsSched.getPlugins().put(id, plugin);
        mJobsSched.log(ILogger.LL_INFO,
                CMS.getLogMessage("ADMIN_SRVLT_JS_PLUGIN_ADD", id));

        NameValuePairs params = new NameValuePairs();

        sendResponse(SUCCESS, null, params, resp);
        return;
    }

    private synchronized void addJobsInst(HttpServletRequest req,
            HttpServletResponse resp, String scope)
            throws ServletException, IOException, EBaseException {

        String id = req.getParameter(Constants.RS_ID);

        if (id == null) {
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                    null, resp);
            return;
        }

        // is the job instance id unique?
        if (mJobsSched.getInstances().containsKey(id)) {
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_JOB_SRVLT_ILL_JOB_INST_ID"),
                    null, resp);
            return;
        }

        // get required parameters
        // SC_JOBS_IMPL_NAME is absolutely required, the rest depend on
        // on each job plugin
        String implname = req.getParameter(Constants.PR_JOBS_IMPL_NAME);

        if (implname == null) {
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_JOB_SRVLT_ADD_MISSING_PARAMS"),
                    null, resp);
            return;
        }

        // check if implementation exists.
        JobPlugin plugin =
                mJobsSched.getPlugins().get(implname);

        if (plugin == null) {
            sendResponse(ERROR,
                    new
                    EJobsException(CMS.getUserMessage(getLocale(req), "CMS_JOB_SRVLT_JOB_PLUGIN_NOT_FOUND",
                            id)).toString(),
                    null, resp);
            return;
        }

        // now the rest of config parameters
        // note that we only check to see if the required parameters
        // are there, but not checking the values are valid
        String[] configParams = mJobsSched.getConfigParams(implname);

        IConfigStore destStore =
                mConfig.getSubStore(DestDef.DEST_JOBS_ADMIN);
        IConfigStore instancesConfig =
                destStore.getSubStore(scope);
        IConfigStore substore = instancesConfig.makeSubStore(id);

        if (configParams != null) {
            for (int i = 0; i < configParams.length; i++) {
                String key = configParams[i];
                String val = req.getParameter(key);

                if (val != null && !val.equals("")) {
                    substore.put(key, val);
                } else if (!key.equals("profileId")) {
                    sendResponse(ERROR,
                            new
                            EJobsException(CMS.getUserMessage(getLocale(req), "CMS_JOB_SRVLT_MISSING_INST_PARAM_VAL",
                                    key)).toString(),
                            null, resp);
                    return;
                }
            }
        }

        substore.put(IJobsScheduler.PROP_PLUGIN, implname);

        // Instantiate an object for this implementation
        String className = plugin.getClassPath();
        IJob jobsInst = null;

        try {
            jobsInst = (IJob) Class.forName(className).newInstance();
        } catch (ClassNotFoundException e) {
            // cleanup
            instancesConfig.removeSubStore(id);
            sendResponse(ERROR,
                    new EJobsException(
                            CMS.getUserMessage(getLocale(req), "CMS_JOB_LOAD_CLASS_FAILED", className)).toString(),
                    null, resp);
            return;
        } catch (InstantiationException e) {
            instancesConfig.removeSubStore(id);
            sendResponse(ERROR,
                    new EJobsException(
                            CMS.getUserMessage(getLocale(req), "CMS_JOB_LOAD_CLASS_FAILED", className)).toString(),
                    null, resp);
            return;
        } catch (IllegalAccessException e) {
            instancesConfig.removeSubStore(id);
            sendResponse(ERROR,
                    new EJobsException(
                            CMS.getUserMessage(getLocale(req), "CMS_JOB_LOAD_CLASS_FAILED", className)).toString(),
                    null, resp);
            return;
        }

        IJobsScheduler scheduler = (IJobsScheduler)
                CMS.getSubsystem(CMS.SUBSYSTEM_JOBS);

        // initialize the job plugin
        try {
            jobsInst.init(scheduler, id, implname, substore);
        } catch (EBaseException e) {
            // don't commit in this case and cleanup the new substore.
            instancesConfig.removeSubStore(id);
            sendResponse(ERROR, e.toString(getLocale(req)), null, resp);
            return;
        }

        // commiting
        try {
            mConfig.commit(true);
        } catch (EBaseException e) {
            // clean up.
            instancesConfig.removeSubStore(id);
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_COMMIT_FAILED"),
                    null, resp);
            return;
        }

        // inited and commited ok. now add manager instance to list.
        mJobsSched.getInstances().put(id, jobsInst);

        mJobsSched.log(ILogger.LL_INFO,
                CMS.getLogMessage("ADMIN_SRVLT_JOB_INST_ADD", id));

        NameValuePairs params = new NameValuePairs();

        params.put(Constants.PR_JOBS_IMPL_NAME, implname);
        sendResponse(SUCCESS, null, params, resp);
        return;
    }

    private synchronized void listJobPlugins(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        NameValuePairs params = new NameValuePairs();
        Enumeration<String> e = mJobsSched.getPlugins().keys();

        while (e.hasMoreElements()) {
            String name = e.nextElement();
            JobPlugin value = mJobsSched.getPlugins().get(name);

            params.put(name, value.getClassPath());
            //				params.add(name, value.getClassPath()+EDIT);
        }
        sendResponse(SUCCESS, null, params, resp);
        return;
    }

    private synchronized void listJobsInsts(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        NameValuePairs params = new NameValuePairs();

        for (Enumeration<String> e = mJobsSched.getInstances().keys(); e.hasMoreElements();) {
            String name = e.nextElement();
            IJob value = mJobsSched.getInstances().get(name);

            //				params.add(name, value.getImplName());
            params.put(name, value.getImplName() + VISIBLE +
                    (value.isEnabled() ? ENABLED : DISABLED)
            );
        }
        sendResponse(SUCCESS, null, params, resp);
        return;
    }

    private synchronized void delJobPlugin(HttpServletRequest req,
            HttpServletResponse resp, String scope) throws ServletException,
            IOException, EBaseException {

        NameValuePairs params = new NameValuePairs();
        String id = req.getParameter(Constants.RS_ID);

        if (id == null) {
            //System.out.println("SRVLT_NULL_RS_ID");
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                    null, resp);
            return;
        }

        // does this job plugin exist?
        if (mJobsSched.getPlugins().containsKey(id) == false) {
            sendResponse(ERROR,
                    new
                    EJobsException(CMS.getUserMessage(getLocale(req), "CMS_JOB_SRVLT_JOB_PLUGIN_NOT_FOUND",
                            id)).toString(),
                    null, resp);
            return;
        }

        // first check if any instances from this job plugin
        // DON'T remove job plugin if any instance
        for (Enumeration<IJob> e = mJobsSched.getInstances().elements(); e.hasMoreElements();) {
            IJob jobs = e.nextElement();

            if ((jobs.getImplName()).equals(id)) {
                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_JOB_SRVLT_JOB_IN_USE"),
                        null, resp);
                return;
            }
        }

        // then delete this job plugin
        mJobsSched.getPlugins().remove(id);

        IConfigStore destStore =
                mConfig.getSubStore(DestDef.DEST_JOBS_ADMIN);
        IConfigStore instancesConfig =
                destStore.getSubStore(scope);

        instancesConfig.removeSubStore(id);
        // commiting
        try {
            mConfig.commit(true);
        } catch (EBaseException e) {
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_COMMIT_FAILED"),
                    null, resp);
            return;
        }

        sendResponse(SUCCESS, null, params, resp);
        return;
    }

    private synchronized void delJobsInst(HttpServletRequest req,
            HttpServletResponse resp, String scope) throws ServletException,
            IOException, EBaseException {

        NameValuePairs params = new NameValuePairs();
        String id = req.getParameter(Constants.RS_ID);

        if (id == null) {
            //System.out.println("SRVLT_NULL_RS_ID");
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                    null, resp);
            return;
        }

        // does job plugin instance exist?
        if (mJobsSched.getInstances().containsKey(id) == false) {
            sendResponse(ERROR,
                    new EJobsException(CMS.getUserMessage(getLocale(req), "CMS_JOB_SRVLT_JOB_NOT_FOUND",
                            id)).toString(),
                    null, resp);
            return;
        }

        // only remove from memory
        // cannot shutdown because we don't keep track of whether it's
        // being used.
        mJobsSched.getInstances().remove(id);

        // remove the configuration.
        IConfigStore destStore =
                mConfig.getSubStore(DestDef.DEST_JOBS_ADMIN);
        IConfigStore instancesConfig =
                destStore.getSubStore(scope);

        instancesConfig.removeSubStore(id);
        // commiting
        try {
            mConfig.commit(true);
        } catch (EBaseException e) {
            //System.out.println("SRVLT_FAIL_COMMIT");
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_COMMIT_FAILED"),
                    null, resp);
            return;
        }

        sendResponse(SUCCESS, null, params, resp);
        return;
    }

    /**
     * used for getting the required configuration parameters (with
     * possible default values) for a particular job plugin
     * implementation name specified in the RS_ID. Actually, there is
     * no logic in here to set any default value here...there's no
     * default value for any parameter in this job scheduler subsystem
     * at this point. Later, if we do have one (or some), it can be
     * added. The interface remains the same.
     */
    private synchronized void getConfig(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException, EBaseException {

        String implname = req.getParameter(Constants.RS_ID);

        if (implname == null) {
            //System.out.println("SRVLT_NULL_RS_ID");
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                    null, resp);
            return;
        }

        String[] configParams = mJobsSched.getConfigParams(implname);
        NameValuePairs params = new NameValuePairs();

        // implName is always required so always send it.
        params.put(Constants.PR_JOBS_IMPL_NAME, "");
        if (configParams != null) {
            for (int i = 0; i < configParams.length; i++) {
                params.put(configParams[i], "");
            }
        }
        sendResponse(0, null, params, resp);
        return;
    }

    private synchronized void getInstConfig(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        String id = req.getParameter(Constants.RS_ID);

        if (id == null) {
            //System.out.println("SRVLT_NULL_RS_ID");
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                    null, resp);
            return;
        }

        // does job plugin instance exist?
        if (mJobsSched.getInstances().containsKey(id) == false) {
            sendResponse(ERROR,
                    new EJobsException(CMS.getUserMessage(getLocale(req), "CMS_JOB_SRVLT_JOB_NOT_FOUND",
                            id)).toString(),
                    null, resp);
            return;
        }

        IJob jobInst = mJobsSched.getInstances().get(id);
        IConfigStore config = jobInst.getConfigStore();
        String[] configParams = jobInst.getConfigParams();
        NameValuePairs params = new NameValuePairs();

        params.put(Constants.PR_JOBS_IMPL_NAME, jobInst.getImplName());

        // implName is always required so always send it.
        if (configParams != null) {
            for (int i = 0; i < configParams.length; i++) {
                String key = configParams[i];

                String val = config.get(key);

                if (val != null && !val.equals("")) {
                    params.put(key, val);
                } else {
                    params.put(key, "");
                }
            }
        }

        sendResponse(SUCCESS, null, params, resp);
        return;
    }

    /**
     * Modify job plugin instance.
     * This will actually create a new instance with new configuration
     * parameters and replace the old instance, if the new instance
     * created and initialized successfully.
     * The old instance is left running. so this is very expensive.
     * Restart of server recommended.
     */
    private synchronized void modJobsInst(HttpServletRequest req,
            HttpServletResponse resp, String scope)
            throws ServletException, IOException, EBaseException {

        // expensive operation.

        String id = req.getParameter(Constants.RS_ID);

        if (id == null) {
            //System.out.println("SRVLT_NULL_RS_ID");
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                    null, resp);
            return;
        }

        // Does the job instance exist?
        if (!mJobsSched.getInstances().containsKey(id)) {
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_JOB_SRVLT_ILL_JOB_INST_ID"),
                    null, resp);
            return;
        }

        // get new implementation (same or different.)
        String implname = req.getParameter(Constants.PR_JOBS_IMPL_NAME);

        if (implname == null) {
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_JOB_SRVLT_ADD_MISSING_PARAMS"),
                    null, resp);
            return;
        }

        // get plugin for implementation
        JobPlugin plugin =
                mJobsSched.getPlugins().get(implname);

        if (plugin == null) {
            sendResponse(ERROR,
                    new EJobsException(CMS.getUserMessage(getLocale(req), "CMS_JOB_SRVLT_JOB_PLUGIN_NOT_FOUND",
                            id)).toString(),
                    null, resp);
            return;
        }

        // save old instance substore params in case new one fails.

        IJob oldinst =
                mJobsSched.getInstances().get(id);
        IConfigStore oldConfig = oldinst.getConfigStore();

        String[] oldConfigParms = oldinst.getConfigParams();
        NameValuePairs saveParams = new NameValuePairs();

        // implName is always required so always include it it.
        saveParams.put(IJobsScheduler.PROP_PLUGIN,
                oldConfig.get(IJobsScheduler.PROP_PLUGIN));
        if (oldConfigParms != null) {
            for (int i = 0; i < oldConfigParms.length; i++) {
                String key = oldConfigParms[i];
                Object val = oldConfig.get(key);

                if (val != null) {
                    saveParams.put(key, (String) val);
                }
            }
        }

        // on to the new instance.

        // remove old substore.

        IConfigStore destStore =
                mConfig.getSubStore(DestDef.DEST_JOBS_ADMIN);
        IConfigStore instancesConfig =
                destStore.getSubStore(scope);

        instancesConfig.removeSubStore(id);

        // create new substore.

        String[] configParams = mJobsSched.getConfigParams(implname);

        IConfigStore substore = instancesConfig.makeSubStore(id);

        substore.put(IJobsScheduler.PROP_PLUGIN, implname);
        if (configParams != null) {
            for (int i = 0; i < configParams.length; i++) {
                String key = configParams[i];
                String val = req.getParameter(key);

                if (val != null && !val.equals("")) {
                    substore.put(key, val);
                } else if (!key.equals("profileId")) {
                    restore(instancesConfig, id, saveParams);
                    sendResponse(ERROR,
                            new
                            EJobsException(CMS.getUserMessage(getLocale(req), "CMS_JOB_SRVLT_MISSING_INST_PARAM_VAL",
                                    key)).toString(),
                            null, resp);
                    return;
                }
            }
        }
        // Instantiate an object for new implementation

        String className = plugin.getClassPath();
        IJob newJobInst = null;

        try {
            newJobInst = (IJob) Class.forName(className).newInstance();
        } catch (ClassNotFoundException e) {
            // cleanup
            restore(instancesConfig, id, saveParams);
            sendResponse(ERROR,
                    new EJobsException(
                            CMS.getUserMessage(getLocale(req), "CMS_JOB_LOAD_CLASS_FAILED", className)).toString(),
                    null, resp);
            return;
        } catch (InstantiationException e) {
            restore(instancesConfig, id, saveParams);
            sendResponse(ERROR,
                    new EJobsException(
                            CMS.getUserMessage(getLocale(req), "CMS_JOB_LOAD_CLASS_FAILED", className)).toString(),
                    null, resp);
            return;
        } catch (IllegalAccessException e) {
            restore(instancesConfig, id, saveParams);
            sendResponse(ERROR,
                    new EJobsException(
                            CMS.getUserMessage(getLocale(req), "CMS_JOB_LOAD_CLASS_FAILED", className)).toString(),
                    null, resp);
            return;
        }

        // initialize the job plugin

        IJobsScheduler scheduler = (IJobsScheduler)
                CMS.getSubsystem(CMS.SUBSYSTEM_JOBS);

        try {
            newJobInst.init(scheduler, id, implname, substore);
        } catch (EBaseException e) {
            // don't commit in this case and cleanup the new substore.
            restore(instancesConfig, id, saveParams);
            sendResponse(ERROR, e.toString(getLocale(req)), null, resp);
            return;
        } catch (Exception e) {
            CMS.debug("JobsAdminServlet: modJobsInst: " + e);
            restore(instancesConfig, id, saveParams);
            sendResponse(ERROR, "unidentified error" + e, null, resp);
            return;
        }

        // initialized ok.  commiting
        try {
            mConfig.commit(true);

        } catch (EBaseException e) {
            // clean up.
            restore(instancesConfig, id, saveParams);
            //System.out.println("SRVLT_FAIL_COMMIT");
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_COMMIT_FAILED"),
                    null, resp);
            return;
        }

        // commited ok. replace instance.

        mJobsSched.getInstances().put(id, newJobInst);

        mJobsSched.log(ILogger.LL_INFO,
                CMS.getLogMessage("ADMIN_SRVLT_JOB_INST_REP", id));

        NameValuePairs params = new NameValuePairs();

        sendResponse(SUCCESS, null, params, resp);
        return;
    }

    private void getSettings(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        NameValuePairs params = new NameValuePairs();
        IConfigStore config = mConfig.getSubStore(DestDef.DEST_JOBS_ADMIN);

        params.put(Constants.PR_ENABLE,
                config.getString(IJobsScheduler.PROP_ENABLED,
                        Constants.FALSE));
        // default 1 minute
        params.put(Constants.PR_JOBS_FREQUENCY,
                config.getString(IJobsScheduler.PROP_INTERVAL, "1"));

        //System.out.println("Send: "+params.toString());
        sendResponse(SUCCESS, null, params, resp);
    }

    private void setSettings(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException, EBaseException {
        //Save New Settings to the config file
        IConfigStore config = mConfig.getSubStore(DestDef.DEST_JOBS_ADMIN);

        String enabled = config.getString(IJobsScheduler.PROP_ENABLED);
        String enabledSetTo = req.getParameter(Constants.PR_ENABLE);
        boolean enabledChanged = false;

        if (!enabled.equalsIgnoreCase(enabledSetTo)) {
            enabledChanged = true;
            // set enable flag
            config.putString(IJobsScheduler.PROP_ENABLED, enabledSetTo);
        }

        //set frequency
        String interval =
                req.getParameter(Constants.PR_JOBS_FREQUENCY);

        if (interval != null) {
            config.putString(IJobsScheduler.PROP_INTERVAL, interval);
            mJobsSched.setInterval(
                    config.getInteger(IJobsScheduler.PROP_INTERVAL));
        }

        if (enabledChanged == true) {
            if (enabled.equalsIgnoreCase("false")) { // turned on
                mJobsSched.startDaemon();
            }
        }
        mConfig.commit(true);

        sendResponse(SUCCESS, null, null, resp);
    }

    // convenience routine.
    private static void restore(IConfigStore store,
            String id, NameValuePairs saveParams) {
        store.removeSubStore(id);
        IConfigStore rstore = store.makeSubStore(id);

        for (String key : saveParams.keySet()) {
            String value = saveParams.get(key);

            if (!value.equals(""))
                rstore.put(key, value);
        }
    }
}
