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
import java.util.Hashtable;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.netscape.certsrv.acls.ACL;
import com.netscape.certsrv.acls.ACLEntry;
import com.netscape.certsrv.acls.IACL;
import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authorization.IAuthzManager;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.common.OpDef;
import com.netscape.certsrv.common.ScopeDef;
import com.netscape.certsrv.evaluators.IAccessEvaluator;
import com.netscape.certsrv.logging.ILogger;

/**
 * Manage Access Control List configuration
 *
 * @version $Revision$, $Date$
 */
public class ACLAdminServlet extends AdminServlet {

    /**
     *
     */
    private static final long serialVersionUID = -322237202045924779L;
    private static final String PROP_EVAL = "accessEvaluator";
    private final static String INFO = "ACLAdminServlet";
    private IAuthzManager mAuthzMgr = null;

    private final static String LOGGING_SIGNED_AUDIT_CONFIG_ACL =
            "LOGGING_SIGNED_AUDIT_CONFIG_ACL_3";

    /**
     * initialize the servlet.
     * <ul>
     * <li>http.param OP_TYPE = OP_SEARCH,
     * <li>http.param OP_SCOPE - the scope of the request operation:
     * <ul>
     * <LI>"impl" ACL implementations
     * <LI>"acls" ACL rules
     * <LI>"evaluatorTypes" ACL evaluators.
     * </ul>
     * </ul>
     *
     * @param config servlet configuration, read from the web.xml file
     */
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        mAuthzMgr = mAuthz.get(mAclMethod);
    }

    /**
     * Returns serlvet information.
     */
    public String getServletInfo() {
        return INFO;
    }

    /**
     * Process the HTTP request.
     *
     * @param req the object holding the request information
     * @param resp the object holding the response information
     */

    public void service(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {

        String scope = super.getParameter(req, Constants.OP_SCOPE);
        String op = super.getParameter(req, Constants.OP_TYPE);

        if (op == null) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_INVALID_PROTOCOL"));
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_INVALID_PROTOCOL"),
                    null, resp);
            return;
        }

        try {
            super.authenticate(req);
        } catch (IOException e) {
            log(ILogger.LL_SECURITY, CMS.getLogMessage("ADMIN_SRVLT_FAIL_AUTHS"));
            sendResponse(ERROR, CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHS_FAILED"),
                    null, resp);
            return;
        }

        try {
            AUTHZ_RES_NAME = "certServer.acl.configuration";

            if (op.equals(OpDef.OP_SEARCH)) {
                mOp = "read";
                if ((mToken = super.authorize(req)) == null) {
                    sendResponse(ERROR,
                            CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHZ_FAILED"),
                            null, resp);
                    return;
                }
                if (scope.equals(ScopeDef.SC_ACL)) {
                    listResources(req, resp);
                    return;
                } else if (scope.equals(ScopeDef.SC_ACL_IMPLS)) {
                    listACLsEvaluators(req, resp);
                    return;
                } else if (scope.equals(ScopeDef.SC_EVALUATOR_TYPES)) {
                    listACLsEvaluatorTypes(req, resp);
                    return;
                }
            } else if (op.equals(OpDef.OP_READ)) {
                mOp = "read";
                if ((mToken = super.authorize(req)) == null) {
                    sendResponse(ERROR,
                            CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHZ_FAILED"),
                            null, resp);
                    return;
                }
                if (scope.equals(ScopeDef.SC_ACL)) {
                    getResourceACL(req, resp);
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
                if (scope.equals(ScopeDef.SC_ACL)) {
                    updateResources(req, resp);
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
                if (scope.equals(ScopeDef.SC_ACL_IMPLS)) {
                    addACLsEvaluator(req, resp, scope);
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
                if (scope.equals(ScopeDef.SC_ACL_IMPLS)) {
                    deleteACLsEvaluator(req, resp, scope);
                    return;
                }
            } else {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_INVALID_OP_SCOPE"));
                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_INVALID_OP_SCOPE"),
                        null, resp);
                return;
            }
        } catch (EBaseException e) {
            log(ILogger.LL_FAILURE, e.toString());
            sendResponse(ERROR, e.toString(getLocale(req)),
                    null, resp);
            return;
        } catch (Exception e) {
            log(ILogger.LL_FAILURE, e.toString());
            log(ILogger.LL_DEBUG, "SRVLT_FAIL_PERFORM 2");

            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_PERFORM_FAILED"),
                    null, resp);
            return;
        }

        log(ILogger.LL_DEBUG, "SRVLT_FAIL_PERFORM 3");

        sendResponse(ERROR,
                CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_PERFORM_FAILED"),
                null, resp);
        return;
    }

    /**
     * list acls resources by name
     */
    private void listResources(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException, IOException,
            EBaseException {

        NameValuePairs params = new NameValuePairs();

        Enumeration<ACL> res = mAuthzMgr.getACLs();

        while (res.hasMoreElements()) {
            ACL acl = res.nextElement();
            String desc = acl.getDescription();

            if (desc == null)
                params.put(acl.getName(), "");
            else
                params.put(acl.getName(), desc);
        }

        sendResponse(SUCCESS, null, params, resp);
    }

    /**
     * get acls information for a resource
     */
    private void getResourceACL(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException, IOException,
            EBaseException {

        NameValuePairs params = new NameValuePairs();
        //get resource id first
        String resourceId = super.getParameter(req, Constants.RS_ID);

        if (resourceId == null) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                    null, resp);
            return;
        }

        IACL acl = mAuthzMgr.getACL(resourceId);

        if (acl != null) {
            Enumeration<String> rightsEnum = acl.rights();

            StringBuffer rights = new StringBuffer();

            if (rightsEnum.hasMoreElements()) {
                while (rightsEnum.hasMoreElements()) {
                    if (rights.length() != 0) {
                        rights.append(",");
                    }
                    String right = rightsEnum.nextElement();

                    rights.append(right);
                }
            }

            params.put(Constants.PR_ACL_OPS, rights.toString());

            Enumeration<ACLEntry> aclEntryEnum;
            aclEntryEnum = acl.entries();
            String acis = "";

            if (aclEntryEnum.hasMoreElements()) {
                while (aclEntryEnum.hasMoreElements()) {
                    if (acis != "") {
                        acis += ";";
                    }
                    ACLEntry aclEntry = aclEntryEnum.nextElement();
                    String aci = aclEntry.getACLEntryString();

                    acis += aci;
                }
            }

            params.put(Constants.PR_ACI, acis);

            sendResponse(SUCCESS, null, params, resp);
            return;

        } else {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("ACLS_SRVLT_RESOURCE_NOT_FOUND"));
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ACL_RESOURCE_NOT_FOUND"),
                    null, resp);
            return;
        }
    }

    /**
     * modify acls information for a resource
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_ACL used when configuring Access Control List (ACL) information
     * </ul>
     *
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     * @exception EBaseException an error has occurred
     */
    private void updateResources(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException, IOException,
            EBaseException {

        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            // get resource id first
            String resourceId = super.getParameter(req, Constants.RS_ID);

            if (resourceId == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_ACL,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                        null, resp);
                return;
            }

            // get resource acls
            String resourceACLs = super.getParameter(req, Constants.PR_ACI);
            String rights = super.getParameter(req, Constants.PR_ACL_RIGHTS);
            String desc = super.getParameter(req, Constants.PR_ACL_DESC);

            try {
                mAuthzMgr.updateACLs(resourceId, rights, resourceACLs, desc);

                NameValuePairs params = new NameValuePairs();

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_ACL,
                            auditSubjectID,
                            ILogger.SUCCESS,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(SUCCESS, null, params, resp);
                return;
            } catch (Exception e) {
                log(ILogger.LL_FAILURE, e.toString());

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_ACL,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_ACL_UPDATE_FAIL"),
                        null, resp);
                return;
            }
            // } catch( EBaseException eAudit1 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_ACL,
            //                        auditSubjectID,
            //                        ILogger.FAILURE,
            //                        auditParams( req ) );
            //
            //     audit( auditMessage );
            //
            //     // rethrow the specific exception to be handled later
            //     throw eAudit1;
        } catch (IOException eAudit2) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_ACL,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit2;
            // } catch( ServletException eAudit3 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_ACL,
            //                        auditSubjectID,
            //                        ILogger.FAILURE,
            //                        auditParams( req ) );
            //
            //     audit( auditMessage );
            //
            //     // rethrow the specific exception to be handled later
            //     throw eAudit3;
        }
    }

    /**
     * list access evaluators by types and class paths
     */
    private void listACLsEvaluators(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException, IOException,
            EBaseException {
        NameValuePairs params = new NameValuePairs();
        Enumeration<IAccessEvaluator> res = mAuthzMgr.aclEvaluatorElements();

        while (res.hasMoreElements()) {
            IAccessEvaluator evaluator = res.nextElement();

            // params.add(evaluator.getType(), evaluator.getDescription());
            params.put(evaluator.getType(), evaluator.getClass().getName());
        }

        sendResponse(SUCCESS, null, params, resp);
    }

    private void listACLsEvaluatorTypes(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException, IOException,
            EBaseException {
        NameValuePairs params = new NameValuePairs();
        Enumeration<IAccessEvaluator> res = mAuthzMgr.aclEvaluatorElements();

        while (res.hasMoreElements()) {
            IAccessEvaluator evaluator = res.nextElement();
            String[] operators = evaluator.getSupportedOperators();
            StringBuffer str = new StringBuffer();

            for (int i = 0; i < operators.length; i++) {
                if (str.length() > 0)
                    str.append(",");
                str.append(operators[i]);
            }

            params.put(evaluator.getType(), str.toString());
        }

        sendResponse(SUCCESS, null, params, resp);
    }

    /**
     * add access evaluators
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_ACL used when configuring Access Control List (ACL) information
     * </ul>
     *
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @param scope string used to obtain the contents of this ACL evaluator's
     *            substore
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     * @exception EBaseException an error has occurred
     */
    private synchronized void addACLsEvaluator(HttpServletRequest req,
            HttpServletResponse resp, String scope)
            throws ServletException, IOException, EBaseException {

        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            // get evaluator type first
            String type = super.getParameter(req, Constants.RS_ID);

            if (type == null) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_ACL,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));
                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                        null, resp);
                return;
            }

            // is the evaluator type unique?
            /*
             if (!mACLs.isTypeUnique(type)) {
             String infoMsg = "replacing existing type: "+ type;
             log(ILogger.LL_WARN, infoMsg);
             }
             */

            // get class
            String classPath = super.getParameter(req, Constants.PR_ACL_CLASS);

            IConfigStore destStore =
                    mConfig.getSubStore(PROP_EVAL);
            IConfigStore mStore =
                    destStore.getSubStore(ScopeDef.SC_ACL_IMPLS);

            // Does the class exist?
            Class<?> newImpl = null;

            try {
                newImpl = Class.forName(classPath);
            } catch (ClassNotFoundException e) {
                String errMsg = "class " + classPath + " not found";

                log(ILogger.LL_FAILURE, errMsg);

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_ACL,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_ACL_CLASS_LOAD_FAIL"),
                        null, resp);
                return;
            }

            // is the class an IAccessEvaluator?
            try {
                if (Class.forName("com.netscape.certsrv.evaluators.IAccessEvaluator").isAssignableFrom(newImpl) == false) {
                    String errMsg = "class not com.netscape.certsrv.evaluators.IAccessEvaluator" +
                            classPath;

                    log(ILogger.LL_FAILURE, errMsg);

                    // store a message in the signed audit log file
                    auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_CONFIG_ACL,
                                auditSubjectID,
                                ILogger.FAILURE,
                                auditParams(req));

                    audit(auditMessage);

                    sendResponse(ERROR,
                            CMS.getUserMessage(getLocale(req), "CMS_ACL_ILL_CLASS"),
                            null, resp);
                    return;
                }
            } catch (Exception e) {
                String errMsg = "class not com.netscape.certsrv.evaluators.IAccessEvaluator" +
                        classPath;

                log(ILogger.LL_FAILURE, errMsg);

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_ACL,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_ACL_ILL_CLASS"),
                        null, resp);
                return;
            }

            IConfigStore substore = mStore.makeSubStore(type);

            substore.put(Constants.PR_ACL_CLASS, classPath);

            // commiting
            try {
                mConfig.commit(true);
            } catch (Exception e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ACLS_SRVLT_FAIL_COMMIT"));

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_ACL,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_ACL_COMMIT_FAIL"),
                        null, resp);
                return;
            }

            // Instantiate an object for this implementation
            IAccessEvaluator evaluator = null;

            try {
                evaluator = (IAccessEvaluator) Class.forName(classPath).newInstance();
            } catch (Exception e) {
                log(ILogger.LL_FAILURE, e.toString());

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_ACL,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_ACL_INST_CLASS_FAIL"),
                        null, resp);
                return;
            }

            // initialize the access evaluator
            if (evaluator != null) {
                evaluator.init();
                // add evaluator to list
                mAuthzMgr.registerEvaluator(type, evaluator);
            }

            //...
            NameValuePairs params = new NameValuePairs();

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_ACL,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req));

            audit(auditMessage);

            sendResponse(SUCCESS, null, params, resp);
            // } catch( EBaseException eAudit1 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_ACL,
            //                        auditSubjectID,
            //                        ILogger.FAILURE,
            //                        auditParams( req ) );
            //
            //     audit( auditMessage );
            //
            //     // rethrow the specific exception to be handled later
            //     throw eAudit1;
        } catch (IOException eAudit2) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_ACL,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit2;
            // } catch( ServletException eAudit3 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_ACL,
            //                        auditSubjectID,
            //                        ILogger.FAILURE,
            //                        auditParams( req ) );
            //
            //     audit( auditMessage );
            //
            //     // rethrow the specific exception to be handled later
            //     throw eAudit3;
        }
    }

    /**
     * remove access evaluators
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_ACL used when configuring Access Control List (ACL) information
     * </ul>
     *
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @param scope string used to obtain the contents of this ACL evaluator's
     *            substore
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     * @exception EBaseException an error has occurred
     */
    private synchronized void deleteACLsEvaluator(HttpServletRequest req,
            HttpServletResponse resp, String scope) throws ServletException,
            IOException, EBaseException {

        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            NameValuePairs params = new NameValuePairs();
            String id = req.getParameter(Constants.RS_ID);

            if (id == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_ACL,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                        null, resp);
                return;
            }

            // does the evaluator exist?
            Hashtable<String, IAccessEvaluator> mEvaluators = mAuthzMgr.getAccessEvaluators();

            if (mEvaluators.containsKey(id) == false) {
                log(ILogger.LL_FAILURE, "evaluator attempted to be removed not found");

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_ACL,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_ACL_EVAL_NOT_FOUND"),
                        null, resp);
                return;
            }

            // it's possibl that it's being used...we have to assume that
            // the administrator knows what she is doing, for now
            mEvaluators.remove(id);

            try {
                IConfigStore destStore =
                        mConfig.getSubStore(PROP_EVAL);
                IConfigStore mStore =
                        destStore.getSubStore(ScopeDef.SC_ACL_IMPLS);

                mStore.removeSubStore(id);
            } catch (Exception eeee) {
                //CMS.debugStackTrace(eeee);
            }
            // commiting
            try {
                mConfig.commit(true);
            } catch (Exception e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ACLS_SRVLT_FAIL_COMMIT"));

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_ACL,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_ACL_COMMIT_FAIL"),
                        null, resp);
                return;
            }

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_ACL,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req));

            audit(auditMessage);

            sendResponse(SUCCESS, null, params, resp);
            return;
            // } catch( EBaseException eAudit1 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_ACL,
            //                        auditSubjectID,
            //                        ILogger.FAILURE,
            //                        auditParams( req ) );
            //
            //     audit( auditMessage );
            //
            //     // rethrow the specific exception to be handled later
            //     throw eAudit1;
        } catch (IOException eAudit2) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_ACL,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit2;
            // } catch( ServletException eAudit3 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_ACL,
            //                        auditSubjectID,
            //                        ILogger.FAILURE,
            //                        auditParams( req ) );
            //
            //     audit( auditMessage );
            //
            //     // rethrow the specific exception to be handled later
            //     throw eAudit3;
        }
    }

    /**
     * Searchs for certificate requests.
     */

    /*
     private void getACLs(HttpServletRequest req,
     HttpServletResponse resp) throws ServletException, IOException,
     EBaseException {
     NameValuePairs params = new NameValuePairs();
     ByteArrayOutputStream bos = new ByteArrayOutputStream();
     ObjectOutputStream oos = new ObjectOutputStream(bos);
     String names = getParameter(req, Constants.PT_NAMES);
     StringTokenizer st = new StringTokenizer(names, ",");
     while (st.hasMoreTokens()) {
     String target = st.nextToken();
     ACL acl = AccessManager.getInstance().getACL(target);
     oos.writeObject(acl);
     }
     // BASE64Encoder encoder = new BASE64Encoder();
     // params.add(Constants.PT_ACLS, encoder.encodeBuffer(bos.toByteArray()));
     params.add(Constants.PT_ACLS, CMS.BtoA(bos.toByteArray()));
     sendResponse(SUCCESS, null, params, resp);
     }
     */

    private void log(int level, String msg) {
        if (mLogger == null)
            return;
        mLogger.log(ILogger.EV_SYSTEM, null, ILogger.S_ACLS,
                level, "ACLAdminServlet: " + msg);
    }
}
