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
package com.netscape.cms.authorization;

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Locale;
import java.util.StringTokenizer;
import java.util.Vector;

import com.netscape.certsrv.acls.ACL;
import com.netscape.certsrv.acls.ACLEntry;
import com.netscape.certsrv.acls.EACLsException;
import com.netscape.certsrv.acls.IACL;
import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.evaluators.IAccessEvaluator;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.cmsutil.util.Utils;

/**
 * An abstract class represents an authorization manager that governs the
 * access of internal resources such as servlets.
 * It parses in the ACLs associated with each protected
 * resources, and provides protected method <CODE>checkPermission</CODE> for code that needs to verify access before
 * performing
 * actions.
 * <P>
 * Here is a sample resourceACLS for a resource
 *
 * <PRE>
 *   certServer.UsrGrpAdminServlet:
 *       execute:
 *           deny (execute) user="tempAdmin";
 *           allow (execute) group="Administrators";
 * </PRE>
 *
 * To perform permission checking, code call authz mgr authorize() method to verify access. See AuthzMgr for calling
 * example.
 * <P>
 * default "evaluators" are used to evaluate the "group=.." or "user=.." rules. See evaluator for more info
 *
 * @version $Revision$, $Date$
 * @see <A HREF="http://developer.netscape.com/library/documentation/enterprise/admnunix/aclfiles.htm">ACL Files</A>
 */
public abstract class AAclAuthz {

    protected static final String PROP_CLASS = "class";
    protected static final String PROP_IMPL = "impl";
    protected static final String PROP_EVAL = "accessEvaluator";

    protected static final String ACLS_ATTR = "aclResources";

    private IConfigStore mConfig = null;

    private Hashtable<String, ACL> mACLs = new Hashtable<String, ACL>();
    private Hashtable<String, IAccessEvaluator> mEvaluators = new Hashtable<String, IAccessEvaluator>();
    private ILogger mLogger = null;

    /* Vector of extendedPluginInfo strings */
    protected static Vector<String> mExtendedPluginInfo = null;

    protected static String[] mConfigParams = null;

    static {
        mExtendedPluginInfo = new Vector<String>();
    }

    /**
     * Constructor
     */
    public AAclAuthz() {
    }

    /**
     * Initializes
     */
    protected void init(IConfigStore config)
            throws EBaseException {

        mLogger = CMS.getLogger();
        CMS.debug("AAclAuthz: init begins");

        mConfig = config;

        // load access evaluators specified in the config file
        IConfigStore mainConfig = CMS.getConfigStore();
        IConfigStore evalConfig = mainConfig.getSubStore(PROP_EVAL);
        IConfigStore i = evalConfig.getSubStore(PROP_IMPL);

        IAccessEvaluator evaluator = null;
        Enumeration<String> mImpls = i.getSubStoreNames();

        while (mImpls.hasMoreElements()) {
            String type = mImpls.nextElement();
            String evalClassPath = null;

            try {
                evalClassPath = i.getString(type + "." + PROP_CLASS);
            } catch (Exception e) {
                log(ILogger.LL_MISCONF, "failed to get config class info");

                throw new EBaseException(CMS.getUserMessage("CMS_BASE_GET_PROPERTY_FAILED",
                            type + "." + PROP_CLASS));
            }

            // instantiate evaluator
            try {
                evaluator =
                        (IAccessEvaluator) Class.forName(evalClassPath).newInstance();
            } catch (Exception e) {
                throw new EACLsException(CMS.getUserMessage("CMS_ACL_CLASS_LOAD_FAIL",
                            evalClassPath));
            }

            if (evaluator != null) {
                evaluator.init();
                // store evaluator
                registerEvaluator(type, evaluator);
            } else {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("AUTHZ_EVALUATOR_NULL", type));
            }
        }

        log(ILogger.LL_INFO, "initialization done");
    }

    /**
     * Parse ACL resource attributes, then update the ACLs memory store
     * This is intended to be used if storing ACLs on ldap is not desired,
     * and the caller is expected to call this method to add resource
     * and acl info into acls memory store. The resACLs format should conform
     * to the following:
     * <resource ID>:right-1[,right-n]:[allow,deny](right(s))<evaluatorType>=<value>:<comment for this resource acl
     * <P>
     * Example: resTurnKnob:left,right:allow(left) group="lefties":door knobs for lefties
     *
     * @param resACLs same format as the resourceACLs attribute
     * @throws EBaseException parsing error from <code>parseACL</code>
     */
    public void addACLs(String resACLs) throws EBaseException {
        ACL acl = (ACL) CMS.parseACL(resACLs);

        if (acl != null) {
            mACLs.put(acl.getName(), acl);
        } else {
            log(ILogger.LL_FAILURE, "parseACL failed");
        }
    }

    public void accessInit(String accessInfo) throws EBaseException {
        addACLs(accessInfo);
    }

    public IACL getACL(String target) {
        return mACLs.get(target);
    }

    protected Enumeration<String> getTargetNames() {
        return mACLs.keys();
    }

    public Enumeration<ACL> getACLs() {
        return mACLs.elements();
    }

    /**
     * Returns the configuration store used by this Authz mgr
     */
    public IConfigStore getConfigStore() {
        return mConfig;
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        String[] s = Utils.getStringArrayFromVector(mExtendedPluginInfo);

        return s;

    }

    /**
     * Returns a list of configuration parameter names.
     * The list is passed to the configuration console so instances of
     * this implementation can be configured through the console.
     *
     * @return String array of configuration parameter names.
     */
    public String[] getConfigParams() {
        return mConfigParams;
    }

    /**
     * graceful shutdown
     */
    public abstract void shutdown();

    /**
     * Registers new handler for the given attribute type
     * in the expressions.
     */
    public void registerEvaluator(String type, IAccessEvaluator evaluator) {
        mEvaluators.put(type, evaluator);
        log(ILogger.LL_INFO, type + " evaluator registered");
    }

    /*******************************************************
     * with session context
     *******************************************************/

    /**
     * Checks if the permission is granted or denied in
     * the current execution context. If the code is
     * marked as privileged, this methods will simply
     * return.
     * <P>
     * note that if a resource does not exist in the aclResources entry, but a higher level node exist, it will still be
     * evaluated. The highest level node's acl determines the permission. If the higher level node doesn't contain any
     * acl information, then it's passed down to the lower node. If a node has no aci in its resourceACLs, then it's
     * considered passed.
     * <p>
     * example: certServer.common.users, if failed permission check for "certServer", then it's considered failed, and
     * there is no need to continue the check. If passed permission check for "certServer", then it's considered passed,
     * and no need to continue the check. If certServer contains no aci then "certServer.common" will be checked for
     * permission instead. If down to the leaf level, the node still contains no aci, then it's considered passed. If at
     * the leaf level, no such resource exist, or no acis, it's considered passed.
     * <p>
     * If there are multiple aci's for a resource, ALL aci's will be checked, and only if all passed permission checks,
     * will the eventual access be granted.
     *
     * @param name resource name
     * @param perm permission requested
     * @exception EACLsException access permission denied
     */
    protected synchronized void checkPermission(String name, String perm)
            throws EACLsException {
        String resource = "";
        StringTokenizer st = new StringTokenizer(name, ".");

        while (st.hasMoreTokens()) {
            String node = st.nextToken();

            if (!"".equals(resource)) {
                resource = resource + "." + node;
            } else {
                resource = node;
            }

            boolean passed = false;

            try {
                passed = checkACLs(resource, perm);
            } catch (EACLsException e) {
                Object[] params = new Object[2];

                params[0] = name;
                params[1] = perm;

                log(ILogger.LL_SECURITY, CMS.getLogMessage("AUTHZ_EVALUATOR_ACCESS_DENIED", name, perm));

                throw new EACLsException(CMS.getUserMessage("CMS_ACL_NO_PERMISSION",
                            (String[]) params));
            }

            if (passed) {
                String infoMsg = "checkPermission(): permission granted for the resource " +
                        name + " on operation " + perm;

                log(ILogger.LL_INFO, infoMsg);

                return;
            } // else, continue
        }
    }

    /**
     * Checks if the permission is granted or denied in
     * the current execution context.
     * <P>
     * An <code>ACL</code> may contain one or more <code>ACLEntry</code>. However, in case of multiple
     * <code>ACLEntry</code>, a subject must pass ALL of the <code>ACLEntry</code> evaluation for permission to be
     * granted
     * <P>
     * negative ("deny") aclEntries are treated differently than positive ("allow") statements. If a negative aclEntries
     * fails the acl check, the permission check will return "false" right away; while in the case of a positive
     * aclEntry, if the the aclEntry fails the acl check, the next aclEntry will be evaluated.
     *
     * @param name resource name
     * @param perm permission requested
     * @return true if access allowed
     *         false if should be passed down to the next node
     * @exception EACLsException if access disallowed
     */
    private boolean checkACLs(String name, String perm)
            throws EACLsException {
        ACL acl = mACLs.get(name);

        // no such resource, pass it down
        if (acl == null) {
            String infoMsg = "checkACLs(): no acl for" +
                    name + "...pass down to next node";

            log(ILogger.LL_INFO, infoMsg);

            return false;
        }

        Enumeration<ACLEntry> e = acl.entries();

        if ((e == null) || (e.hasMoreElements() == false)) {
            // no acis for node, pass down to next node
            String infoMsg = " AAclAuthz.checkACLs(): no acis for " +
                    name + " acl entry...pass down to next node";

            log(ILogger.LL_INFO, infoMsg);

            return false;
        }

        /**
         * must pass all ACLEntry
         */
        for (; e.hasMoreElements();) {
            ACLEntry entry = e.nextElement();

            // if permission not pertinent, move on to next ACLEntry
            if (entry.containPermission(perm) == true) {
                if (evaluateExpressions(entry.getAttributeExpressions())) {
                    if (entry.checkPermission(perm) == false) {
                        log(ILogger.LL_SECURITY, " checkACLs(): permission denied");
                        throw new EACLsException(CMS.getUserMessage("CMS_ACL_PERMISSION_DENIED"));
                    }
                } else if (!entry.isNegative()) {
                    // didn't meet the access expression for "allow", failed
                    log(ILogger.LL_SECURITY, "checkACLs(): permission denied");
                    throw new EACLsException(CMS.getUserMessage("CMS_ACL_PERMISSION_DENIED"));
                }
            }
        }

        return true;
    }

    /**
     * Resolves the given expressions.
     * expression || expression || ...
     * example:
     * group="Administrators" || group="Operators"
     */
    private boolean evaluateExpressions(String s) {
        // XXX - just handle "||" (or) among multiple expressions for now
        // XXX - could use some optimization ... later

        CMS.debug("evaluating expressions: " + s);

        Vector<Object> v = new Vector<Object>();

        while (s.length() > 0) {
            int orIndex = s.indexOf("||");
            int andIndex = s.indexOf("&&");

            // this is the last expression
            if (orIndex == -1 && andIndex == -1) {
                boolean passed = evaluateExpression(s.trim());

                v.addElement(Boolean.valueOf(passed));
                break;

                // || first
            } else if (andIndex == -1 || (orIndex != -1 && orIndex < andIndex)) {
                String s1 = s.substring(0, orIndex);
                boolean passed = evaluateExpression(s1.trim());

                v.addElement(new Boolean(passed));
                v.addElement("||");
                s = s.substring(orIndex + 2);
                // && first
            } else {
                String s1 = s.substring(0, andIndex);
                boolean passed = evaluateExpression(s1.trim());

                v.addElement(new Boolean(passed));
                v.addElement("&&");
                s = s.substring(andIndex + 2);
            }
        }

        if (v.size() == 1) {
            Boolean bool = (Boolean) v.remove(0);

            return bool.booleanValue();
        }
        boolean left = false;
        String op = "";
        boolean right = false;

        while (v.size() > 0) {
            if (op.equals(""))
                left = ((Boolean) v.remove(0)).booleanValue();
            op = (String) v.remove(0);
            right = ((Boolean) v.remove(0)).booleanValue();
            left = evaluateExp(left, op, right);
        }

        return left;
    }

    /**
     * Resolves the given expression.
     */
    private boolean evaluateExpression(String expression) {
        // XXX - just recognize "=" for now!!
        int i = expression.indexOf("=");
        String type = expression.substring(0, i);
        String value = expression.substring(i + 1);
        IAccessEvaluator evaluator = mEvaluators.get(type);

        if (evaluator == null) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("AUTHZ_EVALUATOR_NOT_FOUND", type));
            return false;
        }

        return evaluator.evaluate(type, "=", value);
    }

    /*******************************************************
     * with authToken
     *******************************************************/

    /**
     * Checks if the permission is granted or denied with id from authtoken
     * gotten from authentication that precedes authorization. If the code is
     * marked as privileged, this methods will simply
     * return.
     * <P>
     * note that if a resource does not exist in the aclResources entry, but a higher level node exist, it will still be
     * evaluated. The highest level node's acl determines the permission. If the higher level node doesn't contain any
     * acl information, then it's passed down to the lower node. If a node has no aci in its resourceACLs, then it's
     * considered passed.
     * <p>
     * example: certServer.common.users, if failed permission check for "certServer", then it's considered failed, and
     * there is no need to continue the check. If passed permission check for "certServer", then it's considered passed,
     * and no need to continue the check. If certServer contains no aci then "certServer.common" will be checked for
     * permission instead. If down to the leaf level, the node still contains no aci, then it's considered passed. If at
     * the leaf level, no such resource exist, or no acis, it's considered passed.
     * <p>
     * If there are multiple aci's for a resource, ALL aci's will be checked, and only if all passed permission checks,
     * will the eventual access be granted.
     *
     * @param authToken authentication token gotten from authentication
     * @param name resource name
     * @param perm permission requested
     * @exception EACLsException access permission denied
     */
    public synchronized void checkPermission(IAuthToken authToken, String name,
            String perm)
            throws EACLsException {

        Vector<String> nodev = getNodes(name);
        Enumeration<String> nodes = nodev.elements();
        String order = getOrder();
        Enumeration<ACLEntry> entries = null;

        if (order.equals("deny"))
            entries = getDenyEntries(nodes, perm);
        else
            entries = getAllowEntries(nodes, perm);

        boolean permitted = false;

        while (entries.hasMoreElements()) {
            ACLEntry entry = entries.nextElement();

            CMS.debug("checkACLS(): ACLEntry expressions= " +
                    entry.getAttributeExpressions());
            if (evaluateExpressions(authToken, entry.getAttributeExpressions())) {
                log(ILogger.LL_SECURITY,
                        " checkACLs(): permission denied");
                throw new EACLsException(CMS.getUserMessage("CMS_ACL_PERMISSION_DENIED"));
            }
        }

        nodes = nodev.elements();
        if (order.equals("deny"))
            entries = getAllowEntries(nodes, perm);
        else
            entries = getDenyEntries(nodes, perm);

        while (entries.hasMoreElements()) {
            ACLEntry entry = entries.nextElement();

            CMS.debug("checkACLS(): ACLEntry expressions= " +
                    entry.getAttributeExpressions());
            if (evaluateExpressions(authToken, entry.getAttributeExpressions())) {
                permitted = true;
            }
        }

        nodev = null;
        if (permitted) {
            String infoMsg = "checkPermission(): permission granted for the resource " +
                    name + " on operation " + perm;

            log(ILogger.LL_INFO, infoMsg);
            return;
        } else {
            String[] params = new String[2];

            params[0] = name;
            params[1] = perm;

            log(ILogger.LL_SECURITY,
                    CMS.getLogMessage("AUTHZ_EVALUATOR_ACCESS_DENIED", name, perm));

            throw new EACLsException(CMS.getUserMessage("CMS_ACL_NO_PERMISSION",
                        params));
        }
    }

    protected Enumeration<ACLEntry> getAllowEntries(Enumeration<String> nodes, String operation) {
        String name = "";
        ACL acl = null;
        Enumeration<ACLEntry> e = null;
        Vector<ACLEntry> v = new Vector<ACLEntry>();

        while (nodes.hasMoreElements()) {
            name = nodes.nextElement();
            acl = mACLs.get(name);
            if (acl == null)
                continue;
            e = acl.entries();
            while (e.hasMoreElements()) {
                ACLEntry entry = e.nextElement();

                if (!entry.isNegative() &&
                        entry.containPermission(operation)) {
                    v.addElement(entry);
                }
            }
        }

        return v.elements();
    }

    protected Enumeration<ACLEntry> getDenyEntries(Enumeration<String> nodes, String operation) {
        String name = "";
        ACL acl = null;
        Enumeration<ACLEntry> e = null;
        Vector<ACLEntry> v = new Vector<ACLEntry>();

        while (nodes.hasMoreElements()) {
            name = nodes.nextElement();
            acl = mACLs.get(name);
            if (acl == null)
                continue;
            e = acl.entries();
            while (e.hasMoreElements()) {
                ACLEntry entry = e.nextElement();

                if (entry.isNegative() &&
                        entry.containPermission(operation)) {
                    v.addElement(entry);
                }
            }
        }

        return v.elements();
    }

    /**
     * Resolves the given expressions.
     * expression || expression || ...
     * example:
     * group="Administrators" || group="Operators"
     */
    private boolean evaluateExpressions(IAuthToken authToken, String s) {
        // XXX - just handle "||" (or) among multiple expressions for now
        // XXX - could use some optimization ... later
        CMS.debug("evaluating expressions: " + s);

        Vector<Object> v = new Vector<Object>();

        while (s.length() > 0) {
            int orIndex = s.indexOf("||");
            int andIndex = s.indexOf("&&");

            // this is the last expression
            if (orIndex == -1 && andIndex == -1) {
                boolean passed = evaluateExpression(authToken, s.trim());

                CMS.debug("evaluated expression: " + s.trim() + " to be " + passed);
                v.addElement(Boolean.valueOf(passed));
                break;

                // || first
            } else if (andIndex == -1 || (orIndex != -1 && orIndex < andIndex)) {
                String s1 = s.substring(0, orIndex);
                boolean passed = evaluateExpression(authToken, s1.trim());

                CMS.debug("evaluated expression: " + s1.trim() + " to be " + passed);
                v.addElement(new Boolean(passed));
                v.addElement("||");
                s = s.substring(orIndex + 2);
                // && first
            } else {
                String s1 = s.substring(0, andIndex);
                boolean passed = evaluateExpression(authToken, s1.trim());

                CMS.debug("evaluated expression: " + s1.trim() + " to be " + passed);
                v.addElement(new Boolean(passed));
                v.addElement("&&");
                s = s.substring(andIndex + 2);
            }
        }

        if (v.size() == 0) {
            return false;
        }

        if (v.size() == 1) {
            Boolean bool = (Boolean) v.remove(0);

            return bool.booleanValue();
        }

        boolean left = false;
        String op = "";
        boolean right = false;

        while (v.size() > 0) {
            if (op.equals(""))
                left = ((Boolean) v.remove(0)).booleanValue();
            op = (String) v.remove(0);
            right = ((Boolean) v.remove(0)).booleanValue();
            left = evaluateExp(left, op, right);
        }

        return left;
    }

    public Vector<String> getNodes(String resourceID) {
        Vector<String> v = new Vector<String>();

        if (resourceID != null && !resourceID.equals("")) {
            v.addElement(resourceID);
        } else {
            return v;
        }
        int index = resourceID.lastIndexOf(".");
        String name = resourceID;

        while (index != -1) {
            name = name.substring(0, index);
            v.addElement(name);
            index = name.lastIndexOf(".");
        }

        return v;
    }

    /**
     * Resolves the given expression.
     */
    private boolean evaluateExpression(IAuthToken authToken, String expression) {
        String op = getOp(expression);
        String type = "";
        String value = "";

        if (!op.equals("")) {
            int len = op.length();
            int i = expression.indexOf(op);

            type = expression.substring(0, i).trim();
            value = expression.substring(i + len).trim();
        }
        IAccessEvaluator evaluator = mEvaluators.get(type);

        if (evaluator == null) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("AUTHZ_EVALUATOR_NOT_FOUND", type));
            return false;
        }

        return evaluator.evaluate(authToken, type, op, value);
    }

    private String getOp(String exp) {
        int i = exp.indexOf("!=");

        if (i == -1) {
            i = exp.indexOf("=");
            if (i == -1) {
                i = exp.indexOf(">");
                if (i == -1) {
                    i = exp.indexOf("<");
                    if (i == -1) {
                        log(ILogger.LL_FAILURE, CMS.getLogMessage("AUTHZ_OP_NOT_SUPPORTED", exp));
                    } else {
                        return "<";
                    }
                } else {
                    return ">";
                }
            } else {
                return "=";
            }
        } else {
            return "!=";
        }
        return "";
    }

    private boolean evaluateExp(boolean left, String op, boolean right) {
        if (op.equals("||")) {
            if (left == false && right == false)
                return false;
            return true;
        } else if (op.equals("&&")) {
            if (left == true && right == true)
                return true;
            return false;
        }
        return false;
    }

    /*******************************************************
     * end identification differentiation
     *******************************************************/

    /**
     * This one only updates the memory. Classes extend this class should
     * also update to a permanent storage
     */
    public void updateACLs(String id, String rights, String strACLs,
            String desc) throws EACLsException {
        String resourceACLs = id;

        if (rights != null)
            resourceACLs = id + ":" + rights + ":" + strACLs + ":" + desc;

        // memory update
        ACL ac = null;

        try {
            ac = (ACL) CMS.parseACL(resourceACLs);
        } catch (EBaseException ex) {
            throw new EACLsException(CMS.getUserMessage("CMS_ACL_PARSING_ERROR_0"));
        }

        mACLs.put(ac.getName(), ac);
    }

    /**
     * gets an enumeration of resources
     *
     * @return an enumeration of resources contained in the ACL table
     */
    public Enumeration<ACL> aclResElements() {
        return (mACLs.elements());
    }

    /**
     * gets an enumeration of access evaluators
     *
     * @return an enumeraton of access evaluators
     */
    public Enumeration<IAccessEvaluator> aclEvaluatorElements() {
        return (mEvaluators.elements());
    }

    /**
     * gets the access evaluators
     *
     * @return handle to the access evaluators table
     */
    public Hashtable<String, IAccessEvaluator> getAccessEvaluators() {
        return mEvaluators;
    }

    /**
     * is this resource name unique
     *
     * @return true if unique; false otherwise
     */
    public boolean isTypeUnique(String type) {
        if (mACLs.containsKey(type)) {
            return false;
        } else {
            return true;
        }
    }

    private void log(int level, String msg) {
        if (mLogger == null)
            return;
        mLogger.log(ILogger.EV_SYSTEM, null, ILogger.S_AUTHORIZATION,
                level, msg);
    }

    /*********************************
     * abstract methods
     **********************************/

    /**
     * update acls. called after memory upate is done to flush to permanent
     * storage.
     * <p>
     */
    protected abstract void flushResourceACLs() throws EACLsException;

    /**
     * an abstract class that enforces implementation of the
     * authorize() method that will authorize an operation on a
     * particular resource
     *
     * @param authToken the authToken associated with a user
     * @param resource - the protected resource name
     * @param operation - the protected resource operation name
     * @exception EBaseException If an internal error occurred.
     * @return authzToken
     */
    public abstract AuthzToken authorize(IAuthToken authToken, String resource, String operation) throws EBaseException;

    public String getOrder() {
        IConfigStore mainConfig = CMS.getConfigStore();
        String order = "";

        try {
            order = mainConfig.getString("authz.evaluateOrder", "");
            if (order.startsWith("allow"))
                return "allow";
            else
                return "deny";
        } catch (Exception e) {
        }
        return "deny";
    }

    public boolean evaluateACLs(IAuthToken authToken, String exp) {
        return evaluateExpressions(authToken, exp);
    }
}
