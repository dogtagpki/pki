package com.netscape.cmscore.realm;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Principal;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.List;
import java.util.Properties;
import java.util.StringTokenizer;
import java.util.Vector;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.PartialResultException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.Context;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.deploy.SecurityConstraint;
import org.apache.catalina.realm.JNDIRealm;

/*
 *  Self contained PKI JNDI Real that overrides the standard JNDI Realm
 *
 *  The purpose is to move authentication and authorization code out of the core server.
 *  This realm can be used standalone with only the dependency of having tomcatjss and jss installed
 *  and having tomcatjss connectors configured in the tomcat instance.
 *
 *  This realm allows for configurable SSL client authentication checking as well
 *  as checking against the standard PKI ACLs we have configured in our ldap database.
 *  Those not using a CS instance could either not configure the ACL checking or
 *  override this class to read in and evaluate their own ACL's.
 *
 *  This code makes use and simplifies some existing ACL and authorization code
 *  from the main server for now.
 *
 */

public class PKIJNDIRealm extends JNDIRealm {

    private static final String DEF_CERT_ATTR = "userCert";
    private static final String DEF_ACL_ATTR = "resource";

    private static final String PROP_USER = "user";
    private static final String PROP_GROUP = "group";
    private static final String PROP_USER_ANYBODY = "anybody";
    private static final String PROP_USER_EVERYBODY = "everybody";
    private static final String CERT_VERSION = "2";
    private static final String PROP_AUTH_FILE_PATH = "/WEB-INF/auth.properties";
    private static final int EXPRESSION_SIZE = 2;

    private Hashtable<String, ACL> acls = new Hashtable<String, ACL>();

    private Properties authzProperties = null;

    /* Look up the principal user based on the incoming client auth
     * certificate.
     * @param usercert Incoming client auth certificate presented by user
     * @return Principal Object representing the authenticated user.
     */
    @Override
    protected synchronized Principal getPrincipal(X509Certificate usercert) {

        logDebug("Entering PKIJNDIRealm.getPrincipal");

        if (usercert == null)
            return null;

        String uid = null;
        String certUIDLabel = getCertUIDLabel();

        if (certUIDLabel == null) {
            // We have no uid label, attempt to construct a description

            uid = CERT_VERSION + ";" + usercert.getSerialNumber() + ";"
                    + usercert.getIssuerDN() + ";" + usercert.getSubjectDN();

            //The description field is devoid of spaces and the email label is E
            //instead of EMAIL
            uid = uid.replaceAll(", ", ",");
            uid = uid.replaceAll("EMAILADDRESS", "E");

            logDebug(uid);

        } else {

            String certUIDSrchStr = certUIDLabel + "=";

            StringTokenizer dnTokens =
                    new StringTokenizer(usercert.getSubjectDN().getName(), ",");

            while (dnTokens.hasMoreTokens()) {
                String token = dnTokens.nextToken();
                int index = token.indexOf(certUIDSrchStr);

                if (index != -1) {
                    // Found the entry with the cert's UID

                    try {
                        uid = token.substring(index + certUIDSrchStr.length());
                    } catch (IndexOutOfBoundsException e) {
                        logErr("Out of Bounds Exception when attempting to extract UID from incomgin certificate.");
                        return null;
                    }

                    if (uid != null) {
                        break;
                    }
                }
            }
        }

        //Call the getPrincipal method of the base JNDIRealm class
        //based on the just calculated uid. During the next call
        // one of our methods to extract and store the user's ldap stored
        //client cert will be invoked

        Principal user = getPrincipal(uid);

        //ToDo: Possibly perform some more cert verficiation
        // such as OCSP, even though the tomcat jss connector
        // can already be configured for OCSP

        if (user != null) {
            X509Certificate storedCert = getStoredUserCert();
            setStoredUserCert(null);
            //Compare the stored ldap cert with the incoming cert
            if (usercert.equals(storedCert)) {
                //Success, the incoming certificate matches the
                //certificate stored in LDAP for this user.
                return user;
            }
        }

        setStoredUserCert(null);

        return null;
    }

    /**
     * Return a User object containing information about the user
     * with the specified username, if found in the directory;
     * otherwise return <code>null</code>.
     * Override here to extract the client auth certificate from the
     * ldap db.
     *
     * @param context The directory context
     * @param username Username to be looked up
     *
     * @exception NamingException if a directory server error occurs
     *
     * @see #getUser(DirContext, String, String, int)
     */
    @Override
    protected User getUser(DirContext context, String username)
            throws NamingException {

        //ToDo: Right now we support the Realm attribute
        //  userBase which only allows a single pattern from
        // which to search for users in ldap.
        // We need to use the "userPattern" attribute
        // which supports multiple search patterns.
        // This has not been done because the out of the box
        // Support for SSL client auth does not appear to support
        // the userPattern attribute. Certainly another method here
        // could be overridden to get this working.

        User certUser = super.getUser(context, username);

        if (certUser != null) {
            extractAndSaveStoredX509UserCert(context, certUser);
        }

        return certUser;
    }

    /**
     * Perform access control based on the specified authorization constraint.
     * Return <code>true</code> if this constraint is satisfied and processing
     * should continue, or <code>false</code> otherwise.
     * override to check for custom PKI ACL's authz permissions.
     *
     * @param request Request we are processing
     * @param response Response we are creating
     * @param constraints Security constraint we are enforcing
     * @param context The Context to which client of this class is attached.
     *
     * @exception IOException if an input/output error occurs
     */
    @Override
    public boolean hasResourcePermission(Request request,
            Response response,
            SecurityConstraint[] constraints,
            Context context)
            throws IOException {

        boolean allowed = super.hasResourcePermission(request, response, constraints, context);

        if (allowed == true && hasResourceACLS()) {

            loadAuthzProperties(context);

            if (hasAuthzProperties()) {
                //Let's check against our encoded acls.

                String requestURI = request.getDecodedRequestURI();
                Principal principal = request.getPrincipal();

                String match = getACLEntryDataForURL(requestURI);

                if (match != null) {
                    //first part is the resourceID, second part is the operation
                    String[] authzParams = match.split("\\,");

                    String resourceID = null;
                    String operation = null;

                    if (authzParams.length >= EXPRESSION_SIZE) {
                        resourceID = authzParams[0];
                        operation = authzParams[1];

                        if (resourceID != null) {
                            resourceID = resourceID.trim();
                        }

                        if (operation != null) {
                            operation = operation.trim();
                        }
                    }

                    allowed = checkACLPermission(principal, resourceID, operation);
                    logDebug("resourceID: " + resourceID + " operation: " + operation + " allowed: " + allowed);
                }
            }
        }

        // Return a "Forbidden" message denying access to this resource
        if (!allowed) {
            response.sendError
                    (HttpServletResponse.SC_FORBIDDEN,
                            sm.getString("realmBase.forbidden"));
        }

        return allowed;
    }

    /**
     * Return a List of roles associated with the given User.  Any
     * roles present in the user's directory entry are supplemented by
     * a directory search. If no roles are associated with this user,
     * a zero-length List is returned.
     * Override here to get the PKI Resource ACLs if so configured
     *
     * @param context The directory context we are searching
     * @param user The User to be checked
     *
     * @exception NamingException if a directory server error occurs
     */

    @Override
    protected List<String> getRoles(DirContext context, User user)
            throws NamingException {

        try {
            getResourceACLS(context);
        } catch (NamingException e) {
            logDebug("No aclResources found.");
        }

        return super.getRoles(context, user);
    }

    /* Custom variables, see <Realm> element */

    /* Attribute to find encoded Cert in ldap
     * "userCertificate" is most common value.
     */
    private String certAttrName;

    public String getCertAttrName() {
        return (certAttrName != null) ? certAttrName : DEF_CERT_ATTR;
    }

    public void setCertAttrName(String certAttrName) {
        this.certAttrName = certAttrName;
    }

    /* Attribute to find encoded acl resources in ldap
     * "aclResources" is most common value.
     */
    private String aclAttrName;

    public String getAclAttrName() {
        return (aclAttrName != null) ? aclAttrName : DEF_ACL_ATTR;
    }

    public void setAclAttrName(String aclAttrName) {
        this.aclAttrName = aclAttrName;
    }

    /* Attribute for base dn of acl resources in ldap
     */

    private String aclBase;

    public String getAclBase() {
        return aclBase;
    }

    public void setAclBase(String aclBase) {
        this.aclBase = aclBase;
    }

    /* Substring label to search for user id in presented client auth cert.
     *  "UID" is most common value.
     */

    private String certUIDLabel;

    public String getCertUIDLabel() {
        return certUIDLabel;
    }

    public void setCertUIDStr(String certUIDLabel) {
        this.certUIDLabel = certUIDLabel;
    }

    /* Saved user certificate object obtained during authentication
     * from the user's LDAP record.
     * Will be accessed later to compare with incoming client auth certificate.
     */
    private X509Certificate storedUserCert;

    protected void setStoredUserCert(X509Certificate cert) {
        this.storedUserCert = cert;
    }

    protected X509Certificate getStoredUserCert() {
        return storedUserCert;
    }

    // Check a PKI  ACL resourceID and operation for permissions
    // If the check fails the user (principal) is not authorized to access the resource
    private boolean checkACLPermission(Principal principal, String resourceId, String operation) {

        boolean allowed = true;

        if (!hasAuthzProperties() || !hasResourceACLS()) {
            //We arent' configured for this sort of authz
            return allowed;
        }

        if (principal == null || resourceId == null || operation == null) {
            return allowed;
        }

        ACL acl = acls.get(resourceId);

        if (acl == null) {
            //No such acl, assume true
            return allowed;
        }

        Enumeration<ACLEntry> aclEntries = acl.entries();
        while (aclEntries != null && aclEntries.hasMoreElements()) {
            ACLEntry entry = aclEntries.nextElement();
            boolean isEntryNegative = entry.isNegative();

            String expressions = entry.getAttributeExpressions();

            allowed = evaluateExpressions(principal, expressions);

            if (isEntryNegative) {
                allowed = !allowed;
            }

            // Our current ACLs require that every entry passes for
            // the entire ACL to pass.
            // For some reason the original code allows the negative acls (deny)
            // to be evaluated first or second based on configuration. Here, simply
            // traverse the list as is.

            if (!allowed) {
                break;
            }
        }

        return allowed;
    }

    // Evaluate an expression as part of a PKI ACL
    // Ex: user=anybody , group=Data Recovery Manager Agents
    private boolean evaluateExpression(Principal principal, String expression) {

        boolean allowed = true;
        if (principal == null || expression == null) {
            return allowed;
        }

        String operation = getExpressionOperation(expression);

        if (operation == null) {
            return allowed;
        }

        String[] expBlock = expression.split(operation);

        if (expBlock.length != 2) {
            return allowed;
        }

        String left = expBlock[0];
        String right = expBlock[1];

        if (left != null) {
            left.trim();
        } else {
            return allowed;
        }
        //Massage the right hand side of this expression to be a legal string value.
        if (right != null) {
            right.trim();
            right = right.replace("\"", "");
            right = right.trim();
        } else {
            return allowed;
        }

        boolean negate = false;

        //Otherwise assume "="
        if (operation.equals("!=")) {
            negate = true;
        }

        allowed = false;
        if (left.equals(PROP_GROUP)) {
            // Check JNDI to see if the user has this role/group
            if (hasRole(principal, right)) {
                allowed = true;
            }
        } else if (left.equals(PROP_USER)) {
            if (right.equals(PROP_USER_ANYBODY) || right.equals(PROP_USER_EVERYBODY)) {
                allowed = true;
            }
        } else {
            logDebug("Unknown expression.");
        }

        if (negate) {
            allowed = !allowed;
        }

        return allowed;
    }

    // Convenience method to find the operation in an ACL expression
    private String getExpressionOperation(String exp) {
        //Support only = and !=

        int i = exp.indexOf("!=");

        if (i == -1) {
            i = exp.indexOf("=");
            if (i == -1) {
                return null;
            } else {
                return "=";
            }
        } else {
            return "!=";
        }
    }

    // Take a set of expressions in an ACL and evaluate it
    private boolean evaluateExpressions(Principal principal, String s) {

        Vector<Object> v = new Vector<Object>();

        while (s.length() > 0) {
            int orIndex = s.indexOf("||");
            int andIndex = s.indexOf("&&");

            // this is the last expression
            if (orIndex == -1 && andIndex == -1) {
                boolean passed = evaluateExpression(principal, s.trim());

                v.addElement(Boolean.valueOf(passed));
                break;

                // || first
            } else if (andIndex == -1 || (orIndex != -1 && orIndex < andIndex)) {
                String s1 = s.substring(0, orIndex);
                boolean passed = evaluateExpression(principal, s1.trim());

                v.addElement(Boolean.valueOf(passed));
                v.addElement("||");
                s = s.substring(orIndex + 2);
                // && first
            } else {
                String s1 = s.substring(0, andIndex);
                boolean passed = evaluateExpression(principal, s1.trim());

                v.addElement(Boolean.valueOf(passed));
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

            if (op.equals("||")) {
                if (left == false && right == false)
                    left = false;
                left = true;
            } else if (op.equals("&&")) {
                if (left == true && right == true)
                    left = true;
                left = false;
            }
        }

        return left;

    }

    /* Attempt to get the stored user certificate object and save it for
     * future reference. This all takes place within one command invocation from
     * the getPrincipal method defined here.
     */
    private void extractAndSaveStoredX509UserCert(DirContext context, User certUser)
            throws NamingException {

        setStoredUserCert(null);

        if (certUser != null && context != null) {

            String certAttrStr = this.getCertAttrName();

            // certAttrStr has a default value, can not be null
            String[] attrs = new String[] { certAttrStr };

            Attributes attributes = context.getAttributes(certUser.getDN(), attrs);

            if (attributes == null) {
                logErr("Can not get certificate attributes in extractAndSaveStoredX590UserCert.");
                return;
            }

            Attribute certAttr = null;

            certAttr = attributes.get(certAttrStr);

            if (certAttr == null) {
                logErr("Can not get certificate attribut in extractAndSaveStoredX509UserCert.");
                return;
            }

            Object oAttr = null;

            oAttr = certAttr.get();

            if (oAttr == null) {
                logErr("Can not get certificate attribute object in extractAndSaveStoredX509UserCert.");
                return;
            }

            byte[] certData = null;

            if (oAttr instanceof byte[]) {
                certData = (byte[]) oAttr;
            } else {
                logErr("Can not get certificate data in extractAndSaveStoredX509UserCert.");
                return;
            }

            ByteArrayInputStream inStream = null;
            try {
                X509Certificate x509Cert = null;
                if (certData != null) {
                    inStream = new ByteArrayInputStream(certData);
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");

                    if (cf != null) {
                        x509Cert = (X509Certificate) cf.generateCertificate(inStream);
                    }

                    setStoredUserCert(x509Cert);
                }
            } catch (Exception e) {
                logErr("Certificate encoding error in extractAndSaveStoredX509UserCert: " + e);
            } finally {
                if (inStream != null) {
                    try {
                        inStream.close();
                    } catch (IOException e) {
                        logErr("Can't close ByteArrayStream in extractAndSaveStoredX509UserCert: " + e);
                    }
                }
            }
        }
    }

    // Search for the proper auth.properties entry corresponding
    // to a particular incoming URL
    // ToDo: In the admin interface, often the operation is sent
    // as one of the parameters to the message.
    // There may be a way to extract this information at this level.
    // The parameter name to scan for could be configured with the Realm.

    private String getACLEntryDataForURL(String requestURI) {
        String aclEntryData;

        if (!hasAuthzProperties()) {
            return null;
        }

        aclEntryData = authzProperties.getProperty(requestURI);

        if (aclEntryData == null) {
            //Check for a partial match such as
            // ex: /kra/pki/keyrequest/2
            // ToDo: Check into more sophisticated
            // methods of doing this mapping.
            // Perhaps Rest gives us this more
            // sophisticated mapping ability.

            Properties props = authzProperties;
            Enumeration<?> e = props.propertyNames();

            while (e.hasMoreElements()) {
                String key = (String) e.nextElement();
                if (requestURI.startsWith(key)) {
                    aclEntryData = props.getProperty(key);
                    break;
                }
            }
        }

        return aclEntryData;

    }

    //Go to the directory server, if configured, and go get the Resource ACLs
    private synchronized void getResourceACLS(DirContext context) throws NamingException {

        //for now lets support this on startup
        if (hasResourceACLS()) {
            return;
        }

        String filter = "(" + aclAttrName + "=*)";

        SearchControls constraints = new SearchControls();

        constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);

        constraints.setReturningAttributes(null);

        NamingEnumeration<SearchResult> results =
                context.search(aclBase, filter, constraints);

        try {
            if (results == null || !results.hasMore()) {
                return;
            }
        } catch (PartialResultException ex) {
            throw ex;
        }

        SearchResult result = null;
        try {
            result = results.next();
            if (result != null) {

                Attributes attrs = result.getAttributes();
                if (attrs == null)
                    return;

                Vector<String> aclVec = getAttributeValues(aclAttrName, attrs);

                if (aclVec != null) {

                    Enumeration<String> vEnum = aclVec.elements();

                    while (vEnum.hasMoreElements())
                    {
                        String curAcl = vEnum.nextElement();
                        ACL acl = parseACL(curAcl);
                        if (acl != null) {
                            acls.put(acl.getName(), acl);
                        }
                    }
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

    }

    // Check to see if we have obtained the PKI ACLs from the ldap server
    private boolean hasResourceACLS() {

        if (acls != null && acls.size() > 0) {
            return true;
        } else {
            return false;
        }
    }

    // Check to see if we have read in the auth properties file
    private boolean hasAuthzProperties() {

        if (this.authzProperties != null) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * Parse ACL resource attributes
     *
     * @param res same format as the resource attribute:
     *
     *            <PRE>
     *     <resource name>:<permission1,permission2,...permissionn>:
     *     <allow|deny> (<subset of the permission set>) <evaluator expression>
     * </PRE>
     * @exception EException ACL related parsing errors for res
     * @return an ACL instance built from the parsed res
     */
    private ACL parseACL(String res) throws Exception {
        if (res == null) {
            throw new Exception("Bad input to parseACL.");
        }

        ACL acl = null;
        Vector<String> rights = null;
        int idx1 = res.indexOf(":");

        if (idx1 <= 0) {
            acl = new ACL(res, rights, res);
        } else {
            // getting resource id
            String resource = res.substring(0, idx1);

            if (resource == null) {
                String infoMsg = "resource not specified in resource attribute:" +
                        res;

                String[] params = new String[2];

                params[0] = res;
                params[1] = infoMsg;
                throw new Exception(infoMsg);
            }

            // getting list of applicable rights
            String st = res.substring(idx1 + 1);
            int idx2 = st.indexOf(":");
            String rightsString = null;

            if (idx2 != -1)
                rightsString = st.substring(0, idx2);
            else {
                String infoMsg =
                        "rights not specified in resource attribute:" + res;
                String[] params = new String[2];

                params[0] = res;
                params[1] = infoMsg;
                throw new Exception(infoMsg);
            }

            if (rightsString != null) {
                rights = new Vector<String>();
                StringTokenizer rtok = new StringTokenizer(rightsString, ",");

                while (rtok.hasMoreTokens()) {
                    rights.addElement(rtok.nextToken());
                }
            }

            acl = new ACL(resource, rights, res);

            String stx = st.substring(idx2 + 1);
            int idx3 = stx.indexOf(":");
            String tr = stx.substring(0, idx3);

            // getting list of acl entries
            if (tr != null) {
                StringTokenizer atok = new StringTokenizer(tr, ";");

                while (atok.hasMoreTokens()) {
                    String acs = atok.nextToken();

                    // construct ACL entry
                    ACLEntry entry = ACLEntry.parseACLEntry(acl, acs);

                    if (entry == null) {
                        String infoMsg = "parseACLEntry() call failed";
                        String[] params = new String[2];

                        params[0] = "ACLEntry = " + acs;
                        params[1] = infoMsg;
                        throw new Exception(infoMsg);
                    }

                    entry.setACLEntryString(acs);
                    acl.addEntry(entry);
                }
            } else {
                // fine
                String infoMsg = " not specified in resource attribute:" +

                        res;

                String[] params = new String[2];

                params[0] = res;
                params[1] = infoMsg;
                throw new Exception(infoMsg);
            }

            // getting description
            String desc = stx.substring(idx3 + 1);

            acl.setDescription(desc);
        }

        return (acl);
    }

    //Load the custom mapping file auth.properties, which maps urls to acl resourceID and operation value
    //example entry: /kra/pki/config/cert/transport = certServer.kra.pki.config.cert.transport,read
    // ToDo: Look into a more sophisticated method than this simple properties file if appropriate.
    private synchronized void loadAuthzProperties(Context context) {

        if (authzProperties == null && context != null) {
            ClassLoader loader = this.getClass().getClassLoader();
            if (loader == null)
                loader = ClassLoader.getSystemClassLoader();

            InputStream inputStream = context.getServletContext().getResourceAsStream(PROP_AUTH_FILE_PATH);

            if (inputStream == null)
                return;

            Properties properties = new Properties();

            try {
                properties.load(inputStream);
            } catch (IOException e) {
                properties = null;
            } finally {

                if (properties != null) {
                    authzProperties = properties;
                }
                try {
                    inputStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }

            return;
        }
    }

    /**
     * Return a String representing the value of the specified attribute.
     * Create our own since the super class has it as private
     *
     * @param attrId Attribute name
     * @param attrs Attributes containing the required value
     *
     * @exception NamingException if a directory server error occurs
     */
    private Vector<String> getAttributeValues(String attrId, Attributes attrs)
            throws NamingException {

        if (attrId == null || attrs == null)
            return null;

        Vector<String> values = new Vector<String>();
        Attribute attr = attrs.get(attrId);
        if (attr == null)
            return (null);
        NamingEnumeration<?> value = attr.getAll();
        if (value == null)
            return (null);

        while (value.hasMore()) {
            Object obj = value.next();
            String valueString = null;
            if (obj instanceof byte[])
                valueString = new String((byte[]) obj);
            else
                valueString = obj.toString();
            values.add(valueString);
        }
        return values;
    }

   /*
    * ToDo: Figure out how to do real logging
    */
   private void logErr(String msg) {
       System.err.println(msg);
   }

   private void logDebug(String msg) {
       System.out.println(msg);
   }
}
