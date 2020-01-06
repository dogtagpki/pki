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
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.servlet.csadmin;

import java.io.StringWriter;
import java.net.InetAddress;
import java.security.SecureRandom;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Vector;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.ISecurityDomainSessionTable;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.base.UnauthorizedException;
import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.ConfigRoleEvent;
import com.netscape.certsrv.logging.event.RoleAssumeEvent;
import com.netscape.certsrv.system.DomainInfo;
import com.netscape.certsrv.system.InstallToken;
import com.netscape.certsrv.system.SecurityDomainHost;
import com.netscape.certsrv.system.SecurityDomainSubsystem;
import com.netscape.cms.servlet.processors.CAProcessor;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.LdapBoundConnFactory;
import com.netscape.cmscore.security.JssSubsystem;
import com.netscape.cmscore.usrgrp.UGSubsystem;
import com.netscape.cmsutil.xml.XMLObject;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPModification;
import netscape.ldap.LDAPSearchConstraints;
import netscape.ldap.LDAPSearchResults;

/**
 * @author Endi S. Dewata
 */
public class SecurityDomainProcessor extends CAProcessor {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SecurityDomainProcessor.class);

    public final static String[] TYPES = { "CA", "KRA", "OCSP", "TKS", "RA", "TPS" };
    public final static String SUCCESS = "0";
    public final static String FAILED = "1";

    SecureRandom random;

    public SecurityDomainProcessor(Locale locale) throws EPropertyNotFound, EBaseException {
        super("securitydomain", locale);
        CMSEngine engine = CMS.getCMSEngine();
        JssSubsystem jssSubsystem = engine.getJSSSubsystem();
        random = jssSubsystem.getRandomNumberGenerator();
    }

    public static String getEnterpriseGroupName(String subsystemname) {
        return "Enterprise " + subsystemname + " Administrators";
    }

    public InstallToken getInstallToken(
            String user,
            String host,
            String subsystem) throws Exception {

        subsystem = subsystem.toUpperCase();
        CMSEngine engine = CMS.getCMSEngine();
        UGSubsystem ugSubsystem = (UGSubsystem) engine.getSubsystem(UGSubsystem.ID);

        String group = getEnterpriseGroupName(subsystem);
        logger.debug("SecurityDomainProcessor: group: " + group);

        if (!ugSubsystem.isMemberOf(user, group)) {

            signedAuditLogger.log(RoleAssumeEvent.createFailureEvent(
                    user,
                    group));

            throw new UnauthorizedException("User " + user + " is not a member of " + group + " group.");
        }

        signedAuditLogger.log(RoleAssumeEvent.createSuccessEvent(
                user,
                group));

        String ip = "";
        try {
            ip = InetAddress.getByName(host).getHostAddress();
        } catch (Exception e) {
            logger.warn("Unable to determine IP address for " + host + ": " + e.getMessage(), e);
        }

        // generate random session ID
        // use positive number to avoid CLI issues
        Long num = Math.abs(random.nextLong());
        String sessionID = num.toString();

        String auditParams = "operation;;issue_token+token;;" + sessionID + "+ip;;" + ip +
                      "+uid;;" + user + "+groupname;;" + group;

        ISecurityDomainSessionTable ctable = engine.getSecurityDomainSessionTable();
        int status = ctable.addEntry(sessionID, ip, user, group);
        String message;

        if (status == ISecurityDomainSessionTable.SUCCESS) {
            message = CMS.getLogMessage(
                               AuditEvent.SECURITY_DOMAIN_UPDATE,
                               user,
                               ILogger.SUCCESS,
                               auditParams);
            signedAuditLogger.log(message);

        } else {
            message = CMS.getLogMessage(
                               AuditEvent.SECURITY_DOMAIN_UPDATE,
                               user,
                               ILogger.FAILURE,
                               auditParams);
            signedAuditLogger.log(message);

            throw new PKIException("Failed to create session.");
        }


        return new InstallToken(sessionID);
    }

    public DomainInfo getDomainInfo() throws EBaseException {

        CMSEngine engine = CMS.getCMSEngine();
        EngineConfig cs = engine.getConfig();

        LdapBoundConnFactory connFactory = null;
        LDAPConnection conn = null;

        try {
            LDAPSearchConstraints cons = null;
            String[] attrs = null;

            LDAPConfig ldapConfig = cs.getInternalDBConfig();
            String basedn = ldapConfig.getBaseDN();
            String dn = "ou=Security Domain," + basedn;
            String filter = "objectclass=pkiSecurityGroup";

            connFactory = new LdapBoundConnFactory("SecurityDomainProcessor");
            connFactory.init(cs, ldapConfig, engine.getPasswordStore());

            conn = connFactory.getConn();

            // get the security domain name
            String name = conn.read(dn).getAttribute("name").getStringValues().nextElement();
            logger.debug("SecurityDomainProcessor: name: " + name);

            DomainInfo domain = new DomainInfo();
            domain.setName(name);

            // this should return CAList, KRAList etc.
            LDAPSearchResults res = conn.search(dn, LDAPConnection.SCOPE_ONE, filter,
                    attrs, true, cons);

            while (res.hasMoreElements()) {
                dn = res.next().getDN();
                String listName = dn.substring(3, dn.indexOf(","));
                String subType = listName.substring(0, listName.indexOf("List"));
                logger.debug("SecurityDomainProcessor: subtype: " + subType);

                filter = "objectclass=pkiSubsystem";
                LDAPSearchResults res2 = conn.search(dn, LDAPConnection.SCOPE_ONE, filter,
                        attrs, false, cons);

                while (res2.hasMoreElements()) {
                    LDAPEntry entry = res2.next();
                    logger.debug("SecurityDomainProcessor:  - " + entry.getDN());

                    SecurityDomainHost host = new SecurityDomainHost();

                    LDAPAttributeSet entryAttrs = entry.getAttributeSet();

                    @SuppressWarnings("unchecked")
                    Enumeration<LDAPAttribute> attrsInSet = entryAttrs.getAttributes();
                    while (attrsInSet.hasMoreElements()) {
                        LDAPAttribute nextAttr = attrsInSet.nextElement();
                        String attrName = nextAttr.getName();
                        String attrValue = nextAttr.getStringValues().nextElement();
                        logger.debug("SecurityDomainProcessor:    - " + attrName+": " + attrValue);

                        if ("Host".equalsIgnoreCase(attrName)) {
                            host.setHostname(attrValue);

                        } else if ("UnSecurePort".equalsIgnoreCase(attrName)) {
                            host.setPort(attrValue);

                        } else if ("SecurePort".equalsIgnoreCase(attrName)) {
                            host.setSecurePort(attrValue);

                        } else if ("SecureEEClientAuthPort".equalsIgnoreCase(attrName)) {
                            host.setSecureEEClientAuthPort(attrValue);

                        } else if ("SecureAgentPort".equalsIgnoreCase(attrName)) {
                            host.setSecureAgentPort(attrValue);

                        } else if ("SecureAdminPort".equalsIgnoreCase(attrName)) {
                            host.setSecureAdminPort(attrValue);

                        } else if ("Clone".equalsIgnoreCase(attrName)) {
                            host.setClone(attrValue);

                        } else if ("SubsystemName".equalsIgnoreCase(attrName)) {
                            host.setSubsystemName(attrValue);

                        } else if ("DomainManager".equalsIgnoreCase(attrName)) {
                            host.setDomainManager(attrValue);
                        }
                    }

                    String port = host.getSecurePort();
                    if (port == null) port = host.getSecureEEClientAuthPort();
                    host.setId(subType+" "+host.getHostname()+" "+port);

                    domain.addHost(subType, host);
                }
            }

            return domain;

        } catch (Exception e) {
            logger.error("SecurityDomainProcessor: Failed to read domain info from ldap " + e.getMessage(), e);
            throw new EBaseException(e.getMessage(), e);

        } finally {
            if (conn != null && connFactory != null) {
                logger.debug("Releasing ldap connection");
                connFactory.returnConn(conn);
            }
        }
    }

    public XMLObject getDomainXML() throws EBaseException, ParserConfigurationException {
        return convertDomainInfoToXMLObject(getDomainInfo());
    }

    public static XMLObject convertDomainInfoToXMLObject(DomainInfo domain) throws ParserConfigurationException {

        XMLObject xmlObject = new XMLObject();

        Node domainInfo = xmlObject.createRoot("DomainInfo");
        xmlObject.addItemToContainer(domainInfo, "Name", domain.getName());

        for (String subType : TYPES) {
            SecurityDomainSubsystem subsystem = domain.getSubsystem(subType);
            Node listNode = xmlObject.createContainer(domainInfo, subType+"List");

            int counter;
            if (subsystem == null) {
                counter = 0;

            } else {
                counter = subsystem.getHostArray().length;

                for (SecurityDomainHost host : subsystem.getHostArray()) {
                    Node node = xmlObject.createContainer(listNode, subType);

                    String value = host.getHostname();
                    if (value != null) xmlObject.addItemToContainer(node, "Host", value);

                    value = host.getPort();
                    if (value != null) xmlObject.addItemToContainer(node, "UnSecurePort", value);

                    value = host.getSecurePort();
                    if (value != null) xmlObject.addItemToContainer(node, "SecurePort", value);

                    value = host.getSecureEEClientAuthPort();
                    if (value != null) xmlObject.addItemToContainer(node, "SecureEEClientAuthPort", value);

                    value = host.getSecureAgentPort();
                    if (value != null) xmlObject.addItemToContainer(node, "SecureAgentPort", value);

                    value = host.getSecureAdminPort();
                    if (value != null) xmlObject.addItemToContainer(node, "SecureAdminPort", value);

                    value = host.getClone();
                    if (value != null) xmlObject.addItemToContainer(node, "Clone", value);

                    value = host.getSubsystemName();
                    if (value != null) xmlObject.addItemToContainer(node, "SubsystemName", value);

                    value = host.getDomainManager();
                    if (value != null) xmlObject.addItemToContainer(node, "DomainManager", value);
                }
            }

            xmlObject.addItemToContainer(
                    listNode, "SubsystemCount", Integer.toString(counter));
        }

        return xmlObject;
    }

    public static DomainInfo convertXMLObjectToDomainInfo(XMLObject xmlObject) {

        DomainInfo domain = new DomainInfo();
        Document doc = xmlObject.getDocument();
        Node rootNode = doc.getFirstChild();

        Vector<String> values = xmlObject.getValuesFromContainer(rootNode, "Name");
        if (!values.isEmpty()) domain.setName(values.firstElement());

        for (String type : TYPES) {
            NodeList hosts = doc.getElementsByTagName(type);
            for (int j=0; j<hosts.getLength(); j++) {
                Node hostNode = hosts.item(j);
                SecurityDomainHost host = new SecurityDomainHost();

                values = xmlObject.getValuesFromContainer(hostNode, "Host");
                if (!values.isEmpty()) host.setHostname(values.firstElement());

                values = xmlObject.getValuesFromContainer(hostNode, "UnSecurePort");
                if (!values.isEmpty()) host.setPort(values.firstElement());

                values = xmlObject.getValuesFromContainer(hostNode, "SecurePort");
                if (!values.isEmpty()) host.setSecurePort(values.firstElement());

                values = xmlObject.getValuesFromContainer(hostNode, "SecureEEClientAuthPort");
                if (!values.isEmpty()) host.setSecureEEClientAuthPort(values.firstElement());

                values = xmlObject.getValuesFromContainer(hostNode, "SecureAgentPort");
                if (!values.isEmpty()) host.setSecureAgentPort(values.firstElement());

                values = xmlObject.getValuesFromContainer(hostNode, "SecureAdminPort");
                if (!values.isEmpty()) host.setSecureAdminPort(values.firstElement());

                values = xmlObject.getValuesFromContainer(hostNode, "Clone");
                if (!values.isEmpty()) host.setClone(values.firstElement());

                values = xmlObject.getValuesFromContainer(hostNode, "SubsystemName");
                if (!values.isEmpty()) host.setSubsystemName(values.firstElement());

                values = xmlObject.getValuesFromContainer(hostNode, "DomainManager");
                if (!values.isEmpty()) host.setDomainManager(values.firstElement());

                String port = host.getSecurePort();
                if (port == null) port = host.getSecureEEClientAuthPort();
                host.setId(type+" "+host.getHostname()+" "+port);

                domain.addHost(type, host);
            }
        }

        return domain;
    }

    public String removeHost(
            String dn,
            String type,
            String hostname,
            String securePort,
            String agentSecurePort)
            throws EBaseException {

        logger.info("SecurityDomainProcessor: Removing host " + dn);

        String auditSubjectID = auditSubjectID();

        CMSEngine engine = CMS.getCMSEngine();
        EngineConfig cs = engine.getConfig();
        LDAPConfig ldapConfig = cs.getInternalDBConfig();
        String baseDN = ldapConfig.getBaseDN();

        String status = removeEntry(dn);

        if (!status.equals(SUCCESS)) {
            return status;
        }

        String adminUserDN;
        if (agentSecurePort != null && !agentSecurePort.equals("")) {
            adminUserDN = "uid=" + type + "-" + hostname + "-" + agentSecurePort + ",ou=People," + baseDN;
        } else {
            adminUserDN = "uid=" + type + "-" + hostname + "-" + securePort + ",ou=People," + baseDN;
        }

        logger.info("SecurityDomainProcessor: Removing admin " + adminUserDN);

        String userAuditParams = "Scope;;users+Operation;;OP_DELETE+source;;SecurityDomainProcessor" +
                                     "+resource;;" + adminUserDN;

        status = removeEntry(adminUserDN);

        if (!status.equals(SUCCESS)) {
            signedAuditLogger.log(new ConfigRoleEvent(
                    auditSubjectID,
                    ILogger.FAILURE,
                    userAuditParams));
            return status;
        }

        signedAuditLogger.log(new ConfigRoleEvent(
                               auditSubjectID,
                               ILogger.SUCCESS,
                               userAuditParams));

        dn = "cn=Subsystem Group, ou=groups," + baseDN;

        logger.info("SecurityDomainProcessor: Removing admin from group " + dn);

        userAuditParams = "Scope;;groups+Operation;;OP_DELETE_USER" +
                              "+source;;SecurityDomainProcessor" +
                              "+resource;;Subsystem Group+user;;" + adminUserDN;

        LDAPModification mod = new LDAPModification(
                LDAPModification.DELETE,
                new LDAPAttribute("uniqueMember", adminUserDN));

        status = modifyEntry(dn, mod);

        if (!status.equals(SUCCESS)) {
            signedAuditLogger.log(new ConfigRoleEvent(
                                   auditSubjectID,
                                   ILogger.FAILURE,
                                   userAuditParams));
            return status;
        }

        signedAuditLogger.log(new ConfigRoleEvent(
                auditSubjectID,
                ILogger.SUCCESS,
                userAuditParams));

        return SUCCESS;
    }

    public String addEntry(LDAPEntry entry) {

        logger.info("SecurityDomainProcessor: Adding entry " + entry.getDN());

        String status = SUCCESS;
        LdapBoundConnFactory connFactory = null;
        LDAPConnection conn = null;

        CMSEngine engine = CMS.getCMSEngine();
        EngineConfig cs = engine.getConfig();

        try {
            LDAPConfig ldapConfig = cs.getInternalDBConfig();
            connFactory = new LdapBoundConnFactory("UpdateDomainXML");
            connFactory.init(cs, ldapConfig, engine.getPasswordStore());

            conn = connFactory.getConn();
            conn.add(entry);

        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.ENTRY_ALREADY_EXISTS) {
                logger.warn("SecurityDomainProcessor: Entry already exists");
                try {
                    conn.delete(entry.getDN());
                    conn.add(entry);

                } catch (LDAPException ee) {
                    logger.error("SecurityDomainProcessor: Unable to replace entry: " + e.getMessage(), e);
                    status = FAILED;
                }

            } else {
                logger.error("SecurityDomainProcessor: Unable to add entry: " + e.getMessage(), e);
                status = FAILED;
            }

        } catch (Exception e) {
            logger.warn("SecurityDomainProcessor: Unable to add entry: " + e.getMessage(), e);

        } finally {
            try {
                if (conn != null && connFactory != null) {
                    logger.debug("SecurityDomainProcessor: Releasing LDAP connection");
                    connFactory.returnConn(conn);
                }

            } catch (Exception e) {
                logger.warn("SecurityDomainProcessor: Unable to release LDAP connection: " + e.getMessage(), e);
            }
        }

        return status;
    }

    public String modifyEntry(String dn, LDAPModification mod) {

        logger.info("SecurityDomainProcessor: Modifying entry " + dn);

        String status = SUCCESS;
        LdapBoundConnFactory connFactory = null;
        LDAPConnection conn = null;

        CMSEngine engine = CMS.getCMSEngine();
        EngineConfig cs = engine.getConfig();

        try {
            LDAPConfig ldapConfig = cs.getInternalDBConfig();
            connFactory = new LdapBoundConnFactory("UpdateDomainXML");
            connFactory.init(cs, ldapConfig, engine.getPasswordStore());

            conn = connFactory.getConn();
            conn.modify(dn, mod);

        } catch (LDAPException e) {
            int resultCode = e.getLDAPResultCode();
            if (resultCode != LDAPException.NO_SUCH_OBJECT && resultCode != LDAPException.NO_SUCH_ATTRIBUTE) {
                logger.error("SecurityDomainProcessor: Unable to modify entry: " + e.getMessage(), e);
                status = FAILED;
            }

        } catch (Exception e) {
            logger.warn("SecurityDomainProcessor: Unable to modify entry: " + e.getMessage(), e);

        } finally {
            try {
                if (conn != null && connFactory != null) {
                    logger.debug("SecurityDomainProcessor: Releasing LDAP connection");
                    connFactory.returnConn(conn);
                }

            } catch (Exception e) {
                logger.warn("SecurityDomainProcessor: Unable to release LDAP connection: " + e.getMessage(), e);
            }
        }

        return status;
    }

    public String removeEntry(String dn) {

        logger.info("SecurityDomainProcessor: Removing entry " + dn);

        String status = SUCCESS;
        LdapBoundConnFactory connFactory = null;
        LDAPConnection conn = null;

        CMSEngine engine = CMS.getCMSEngine();
        EngineConfig cs = engine.getConfig();

        try {
            LDAPConfig ldapConfig = cs.getInternalDBConfig();
            connFactory = new LdapBoundConnFactory("UpdateDomainXML");
            connFactory.init(cs, ldapConfig, engine.getPasswordStore());

            conn = connFactory.getConn();
            conn.delete(dn);

        } catch (LDAPException e) {
            int resultCode = e.getLDAPResultCode();
            if (resultCode != LDAPException.NO_SUCH_OBJECT) {
                status = FAILED;
                logger.error("SecurityDomainProcessor: Unable to delete entry: " + e.getMessage(), e);
            }

        } catch (Exception e) {
            logger.warn("SecurityDomainProcessor: Unable to delete entry: " + e.getMessage(), e);

        } finally {
            try {
                if (conn != null && connFactory != null) {
                    logger.debug("SecurityDomainProcessor: Releasing LDAP connection");
                    connFactory.returnConn(conn);
                }

            } catch (Exception e) {
                logger.warn("SecurityDomainProcessor: Unable to release LDAP connection: " + e.getMessage(), e);
            }
        }

        return status;
    }

    protected String auditSubjectID() {

        SessionContext auditContext = SessionContext.getExistingContext();

        if (auditContext == null) {
            return ILogger.UNIDENTIFIED;
        }

        String subjectID = (String) auditContext.get(SessionContext.USER_ID);

        if (subjectID == null) {
            return ILogger.NONROLEUSER;
        }

        return subjectID.trim();
    }

    public static void main(String args[]) throws Exception {

        DomainInfo before = new DomainInfo();
        before.setName("EXAMPLE");

        SecurityDomainHost host = new SecurityDomainHost();
        host.setId("CA localhost 8443");
        host.setHostname("localhost");
        host.setPort("8080");
        host.setSecurePort("8443");
        host.setDomainManager("TRUE");

        before.addHost("CA", host);

        System.out.println("Before:");
        System.out.println(before);

        XMLObject xmlObject = convertDomainInfoToXMLObject(before);
        Document document = xmlObject.getDocument();

        Transformer transformer = TransformerFactory.newInstance().newTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");

        StringWriter sw = new StringWriter();
        transformer.transform(new DOMSource(document), new StreamResult(sw));

        System.out.println("Domain XML:");
        System.out.println(sw);

        DomainInfo after = convertXMLObjectToDomainInfo(xmlObject);

        System.out.println("After:");
        System.out.println(after);
    }
}
