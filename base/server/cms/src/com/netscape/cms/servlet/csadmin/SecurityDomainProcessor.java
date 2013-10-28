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
import java.util.Enumeration;
import java.util.Locale;
import java.util.Random;
import java.util.Vector;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPSearchConstraints;
import netscape.ldap.LDAPSearchResults;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISecurityDomainSessionTable;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.UnauthorizedException;
import com.netscape.certsrv.ldap.ILdapConnFactory;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.system.DomainInfo;
import com.netscape.certsrv.system.InstallToken;
import com.netscape.certsrv.system.SecurityDomainHost;
import com.netscape.certsrv.system.SecurityDomainSubsystem;
import com.netscape.cms.servlet.processors.CAProcessor;
import com.netscape.cmsutil.xml.XMLObject;

/**
 * @author Endi S. Dewata
 */
public class SecurityDomainProcessor extends CAProcessor {

    public final static String LOGGING_SIGNED_AUDIT_SECURITY_DOMAIN_UPDATE =
            "LOGGING_SIGNED_AUDIT_SECURITY_DOMAIN_UPDATE_1";

    public final static String[] TYPES = { "CA", "KRA", "OCSP", "TKS", "RA", "TPS" };

    Random random = new Random();

    public SecurityDomainProcessor(Locale locale) throws EPropertyNotFound, EBaseException {
        super("securitydomain", locale);
    }

    public InstallToken getInstallToken(
            String user,
            String hostname,
            String subsystem) throws EBaseException {

        String groupname = ConfigurationUtils.getGroupName(user, subsystem);

        if (groupname == null) {
            String message = CMS.getLogMessage(
                    LOGGING_SIGNED_AUDIT_ROLE_ASSUME,
                    user,
                    ILogger.FAILURE,
                    "Enterprise " + subsystem + " Administrators");
            audit(message);

            throw new UnauthorizedException("Access denied.");
        }

        String message = CMS.getLogMessage(
                LOGGING_SIGNED_AUDIT_ROLE_ASSUME,
                user,
                ILogger.SUCCESS,
                groupname);
        audit(message);

        String ip = "";
        try {
            ip = InetAddress.getByName(hostname).getHostAddress();
        } catch (Exception e) {
            CMS.debug("Unable to determine IP address for "+hostname);
        }

        // assign cookie
        Long num = random.nextLong();
        String cookie = num.toString();

        String auditParams = "operation;;issue_token+token;;" + cookie + "+ip;;" + ip +
                      "+uid;;" + user + "+groupname;;" + groupname;

        ISecurityDomainSessionTable ctable = CMS.getSecurityDomainSessionTable();
        int status = ctable.addEntry(cookie, ip, user, groupname);

        if (status == ISecurityDomainSessionTable.SUCCESS) {
            message = CMS.getLogMessage(
                               LOGGING_SIGNED_AUDIT_SECURITY_DOMAIN_UPDATE,
                               user,
                               ILogger.SUCCESS,
                               auditParams);
            audit(message);

        } else {
            message = CMS.getLogMessage(
                               LOGGING_SIGNED_AUDIT_SECURITY_DOMAIN_UPDATE,
                               user,
                               ILogger.FAILURE,
                               auditParams);
            audit(message);

            throw new PKIException("Failed to update security domain.");
        }


        return new InstallToken(cookie);
    }

    public DomainInfo getDomainInfo() throws EBaseException {

        ILdapConnFactory connFactory = null;
        LDAPConnection conn = null;

        try {
            LDAPSearchConstraints cons = null;
            String[] attrs = null;

            IConfigStore cs = CMS.getConfigStore();
            String basedn = cs.getString("internaldb.basedn");
            String dn = "ou=Security Domain," + basedn;
            String filter = "objectclass=pkiSecurityGroup";

            IConfigStore ldapConfig = cs.getSubStore("internaldb");
            connFactory = CMS.getLdapBoundConnFactory();
            connFactory.init(ldapConfig);
            conn = connFactory.getConn();

            // get the security domain name
            String name = (String) conn.read(dn).getAttribute("name").getStringValues().nextElement();
            CMS.debug("SecurityDomainProcessor: name: "+name);

            DomainInfo domain = new DomainInfo();
            domain.setName(name);

            // this should return CAList, KRAList etc.
            LDAPSearchResults res = conn.search(dn, LDAPConnection.SCOPE_ONE, filter,
                    attrs, true, cons);

            while (res.hasMoreElements()) {
                dn = res.next().getDN();
                String listName = dn.substring(3, dn.indexOf(","));
                String subType = listName.substring(0, listName.indexOf("List"));
                CMS.debug("SecurityDomainProcessor: subtype: "+subType);

                filter = "objectclass=pkiSubsystem";
                LDAPSearchResults res2 = conn.search(dn, LDAPConnection.SCOPE_ONE, filter,
                        attrs, false, cons);

                while (res2.hasMoreElements()) {
                    LDAPEntry entry = res2.next();
                    CMS.debug("SecurityDomainProcessor:  - "+entry.getDN());

                    SecurityDomainHost host = new SecurityDomainHost();

                    LDAPAttributeSet entryAttrs = entry.getAttributeSet();

                    @SuppressWarnings("unchecked")
                    Enumeration<LDAPAttribute> attrsInSet = entryAttrs.getAttributes();
                    while (attrsInSet.hasMoreElements()) {
                        LDAPAttribute nextAttr = attrsInSet.nextElement();
                        String attrName = nextAttr.getName();
                        String attrValue = (String) nextAttr.getStringValues().nextElement();
                        CMS.debug("SecurityDomainProcessor:    - "+attrName+": "+attrValue);

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
            CMS.debug("SecurityDomainProcessor: Failed to read domain info from ldap " + e);
            throw new EBaseException(e.getMessage(), e);

        } finally {
            if (conn != null && connFactory != null) {
                CMS.debug("Releasing ldap connection");
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
                counter = subsystem.getHosts().length;

                for (SecurityDomainHost host : subsystem.getHosts()) {
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
