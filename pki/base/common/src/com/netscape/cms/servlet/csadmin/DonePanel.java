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
package com.netscape.cms.servlet.csadmin;


import org.apache.velocity.Template;
import org.apache.velocity.servlet.VelocityServlet;
import org.apache.velocity.app.Velocity;
import org.apache.velocity.context.Context;
import javax.servlet.*;
import javax.servlet.http.*;
import com.netscape.cmsutil.xml.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.usrgrp.*;
import com.netscape.certsrv.property.*;
import com.netscape.certsrv.authority.*;
import com.netscape.certsrv.dbs.crldb.*;
import com.netscape.certsrv.ocsp.*;
import com.netscape.certsrv.logging.*;
import com.netscape.cmsutil.util.Cert;
import netscape.security.x509.*;
import netscape.ldap.*;
import java.net.*;
import java.io.*;
import java.math.*;
import java.security.cert.*;
import org.w3c.dom.*;

import com.netscape.cms.servlet.wizard.*;

public class DonePanel extends WizardPanelBase {

    public static final BigInteger BIG_ZERO = new BigInteger("0");
    public static final Long MINUS_ONE = Long.valueOf(-1);

    public DonePanel() {}

    /**
     * Initializes this panel.
     */
    public void init(ServletConfig config, int panelno) 
        throws ServletException {
        setPanelNo(panelno);
        setName("Done");
    }

    public void init(WizardServlet servlet, ServletConfig config, int panelno, String id)
        throws ServletException {
        setPanelNo(panelno);
        setName("Done");
        setId(id);
    }

    public boolean hasSubPanel() {
        return false;
    }

    public void cleanUp() throws IOException {
    }

    public PropertySet getUsage() {
        PropertySet set = new PropertySet();
                                                                                
        /* XXX */
                                                                                
        return set;
    }

    /**
     * Display the panel.
     */
    public void display(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        CMS.debug("DonePanel: display()");

        // update session id 
        String session_id = request.getParameter("session_id");
        if (session_id != null) {
            CMS.debug("NamePanel setting session id.");
            CMS.setConfigSDSessionId(session_id);
        }

        IConfigStore cs = CMS.getConfigStore();
        String ownsport = CMS.getEESSLPort();
        String ownhost = CMS.getEESSLHost();
        String select = "";

        String type = "";
        String instanceId = "";
        try {
            type = cs.getString("cs.type", "");
            instanceId = cs.getString("instanceId");
            select = cs.getString("preop.subsystem.select", "");
        } catch (Exception e) {}

        context.put("instanceId", instanceId);
        context.put("title", "Done");
        context.put("panel", "admin/console/config/donepanel.vm");
        context.put("host", ownhost);
        context.put("port", ownsport);
        String subsystemType = toLowerCaseSubsystemType(type);
        context.put("systemType", subsystemType);

        try {
            int state = cs.getInteger("cs.state");
            if (state == 1) {
                context.put("csstate", "1");
                return;
            } else
                context.put("csstate", "0");
       
        } catch (Exception e) {
        }

        String sd_port = "";
        String sd_host = "";
        String ca_host = "";
        try {
            sd_host = cs.getString("preop.securitydomain.host", "");
            sd_port = cs.getString("preop.securitydomain.httpsport", "");
            ca_host = cs.getString("preop.ca.hostname", "");
        } catch (Exception e) {
        }

        if (ca_host.equals(""))
            context.put("externalCA", "true");
        else
            context.put("externalCA", "false");

        // update security domain
        String sdtype = "";
        String instanceName = "";
        String subsystemName = "";
        try {
            sdtype = cs.getString("preop.securitydomain.select", "");
            instanceName = cs.getString("instanceId", "");
            subsystemName = cs.getString("preop.subsystem.name", "");
        } catch (Exception e) {
        }

        String s = getSubsystemNodeName(type);
        if (sdtype.equals("new")) {
            try {
                String instanceRoot = cs.getString("instanceRoot", "");
                String domainxml = instanceRoot+"/conf/domain.xml";
                XMLObject obj = new XMLObject(new FileInputStream(domainxml));
                Node n = obj.getContainer(s);
                NodeList nlist = n.getChildNodes();
                String countS = "";
                Node countnode = null;
                for (int i=0; i<nlist.getLength(); i++) {
                    Element nn = (Element)nlist.item(i);
                    String tagname = nn.getTagName();
                    if (tagname.equals("SubsystemCount")) {
                        countnode = nn;
                        NodeList nlist1 = nn.getChildNodes();
                        Node nn1 = nlist1.item(0);
                        countS = nn1.getNodeValue();
                        break;
                    }
                }
                Node parent = obj.createContainer(n, type);
                obj.addItemToContainer(parent, "SubsystemName", subsystemName);
                obj.addItemToContainer(parent, "Host", sd_host);
                obj.addItemToContainer(parent, "SecurePort", sd_port);
                obj.addItemToContainer(parent, "DomainManager", "true");
                obj.addItemToContainer(parent, "Clone", "false");
        
                CMS.debug("DonePanel display: SubsystemCount="+countS);
                int count = 0;
                try {
                    count = Integer.parseInt(countS);
                    count++;
                } catch (Exception ee) {
                }

                Node nn2 = n.removeChild(countnode);
                obj.addItemToContainer(n, "SubsystemCount", ""+count); 
                CMS.debug("DonePanel display: finish updating domain.xml");
                byte[] b = obj.toByteArray();
                FileOutputStream fos = new FileOutputStream(domainxml);
                fos.write(b); 
                fos.close();
            } catch (Exception e) {
                CMS.debug("DonePanel display: "+e.toString());
            }
        } else { //existing domain
            int p = -1;
            try {
                p = Integer.parseInt(sd_port);
            } catch (Exception e) {
            }

            try {
                String cloneStr = "";
                if (select.equals("clone"))
                    cloneStr = "&clone=true";
                else
                    cloneStr = "&clone=false";
                updateDomainXML(sd_host, p, true, "/ca/agent/ca/updateDomainXML", 
                  "list="+s+"&type="+type+"&host="+ownhost+"&name="+subsystemName+"&sport="+ownsport+"&dm=false"+cloneStr);
            } catch (Exception e) {
                context.put("errorString", "Failed to update the domain.xml.");
                return;
            }
        }

        // need to push connector information to the CA
        if (type.equals("KRA") && !ca_host.equals("")) {
            try {
                updateConnectorInfo(ownhost, ownsport, sd_host, sd_port);
            } catch (IOException e) {
                context.put("errorString", "Failed to update connector information.");
                return;
            }

            // retrieve CA subsystem certificate from the CA
            IUGSubsystem system = 
              (IUGSubsystem) (CMS.getSubsystem(IUGSubsystem.ID));
            String id = "";
            try {
                String b64 = getCASubsystemCert();
                if (b64 != null) { 
                    int num = cs.getInteger("preop.subsystem.count", 0);
                    id = getCAUserId();
                    num++;
                    cs.putInteger("preop.subsystem.count", num);
                    cs.putInteger("subsystem.count", num);
                    IUser user = system.createUser(id);
                    user.setFullName(id);
                    user.setEmail("");
                    user.setPassword("");
                    user.setUserType("agentType");
                    user.setState("1");
                    user.setPhone("");
                    X509CertImpl[] certs = new X509CertImpl[1];
                    certs[0] = new X509CertImpl(CMS.AtoB(b64));
                    user.setX509Certificates(certs);
                    system.addUser(user);
                    CMS.debug("DonePanel display: successfully add the user");
                    system.addUserCert(user);
                    CMS.debug("DonePanel display: successfully add the user certificate");
                    cs.commit(false);
                }
            } catch (Exception e) {
            }

            try {
                String groupName = "Trusted Managers";
                IGroup group = system.getGroupFromName(groupName);
                if (!group.isMember(id)) {
                    group.addMemberName(id);
                    system.modifyGroup(group);
                    CMS.debug("DonePanel display: successfully added the user to the group.");
                }
            } catch (Exception e) {
            }
        } // if KRA

        // import the CA certificate into the OCSP
        // configure the CRL Publishing to OCSP in CA
        if (type.equals("OCSP") && !ca_host.equals("")) {
            try {
                CMS.reinit(IOCSPAuthority.ID);
                importCACertToOCSP();
            } catch (Exception e) {
                CMS.debug("DonePanel display: Failed to import the CA certificate into OCSP.");
            }

            try {
                updateOCSPConfig(response);
            } catch (Exception e) {
                CMS.debug("DonePanel display: Failed to update OCSP information in CA.");
            }
        }
        
        if (!select.equals("clone")) {
            if (type.equals("CA") || type.equals("KRA")) {
                String beginRequestNumStr = "";
                String endRequestNumStr = "";
                String beginSerialNumStr = "";
                String endSerialNumStr = "";
                String requestIncStr = "";
                String serialIncStr = "";
              
                try {
                    endRequestNumStr = cs.getString("dbs.endRequestNumber", "");
                    endSerialNumStr = cs.getString("dbs.endSerialNumber", "");
                    BigInteger endRequestNum = new BigInteger(endRequestNumStr);
                    BigInteger endSerialNum = new BigInteger(endSerialNumStr);
                    BigInteger oneNum = new BigInteger("1");
                    cs.putString("dbs.nextBeginRequestNumber", 
                      endRequestNum.add(oneNum).toString());
                    cs.putString("dbs.nextBeginSerialNumber", 
                      endSerialNum.add(oneNum).toString());
                } catch (Exception e) {
                }
            }
        }

        cs.putInteger("cs.state", 1);
        cs.removeSubStore("preop");
        try {
            cs.commit(false);
        } catch (Exception e) {
        }

        context.put("csstate", "1");
    }

    private void updateOCSPConfig(HttpServletResponse response) 
      throws IOException {
        IConfigStore config = CMS.getConfigStore();
        String cahost = "";
        int caport = -1;
        String sdhost = "";
        int sdport = -1;

        try {
            cahost = config.getString("preop.ca.hostname", "");
            caport = config.getInteger("preop.ca.httpsport", -1);
            sdhost = config.getString("preop.securitydomain.host", "");
            sdport = config.getInteger("preop.securitydomain.httpsport", -1);
        } catch (Exception e) {
        }

        String ocsphost = CMS.getEESSLHost();
        int ocspport = Integer.parseInt(CMS.getEESSLPort());
        String session_id = CMS.getConfigSDSessionId();
        String content = "xmlOutput=true&sessionID="+session_id+"&ocsp_host="+ocsphost+"&ocsp_port="+ocspport;

        updateOCSPConfig(cahost, caport, true, content, response);
    }

    private void importCACertToOCSP() throws IOException {
        IConfigStore config = CMS.getConfigStore();

        // get certificate chain from CA
        try {
            String b64 = config.getString("preop.ca.pkcs7", "");

            if (b64.equals(""))
                throw new IOException("Failed to get certificate chain.");
  
            try {
                // this could be a chain
                X509Certificate[] certs = Cert.mapCertFromPKCS7(b64);
                X509Certificate leafCert = null;
                if (certs != null && certs.length > 0) {
                    if (certs[0].getSubjectDN().getName().equals(certs[0].getIssuerDN().getName())) {
                        leafCert = certs[certs.length - 1];
                    } else {
                        leafCert = certs[0];
                    }
 
                    IOCSPAuthority ocsp = 
                      (IOCSPAuthority)CMS.getSubsystem(IOCSPAuthority.ID);
                    IDefStore defStore = ocsp.getDefaultStore();

                    // (1) need to normalize (sort) the chain

                    // (2) store certificate (and certificate chain) into
                    // database
                    ICRLIssuingPointRecord rec = defStore.createCRLIssuingPointRecord(
                      leafCert.getSubjectDN().getName(),
                      BIG_ZERO,
                      MINUS_ONE, null, null);

                    try {
                        rec.set(ICRLIssuingPointRecord.ATTR_CA_CERT, leafCert.getEncoded());
                    } catch (Exception e) {
                        // error
                    }
                    defStore.addCRLIssuingPoint(leafCert.getSubjectDN().getName(), rec);
                    //log(ILogger.EV_AUDIT, AuditFormat.LEVEL, "Added CA certificate " + leafCert.getSubjectDN().getName());

                    CMS.debug("DonePanel importCACertToOCSP: Added CA certificate.");
                }
            } catch (Exception e) {
                throw new IOException("Failed to encode the certificate chain");
            }
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            CMS.debug("DonePanel importCACertToOCSP: Failed to import the certificate chain into the OCSP");
            throw new IOException("Failed to import the certificate chain into the OCSP");
        }
    }

    private String getCASubsystemCert() throws IOException {
        IConfigStore cs = CMS.getConfigStore();
        String host = "";
        int port = -1;
        try {
            host = cs.getString("preop.ca.hostname", "");
            port = cs.getInteger("preop.ca.httpsport", -1);
        } catch (Exception e) {
        }

        return getSubsystemCert(host, port, true);
    }

    private String getCAUserId() throws IOException {
        IConfigStore cs = CMS.getConfigStore();
        String host = "";
        int port = -1;
        try {
            host = cs.getString("preop.ca.hostname", "");
            port = cs.getInteger("preop.ca.httpsport", -1);
        } catch (Exception e) {
        }

        return "CA-" + host + "-" + port;
    }

    private void updateConnectorInfo(String ownhost, String ownsport, 
      String sd_host, String sd_port)
      throws IOException {
        IConfigStore cs = CMS.getConfigStore();
        int port = -1;
        URL urlx = null;
        String url = "";
        String host = null;
        String transportCert = "";
        try {
            url = cs.getString("preop.ca.url", "");
            if (!url.equals("")) {
              urlx = new URL(url);
              host = urlx.getHost();
              port = urlx.getPort();
              transportCert = cs.getString("kra.transport.cert", "");
            }
        } catch (Exception e) {
        }

        if (host == null) {
          CMS.debug("DonePanel: preop.ca.url is not defined. External CA selected. No transport certificate setup is required");
        } else {
          CMS.debug("DonePanel: Transport certificate is being setup in " + url);
          String session_id = CMS.getConfigSDSessionId();
          String content = "ca.connector.KRA.enable=true&ca.connector.KRA.local=false&ca.connector.KRA.timeout=30&ca.connector.KRA.uri=/kra/agent/kra/connector&ca.connector.KRA.host="+ownhost+"&ca.connector.KRA.port="+ownsport+"&ca.connector.KRA.transportCert="+URLEncoder.encode(transportCert)+"&sessionID="+session_id; 

          updateConnectorInfo(host, port, true, content);
        }
    }

    private String getSubsystemNodeName(String type) {
        if (type.equals("CA")) {
            return "CAList";
        } else if (type.equals("KRA")) {
            return "KRAList";
        } else if (type.equals("TKS")) {
            return "TKSList";
        } else if (type.equals("OCSP")) {
            return "OCSPList";
        }

        return "";
    }

    /**
     * Checks if the given parameters are valid.
     */
    public void validate(HttpServletRequest request,
            HttpServletResponse response,
            Context context) throws IOException {
    }

    /**
     * Commit parameter changes
     */
    public void update(HttpServletRequest request,
            HttpServletResponse response,
            Context context) throws IOException {}

    /**
     * If validiate() returns false, this method will be called.
     */
    public void displayError(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {/* This should never be called */}
}
