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

import java.util.*;
import java.io.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.util.*;
import com.netscape.certsrv.property.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.dbs.certdb.*;

import com.netscape.cmsutil.crypto.*;
import com.netscape.certsrv.profile.*;
import com.netscape.certsrv.ca.*;
import com.netscape.certsrv.base.*;
import java.net.*;
import java.security.*;
import org.mozilla.jss.*;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.crypto.KeyPairGenerator;

import netscape.security.x509.*;

import com.netscape.cms.servlet.wizard.*;

public class NamePanel extends WizardPanelBase {
    private Vector mCerts = null;
    private WizardServlet mServlet = null;

    public NamePanel() {}

    /**
     * Initializes this panel.
     */
    public void init(ServletConfig config, int panelno) 
        throws ServletException {
        setPanelNo(panelno);
        setName("Subject Names");
    }

    public void init(WizardServlet servlet, ServletConfig config, int panelno, String id)
        throws ServletException {
        setPanelNo(panelno);
        setName("Subject Names");
        setId(id);
        mServlet = servlet;
    }

    /**
     * Returns the usage.XXX usage needs to be made dynamic
     */
    public PropertySet getUsage() {
        PropertySet set = new PropertySet();

        Descriptor caDN = new Descriptor(IDescriptor.STRING, null, /* no constraint */
                null, /* no default parameter */ 
                "CA Signing Certificate's DN");

        set.add("caDN", caDN);

        Descriptor sslDN = new Descriptor(IDescriptor.STRING, null, /* no constraint */
                null, /* no default parameter */ 
                "SSL Server Certificate's DN");

        set.add("sslDN", sslDN);

        Descriptor subsystemDN = new Descriptor(IDescriptor.STRING, null, /* no constraint */
                null, /* no default parameter */ 
                "CA Subsystem Certificate's DN");

        set.add("subsystemDN", subsystemDN);

        Descriptor ocspDN = new Descriptor(IDescriptor.STRING, null, /* no constraint */
                null, /* no default parameter */ 
                "OCSP Signing Certificate's DN");

        set.add("ocspDN", ocspDN);

        return set;
    }

    public void cleanUp() throws IOException {
        IConfigStore cs = CMS.getConfigStore();
        try {
            boolean done = cs.getBoolean("preop.NamePanel.done");
            cs.putBoolean("preop.NamePanel.done", false);
            cs.commit(false);
        } catch (Exception e) {
        }

        String list = "";
        try {
            list = cs.getString("preop.cert.list", "");
        } catch (Exception e) {
        }

        StringTokenizer st = new StringTokenizer(list, ",");
        while (st.hasMoreTokens()) {
            String t = st.nextToken();
            cs.remove("preop.cert."+t+".done");
        }

        try {
            cs.commit(false);
        } catch (Exception e) {
        }
    }

    public boolean isPanelDone() {
        IConfigStore cs = CMS.getConfigStore();
        try {
            boolean s = cs.getBoolean("preop.NamePanel.done", false);
            if (s != true) {
                return false;
            } else {
                return true;
            }
        } catch (EBaseException e) {}

        return false;
    }

    public String capitalize(String s) {
        if (s.length() == 0) {
            return s;
        } else {
            return s.substring(0, 1).toUpperCase() + s.substring(1);
        }
    }

    /**
     * Display the panel.
     */
    public void display(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        CMS.debug("NamePanel: display()");
        context.put("title", "Subject Names");

        // update session id 
        String session_id = request.getParameter("session_id");
        if (session_id != null) {
            CMS.debug("NamePanel setting session id.");
            CMS.setConfigSDSessionId(session_id);
        }

        mCerts = new Vector();

        String domainname = "";
        IConfigStore config = CMS.getConfigStore();
        String select = "";
        String hselect = "";
        String cstype = "";
        try {
            //if CA, at the hierarchy panel, was it root or subord?
            hselect = config.getString("preop.hierarchy.select", "");
            select = config.getString("preop.subsystem.select", "");
            cstype = config.getString("cs.type", "");
            context.put("select", select);
            if (cstype.equals("CA") && hselect.equals("root")) {
                CMS.debug("NamePanel ca is root"); 
                context.put("isRoot", "true");
            } else {
                CMS.debug("NamePanel not ca or not root"); 
                context.put("isRoot", "false");
            }
        } catch (Exception e) {
        }

        try {
            domainname = config.getString("securitydomain.name", "");

            String certTags = config.getString("preop.cert.list");
            // same token for now
            String token = config.getString(PRE_CONF_CA_TOKEN);
            StringTokenizer st = new StringTokenizer(certTags, ",");
            String domaintype = config.getString("securitydomain.select");
            int count = 0;
            String host = "";
            int sd_admin_port = -1;
            if (domaintype.equals("existing")) {
                host = config.getString("securitydomain.host", "");
                sd_admin_port = config.getInteger("securitydomain.httpsadminport", -1);
                count = getSubsystemCount(host, sd_admin_port, true, cstype);
            }

            while (st.hasMoreTokens()) {
                String certTag = st.nextToken();

                CMS.debug("NamePanel: display() about to process certTag :" + certTag);
                String nn = config.getString(
                        PCERT_PREFIX + certTag + ".nickname");
                Cert c = new Cert(token, nn, certTag);
                String userfriendlyname = config.getString(
                        PCERT_PREFIX + certTag + ".userfriendlyname");
                String subsystem = config.getString(
                        PCERT_PREFIX + certTag + ".subsystem");

                c.setUserFriendlyName(userfriendlyname);

                String type = config.getString(PCERT_PREFIX + certTag + ".type");
                c.setType(type);
                boolean enable = config.getBoolean(PCERT_PREFIX+certTag+".enable", true);
                c.setEnable(enable);

                String cert = config.getString(subsystem +"."+certTag +".cert", "");
                String certreq = 
                  config.getString(subsystem + "." +certTag +".certreq", "");

                String dn = config.getString(PCERT_PREFIX + certTag + ".dn");
                boolean override = config.getBoolean(PCERT_PREFIX + certTag + 
                  ".cncomponent.override", true);
		//o_sd is to add o=secritydomainname
                boolean o_sd = config.getBoolean(PCERT_PREFIX + certTag +
						 "o_securitydomain", true);
		domainname = config.getString("securitydomain.name", "");
		CMS.debug("NamePanel: display() override is "+override);
		CMS.debug("NamePanel: display() o_securitydomain is "+o_sd);
		CMS.debug("NamePanel: display() domainname is "+domainname);

                boolean dnUpdated = false;
                try {
                    dnUpdated = config.getBoolean(PCERT_PREFIX+certTag+".updatedDN");
                } catch (Exception e) {
                }

                try {
                    boolean done = config.getBoolean("preop.NamePanel.done");
                    c.setDN(dn);
                } catch (Exception e) {
                    if (select.equals("clone") || dnUpdated) {
                        c.setDN(dn);
                    } else if (count != 0 && override && (cert.equals("") || certreq.equals(""))) {
                        CMS.debug("NamePanel subsystemCount = "+count);
                        c.setDN(dn + " "+count+ ((o_sd)? (",O=" + domainname):""));
                        config.putBoolean(PCERT_PREFIX+certTag+".updatedDN", true);
                    } else {
                        c.setDN(dn + ((o_sd)? (",O=" + domainname):""));
                        config.putBoolean(PCERT_PREFIX+certTag+".updatedDN", true);
                    }
                }

                mCerts.addElement(c);
                CMS.debug(
                        "NamePanel: display() added cert to mCerts: certTag "
                                + certTag);
                config.putString(PCERT_PREFIX + c.getCertTag() + ".dn", c.getDN());
            }// while
        } catch (EBaseException e) {
            CMS.debug("NamePanel: display() exception caught:" + e.toString());
        } catch (Exception e) {
            CMS.debug("NamePanel: " + e.toString());
        }

        CMS.debug("NamePanel: Ready to get SSL EE HTTPS urls");
        Vector v = getUrlListFromSecurityDomain(config, "CA", "SecurePort");
        v.addElement("External CA");
        StringBuffer list = new StringBuffer();
        int size = v.size();

        for (int i = 0; i < size; i++) {
            if (i == size - 1) {
                list.append(v.elementAt(i));
            } else {
                list.append(v.elementAt(i));
                list.append(",");
            }
        }

        try {
            config.putString("preop.ca.list", list.toString());
            config.commit(false);
        } catch (Exception e) {}

        context.put("urls", v);

        context.put("certs", mCerts);
        context.put("panel", "admin/console/config/namepanel.vm");
        context.put("errorString", "");

    }

    /**
     * Checks if the given parameters are valid.
     */
    public void validate(HttpServletRequest request,
            HttpServletResponse response,
            Context context) throws IOException {
        Enumeration c = mCerts.elements();

        while (c.hasMoreElements()) {
            Cert cert = (Cert) c.nextElement();
            // get the dn's and put in config
            if (cert.isEnable()) {
                String dn = HttpInput.getDN(request, cert.getCertTag());

                if (dn == null || dn.length() == 0) {
                    throw new IOException("Empty DN for " + cert.getUserFriendlyName());
                }
            }
        } // while
    }

    /*
     * get some of the "preop" parameters to persisting parameters
     */
    public void updateConfig(IConfigStore config, String certTag)
        throws EBaseException, IOException {
        String token = config.getString(PRE_CONF_CA_TOKEN);
        String subsystem = config.getString(PCERT_PREFIX + certTag + ".subsystem");
        CMS.debug("NamePanel: subsystem " + subsystem);
        String nickname = getNickname(config, certTag);

        CMS.debug("NamePanel: updateConfig() for certTag " + certTag);
        // XXX these two are used throughout the CA so have to write them
        // should change the entire system to use the uniformed names later
        if (certTag.equals("signing") || certTag.equals("ocsp_signing")) {
            CMS.debug("NamePanel: setting signing nickname=" + nickname);
            config.putString(subsystem + "." + certTag + ".cacertnickname", nickname);
            config.putString(subsystem + "." + certTag + ".certnickname", nickname);
        }

        // if KRA, hardware token needs param "kra.storageUnit.hardware" in CS.cfg
        String cstype = config.getString("cs.type", null);
        cstype = toLowerCaseSubsystemType(cstype);
        if (cstype.equals("kra")) {
	    if (!token.equals("Internal Key Storage Token")) {
	      if (certTag.equals("storage")) {
                config.putString(subsystem + ".storageUnit.hardware", token);
                config.putString(subsystem + ".storageUnit.nickName", token+":"+nickname);
	      } else if (certTag.equals("transport")) {
                config.putString(subsystem + ".transportUnit.nickName", token+":"+nickname);
          }
	    } else { // software token
	      if (certTag.equals("storage")) {
                config.putString(subsystem + ".storageUnit.nickName", nickname);
	      } else if (certTag.equals("transport")) {
                config.putString(subsystem + ".transportUnit.nickName", nickname);
              }
	    }
        }

        String serverCertNickname = nickname;
        String path = CMS.getConfigStore().getString("instanceRoot", "");
        if (certTag.equals("sslserver")) {
	        if (!token.equals("Internal Key Storage Token")) {
                serverCertNickname = token+":"+nickname;
            }
            File file = new File(path+"/conf/serverCertNick.conf");
            PrintStream ps = new PrintStream(new FileOutputStream(path+"/conf/serverCertNick.conf"));
            ps.println(serverCertNickname);
            ps.close();
        }

        config.putString(subsystem + "." + certTag + ".nickname", nickname);
        config.putString(subsystem + "." + certTag + ".tokenname", token);
        /*
        config.putString(CERT_PREFIX + certTag + ".defaultSigningAlgorithm",
                "SHA1withRSA");
         */

        config.commit(false);
        CMS.debug("NamePanel: updateConfig() done");
    }

    /**
     * create and sign a cert locally (handles both "selfsign" and "local")
     */
    public void configCert(HttpServletRequest request,
            HttpServletResponse response,
            Context context, Cert certObj) throws IOException {
        CMS.debug("NamePanel: configCert called");

        IConfigStore config = CMS.getConfigStore();
        String caType = certObj.getType();
        CMS.debug("NamePanel: in configCert caType is "+ caType);
        X509CertImpl cert = null;
        String certTag = certObj.getCertTag();

        try {
            updateConfig(config, certTag);
            if (caType.equals("remote")) {
                String v = config.getString("preop.ca.type", "");

                CMS.debug("NamePanel configCert: remote CA");
                String pkcs10 = CertUtil.getPKCS10(config, PCERT_PREFIX, 
                  certObj, context);
                certObj.setRequest(pkcs10);
                String subsystem = config.getString(
                        PCERT_PREFIX + certTag + ".subsystem");
                config.putString(subsystem + "." + certTag + ".certreq", pkcs10);
                String profileId = config.getString(PCERT_PREFIX+certTag+".profile");
                String session_id = CMS.getConfigSDSessionId();
                String sd_hostname = "";
                int sd_ee_port = -1;
                try {
                    sd_hostname = config.getString("securitydomain.host", "");
                    sd_ee_port = config.getInteger("securitydomain.httpseeport", -1);
                } catch (Exception ee) {
                    CMS.debug("NamePanel: configCert() exception caught:"+ee.toString());
                }
                String sysType = config.getString("cs.type", "");
                String machineName = config.getString("machineName", "");
                String securePort = config.getString("service.securePort", "");
                if (certTag.equals("subsystem")) {
                    String content = "requestor_name=" + sysType + "-" + machineName + "-" + securePort + "&profileId="+profileId+"&cert_request_type=pkcs10&cert_request="+URLEncoder.encode(pkcs10, "UTF-8")+"&xmlOutput=true&sessionID="+session_id;
                    cert = CertUtil.createRemoteCert(sd_hostname, sd_ee_port, 
                      content, response, this);
                    if (cert == null) {
                        throw new IOException("Error: remote certificate is null");
                    }
                } else if (v.equals("sdca")) {
                    String ca_hostname = "";
                    int ca_port = -1;
                    try {
                        ca_hostname = config.getString("preop.ca.hostname", "");
                        ca_port = config.getInteger("preop.ca.httpsport", -1);
                    } catch (Exception ee) {
                    }

                    String content = "requestor_name=" + sysType + "-" + machineName + "-" + securePort + "&profileId="+profileId+"&cert_request_type=pkcs10&cert_request="+URLEncoder.encode(pkcs10, "UTF-8")+"&xmlOutput=true&sessionID="+session_id;
                    cert = CertUtil.createRemoteCert(ca_hostname, ca_port, 
                      content, response, this);
                    if (cert == null) {
                        throw new IOException("Error: remote certificate is null");
                    }
                } else if (v.equals("otherca")) {
                    config.putString(subsystem + "." + certTag + ".cert",
                            "...paste certificate here...");
                } else {  
                    CMS.debug("NamePanel: no preop.ca.type is provided");
                }    
            } else { // not remote CA, ie, self-signed or local
                ISubsystem ca = CMS.getSubsystem(ICertificateAuthority.ID);

                if (ca == null) {
                    String s = PCERT_PREFIX + certTag + ".type";

                    CMS.debug(
                            "The value for " + s
                            + " should be remote, nothing else.");
                    throw new IOException(
                            "The value for " + s + " should be remote");
                } 
      
                String pubKeyType = config.getString(
                        PCERT_PREFIX + certTag + ".keytype");
                if (pubKeyType.equals("rsa")) {

                  String pubKeyModulus = config.getString(
                        PCERT_PREFIX + certTag + ".pubkey.modulus");
                  String pubKeyPublicExponent = config.getString(
                        PCERT_PREFIX + certTag + ".pubkey.exponent");
                  String subsystem = config.getString(
                        PCERT_PREFIX + certTag + ".subsystem");

                  if (certTag.equals("signing")) {
                    X509Key x509key = CryptoUtil.getPublicX509Key(
                            CryptoUtil.string2byte(pubKeyModulus),
                            CryptoUtil.string2byte(pubKeyPublicExponent));

                    cert = CertUtil.createLocalCert(config, x509key,
                            PCERT_PREFIX, certTag, caType, context);
                  } else {
                    String cacert = config.getString("ca.signing.cert", "");

                    if (cacert.equals("") || cacert.startsWith("...")) {
                        certObj.setCert(
                                "...certificate be generated internally...");
                        config.putString(subsystem + "." + certTag + ".cert",
                                "...certificate be generated internally...");
                    } else {
                        X509Key x509key = CryptoUtil.getPublicX509Key(
                                CryptoUtil.string2byte(pubKeyModulus),
                                CryptoUtil.string2byte(pubKeyPublicExponent));

                        cert = CertUtil.createLocalCert(config, x509key,
                                PCERT_PREFIX, certTag, caType, context);
                    }
                  }
                } else if (pubKeyType.equals("ecc")) {
                  String pubKeyEncoded = config.getString(
                        PCERT_PREFIX + certTag + ".pubkey.encoded");
                  String subsystem = config.getString(
                        PCERT_PREFIX + certTag + ".subsystem");

                  if (certTag.equals("signing")) {

                    X509Key x509key = CryptoUtil.getPublicX509ECCKey(CryptoUtil.string2byte(pubKeyEncoded));
                    cert = CertUtil.createLocalCert(config, x509key,
                            PCERT_PREFIX, certTag, caType, context);
                  } else {
                    String cacert = config.getString("ca.signing.cert", "");

                    if (cacert.equals("") || cacert.startsWith("...")) {
                        certObj.setCert(
                                "...certificate be generated internally...");
                        config.putString(subsystem + "." + certTag + ".cert",
                                "...certificate be generated internally...");
                    } else {
                        X509Key x509key = CryptoUtil.getPublicX509ECCKey(
                                CryptoUtil.string2byte(pubKeyEncoded));

                        cert = CertUtil.createLocalCert(config, x509key,
                                PCERT_PREFIX, certTag, caType, context);
                    }
                  }
                } else {
                   // invalid key type
                   CMS.debug("Invalid key type " + pubKeyType);
                }
                if (cert != null) {
                    if (certTag.equals("subsystem"))
                        CertUtil.addUserCertificate(cert);
                }
            } // done self-signed or local

            if (cert != null) {
                byte[] certb = cert.getEncoded();
                String certs = CryptoUtil.base64Encode(certb);

               // certObj.setCert(certs);
                String subsystem = config.getString(
                        PCERT_PREFIX + certTag + ".subsystem");
                config.putString(subsystem + "." + certTag + ".cert", certs);
            }
            config.commit(false);
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            CMS.debug("NamePanel configCert() exception caught:" + e.toString());
        }
    }
 
    public void configCertWithTag(HttpServletRequest request,
            HttpServletResponse response,
            Context context, String tag) throws IOException 
   {
            CMS.debug("NamePanel: configCertWithTag start");
            Enumeration c = mCerts.elements();
            IConfigStore config = CMS.getConfigStore();
         
            while (c.hasMoreElements()) {
                Cert cert = (Cert) c.nextElement();
                String ct = cert.getCertTag(); 
                CMS.debug("NamePanel: configCertWithTag ct=" + ct + 
                        " tag=" +tag);
                if (ct.equals(tag)) {
                    try {
                        String nickname = HttpInput.getNickname(request, ct + "_nick");
                        if (nickname != null) {
                            CMS.debug("configCertWithTag: Setting nickname for " + ct + " to " + nickname);
                            config.putString(PCERT_PREFIX  + ct + ".nickname", nickname);
                            cert.setNickname(nickname);
                            config.commit(false);
			}
                    } catch (Exception e) {
                        CMS.debug("NamePanel: configCertWithTag: Exception in setting nickname for " + ct + ": " + e.toString());
                    }

                    configCert(request, response, context, cert);
                    CMS.debug("NamePanel: configCertWithTag done with tag=" + tag);
                    return;
                }
           }
            CMS.debug("NamePanel: configCertWithTag done");
    }

    private boolean inputChanged(HttpServletRequest request)
      throws IOException {
        IConfigStore config = CMS.getConfigStore();         
       
        boolean hasChanged = false;
        try {
            Enumeration c = mCerts.elements();

            while (c.hasMoreElements()) {
                Cert cert = (Cert) c.nextElement();
                String ct = cert.getCertTag(); 
                boolean enable = config.getBoolean(PCERT_PREFIX+ct+".enable", true);
                if (!enable)
                    continue;

                String olddn = config.getString(PCERT_PREFIX + cert.getCertTag() + ".dn", "");
                // get the dn's and put in config
                String dn = HttpInput.getDN(request, cert.getCertTag());

                if (!olddn.equals(dn))
                    hasChanged = true;

               String oldnick = config.getString(PCERT_PREFIX + ct + ".nickname");
               String nick = HttpInput.getNickname(request, ct + "_nick");
               if (!oldnick.equals(nick))
                   hasChanged = true;

            }
        } catch (Exception e) {
        }

        return hasChanged;
    }
   
    public String getURL(HttpServletRequest request, IConfigStore config)
    {
        String index = request.getParameter("urls");
        if (index == null){
          return null;
        }
        String url = "";
        if (index.startsWith("http")) {
           // user may submit url directlry
           url = index;
        } else {
          try {
            int x = Integer.parseInt(index);
            String list = config.getString("preop.ca.list", "");
            StringTokenizer tokenizer = new StringTokenizer(list, ",");
            int counter = 0;

            while (tokenizer.hasMoreTokens()) {
                url = tokenizer.nextToken();
                if (counter == x) {
                    break;
                }
                counter++;
            }
          } catch (Exception e) {}
        }
       return url;
    }

    /**
     * Commit parameter changes
     */
    public void update(HttpServletRequest request,
            HttpServletResponse response,
            Context context) throws IOException {
        CMS.debug("NamePanel: in update()");
	boolean hasErr = false;

        if (inputChanged(request)) {
            mServlet.cleanUpFromPanel(mServlet.getPanelNo(request));
        } else if (isPanelDone()) {
            return;
        }

        IConfigStore config = CMS.getConfigStore();         

        String hselect = "";
        ISubsystem subsystem = CMS.getSubsystem(ICertificateAuthority.ID);
        try {
            //if CA, at the hierarchy panel, was it root or subord?
            hselect = config.getString("preop.hierarchy.select", "");
            String cstype = config.getString("preop.subsystem.select", "");
            if (cstype.equals("clone")) {
                CMS.debug("NamePanel: clone configuration detected");
                // still need to handle SSL certificate
                configCertWithTag(request, response, context, "sslserver");
                String url = getURL(request, config);
                if (url != null && !url.equals("External CA")) {
                   // preop.ca.url is required for setting KRA connector
                   url = url.substring(url.indexOf("https"));
                   config.putString("preop.ca.url", url);
                }
                CMS.debug("NamePanel: clone configuration done");
                return;
            }
        } catch (Exception e) {
            CMS.debug("NamePanel: configCertWithTag failure - " + e);
            return;
        }

        //if no hselect, then not CA
      if (hselect.equals("") || hselect.equals("join")) {
        String select = null;
        String url = getURL(request, config);

        URL urlx = null;

        if (url.equals("External CA")) {
            CMS.debug("NamePanel: external CA selected");
            select = "otherca";
            config.putString("preop.ca.type", "otherca");
            if (subsystem != null) {
                config.putString(PCERT_PREFIX+"signing.type", "remote");
            }

            config.putString("preop.ca.pkcs7", "");
            config.putInteger("preop.ca.certchain.size", 0);
            context.put("check_otherca", "checked");
            CMS.debug("NamePanel: update: this is the external CA.");
        } else {
            CMS.debug("NamePanel: local CA selected");
            select = "sdca";
            // parse URL (CA1 - https://...)
            url = url.substring(url.indexOf("https"));
            config.putString("preop.ca.url", url);

            urlx = new URL(url);
            config.putString("preop.ca.type", "sdca");
            CMS.debug("NamePanel: update: this is a CA in the security domain.");
            context.put("check_sdca", "checked");
            sdca(request, context, urlx.getHost(),
                    Integer.toString(urlx.getPort()));
            if (subsystem != null) {
                config.putString(PCERT_PREFIX + "signing.type", "remote");
                config.putString(PCERT_PREFIX + "signing.profile",
                        "caInstallCACert");
            }
        }

        try {
            config.commit(false);
        } catch (Exception e) {}

     }

        try {

            Enumeration c = mCerts.elements();

            while (c.hasMoreElements()) {
                Cert cert = (Cert) c.nextElement();
                String ct = cert.getCertTag(); 
                String tokenname = cert.getTokenname();
                boolean enable = config.getBoolean(PCERT_PREFIX+ct+".enable", true);
                if (!enable)
                    continue;

                boolean certDone = config.getBoolean(PCERT_PREFIX+ct+".done", false);
                if (certDone)
                    continue;

                // get the nicknames and put in config
                String nickname = HttpInput.getNickname(request, ct + "_nick");
                if (nickname != null) {
                    CMS.debug("NamePanel: update: Setting nickname for " + ct + " to " + nickname);
                    config.putString(PCERT_PREFIX + ct + ".nickname", nickname);
                    cert.setNickname(nickname);
                } else {
                    nickname = cert.getNickname();
                }

                // get the dn's and put in config
                String dn = HttpInput.getDN(request, ct);

                config.putString(PCERT_PREFIX + ct + ".dn", dn);
                // commit here in case it changes
                config.commit(false);

                try {
                    configCert(request, response, context, cert);
                    config.putBoolean("preop.cert."+cert.getCertTag()+".done", 
                      true);
                    config.commit(false);
                } catch (Exception e) {
                    CMS.debug(
                            "NamePanel: update() exception caught:"
                                    + e.toString());
		    hasErr = true;
                    System.err.println("Exception caught: " + e.toString());
                }

            } // while 
	        if (hasErr == false) {
              config.putBoolean("preop.NamePanel.done", true);
              config.commit(false);
	        }

        } catch (Exception e) {
            CMS.debug("NamePanel: Exception caught: " + e.toString());
            System.err.println("Exception caught: " + e.toString());
        }// try


        try {
            config.commit(false);
        } catch (Exception e) {}


        CMS.debug("NamePanel: update() done");
    }

    private void sdca(HttpServletRequest request, Context context, String hostname, String httpsPortStr) throws IOException {
        CMS.debug("NamePanel update: this is the CA in the security domain.");
        CMS.debug("NamePanel update: selected CA hostname=" + hostname + " port=" + httpsPortStr);
        String https_admin_port = "";
        IConfigStore config = CMS.getConfigStore();

        context.put("sdcaHostname", hostname);
        context.put("sdHttpPort", httpsPortStr);

        if (hostname == null || hostname.length() == 0) {
            context.put("errorString", "Hostname is null");
            throw new IOException("Hostname is null");
        }

        // Retrieve the associated HTTPS Admin port so that it
        // may be stored for use with ImportAdminCertPanel
        https_admin_port = getSecurityDomainAdminPort( config,
                                                       hostname,
                                                       httpsPortStr );

        int httpsport = -1;

        try {
             httpsport = Integer.parseInt(httpsPortStr);
        } catch (Exception e) {
            CMS.debug(
                    "NamePanel update: Https port is not valid. Exception: "
                            + e.toString());
            throw new IOException("Https Port is not valid.");
        }

        config.putString("preop.ca.hostname", hostname);
        config.putString("preop.ca.httpsport", httpsPortStr);
        config.putString("preop.ca.httpsadminport", https_admin_port);
        ConfigCertApprovalCallback certApprovalCallback = new ConfigCertApprovalCallback();
        updateCertChainUsingSecureEEPort( config, "ca", hostname,
                                          httpsport, true, context,
                                          certApprovalCallback );
        try {
           CMS.debug("Importing CA chain");
           importCertChain("ca");
        } catch (Exception e1) {
           CMS.debug("Failed in importing CA chain");
        }
    }


    public void initParams(HttpServletRequest request, Context context)
                   throws IOException
    {
        context.put("certs", mCerts);
    }

    /**
     * If validiate() returns false, this method will be called.
     */
    public void displayError(HttpServletRequest request,
            HttpServletResponse response,
            Context context) 
    {
        try {
          initParams(request, context);
        } catch (IOException e) {
        }
        context.put("title", "Subject Names");
        context.put("panel", "admin/console/config/namepanel.vm");
    }
}
