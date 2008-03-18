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
import java.security.*;
import java.math.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.util.*;
import com.netscape.certsrv.property.*;
import com.netscape.certsrv.ca.*;
import com.netscape.certsrv.security.*;
import com.netscape.certsrv.apps.CMS;
import com.netscape.cmsutil.crypto.*;
import com.netscape.certsrv.ca.*;
import com.netscape.certsrv.dbs.certdb.*;
import com.netscape.certsrv.request.*;

import org.mozilla.jss.*;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.pkcs11.*;

import netscape.security.util.*;
import netscape.security.pkcs.*;
import netscape.security.x509.*;

import com.netscape.cms.servlet.wizard.*;

public class CertRequestPanel extends WizardPanelBase {
    private Vector mCerts = null;
    private WizardServlet mServlet = null;

    public CertRequestPanel() {}

    /**
     * Initializes this panel.
     */
    public void init(ServletConfig config, int panelno) 
        throws ServletException {
        setPanelNo(panelno);
        setName("Requests & Certificates");
    }

    public void init(WizardServlet servlet, ServletConfig config, int panelno, String id)
        throws ServletException {
        setPanelNo(panelno);
        setName("Requests and Certificates");
        mServlet = servlet;
        setId(id);
    }

    // XXX how do you do this?  There could be multiple certs.
    public PropertySet getUsage() {
        PropertySet set = new PropertySet();
                                                                                
        Descriptor certDesc = new Descriptor(IDescriptor.STRING, null, /* no constraint */
                null, /* no default parameters */
                null);

        set.add("cert", certDesc);
                                                                                
        return set;
    }

    /**
     * Show "Apply" button on frame?
     */
    public boolean showApplyButton() {
        if (isPanelDone())
          return false;
        else
          return true;
    }

    private boolean findCertificate(String tokenname, String nickname) 
      throws IOException {
        IConfigStore cs = CMS.getConfigStore();
        CryptoManager cm = null;
        try {
            cm = CryptoManager.getInstance();
        } catch (Exception e) {
        }

        String fullnickname = nickname;

        boolean hardware = false;
        if (!tokenname.equals("internal") && !tokenname.equals("Internal Key Storage Token")) {
            hardware = true;
            fullnickname = tokenname+":"+nickname;
        }

        try {
            X509Certificate cert = cm.findCertByNickname(fullnickname);
            if (cert == null)
                return false;
            try {
                boolean done = cs.getBoolean("preop.CertRequestPanel.done");
                return true;
            } catch (Exception ee) {
                if (hardware) {
                    CMS.debug("CertRequestPanel findCertificate: The certificate with the same nickname has been found on HSM. Please remove it before proceeding.");
                    throw new IOException("The certificate with the same nickname has been found on HSM. Please remove it before proceeding.");
                }
                return true;
            }
        } catch (IOException e) {
            CMS.debug("CertRequestPanel findCertificate: throw exception:"+e.toString());
            throw e;
        } catch (Exception e) {
            CMS.debug("CertRequestPanel findCertificate: Exception="+e.toString());
            return false;
        }
    }

    public void cleanUp() throws IOException {
        IConfigStore cs = CMS.getConfigStore();
        String select = "";
        String list = "";
        String tokenname = "";
        try {
            select = cs.getString("preop.subsystem.select", "");
            list = cs.getString("preop.cert.list", "");
            tokenname = cs.getString("preop.module.token", "");      
        } catch (Exception e) {
        }

        ICertificateAuthority ca = (ICertificateAuthority) CMS.getSubsystem(
          ICertificateAuthority.ID);
        
        if (ca != null) {
            CMS.debug("CertRequestPanel cleanup: get certificate repository");
            BigInteger beginS = null;
            BigInteger endS = null;
            String beginNum = "";
            String endNum = "";
            try {
                beginNum = cs.getString("dbs.beginSerialNumber", "");
                endNum = cs.getString("dbs.endSerialNumber", "");
                if (!beginNum.equals(""))
                    beginS = new BigInteger(beginNum, 16);
                if (!endNum.equals(""))
                    endS = new BigInteger(endNum, 16);
            } catch (Exception e) {
            }

            ICertificateRepository cr = ca.getCertificateRepository();
            if (cr != null) {
                try {
                    cr.removeCertRecords(beginS, endS);
                } catch (Exception e) {
                    CMS.debug("CertRequestPanel cleanUp exception in removing all objects: "+e.toString());
                }
      
                try {
                    cr.resetSerialNumber(new BigInteger(beginNum));
                } catch (Exception e) {
                    CMS.debug("CertRequestPanel cleanUp exception in resetting serial number: "+e.toString());
                }
            }
        }


        StringTokenizer st = new StringTokenizer(list, ",");
        String nickname = "";
        boolean enable = false;
        while (st.hasMoreTokens()) {
            String t = st.nextToken();
          
            try {
                enable = cs.getBoolean(PCERT_PREFIX+t+".enable", true);
                nickname = cs.getString(PCERT_PREFIX +t+".nickname", "");
            } catch (Exception e) {
            }

            if (!enable)
                continue;

            if (t.equals("sslserver"))
                continue;

            if (findCertificate(tokenname, nickname)) {
                try {
                    CMS.debug("CertRequestPanel cleanup: deleting certificate ("+nickname+").");
                        deleteCert(tokenname, nickname);
                } catch (Exception e) {
                    CMS.debug("CertRequestPanel cleanup: failed to delete certificate (" +nickname+"). Exception: " +e.toString());
                }
            }
        }

        try {
            boolean done = cs.getBoolean("preop.CertRequestPanel.done");
            cs.putBoolean("preop.CertRequestPanel.done", false);
            cs.commit(false);
        } catch (Exception e) {
        }
    }

    public boolean isPanelDone() {
        IConfigStore cs = CMS.getConfigStore();
        try {
            boolean s = cs.getBoolean("preop.CertRequestPanel.done",
                    false);

            if (s != true) {
                return false;
            } else {
                return true;
            }
        } catch (EBaseException e) {}

        return false;
    }

    public void getCert(IConfigStore config,
            Context context, String certTag, Cert cert) {
        try {

            String subsystem = config.getString(
                    PCERT_PREFIX + certTag + ".subsystem");

            String certs = config.getString(subsystem + "." + certTag + ".cert", "");

            if (cert != null) {
                String certf = certs;

                CMS.debug(
                        "CertRequestPanel getCert: certTag=" + certTag
                        + " cert=" + certs);
                //get and set formated cert
                if (!certs.startsWith("...")) { 
                    certf = CryptoUtil.certFormat(certs);
                }
                cert.setCert(certf);

                //get and set cert pretty print
                byte[] certb = CryptoUtil.base64Decode(certs);
                CertPrettyPrint pp = new CertPrettyPrint(certb);
                cert.setCertpp(pp.toString(Locale.getDefault()));
            } else {
                CMS.debug( "CertRequestPanel::getCert() - cert is null!" );
                return;
            }
            String userfriendlyname = config.getString(
                    PCERT_PREFIX + certTag + ".userfriendlyname");

            cert.setUserFriendlyName(userfriendlyname);
            String type = config.getString(PCERT_PREFIX + certTag + ".type");

            cert.setType(type);
            String dn = config.getString(PCERT_PREFIX + certTag + ".dn");

            cert.setDN(dn);
        } catch (Exception e) {
            CMS.debug("CertRequestPanel:getCert" + e.toString());
        } // try
    }

    public X509Key getECCX509Key(IConfigStore config, String certTag)
                     throws Exception
    {
        X509Key pubk = null;
        String pubKeyEncoded = config.getString(
                    PCERT_PREFIX + certTag + ".pubkey.encoded");
        pubk = CryptoUtil.getPublicX509ECCKey(CryptoUtil.string2byte(pubKeyEncoded)); 
        return pubk;
    }

    public X509Key getRSAX509Key(IConfigStore config, String certTag)
                     throws Exception
    {
        X509Key pubk = null;

        String pubKeyModulus = config.getString(
                    PCERT_PREFIX + certTag + ".pubkey.modulus");
        String pubKeyPublicExponent = config.getString(
                    PCERT_PREFIX + certTag + ".pubkey.exponent");
        pubk = CryptoUtil.getPublicX509Key(
                   CryptoUtil.string2byte(pubKeyModulus),
                   CryptoUtil.string2byte(pubKeyPublicExponent)); 
        return pubk;
    }

    public void handleCertRequest(IConfigStore config,
            Context context, String certTag, Cert cert) {
        try {
            // get public key
            String pubKeyType = config.getString(
                    PCERT_PREFIX + certTag + ".keytype");
            X509Key pubk = null;
            if (pubKeyType.equals("rsa")) {
                pubk = getRSAX509Key(config, certTag);
            } else if (pubKeyType.equals("ecc")) {
                pubk = getECCX509Key(config, certTag);
            } else {
                CMS.debug( "CertRequestPanel::handleCertRequest() - "
                         + "pubKeyType " + pubKeyType + " is unsupported!" );
                return;
            }

            CMS.debug("CertRequestPanel: tag=" + certTag);
            if (pubk != null) {
                CMS.debug("CertRequestPanel: got public key");
            } else {
                CMS.debug("CertRequestPanel: error getting public key null");
                return;
            }

            // get private key
            String privKeyID = config.getString(
                    PCERT_PREFIX + certTag + ".privkey.id");
            CMS.debug("CertRequestPanel: privKeyID=" + privKeyID);
            byte[] keyIDb = CryptoUtil.string2byte(privKeyID);
	      
            PrivateKey privk = CryptoUtil.findPrivateKeyFromID(keyIDb);

            if (privk != null) {
                CMS.debug("CertRequestPanel: got private key");
            } else {
                CMS.debug("CertRequestPanel: error getting private key null");
            }
	    
            // construct cert request
            String caDN = config.getString(PCERT_PREFIX + certTag + ".dn");

            cert.setDN(caDN);
            PKCS10 certReq = CryptoUtil.createCertificationRequest(caDN, pubk,
                    privk);

            CMS.debug("CertRequestPanel: created cert request");
            byte[] certReqb = certReq.toByteArray();
            String certReqs = CryptoUtil.base64Encode(certReqb);
            String certReqf = CryptoUtil.reqFormat(certReqs);
		
            String subsystem = config.getString(
                            PCERT_PREFIX + certTag + ".subsystem");
            config.putString(subsystem + "." + certTag + ".certreq", certReqs);
            config.commit(false);
            cert.setRequest(certReqf);
        } catch (Exception e) {
            CMS.debug("CertRequestPanel::handleCertRequest" + e.toString());
            CMS.debug(e);
        } // try

    }

    /**
     * Display the panel.
     */
    public void display(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {

        CMS.debug("CertRequestPanel: display()");
        context.put("title", "Requests and Certificates");

        try {
            mCerts = new Vector();

            IConfigStore config = CMS.getConfigStore();

            String certTags = config.getString("preop.cert.list");
            StringTokenizer st = new StringTokenizer(certTags, ",");

            while (st.hasMoreTokens()) {
                String certTag = st.nextToken();

                try {
                    String subsystem = config.getString(
                            PCERT_PREFIX + certTag + ".subsystem");
                    String nickname = config.getString(
                            subsystem + "." + certTag + ".nickname");
                    String tokenname = config.getString(
                            subsystem + "." + certTag + ".tokenname");
                    Cert c = new Cert(tokenname, nickname, certTag);

                    handleCertRequest(config, context, certTag, c);

                    String type = config.getString(
                            PCERT_PREFIX + certTag + ".type");

                    c.setType(type);
                    boolean enable = config.getBoolean(PCERT_PREFIX+certTag+".enable", true);
                    c.setEnable(enable);
                    getCert(config, context, certTag, c);

                    c.setSubsystem(subsystem);
                    mCerts.addElement(c);
                } catch (Exception e) {
                    CMS.debug(
                            "CertRequestPanel:display() Exception caught: "
                                    + e.toString() + " for certTag " + certTag);
                }
            }
        } catch (Exception e) {
            CMS.debug(
                    "CertRequestPanel:display() Exception caught: "
                            + e.toString());
            System.err.println("Exception caught: " + e.toString());

        } // try

        context.put("reqscerts", mCerts);
        context.put("status", "display");
        // context.put("status_token", "None");
        context.put("panel", "admin/console/config/certrequestpanel.vm");

    }

    /**
     * Checks if the given parameters are valid.
     */
    public void validate(HttpServletRequest request,
            HttpServletResponse response,
            Context context) throws IOException {
    }

    private boolean findBootstrapServerCert() {
        IConfigStore cs = CMS.getConfigStore();
        try {
            String nickname = cs.getString("preop.cert.sslserver.nickname", "");
            CryptoManager cm = CryptoManager.getInstance();
            X509Certificate cert = cm.findCertByNickname(nickname);
            Principal issuerDN = cert.getIssuerDN();
            Principal subjectDN = cert.getSubjectDN();
            if (issuerDN.equals(subjectDN))
                return true;
        } catch (Exception e) {
            CMS.debug("CertRequestPanel findBootstrapServerCert Exception="+e.toString());
        }

        return false;
    }

    private void deleteBootstrapServerCert() {
        IConfigStore cs = CMS.getConfigStore();
        try {
            String nickname = cs.getString("preop.cert.sslserver.nickname", "");
            deleteCert("Internal Key Storage Token", nickname);
        } catch (Exception e) {
            CMS.debug("CertRequestPanel deleteBootstrapServerCert Exception="+e.toString());
        }
    }

    /**
     * Commit parameter changes
     */
    public void update(HttpServletRequest request,
            HttpServletResponse response,
            Context context) throws IOException {
        CMS.debug("CertRequestPanel: in update()");
        boolean hasErr = false;
        IConfigStore config = CMS.getConfigStore();

        String catype = "";
        try {
            catype = config.getString("preop.ca.type", "");
        } catch (Exception e) {
        }

        if (isPanelDone())
            return;

        try {
            Enumeration c = mCerts.elements();

            String tokenname = "";
            try {
                tokenname = config.getString("preop.module.token", "");      
            } catch (Exception e) {
            }

            while (c.hasMoreElements()) {
                Cert cert = (Cert) c.nextElement();
                String certTag = cert.getCertTag();
                String subsystem = cert.getSubsystem();
                boolean enable = config.getBoolean(PCERT_PREFIX+certTag+".enable", true);
                if (!enable)
                    continue;

                String nickname = cert.getNickname();

                CMS.debug(
                        "CertRequestPanel: update() for cert tag "
                                + cert.getCertTag());
                // String b64 = config.getString(CERT_PREFIX+ certTag +".cert", "");
                String b64 = HttpInput.getCert(request, certTag);

                if (cert.getType().equals("local")
                        && b64.equals(
                                "...certificate be generated internally...")) {

                    String pubKeyType = config.getString(
                            PCERT_PREFIX + certTag + ".keytype");
                    X509Key x509key = null;
                    if (pubKeyType.equals("rsa")) {
                      x509key = getRSAX509Key(config, certTag);
                    } else if (pubKeyType.equals("ecc")) {
                      x509key = getECCX509Key(config, certTag);
                    }
                        
                    if (findCertificate(tokenname, nickname)) {
                        if (!certTag.equals("sslserver"))
                            continue; 
                    }
                    X509CertImpl impl = CertUtil.createLocalCert(config, x509key, 
                            PCERT_PREFIX, certTag, cert.getType(), context);

                    if (impl != null) {
                        byte[] certb = impl.getEncoded(); 
                        String certs = CryptoUtil.base64Encode(certb);

                        cert.setCert(certs);
                        config.putString(subsystem + "." + certTag + ".cert", certs);
                        /* import certificate */
                        CMS.debug(
                                "CertRequestPanel configCert: nickname="
                                        + nickname);

                        try {
                            if (certTag.equals("sslserver") && findBootstrapServerCert())
                                deleteBootstrapServerCert();
                            if (findCertificate(tokenname, nickname))
                                deleteCert(tokenname, nickname);
                            if (certTag.equals("signing") && subsystem.equals("ca"))
                                CryptoUtil.importUserCertificate(impl, nickname);
                            else
                                CryptoUtil.importUserCertificate(impl, nickname, false);
                            CMS.debug(
                                    "CertRequestPanel configCert: cert imported for certTag "
                                            + certTag);
                        } catch (Exception ee) {
                            CMS.debug(
                                    "CertRequestPanel configCert: Failed to import certificate "
                                            + certTag + " Exception: "
                                            + ee.toString());
                        }
                    }
                } else if (cert.getType().equals("remote")) {
                    if (b64 != null && b64.length() > 0
                            && !b64.startsWith("...")) {
                        String b64chain = HttpInput.getCertChain(request, certTag+"_cc");
                        CMS.debug(
                                "CertRequestPanel: in update() process remote...import cert");

                        String input = HttpInput.getCert(request, cert.getCertTag());

                        if (input != null) {
                            try {
                                if (certTag.equals("sslserver") && findBootstrapServerCert())
                                    deleteBootstrapServerCert();
                                if (findCertificate(tokenname, nickname)) { 
                                        deleteCert(tokenname, nickname);
                                }
                            } catch (Exception e) {
                                CMS.debug("CertRequestPanel update (remote): deleteCert Exception="+e.toString());
                            }
                            input = CryptoUtil.stripCertBrackets(input.trim());
                            String certs = CryptoUtil.normalizeCertStr(input);
                            byte[] certb = CryptoUtil.base64Decode(certs);

                            config.putString(subsystem + "." + certTag + ".cert",
                                    certs);
                            try {
                                CryptoManager cm = CryptoManager.getInstance();
                                X509Certificate x509cert = cm.importCertPackage(
                                        certb, nickname);

                                CryptoUtil.trustCertByNickname(nickname);
                                X509Certificate[] certchains = cm.buildCertificateChain(
                                        x509cert);
                                X509Certificate leaf = null;

                                if (certchains != null) {
                                    CMS.debug(
                                            "CertRequestPanel certchains length="
                                                    + certchains.length);
                                    leaf = certchains[certchains.length - 1];
                                }

                                if( leaf == null ) {
                                    CMS.debug( "CertRequestPanel::update() - "
                                             + "leaf is null!" );
                                    throw new IOException( "leaf is null" );
                                }

                                if (/*(certchains.length <= 1) &&*/
				    (b64chain != null)) {
                                  CMS.debug("CertRequestPanel: cert might not have contained chain...calling importCertificateChain");
                                  try {
                                    CryptoUtil.importCertificateChain(
				      CryptoUtil.normalizeCertAndReq(b64chain));
                                  } catch (Exception e) {
                CMS.debug("CertRequestPanel: importCertChain: Exception: "+e.toString());
                                  }
                                }

                                InternalCertificate icert = (InternalCertificate) leaf;

                                icert.setSSLTrust(
                                        InternalCertificate.TRUSTED_CA
                                                | InternalCertificate.TRUSTED_CLIENT_CA
                                                | InternalCertificate.VALID_CA);
                                CMS.debug(
                                        "CertRequestPanel configCert: import certificate successfully, certTag="
                                                + certTag);
                            } catch (Exception ee) {
                                CMS.debug(
                                        "CertRequestPanel configCert: Failed to import certificate "
                                                + certTag + " Exception: "
                                                + ee.toString());
                            }
                        } else {
                            CMS.debug("CertRequestPanel: in update() input null");
                        }
                    }
                } else {
                    b64 = CryptoUtil.stripCertBrackets(b64.trim());
                    String certs = CryptoUtil.normalizeCertStr(b64);
                    byte[] certb = CryptoUtil.base64Decode(certs);
                    X509CertImpl impl = new X509CertImpl(certb);
                    try {
                        if (certTag.equals("sslserver") && findBootstrapServerCert())
                            deleteBootstrapServerCert();
                        if (findCertificate(tokenname, nickname)) {
                                deleteCert(tokenname, nickname);
                        }
                    } catch (Exception ee) {
                        CMS.debug("CertRequestPanel update: deleteCert Exception="+ee.toString());
                    }

                    try {
                        if (certTag.equals("signing") && subsystem.equals("ca"))
                            CryptoUtil.importUserCertificate(impl, nickname);
                        else
                            CryptoUtil.importUserCertificate(impl, nickname, false);
                    } catch (Exception ee) {
                        CMS.debug("CertRequestPanel: Failed to import user certificate."+ee.toString());
                    }
                }

                if (certTag.equals("signing") && subsystem.equals("ca")) {
                    String NickName = nickname;
                    if (!tokenname.equals("internal") && !tokenname.equals("Internal Key Storage Token"))
                        NickName = tokenname+ ":"+ nickname;

                    CMS.debug("CertRequestPanel update: set trust on CA signing cert "+NickName);
                    CryptoUtil.trustCertByNickname(NickName);
                    CMS.reinit(ICertificateAuthority.ID);
                } 
            } //while loop

            if (hasErr == false) {
              config.putBoolean("preop.CertRequestPanel.done", true);
            }
            config.commit(false);
        } catch (Exception e) {
            CMS.debug("CertRequestPanel: Exception caught: " + e.toString());
            System.err.println("Exception caught: " + e.toString());
        }

        //reset the attribute of the user certificate to u,u,u
        String certlist = "";
        try {
            certlist = config.getString("preop.cert.list", "");
            StringTokenizer tokenizer = new StringTokenizer(certlist, ",");
            CryptoManager cm = CryptoManager.getInstance();
            while (tokenizer.hasMoreTokens()) {
                String tag = tokenizer.nextToken();
                if (tag.equals("signing"))
                    continue;
                String nickname = config.getString("preop.cert."+tag+".nickname", "");
                String tokenname = config.getString("preop.module.token", "");
                if (!tokenname.equals("Internal Key Storage Token"))
                    nickname = tokenname+":"+nickname;
                X509Certificate c = cm.findCertByNickname(nickname);
                if (c instanceof InternalCertificate) {
                    InternalCertificate ic = (InternalCertificate)c;
                    ic.setSSLTrust(InternalCertificate.USER);
                    ic.setEmailTrust(InternalCertificate.USER);
                    ic.setObjectSigningTrust(InternalCertificate.USER);
                }
            }  
        } catch (Exception e) {
        }
    }

    /**
     * If validiate() returns false, this method will be called.
     */
    public void displayError(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        context.put("title", "Certificate Request");
        context.put("panel", "admin/console/config/certrequestpanel.vm");
    }
}
