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
import java.security.*;
import java.math.*;
import netscape.security.x509.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.util.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.property.*;
import java.io.*;
import java.net.URL;
import com.netscape.certsrv.base.*;
import java.util.*;
import org.mozilla.jss.*;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.util.*;
import org.mozilla.jss.pkcs12.*;
import org.mozilla.jss.pkcs11.*;
import org.mozilla.jss.asn1.*;
import org.mozilla.jss.crypto.PrivateKey.Type;
import org.mozilla.jss.pkix.primitive.*;
import org.mozilla.jss.pkix.primitive.Attribute;
import com.netscape.cms.servlet.wizard.*;
import netscape.ldap.*;
import java.security.interfaces.*;

public class RestoreKeyCertPanel extends WizardPanelBase {

    public RestoreKeyCertPanel() {}

    /**
     * Initializes this panel.
     */
    public void init(ServletConfig config, int panelno) 
        throws ServletException {
        setPanelNo(panelno);
        setName("Import Keys and Certificates");
    }

    public void init(WizardServlet servlet, ServletConfig config, int panelno, String id)
        throws ServletException {
        setPanelNo(panelno);
        setName("Import Keys and Certificates");
        setId(id);
    }

    /**
     * Should we skip this panel for the configuration.
     */
    public boolean shouldSkip() {
        CMS.debug("RestoreKeyCertPanel: should skip");
                                                                                
        IConfigStore cs = CMS.getConfigStore();
        // if we are root, no need to get the certificate chain.
                                                                                
        try {
            String select = cs.getString("preop.subsystem.select","");
            if (select.equals("clone")) {
                return false;
            }
        } catch (EBaseException e) {
        }
                                                                                
        return true;
    }

    public boolean isSubPanel() {
        return true;
    }

    public void cleanUp() throws IOException {
        IConfigStore cs = CMS.getConfigStore();
        /* clean up if necessary */
        try {
            boolean done = cs.getBoolean("preop.restorekeycert.done");
            cs.putBoolean("preop.restorekeycert.done", false);
            cs.commit(false);
        } catch (Exception e) {
        }
    }

    public boolean isPanelDone() {
        IConfigStore cs = CMS.getConfigStore();
        try {
            String s = cs.getString("preop.restorekeycert.done", "");
            if (s == null || s.equals("")) {
                return false;
            } else {
                return true;
            }
        } catch (EBaseException e) {}
        return false;
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
        context.put("title", "Import Keys and Certificates");
        IConfigStore config = CMS.getConfigStore();

        if (isPanelDone()) {
            
            try {
                String s = config.getString("preop.pk12.path", "");
                String type = config.getString("preop.subsystem.select", "");
                context.put("path", s);
            } catch (Exception e) {
                CMS.debug(e.toString());
            }
        } else {
            context.put("path", "");
        }

        context.put("password", "");
        context.put("panel", "admin/console/config/restorekeycertpanel.vm");
        context.put("errorString", "");
    }

    /**
     * Checks if the given parameters are valid.
     */
    public void validate(HttpServletRequest request,
            HttpServletResponse response,
            Context context) throws IOException {
        IConfigStore config = CMS.getConfigStore();
        String tokenname = "";
        try {
            tokenname = config.getString("preop.module.token", "");
        } catch (Exception e) {
        }

        if (!tokenname.equals("Internal Key Storage Token"))
            return;

        // Path can be empty. If this case, we just want to 
        // get to the next panel. Customer has HSM.
        String s = HttpInput.getString(request, "path");
        // if (s == null || s.equals("")) {
        //    CMS.debug("RestoreKeyCertPanel validate: path is empty");
        //    throw new IOException("Path is empty");
        // }

        
        if (s != null && !s.equals("")) {
            s = HttpInput.getPassword(request, "__password");
            if (s == null || s.equals("")) {
                CMS.debug("RestoreKeyCertPanel validate: password is empty");
                context.put("updateStatus", "validate-failure");
                throw new IOException("Empty password");
            }
        }
    }

    /**
     * Commit parameter changes
     */
    public void update(HttpServletRequest request,
            HttpServletResponse response,
            Context context) throws IOException 
    {
        IConfigStore config = CMS.getConfigStore();
        String path = HttpInput.getString(request, "path");
        if (path == null || path.equals("")) {
              // skip to next panel
            config.putBoolean("preop.restorekeycert.done", true);
            try {
              config.commit(false);
            } catch (EBaseException e) {
            }
            getConfigEntriesFromMaster(request, response, context);
            context.put("updateStatus", "success");
            return;
        }
        String pwd = HttpInput.getPassword(request, "__password");
        
        String tokenn = "";
        String instanceRoot = "";

        try {
            tokenn = config.getString("preop.module.token");
            instanceRoot = config.getString("instanceRoot");
        } catch (Exception e) {
        }

        if (tokenn.equals("Internal Key Storage Token")) {
            byte b[] = new byte[1000000];
            FileInputStream fis = new FileInputStream(instanceRoot + "/alias/" + path);
            while (fis.available() > 0) 
                fis.read(b);
            fis.close();

            ByteArrayInputStream bis = new ByteArrayInputStream(b);
            StringBuffer reason = new StringBuffer();
            Password password = new Password(pwd.toCharArray());
            PFX pfx = null;
            boolean verifypfx = false;
            try {
                pfx = (PFX)(new PFX.Template()).decode(bis);
                verifypfx = pfx.verifyAuthSafes(password, reason); 
            } catch (Exception e) {
                CMS.debug("RestoreKeyCertPanel update: Exception="+e.toString());
            }

            if (verifypfx) {
                CMS.debug("RestoreKeyCertPanel verify the PFX.");
                AuthenticatedSafes safes = pfx.getAuthSafes();
                Vector pkeyinfo_collection = new Vector();
                Vector cert_collection = new Vector();
                for (int i=0; i<safes.getSize(); i++) {
                    try {
                        SEQUENCE scontent = safes.getSafeContentsAt(null, i); 
                        for (int j=0; j<scontent.size(); j++) {
                            SafeBag bag = (SafeBag)scontent.elementAt(j);
                            OBJECT_IDENTIFIER oid = bag.getBagType();
                            if (oid.equals(SafeBag.PKCS8_SHROUDED_KEY_BAG)) {
                                EncryptedPrivateKeyInfo privkeyinfo = 
                                  (EncryptedPrivateKeyInfo)bag.getInterpretedBagContent();
                                PasswordConverter passConverter = new PasswordConverter();
                                PrivateKeyInfo pkeyinfo = privkeyinfo.decrypt(password, new PasswordConverter());
                                Vector pkeyinfo_v = new Vector();
                                pkeyinfo_v.addElement(pkeyinfo);
                                SET bagAttrs = bag.getBagAttributes();
                                for (int k=0; k<bagAttrs.size(); k++) {
                                    Attribute attrs = (Attribute)bagAttrs.elementAt(k);
                                    OBJECT_IDENTIFIER aoid = attrs.getType();
                                    if (aoid.equals(SafeBag.FRIENDLY_NAME)) {
                                        SET val = attrs.getValues();
                                        ANY ss = (ANY)val.elementAt(0);
                                        ByteArrayInputStream bbis = new ByteArrayInputStream(ss.getEncoded());
                                        BMPString sss = (BMPString)(new BMPString.Template()).decode(bbis);
                                        String s = sss.toString();
                                        pkeyinfo_v.addElement(s);
                                    }
                                }
                                pkeyinfo_collection.addElement(pkeyinfo_v);
                            } else if (oid.equals(SafeBag.CERT_BAG)) {
                                CertBag cbag = (CertBag)bag.getInterpretedBagContent();    
                                OCTET_STRING str = (OCTET_STRING)cbag.getInterpretedCert();
                                byte[] x509cert = str.toByteArray();
                                Vector cert_v = new Vector();
                                cert_v.addElement(x509cert);
                                SET bagAttrs = bag.getBagAttributes();
                         
                                if (bagAttrs != null) {
                                    for (int k=0; k<bagAttrs.size(); k++) {
                                        Attribute attrs = (Attribute)bagAttrs.elementAt(k);
                                        OBJECT_IDENTIFIER aoid = attrs.getType();
                                        if (aoid.equals(SafeBag.FRIENDLY_NAME)) {
                                            SET val = attrs.getValues();
                                            ANY ss = (ANY)val.elementAt(0);
                                            ByteArrayInputStream bbis = new ByteArrayInputStream(ss.getEncoded());
                                            BMPString sss = (BMPString)(new BMPString.Template()).decode(bbis);
                                            String s = sss.toString();
                                            cert_v.addElement(s);
                                        }
                                    }
                                }

                                cert_collection.addElement(cert_v);
                            }
                        }
                    } catch (Exception e) {
                        CMS.debug("RestoreKeyCertPanel update: Exception="+e.toString());
                    }
                }
            
                importkeycert(pkeyinfo_collection, cert_collection);
            } else {
                context.put("updateStatus", "failure");
                throw new IOException("The pkcs12 file is not correct.");
            }
        }

        String subsystemtype = "";
        String cstype = "";
        try {
            subsystemtype = config.getString("preop.subsystem.select", "");
            cstype = config.getString("cs.type", "");
        } catch (Exception e) {
        }
        cstype = toLowerCaseSubsystemType(cstype);

        if (subsystemtype.equals("clone")) {
            CMS.debug("RestoreKeyCertPanel: this is the clone subsystem"); 
            boolean cloneReady = isCertdbCloned(request, context);
            if (!cloneReady) {
                CMS.debug("RestoreKeyCertPanel update: clone does not have all the certificates.");
                context.put("errorString", "Make sure you have copied the certificate database over to the clone");
                context.put("updateStatus", "failure");
                throw new IOException("Clone is not ready");
            }
        }

        config.putBoolean("preop.restorekeycert.done", true);
        try {
            config.commit(false);
        } catch (EBaseException e) {
        }

        getConfigEntriesFromMaster(request, response, context);
        context.put("updateStatus", "success");
    }

    private void getConfigEntriesFromMaster(HttpServletRequest request,
      HttpServletResponse response, Context context) throws IOException {
        try {
            IConfigStore config = CMS.getConfigStore();
            String cstype = "";
            try {
                cstype = config.getString("cs.type", "");
            } catch (Exception e) {
            }
            cstype = toLowerCaseSubsystemType(cstype);

            String session_id = CMS.getConfigSDSessionId();
            String sd_hostname = "";
            int sd_port = -1;
            String master_hostname = "";
            int master_port = -1;
            int master_ee_port = -1;
            try {
                sd_hostname = config.getString("securitydomain.host", "");
                sd_port = config.getInteger("securitydomain.httpsadminport", -1);
                master_hostname = config.getString("preop.master.hostname", "");
                master_port = config.getInteger("preop.master.httpsadminport", -1);
                master_ee_port = config.getInteger("preop.master.httpsport", -1);

                String content = "";
                if (cstype.equals("ca") || cstype.equals("kra")) {
                    content = "type=request&xmlOutput=true&sessionID="+session_id;
                    CMS.debug("http content=" + content);
                    updateNumberRange(master_hostname, master_ee_port, true, content, "request", response);

                    content = "type=serialNo&xmlOutput=true&sessionID="+session_id;
                    updateNumberRange(master_hostname, master_ee_port, true, content, "serialNo", response);

                    content = "type=replicaId&xmlOutput=true&sessionID="+session_id;
                    updateNumberRange(master_hostname, master_ee_port, true, content, "replicaId", response);
                }

                String list = "";
                try {
                    list = config.getString("preop.cert.list", "");
                } catch (Exception e) {
                }

                StringBuffer c1 = new StringBuffer();
                StringBuffer s1 = new StringBuffer(); 
                StringTokenizer tok = new StringTokenizer(list, ",");
                while (tok.hasMoreTokens()) {
                    String t1 = tok.nextToken();
                    if (t1.equals("sslserver"))
                        continue;
                    c1.append(",");
                    c1.append("cloning.");
                    c1.append(t1);
                    c1.append(".nickname,");
                    c1.append("cloning.");
                    c1.append(t1);
                    c1.append(".dn,");
                    c1.append("cloning.");
                    c1.append(t1);
                    c1.append(".keytype,");
                    c1.append("cloning.");
                    c1.append(t1);
                    c1.append(".keyalgorithm,");
                    c1.append("cloning.");
                    c1.append(t1);
                    c1.append(".privkey.id,");
                    c1.append("cloning.");
                    c1.append(t1);
                    c1.append(".pubkey.exponent,");
                    c1.append("cloning.");
                    c1.append(t1);
                    c1.append(".pubkey.modulus,");
                    c1.append("cloning.");
                    c1.append(t1);
                    c1.append(".pubkey.encoded");


                    if (s1.length()!=0)
                        s1.append(",");

                    s1.append(cstype);
                    s1.append(".");
                    s1.append(t1);
                }

                if (!cstype.equals("ca")) {
                    c1.append(",cloning.ca.hostname,cloning.ca.httpport,cloning.ca.httpsport,cloning.ca.list,cloning.ca.pkcs7,cloning.ca.type");
                } 

                if (cstype.equals("ca")) {
                    /* get ca connector details */
                    if (s1.length()!=0)
                        s1.append(",");
                    s1.append("ca.connector.KRA");
                }
                
                s1.append(",internaldb,internaldb.ldapauth,internaldb.ldapconn");

                content =
                        "op=get&names=cloning.token,instanceId,internaldb.basedn,internaldb.ldapauth.password,"
                        + "internaldb.replication.password" + c1.toString()
                        + "&substores=" + s1.toString()
                        + "&xmlOutput=true&sessionID="
                        + session_id;
                boolean success = updateConfigEntries(master_hostname, master_port, true,
                  "/"+cstype+"/admin/"+cstype+"/getConfigEntries", content, config, response);
                if (!success) {
                    context.put("errorString", "Failed to get configuration entries from the master");
                    throw new IOException("Failed to get configuration entries from the master");
                }
                config.putString("preop.clone.configuration", "true");
                try {
                    config.commit(false);
                } catch (Exception ee) {
                }
            } catch (IOException eee) {
                throw eee;
            } catch (Exception eee) {
                CMS.debug("RestoreKeyCertPanel: update exception caught:"+eee.toString());
            }

        } catch (IOException ee) {
            throw ee;
        } catch (Exception ee) {
        }
    }

    private void deleteExistingCerts() {
        IConfigStore cs = CMS.getConfigStore();
        try {
            String list = cs.getString("preop.cert.list", "");
            StringTokenizer st = new StringTokenizer(list, ",");
            while (st.hasMoreTokens()) {
                String s = st.nextToken();
                if (s.equals("sslserver"))
                    continue;
                String name = "preop.master."+s+".nickname";
                String nickname = cs.getString(name, "");
                CryptoManager cm = CryptoManager.getInstance();
                X509Certificate xcert = null;
                try {
                    xcert = cm.findCertByNickname(nickname);
                } catch (Exception ee) {
                    CMS.debug("RestoreKeyCertPanel deleteExistingCerts: Exception="+ee.toString());
                }
                CryptoToken ct = cm.getInternalKeyStorageToken();
                CryptoStore store = ct.getCryptoStore();
                try {
                    store.deleteCert(xcert);
                } catch (Exception ee) {
                    CMS.debug("RestoreKeyCertPanel deleteExistingCerts: Exception="+ee.toString());
                }
            }
        } catch (Exception e) {
            CMS.debug("RestoreKeyCertPanel deleteExistingCerts: Exception="+e.toString());
        } 
    }

    private org.mozilla.jss.crypto.PrivateKey.Type getPrivateKeyType(PublicKey pubkey) {
      CMS.debug("Key Algorithm '"+pubkey.getAlgorithm()+"'");
      if (pubkey.getAlgorithm().equals("EC")) {
        return org.mozilla.jss.crypto.PrivateKey.Type.EC;
      }
      return org.mozilla.jss.crypto.PrivateKey.Type.RSA;
    }

    private void importkeycert(Vector pkeyinfo_collection, 
      Vector cert_collection) throws IOException {
        CryptoManager cm = null;
        try {
            cm = CryptoManager.getInstance();
        } catch (Exception e) {
        }

        // delete all existing certificates first
        deleteExistingCerts();

        for (int i=0; i<pkeyinfo_collection.size(); i++) {
            try {
                Vector pkeyinfo_v = (Vector)pkeyinfo_collection.elementAt(i);
                PrivateKeyInfo pkeyinfo = (PrivateKeyInfo)pkeyinfo_v.elementAt(0);
                String nickname = (String)pkeyinfo_v.elementAt(1);
                byte[] x509cert = getX509Cert(nickname, cert_collection); 
                X509Certificate cert = cm.importCACertPackage(x509cert);
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                pkeyinfo.encode(bos);
                byte[] pkey = bos.toByteArray();

                PublicKey publickey = cert.getPublicKey();
                CryptoToken token = cm.getInternalKeyStorageToken();
                CryptoStore store = token.getCryptoStore();
                CMS.debug("RestoreKeyCertPanel deleteCert: this is pk11store");
                try {
                    store.deleteCert(cert);
                } catch (Exception ee) {
                    CMS.debug("RestoreKeyCertPanel importKeyCert: Exception="+ee.toString());
                }

                KeyGenerator kg = token.getKeyGenerator(KeyGenAlgorithm.DES3);
                SymmetricKey sk = kg.generate();
                byte iv[] = {0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1};
                IVParameterSpec param = new IVParameterSpec(iv);
                Cipher c = token.getCipherContext(EncryptionAlgorithm.DES3_CBC_PAD);
                c.initEncrypt(sk, param);
                byte[] encpkey = c.doFinal(pkey);
                
                KeyWrapper wrapper = token.getKeyWrapper(KeyWrapAlgorithm.DES3_CBC_PAD);
                wrapper.initUnwrap(sk, param);
                org.mozilla.jss.crypto.PrivateKey pp = wrapper.unwrapPrivate(encpkey, getPrivateKeyType(publickey), publickey);

            } catch (Exception e) {
                CMS.debug("RestoreKeyCertPanel importkeycert: Exception="+e.toString());
            }
        }

        for (int i=0; i<cert_collection.size(); i++) {
            try {
                Vector cert_v = (Vector)cert_collection.elementAt(i);
                byte[] cert = (byte[])cert_v.elementAt(0);
                if (cert_v.size() > 1) {
                    String name = (String)cert_v.elementAt(1);
                    // we need to delete the trusted CA certificate if it is
                    // the same as the ca signing certificate
                    if (isCASigningCert(name)) {
                        X509Certificate certchain = getX509CertFromToken(cert);
                        if (certchain != null) {
                            CryptoToken token = cm.getInternalKeyStorageToken();
                            CryptoStore store = token.getCryptoStore();
                            CMS.debug("RestoreKeyCertPanel deleteCert: this is pk11store");
                            if (store instanceof PK11Store) {
                                try {
                                    PK11Store pk11store = (PK11Store)store;
                                    pk11store.deleteCertOnly(certchain);
                                } catch (Exception ee) {
                                    CMS.debug("RestoreKeyCertPanel importKeyCert: Exception="+ee.toString());
                                }
                            }
                        }
                    }

                    X509Certificate xcert = cm.importUserCACertPackage(cert, name);
                    if (name.startsWith("caSigningCert")) {
                        // we need to change the trust attribute to CT
                        InternalCertificate icert = (InternalCertificate)xcert;
                        icert.setSSLTrust(InternalCertificate.TRUSTED_CA 
                          | InternalCertificate.TRUSTED_CLIENT_CA
                          | InternalCertificate.VALID_CA);
                    } else if (name.startsWith("auditSigningCert")) {
                        InternalCertificate icert = (InternalCertificate)xcert;
                        icert.setObjectSigningTrust(InternalCertificate.USER | InternalCertificate.VALID_PEER | InternalCertificate.TRUSTED_PEER);
                    }
                } else
                    cm.importCACertPackage(cert);
            } catch (Exception e) {
                CMS.debug("RestoreKeyCertPanel importkeycert: Exception="+e.toString());
            }
        }
    }

    private boolean isCASigningCert(String name) {
        String n = "preop.master.signing.nickname";
        IConfigStore cs = CMS.getConfigStore();
        try {
            String nickname = cs.getString(n);
            if (nickname.equals(name))
                return true;
        } catch (Exception e) {
            return false;
        }

        return false;
    }

    private X509Certificate getX509CertFromToken(byte[] cert) 
      throws IOException {
        try {
            X509CertImpl impl = new X509CertImpl(cert);
            String issuer_impl = impl.getIssuerDN().toString();
            BigInteger serial_impl = impl.getSerialNumber();
            CryptoManager cm = CryptoManager.getInstance();
            X509Certificate[] permcerts = cm.getPermCerts();
            for (int i=0; i<permcerts.length; i++) {
                String issuer_p = permcerts[i].getSubjectDN().toString();
                BigInteger serial_p = permcerts[i].getSerialNumber();
                if (issuer_p.equals(issuer_impl) && serial_p.compareTo(serial_impl) == 0) {
                    return permcerts[i];
                }
            }
        } catch (Exception e) {
            CMS.debug("RestoreKeyCertPanel getX509CertFromToken: Exception="+e.toString());
        }

        return null;
    }

    private byte[] getX509Cert(String nickname, Vector cert_collection) 
      throws IOException {
        for (int i=0; i<cert_collection.size(); i++) {
            Vector v = (Vector)cert_collection.elementAt(i);
            byte[] b = (byte[])v.elementAt(0);
            X509CertImpl impl = null;
            try {
                impl = new X509CertImpl(b);
            } catch (Exception e) {
                CMS.debug("RestoreKeyCertPanel getX509Cert: Exception="+e.toString());
                throw new IOException( e.toString() );
            }
            Principal subjectdn = impl.getSubjectDN();    
            if (LDAPDN.equals(subjectdn.toString(), nickname))
                return b;
        }

        return null;
    }

    /**
     * If validiate() returns false, this method will be called.
     */
    public void displayError(HttpServletRequest request,
        HttpServletResponse response,
        Context context)
    {
        context.put("title", "Import Keys and Certificates");
        context.put("password", "");
        context.put("path", "");
        context.put("panel", "admin/console/config/restorekeycertpanel.vm");
    }

    private boolean isCertdbCloned(HttpServletRequest request,
      Context context) {
        IConfigStore config = CMS.getConfigStore();
        String certList = "";
        try {
            CryptoManager cm = CryptoManager.getInstance();
            certList = config.getString("preop.cert.list");
            StringTokenizer st = new StringTokenizer(certList, ",");
            while (st.hasMoreTokens()) {
                String token = st.nextToken();
                if (token.equals("sslserver"))
                    continue;
                String tokenname = config.getString("preop.module.token", "");
                CryptoToken tok = cm.getTokenByName(tokenname);
                CryptoStore store = tok.getCryptoStore();
                String name1 = "preop.master."+token+".nickname";
                String nickname = config.getString(name1, "");
                if (!tokenname.equals("Internal Key Storage Token") &&
                  !tokenname.equals("internal"))
                    nickname = tokenname+":"+nickname;

                CMS.debug("RestoreKeyCertPanel isCertdbCloned: "+nickname);
                X509Certificate cert = cm.findCertByNickname(nickname);
                if (cert == null)
                    return false;
            }
        } catch (Exception e) {
            context.put("errorString", "Check your CS.cfg for cloning");
            return false;
        }

        return true;
    }
}
