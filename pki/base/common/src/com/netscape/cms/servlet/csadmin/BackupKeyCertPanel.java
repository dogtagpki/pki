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
import org.mozilla.jss.util.Password;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.util.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.property.*;
import java.io.*;
import java.net.URL;
import com.netscape.certsrv.base.*;
import java.util.*;
import java.security.*;
import java.security.cert.*;
import java.security.KeyPair;
import netscape.security.util.*;
import netscape.security.pkcs.*;
import netscape.security.x509.*;
import org.mozilla.jss.*;
import org.mozilla.jss.asn1.*;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.pkcs12.*;
import org.mozilla.jss.pkix.primitive.*;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.crypto.PrivateKey;
import com.netscape.cmsutil.crypto.*;

import com.netscape.cms.servlet.wizard.*;

public class BackupKeyCertPanel extends WizardPanelBase {

    public BackupKeyCertPanel() {}

    /**
     * Initializes this panel.
     */
    public void init(ServletConfig config, int panelno) 
        throws ServletException {
        setPanelNo(panelno);
        setName("Export Keys and Certificates");
    }

    public void init(WizardServlet servlet, ServletConfig config, int panelno, String id)
        throws ServletException {
        setPanelNo(panelno);
        setName("Export Keys and Certificates");
        setId(id);
    }

    public void cleanUp() throws IOException {
        IConfigStore cs = CMS.getConfigStore();
        /* clean up if necessary */
        try {
            boolean done = cs.getBoolean("preop.backupkeycert.done");
            cs.putBoolean("preop.backupkeycert.done", false);
            cs.commit(false);
        } catch (Exception e) {
        }
    }

    public boolean shouldSkip() {
        IConfigStore cs = CMS.getConfigStore();

        try {
            String s = cs.getString("preop.module.token", "");
            if (s.equals("Internal Key Storage Token")) 
                return false;
        } catch (Exception e) {
        }
 
        return true;
    }

    public boolean isPanelDone() {
        IConfigStore cs = CMS.getConfigStore();
        try {
            String s = cs.getString("preop.backupkeycert.done", "");
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
        context.put("title", "Export Keys and Certificates");
        IConfigStore config = CMS.getConfigStore();

        if (isPanelDone()) {
            try {
                boolean enable = config.getBoolean("preop.backupkeys.enable");
                if (enable) {
                    context.put("dobackup", "checked");
                    context.put("nobackup", "");
                } else {
                    context.put("dobackup", "");
                    context.put("nobackup", "checked");
                }
            } catch (Exception e) {
            }
        } else {
            context.put("dobackup", "");
            context.put("nobackup", "checked");
        }

        context.put("panel", "admin/console/config/backupkeycertpanel.vm");
        context.put("pwd", "");
        context.put("pwdagain", "");
        context.put("errorString", "");
    }

    /**
     * Checks if the given parameters are valid.
     */
    public void validate(HttpServletRequest request,
      HttpServletResponse response, Context context) throws IOException {
        String select = HttpInput.getID(request, "choice");
        if (select.equals("backupkey")) {
            String pwd = request.getParameter("__pwd");
            String pwdAgain = request.getParameter("__pwdagain");
            if (pwd == null || pwdAgain == null || pwd.equals("") || pwdAgain.equals("")) {
                CMS.debug("BackupKeyCertPanel validate: Password is null");
                context.put("updateStatus", "validate-failure");
                throw new IOException("PK12 password is empty.");
            }

            if (!pwd.equals(pwdAgain)) {
                CMS.debug("BackupKeyCertPanel validate: Password and password again are not the same.");
                context.put("updateStatus", "validate-failure");
                throw new IOException("PK12 password is different from the PK12 password again.");
            }
        }
    }

    /**
     * Commit parameter changes
     */
    public void update(HttpServletRequest request,
            HttpServletResponse response,
            Context context) throws IOException {
        IConfigStore config = CMS.getConfigStore();

        String select = HttpInput.getID(request, "choice");
        if (select.equals("backupkey")) {
            CMS.debug("BackupKeyCertPanel update: backup");
            config.putBoolean("preop.backupkeys.enable", true);
            backupKeysCerts(request);
        } else {
            CMS.debug("BackupKeyCertPanel update: no backup");
            config.putBoolean("preop.backupkeys.enable", false);
        }

        config.putBoolean("preop.backupkeycert.done", true);
        try {
            config.commit(false);
        } catch (EBaseException e) {
        }
        context.put("updateStatus", "success");
    }

    /**
     * If validiate() returns false, this method will be called.
     */
    public void displayError(HttpServletRequest request,
        HttpServletResponse response,
        Context context)
    {
        String select = "";
        try {
            select = HttpInput.getID(request, "choice");
        } catch (Exception e) {
        }

        if (select.equals("backupkey")) {
            context.put("dobackup", "checked");
            context.put("nobackup", "");
        } else {
            context.put("dobackup", "");
            context.put("nobackup", "checked");
        }

        context.put("pwd", "");
        context.put("pwdagain", "");
        context.put("title", "Export Keys and Certificates");
        context.put("panel", "admin/console/config/backupkeycertpanel.vm");
    }

    public void backupKeysCerts(HttpServletRequest request) 
      throws IOException {
        CMS.debug("BackupKeyCertPanel backupKeysCerts: start");
        IConfigStore cs = CMS.getConfigStore();
        String certlist = "";
        try {
            certlist = cs.getString("preop.cert.list");
        } catch (Exception e) {
        }

        StringTokenizer st = new StringTokenizer(certlist, ",");
        CryptoManager cm = null;
        try {
            cm = CryptoManager.getInstance();
        } catch (Exception e) {
            CMS.debug( "BackupKeyCertPanel::backupKeysCerts() - "
                     + "Exception="+e.toString() );
            throw new IOException( e.toString() );
        }

        String pwd = request.getParameter("__pwd");
        Password pass = new org.mozilla.jss.util.Password(pwd.toCharArray());
        SEQUENCE encSafeContents = new SEQUENCE();
        SEQUENCE safeContents = new SEQUENCE();
        while (st.hasMoreTokens()) {
            String t = st.nextToken();
            if (t.equals("sslserver"))
                continue;
            String nickname = "";
            String modname = "";
            try {
                nickname = cs.getString("preop.cert."+t+".nickname");
                modname = cs.getString("preop.module.token");
            } catch (Exception e) {
            }
            if (!modname.equals("Internal Key Storage Token"))
                nickname = modname+":"+nickname;

            X509Certificate x509cert = null;
            byte localKeyId[] = null;
            try {
                x509cert = cm.findCertByNickname(nickname);
                localKeyId = addCertBag(x509cert, nickname, safeContents);
            } catch (IOException e) {
                throw e;
            } catch (Exception e) {
                CMS.debug("BackupKeyCertPanel: Exception="+e.toString());
                throw new IOException("Failed to create pkcs12 file.");
            }

            try {
                PrivateKey pkey = cm.findPrivKeyByCert(x509cert);
                addKeyBag(pkey, x509cert, pass, localKeyId, encSafeContents);
            } catch (Exception e) {
                CMS.debug("BackupKeyCertPanel: Exception="+e.toString());
                throw new IOException("Failed to create pkcs12 file.");
            }
        } //while loop
   
        X509Certificate[] cacerts = cm.getCACerts();

        for (int i=0; i<cacerts.length; i++) {
            //String nickname = cacerts[i].getSubjectDN().toString();
            String nickname = null;
            try {
                byte[] localKeyId = addCertBag(cacerts[i], nickname, safeContents);
            } catch (IOException e) {
                throw e;
            } catch (Exception e) {
                CMS.debug("BackupKeyCertPanel backKeysCerts: Exception="+e.toString());
                throw new IOException("Failed to create pkcs12 file.");
            }
        }

        try {
            AuthenticatedSafes authSafes = new AuthenticatedSafes();
            authSafes.addSafeContents(safeContents);
            authSafes.addSafeContents(encSafeContents);                  
            PFX pfx = new PFX(authSafes);
            pfx.computeMacData(pass, null, 5); 
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            pfx.encode(bos);
            byte[] output = bos.toByteArray();
            cs.putString("preop.pkcs12", CryptoUtil.byte2string(output));
            pass.clear();
            cs.commit(false);
        } catch (Exception e) {
            CMS.debug("BackupKeyCertPanel backupKeysCerts: Exception="+e.toString());
        }
    }

    private void addKeyBag(PrivateKey pkey, X509Certificate x509cert,
      Password pass, byte[] localKeyId, SEQUENCE safeContents) 
      throws IOException {
        try {
            PasswordConverter passConverter = new PasswordConverter();

            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            byte salt[] = random.generateSeed(4); // 4 bytes salt
            byte[] priData = getEncodedKey(pkey);

            PrivateKeyInfo pki = (PrivateKeyInfo)
              ASN1Util.decode(PrivateKeyInfo.getTemplate(), priData);
            ASN1Value key = EncryptedPrivateKeyInfo.createPBE(
              PBEAlgorithm.PBE_SHA1_DES3_CBC,
              pass, salt, 1, passConverter, pki);
            SET keyAttrs = createBagAttrs(
              x509cert.getSubjectDN().toString(), localKeyId);
            SafeBag keyBag = new SafeBag(SafeBag.PKCS8_SHROUDED_KEY_BAG, 
              key, keyAttrs);
            safeContents.addElement(keyBag);
        } catch (Exception e) {
            CMS.debug("BackupKeyCertPanel getKeyBag: Exception="+e.toString());
            throw new IOException("Failed to create pk12 file.");
        }
    }

    private byte[] addCertBag(X509Certificate x509cert, String nickname, 
      SEQUENCE safeContents) throws IOException {
        byte[] localKeyId = null;
        try {
            ASN1Value cert = new OCTET_STRING(x509cert.getEncoded());
            localKeyId = createLocalKeyId(x509cert);
            SET certAttrs = null;
            if (nickname != null)
                certAttrs = createBagAttrs(nickname, localKeyId);
            SafeBag certBag = new SafeBag(SafeBag.CERT_BAG,
              new CertBag(CertBag.X509_CERT_TYPE, cert), certAttrs);
            safeContents.addElement(certBag);
        } catch (Exception e) {
            CMS.debug("BackupKeyCertPanel addCertBag: "+e.toString());
            throw new IOException("Failed to create pk12 file.");
        }

        return localKeyId;
    }

    private byte[] getEncodedKey(PrivateKey pkey) {
        try {
            CryptoManager cm = CryptoManager.getInstance();
            CryptoToken token = cm.getInternalKeyStorageToken();
            KeyGenerator kg = token.getKeyGenerator(KeyGenAlgorithm.DES3);
            SymmetricKey sk = kg.generate();
            KeyWrapper wrapper = token.getKeyWrapper(KeyWrapAlgorithm.DES3_CBC_PAD);
            byte iv[] = {0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1};
            IVParameterSpec param = new IVParameterSpec(iv);
            wrapper.initWrap(sk, param);
            byte[] enckey = wrapper.wrap(pkey);
            Cipher c = token.getCipherContext(EncryptionAlgorithm.DES3_CBC_PAD);
            c.initDecrypt(sk, param);
            byte[] recovered = c.doFinal(enckey);
            return recovered;
        } catch (Exception e) {
            CMS.debug("BackupKeyCertPanel getEncodedKey: Exception="+e.toString());
        }

        return null;
    }

    private byte[] createLocalKeyId(X509Certificate cert) 
      throws IOException {
        try {
            // SHA1 hash of the X509Cert der encoding
            byte certDer[] = cert.getEncoded();

            MessageDigest md = MessageDigest.getInstance("SHA");

            md.update(certDer);
            return md.digest();
        } catch (CertificateEncodingException e) {
            CMS.debug("BackupKeyCertPanel createLocalKeyId: Exception: "+e.toString());
            throw new IOException("Failed to encode certificate.");
        } catch (NoSuchAlgorithmException e) {
            CMS.debug("BackupKeyCertPanel createLocalKeyId: Exception: "+e.toString());
            throw new IOException("No such algorithm supported.");
        }
    }

    private SET createBagAttrs(String nickName, byte localKeyId[])
      throws IOException {
        try {
            SET attrs = new SET();
            SEQUENCE nickNameAttr = new SEQUENCE();

            nickNameAttr.addElement(SafeBag.FRIENDLY_NAME);
            SET nickNameSet = new SET();

            nickNameSet.addElement(new BMPString(nickName));
            nickNameAttr.addElement(nickNameSet);
            attrs.addElement(nickNameAttr);
            SEQUENCE localKeyAttr = new SEQUENCE();

            localKeyAttr.addElement(SafeBag.LOCAL_KEY_ID);
            SET localKeySet = new SET();

            localKeySet.addElement(new OCTET_STRING(localKeyId));
            localKeyAttr.addElement(localKeySet);
            attrs.addElement(localKeyAttr);
            return attrs;
        } catch (CharConversionException e) {
            CMS.debug("BackupKeyCertPanel createBagAttrs: Exception="+e.toString());
            throw new IOException("Failed to create PKCS12 file.");
        }
    }
}
