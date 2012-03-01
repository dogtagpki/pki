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

import java.io.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.util.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.property.*;
import com.netscape.cmsutil.crypto.*;

import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.security.*;
import org.mozilla.jss.*;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.crypto.KeyPairGenerator;
import org.mozilla.jss.pkcs11.PK11KeyPairGenerator;

import com.netscape.cms.servlet.wizard.*;

public class SizePanel extends WizardPanelBase {
    private Vector mCerts = null;
    private WizardServlet mServlet = null;

    private String default_ecc_curve_name;
    private String default_rsa_key_size;
    private boolean mShowSigning = false;

    public SizePanel() {}

    /**
     * Initializes this panel.
     */
    public void init(WizardServlet servlet, ServletConfig config, int panelno, String id) 
        throws ServletException {
        setPanelNo(panelno);
        setName("Key Pairs");
        setId(id);
        mServlet = servlet;
    }

    public PropertySet getUsage() {
        PropertySet set = new PropertySet();
                                                                                
        Descriptor choiceDesc = new Descriptor(IDescriptor.CHOICE,
                "default,custom", null, /* no default parameter */
                "If 'default', the key size will be configured automatically. If 'custom', the key size will be set to the value of the parameter 'custom_size'.");

        set.add("choice", choiceDesc);
                                                                                
        Descriptor customSizeDesc = new Descriptor(IDescriptor.STRING, null, /* no constraint */
                null, /* no default parameter */
                "Custom Key Size");

        set.add("custom_size", customSizeDesc);
                                                                                
        return set;
    }

    public void cleanUp() throws IOException {
        IConfigStore cs = CMS.getConfigStore();
        /* clean up if necessary*/
        try {
            boolean done = cs.getBoolean("preop.SizePanel.done");
            cs.putBoolean("preop.SizePanel.done", false);
            cs.commit(false);
        } catch (Exception e) {
        }
    }

    public boolean isPanelDone() {
        IConfigStore cs = CMS.getConfigStore();
        try {
            boolean s = cs.getBoolean("preop.SizePanel.done", false);
            if (s != true) {
                return false;
            } else {
                return true;
            }
        } catch (EBaseException e) {}

        return false;
    }

    /**
     * Display the panel.
     */
    public void display(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        CMS.debug("SizePanel: display()");
        try {
          initParams(request, context);
        } catch (IOException e) {
        }

        context.put("firsttime", "false");
        String errorString = "";
        mCerts = new Vector();

        IConfigStore config = CMS.getConfigStore();
        try {
            boolean done = config.getBoolean("preop.SizePanel.done");
        } catch (Exception e) {
            context.put("firsttime", "true");
        }

        try {
            default_ecc_curve_name = config.getString("keys.ecc.curve.default", "nistp256"); 
        } catch (Exception e) {
        }

        try {
            default_rsa_key_size = config.getString("keys.rsa.keysize.default", "2048"); 
        } catch (Exception e) {
        }

        try {
            // same token for now
            String token = config.getString(PRE_CONF_CA_TOKEN);
            String certTags = config.getString("preop.cert.list");
            String rsaCertTags = config.getString("preop.cert.rsalist", "");
            context.put("rsaTags", rsaCertTags);
            StringTokenizer st = new StringTokenizer(certTags, ",");
            mShowSigning = false;

            while (st.hasMoreTokens()) {
                String certTag = st.nextToken();
                String nn = config.getString(
                        PCERT_PREFIX + certTag + ".nickname");
                Cert c = new Cert(token, nn, certTag);

                String s = config.getString(
                        PCERT_PREFIX + certTag + ".keysize.select", "default");

                if (s.equals("default")) {
                    c.setKeyOption("default");
                }
                if (s.equals("custom")) {
                    c.setKeyOption("custom");
                }

                s = config.getString(
                        PCERT_PREFIX + certTag + ".keysize.custom_size",
                        default_rsa_key_size);
                c.setCustomKeysize(s);

                s = config.getString(
                        PCERT_PREFIX + certTag + ".curvename.custom_name",
                        default_ecc_curve_name);
                c.setCustomCurvename(s);

                boolean signingRequired = config.getBoolean(
                        PCERT_PREFIX + certTag + ".signing.required",
                        false);
                c.setSigningRequired(signingRequired);
                if (signingRequired) mShowSigning = true;

                String userfriendlyname = config.getString(
                        PCERT_PREFIX + certTag + ".userfriendlyname");
                c.setUserFriendlyName(userfriendlyname);
                boolean enable = config.getBoolean(PCERT_PREFIX+certTag+".enable", true); 
                c.setEnable(enable);
                mCerts.addElement(c);
            }// while
        } catch (Exception e) {
            CMS.debug("SizePanel: display() " + e.toString());
        }
        CMS.debug("SizePanel: display() 1");

        context.put("show_signing", mShowSigning ? "true" : "false");
        context.put("certs", mCerts);
        context.put("errorString", errorString);
        context.put("default_keysize", default_rsa_key_size);
        context.put("default_ecc_curvename", default_ecc_curve_name);
        context.put("panel", "admin/console/config/sizepanel.vm");
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
            Context context) throws IOException, NumberFormatException {
        CMS.debug("SizePanel: update()");
        boolean hasErr = false;
        IConfigStore config = CMS.getConfigStore();
        String select1 = "";
        String val1 = null;
        boolean hasChanged = false;
        try {
            select1 = config.getString("preop.subsystem.select", "");
        } catch (Exception e) {
        }

        context.put("firsttime", "false");
        boolean done = false;
        try {
            done = config.getBoolean("preop.SizePanel.done");
        } catch (Exception e) {
            context.put("firsttime", "true");
            if (select1.equals("clone")) {
                // preset the sslserver dn for cloning case
                try {
                   String val = config.getString("preop.cert.sslserver.dn", "");
                   config.putString("preop.cert.sslserver.dn", val+",o=clone");
                } catch (Exception ee) {
                }
            }
        }
            
        String token = "";
        try {
            token = config.getString(PRE_CONF_CA_TOKEN, "");
            Enumeration c = mCerts.elements();

            while (c.hasMoreElements()) {
                Cert cert = (Cert) c.nextElement();
                String ct = cert.getCertTag();
                boolean enable = config.getBoolean(PCERT_PREFIX+ct+".enable", true); 
                if (!enable)
                    continue;

                String keytype = HttpInput.getKeyType(request, ct + "_keytype"); // rsa or ecc

                String keyalgorithm = HttpInput.getString(request, ct + "_keyalgorithm");
                if (keyalgorithm == null) {
                    if (keytype != null && keytype.equals("ecc")) {
                        keyalgorithm = "SHA256withEC";
                    } else {
                        keyalgorithm = "SHA256withRSA";
                    }
                }

                String signingalgorithm = HttpInput.getString(request, ct + "_signingalgorithm");
                if (signingalgorithm == null) {
                    signingalgorithm = keyalgorithm;
                }

                String select = HttpInput.getID(request, ct + "_choice");

                if (select == null) {
                    CMS.debug("SizePanel: " + ct + "_choice not found");
                    throw new IOException(
                            "SizePanel: " + ct + "_choice not found");
                }
                CMS.debug(
                        "SizePanel: update() keysize choice selected:" + select);
                String oldkeysize = 
                  config.getString(PCERT_PREFIX+ct+".keysize.size", "");
                String oldkeytype = 
                  config.getString(PCERT_PREFIX + ct + ".keytype", "");
                String oldkeyalgorithm = 
                  config.getString(PCERT_PREFIX + ct + ".keyalgorithm", "");
                String oldsigningalgorithm = 
                  config.getString(PCERT_PREFIX + ct + ".signingalgorithm", "");
                String oldcurvename =
                  config.getString(PCERT_PREFIX + ct + ".curvename.name", "");

                if (select.equals("default")) {
                    // XXXrenaming these...keep for now just in case
                    config.putString("preop.keysize.select", "default");
                    if (keytype != null && keytype.equals("ecc")) {
                      config.putString("preop.curvename.custom_name",
                            default_ecc_curve_name);
                      config.putString("preop.curvename.name", default_ecc_curve_name);
                    } else {
                      config.putString("preop.keysize.custom_size",
                            default_rsa_key_size);
                      config.putString("preop.keysize.size", default_rsa_key_size);
                    }

                    config.putString(PCERT_PREFIX + ct + ".keytype", keytype);
                    config.putString(PCERT_PREFIX + ct + ".keyalgorithm", keyalgorithm);
                    config.putString(PCERT_PREFIX + ct + ".signingalgorithm", signingalgorithm);
                    config.putString(PCERT_PREFIX + ct + ".keysize.select",
                            "default");

                    if (keytype != null && keytype.equals("ecc")) {
                      config.putString(PCERT_PREFIX + ct + 
                            ".curvename.custom_name",
                            default_ecc_curve_name);
                      config.putString(PCERT_PREFIX + ct + ".curvename.name",
                            default_ecc_curve_name);
                    } else {
                      config.putString(PCERT_PREFIX + ct + 
                            ".keysize.custom_size",
                            default_rsa_key_size);
                      config.putString(PCERT_PREFIX + ct + ".keysize.size",
                            default_rsa_key_size);
                    }
                } else if (select.equals("custom")) {
                    // XXXrenaming these...keep for now just in case
                    config.putString("preop.keysize.select", "custom");
                    if (keytype != null && keytype.equals("ecc")) {
                        config.putString("preop.curvename.name", 
                            HttpInput.getString(request, ct + "_custom_curvename"));
                        config.putString("preop.curvename.custom_name",
                            HttpInput.getString(request, ct + "_custom_curvename"));
                    } else {
                        config.putString("preop.keysize.size", 
                            HttpInput.getKeySize(request, ct + "_custom_size", keytype));
                        config.putString("preop.keysize.custom_size",
                            HttpInput.getKeySize(request, ct + "_custom_size", keytype));
                    }

                    config.putString(PCERT_PREFIX + ct + ".keytype", keytype);
                    config.putString(PCERT_PREFIX + ct + ".keyalgorithm", keyalgorithm);
                    config.putString(PCERT_PREFIX + ct + ".signingalgorithm", signingalgorithm);
                    config.putString(PCERT_PREFIX + ct + ".keysize.select",
                            "custom");

                    if (keytype != null && keytype.equals("ecc")) {
                        config.putString(PCERT_PREFIX + ct + ".curvename.custom_name",
                            HttpInput.getString(request, ct + "_custom_curvename"));
                        config.putString(PCERT_PREFIX + ct + ".curvename.name",
                            HttpInput.getString(request, ct + "_custom_curvename"));
                    } else {
                        config.putString(PCERT_PREFIX + ct + ".keysize.custom_size",
                            HttpInput.getKeySize(request, ct + "_custom_size"));
                        config.putString(PCERT_PREFIX + ct + ".keysize.size",
                            HttpInput.getKeySize(request, ct + "_custom_size"));
                    }
                } else {
                    CMS.debug("SizePanel: invalid choice " + select);
                    throw new IOException("invalid choice " + select);
                }

                String newkeysize = 
                  config.getString(PCERT_PREFIX+ct+".keysize.size", "");
                String newkeytype = 
                  config.getString(PCERT_PREFIX + ct + ".keytype", "");
                String newkeyalgorithm = 
                  config.getString(PCERT_PREFIX + ct + ".keyalgorithm", "");
                String newsigningalgorithm = 
                  config.getString(PCERT_PREFIX + ct + ".signingalgorithm", "");
                String newcurvename = 
                  config.getString(PCERT_PREFIX+ct+".curvename.name", "");

                if (!oldkeysize.equals(newkeysize) || 
                  !oldkeytype.equals(newkeytype) ||
                  !oldkeyalgorithm.equals(newkeyalgorithm) ||
                  !oldsigningalgorithm.equals(newsigningalgorithm) ||
                  !oldcurvename.equals(newcurvename))
                    hasChanged = true;
            }// while

            try {
                config.commit(false);
            } catch (EBaseException e) { 
                CMS.debug("SizePanel: update() Exception caught at config commit: " + e.toString());
            }

            val1 = HttpInput.getID(request, "generateKeyPair");

            if (hasChanged || (val1 != null && !val1.equals(""))) {
                mServlet.cleanUpFromPanel(mServlet.getPanelNo(request));
            } else if (isPanelDone()) {
                context.put("updateStatus", "success");
                return;
            }
        } catch (IOException e) { 
            CMS.debug("SizePanel: update() IOException caught: " + e.toString());
            context.put("updateStatus", "failure");
            throw e;
        } catch (NumberFormatException e) {
            CMS.debug("SizePanel: update() NumberFormatException caught: " + e.toString());
            context.put("updateStatus", "failure");
            throw e;
        } catch (Exception e) { 
            CMS.debug("SizePanel: update() Exception caught: " + e.toString());
        }

        // generate key pair 
        Enumeration c = mCerts.elements();

        while (c.hasMoreElements()) {
            Cert cert = (Cert) c.nextElement();
            String ct = cert.getCertTag();
            String friendlyName = ct;
            boolean enable = true;
            try {
                enable = config.getBoolean(PCERT_PREFIX+ct+".enable", true);
                friendlyName = config.getString(PCERT_PREFIX + ct + ".userfriendlyname", ct);
            } catch (Exception e) {
            }

            if (!enable)
                continue;

            try {
                String keytype = config.getString(PCERT_PREFIX + ct + ".keytype");
                String keyalgorithm = config.getString(PCERT_PREFIX + ct + ".keyalgorithm");
                                                                               
                if (keytype.equals("rsa")) {
                    int keysize = config.getInteger(
                        PCERT_PREFIX + ct + ".keysize.size");

                    createRSAKeyPair(token, keysize, config, ct);
                } else {
                    String curveName = config.getString(
                        PCERT_PREFIX + ct + ".curvename.name", default_ecc_curve_name);
                    createECCKeyPair(token, curveName, config, ct);
                }
                config.commit(false);
            } catch (Exception e) {
                CMS.debug(e);
                CMS.debug("SizePanel: key generation failure: " + e.toString());
                context.put("updateStatus", "failure");
                throw new IOException("key generation failure for the certificate: " + friendlyName + 
                                      ".  See the logs for details.");
            }
        } // while

        if (hasErr == false) {
          config.putBoolean("preop.SizePanel.done", true);
          try {
            config.commit(false);
          } catch (EBaseException e) { 
            CMS.debug(
                  "SizePanel: update() Exception caught at config commit: "
                            + e.toString());
	  }
	}
        CMS.debug("SizePanel: update() done");
        context.put("updateStatus", "success");

    }

    public void createECCKeyPair(String token, String curveName, IConfigStore config, String ct) 
            throws NoSuchAlgorithmException, NoSuchTokenException, TokenException, CryptoManager.NotInitializedException
    {
        CMS.debug("Generating ECC key pair with curvename="+ curveName +
                    ", token="+token);
        KeyPair pair = null;
        /*
         * default ssl server cert to ECDHE unless stated otherwise
         * note: IE only supports "ECDHE", but "ECDH" is more efficient
         *
         * for "ECDHE", server.xml should have the following for ciphers:
         * +TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
         * -TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
         *
         * for "ECDH", server.xml should have the following for ciphers:
         * -TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
         * +TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
         */
        String sslType = "ECDHE";
        try {
            sslType = config.getString(PCERT_PREFIX + ct + "ec.type", "ECDHE");
        } catch (Exception e) {
            CMS.debug("SizePanel: createECCKeyPair() Exception caught at config.getString for ec type");
        }

        // ECDHE needs "SIGN" but no "DERIVE"
        org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage usages_mask[] = {
            org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage.DERIVE
        };

        // ECDH needs "DERIVE" but no any kind of "SIGN"
        org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage ECDH_usages_mask[] = {
            org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage.SIGN,
            org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage.SIGN_RECOVER,
        };

        do {
          if (ct.equals("sslserver") && sslType.equalsIgnoreCase("ECDH")) {
              CMS.debug("SizePanel: createECCKeypair: sslserver cert for ECDH. Make sure server.xml is set properly with -TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,+TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA");
              pair = CryptoUtil.generateECCKeyPair(token, curveName,
                    null,
                    ECDH_usages_mask);
          } else {
              if (ct.equals("sslserver")) {
                CMS.debug("SizePanel: createECCKeypair: sslserver cert for ECDHE. Make sure server.xml is set properly with +TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,-TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA");
              }
              pair = CryptoUtil.generateECCKeyPair(token, curveName,
                    null,
                    usages_mask);
          }

          // XXX - store curve , w
          byte id[] = ((org.mozilla.jss.crypto.PrivateKey) pair.getPrivate()).getUniqueID();
          String kid = CryptoUtil.byte2string(id);
          config.putString(PCERT_PREFIX + ct + ".privkey.id", kid);

          // try to locate the private key
            org.mozilla.jss.crypto.PrivateKey privk = 
                CryptoUtil.findPrivateKeyFromID(CryptoUtil.string2byte(kid));
            if (privk == null)  {
              CMS.debug("Found bad ECC key id " + kid);
              pair = null;
            }
        } while (pair == null);

        CMS.debug("Public key class " + pair.getPublic().getClass().getName()); 
        byte encoded[] = pair.getPublic().getEncoded();
        config.putString(PCERT_PREFIX + ct + ".pubkey.encoded",
          CryptoUtil.byte2string(encoded));

        String keyAlgo = "";
        try {
            keyAlgo = config.getString(PCERT_PREFIX + ct + ".signingalgorithm");
        } catch (Exception e1) {
        }

        setSigningAlgorithm(ct, keyAlgo, config); 
    }

    public void createRSAKeyPair(String token, int keysize, IConfigStore config, String ct) 
            throws NoSuchAlgorithmException, NoSuchTokenException, TokenException, CryptoManager.NotInitializedException
    {
        /* generate key pair */
        KeyPair pair = null;
        do {
          pair = CryptoUtil.generateRSAKeyPair(token, keysize);
          byte id[] = ((org.mozilla.jss.crypto.PrivateKey) pair.getPrivate()).getUniqueID();
          String kid =  CryptoUtil.byte2string(id);
          config.putString(PCERT_PREFIX + ct + ".privkey.id", kid);
          // try to locate the private key
          org.mozilla.jss.crypto.PrivateKey privk = 
                CryptoUtil.findPrivateKeyFromID(CryptoUtil.string2byte(kid));
            if (privk == null)  {
              CMS.debug("Found bad RSA key id " + kid);
              pair = null;
            }
        } while (pair == null);

        byte modulus[] = ((RSAPublicKey) pair.getPublic()).getModulus().toByteArray();
        byte exponent[] = ((RSAPublicKey) pair.getPublic()).getPublicExponent().toByteArray();

        config.putString(PCERT_PREFIX + ct + ".pubkey.modulus",
            CryptoUtil.byte2string(modulus));
        config.putString(PCERT_PREFIX + ct + ".pubkey.exponent",
            CryptoUtil.byte2string(exponent));

        String keyAlgo = "";
        try {
            keyAlgo = config.getString(PCERT_PREFIX + ct + ".signingalgorithm");
        } catch (Exception e1) {
        }

        setSigningAlgorithm(ct, keyAlgo, config); 
    }

    public void setSigningAlgorithm(String ct, String keyAlgo, IConfigStore config) {
        String systemType = "";
        try {
          systemType = config.getString("preop.system.name");
        } catch (Exception e1) {
        }
        if (systemType.equalsIgnoreCase("CA")) {
          if (ct.equals("signing")) {
            config.putString("ca.signing.defaultSigningAlgorithm",
                           keyAlgo);
            config.putString("ca.crl.MasterCRL.signingAlgorithm",
                           keyAlgo);
          } else if (ct.equals("ocsp_signing")) {
            config.putString("ca.ocsp_signing.defaultSigningAlgorithm",
                           keyAlgo);
          }
        } else if (systemType.equalsIgnoreCase("OCSP")) {
          if (ct.equals("signing")) {
             config.putString("ocsp.signing.defaultSigningAlgorithm",
                           keyAlgo);
           }
        } else if (systemType.equalsIgnoreCase("KRA") ||
               systemType.equalsIgnoreCase("DRM")) {
           if (ct.equals("transport")) {
                config.putString("kra.transportUnit.signingAlgorithm", keyAlgo);
           }
        }
    }

    public void initParams(HttpServletRequest request, Context context)
                   throws IOException
    {
        IConfigStore config = CMS.getConfigStore();
        String s = "";
        try {
            context.put("title", "Key Pairs");

            s = config.getString("preop.subsystem.select", "");
            context.put("select", s);

            s = config.getString("preop.hierarchy.select", "root");
            context.put("hselect", s);

            s = config.getString("preop.ecc.algorithm.list", "SHA256withEC,SHA1withEC,SHA384withEC,SHA512withEC");
            context.put("ecclist", s);

            s = config.getString("preop.rsa.algorithm.list", "SHA256withRSA,SHA1withRSA,SHA512withRSA,MD5withRSA,MD2withRSA");
            context.put("rsalist", s);

            s = config.getString("keys.ecc.curve.list", "nistp256");
            context.put("curvelist", s);

            s = config.getString("keys.ecc.curve.display.list", "nistp256");
            context.put("displaycurvelist", s);

            s = config.getString("pkicreate.subsystem_type");
            context.put("subsystemtype", s);

        } catch (Exception e) {
            CMS.debug("SizePanel(): initParams: unable to set all initial parameters:" + e);
        }
    }

    /**
     * If validiate() returns false, this method will be called.
     */
    public void displayError(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        try {
          initParams(request, context);
        } catch (IOException e) {
        }

        context.put("certs", mCerts);
        context.put("show_signing", mShowSigning ? "true" : "false");
        context.put("default_keysize", default_rsa_key_size);
        context.put("default_ecc_curvename", default_ecc_curve_name);

        context.put("panel", "admin/console/config/sizepanel.vm");
    }
}
