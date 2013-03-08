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
package com.netscape.ocsp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.util.Enumeration;
import java.util.Hashtable;

import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;
import netscape.security.x509.AlgorithmId;
import netscape.security.x509.CertificateChain;
import netscape.security.x509.X500Name;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509Key;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.pkix.primitive.AlgorithmIdentifier;
import org.mozilla.jss.pkix.primitive.Name;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.ocsp.IDefStore;
import com.netscape.certsrv.ocsp.IOCSPAuthority;
import com.netscape.certsrv.ocsp.IOCSPService;
import com.netscape.certsrv.ocsp.IOCSPStore;
import com.netscape.certsrv.request.IRequestListener;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.security.ISigningUnit;
import com.netscape.cmscore.util.Debug;
import com.netscape.cmsutil.ocsp.BasicOCSPResponse;
import com.netscape.cmsutil.ocsp.KeyHashID;
import com.netscape.cmsutil.ocsp.NameID;
import com.netscape.cmsutil.ocsp.OCSPRequest;
import com.netscape.cmsutil.ocsp.OCSPResponse;
import com.netscape.cmsutil.ocsp.ResponderID;
import com.netscape.cmsutil.ocsp.ResponseData;

/**
 * A class represents a Certificate Authority that is
 * responsible for certificate specific operations.
 * <P>
 *
 * @author lhsiao
 * @version $Revision$, $Date$
 */
public class OCSPAuthority implements IOCSPAuthority, IOCSPService, ISubsystem, IAuthority {

    private long mServedTime = 0;

    public final static OBJECT_IDENTIFIER OCSP_NONCE = new OBJECT_IDENTIFIER("1.3.6.1.5.5.7.48.1.2");

    private Hashtable<String, IOCSPStore> mStores = new Hashtable<String, IOCSPStore>();
    private String mId = "ocsp";
    private IConfigStore mConfig = null;
    private SigningUnit mSigningUnit;
    private CertificateChain mCertChain = null;
    private X509CertImpl mCert = null;
    private X500Name mName = null;
    private String mNickname = null;
    private String[] mOCSPSigningAlgorithms = null;
    private IOCSPStore mDefStore = null;

    public long mNumOCSPRequest = 0;
    public long mTotalTime = 0;
    public long mTotalData = 0;
    public long mSignTime = 0;
    public long mLookupTime = 0;

    protected ILogger mLogger = CMS.getLogger();

    /**
     * Retrieves the name of this subsystem.
     */
    public String getId() {
        return mId;
    }

    /**
     * Sets specific to this subsystem.
     */
    public void setId(String id) throws EBaseException {
        mId = id;
    }

    /**
     * Initializes this subsystem with the given configuration
     * store.
     * <P>
     *
     * @param owner owner of this subsystem
     * @param config configuration store
     * @exception EBaseException failed to initialize
     */
    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {
        try {
            mConfig = config;

            initSigUnit();

            // create default OCSP Store
            try {
                String defStoreId = mConfig.getString(PROP_DEF_STORE_ID, null);

                if (defStoreId == null) {
                    throw new EBaseException("default id not found");
                }

                IConfigStore storeConfig = mConfig.getSubStore(PROP_STORE);
                Enumeration<String> ids = storeConfig.getSubStoreNames();

                while (ids.hasMoreElements()) {
                    String id = ids.nextElement();
                    String className = mConfig.getString(PROP_STORE + "." + id + ".class", null);
                    IOCSPStore store = (IOCSPStore) Class.forName(className).newInstance();

                    store.init(this, mConfig.getSubStore(PROP_STORE + "." + id));
                    mStores.put(id, store);
                    if (id.equals(defStoreId)) {
                        mDefStore = store;
                    }
                }
            } catch (ClassNotFoundException e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_OCSP_SIGNING_UNIT", e.toString()));
            } catch (InstantiationException e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_OCSP_SIGNING_UNIT", e.toString()));
            } catch (IllegalAccessException e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_OCSP_SIGNING_UNIT", e.toString()));
            }
        } catch (EBaseException ee) {
            if (CMS.isPreOpMode())
                return;
            else
                throw ee;
        }
    }

    /**
     * Retrieves the specificed OCSP store.
     */
    public IOCSPStore getOCSPStore(String id) {
        return mStores.get(id);
    }

    public IConfigStore getOCSPStoreConfig(String id) {
        return mConfig.getSubStore(PROP_STORE + "." + id);
    }

    public String getOCSPStoreClassPath(String id) {
        try {
            return mConfig.getString(PROP_STORE + "." + id + ".class", null);
        } catch (EBaseException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_OCSP_CLASSPATH", id, e.toString()));
            return null;
        }
    }

    public ResponderID getResponderIDByName() {
        try {
            X500Name name = getName();
            Name.Template nameTemplate = new Name.Template();

            return new NameID((Name) nameTemplate.decode(
                        new ByteArrayInputStream(name.getEncoded())));
        } catch (IOException e) {
            return null;
        } catch (InvalidBERException e) {
            return null;
        }
    }

    public ResponderID getResponderIDByHash() {

        /*
         KeyHash ::= OCTET STRING --SHA-1 hash of responder's public key
         --(excluding the tag and length fields)
         */
        PublicKey publicKey = getSigningUnit().getPublicKey();
        MessageDigest md = null;

        try {
            md = MessageDigest.getInstance("SHA1");
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
        md.update(publicKey.getEncoded());
        byte digested[] = md.digest();

        return new KeyHashID(new OCTET_STRING(digested));
    }

    /**
     * Retrieves supported signing algorithms.
     */
    public String[] getOCSPSigningAlgorithms() {
        if (mOCSPSigningAlgorithms != null) {
            return mOCSPSigningAlgorithms;
        }

        if (mCert == null) {
            return null; // CA not inited yet.
        }

        X509Key caPubKey = null;

        try {
            caPubKey = (X509Key) mCert.get(X509CertImpl.PUBLIC_KEY);
        } catch (CertificateParsingException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_OCSP_RETRIEVE_KEY", e.toString()));
        }
        if (caPubKey == null) {
            return null; // something seriously wrong.
        }
        AlgorithmId alg = caPubKey.getAlgorithmId();

        if (alg == null) {
            return null; // something seriously wrong.
        }
        mOCSPSigningAlgorithms = AlgorithmId.getSigningAlgorithms(alg);
        if (mOCSPSigningAlgorithms == null) {
            CMS.debug(
                    "OCSP - no signing algorithms for " + alg.getName());
        } else {
            CMS.debug("OCSP First signing algorithm ");
        }
        return mOCSPSigningAlgorithms;
    }

    public static final OBJECT_IDENTIFIER MD2 =
            new OBJECT_IDENTIFIER("1.2.840.113549.2.2");
    public static final OBJECT_IDENTIFIER MD5 =
            new OBJECT_IDENTIFIER("1.2.840.113549.2.5");
    public static final OBJECT_IDENTIFIER SHA1 =
            new OBJECT_IDENTIFIER("1.3.14.3.2.26");

    public String getDigestName(AlgorithmIdentifier alg) {
        if (alg == null) {
            return null;
        } else if (alg.getOID().equals(MD2)) {
            return "MD2";
        } else if (alg.getOID().equals(MD5)) {
            return "MD5";
        } else if (alg.getOID().equals(SHA1)) {
            return "SHA1"; // 1.3.14.3.2.26
        } else {
            return null;
        }
    }

    /**
     * Retrieves the name of this OCSP server.
     */
    public X500Name getName() {
        return mName;
    }

    public IDefStore getDefaultStore() {
        return (IDefStore) mDefStore;
    }

    private void initSigUnit() throws EBaseException {
        try {
            // init signing unit
            mSigningUnit = new SigningUnit();
            mSigningUnit.init(this, mConfig.getSubStore(PROP_SIGNING_SUBSTORE));
            CMS.debug("OCSP signing unit inited");

            // init cert chain
            CryptoManager manager = CryptoManager.getInstance();
            org.mozilla.jss.crypto.X509Certificate[] chain =
                    manager.buildCertificateChain(mSigningUnit.getCert());
            // XXX do this in case other subsyss expect a X509CertImpl
            // until JSS implements all methods of X509Certificate
            java.security.cert.X509Certificate[] implchain =
                    new java.security.cert.X509Certificate[chain.length];

            for (int i = 0; i < chain.length; i++) {
                implchain[i] = new X509CertImpl(chain[i].getEncoded());
            }
            mCertChain = new CertificateChain(implchain);
            CMS.debug("in init - got CA chain from JSS.");

            // init issuer name - take name from the cert.

            mCert = new X509CertImpl(mSigningUnit.getCert().getEncoded());
            getOCSPSigningAlgorithms();
            mName = (X500Name) mCert.getSubjectDN();
            mNickname = mSigningUnit.getNickname();
            CMS.debug("in init - got CA name " + mName);

        } catch (CryptoManager.NotInitializedException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_OCSP_SIGNING", e.toString()));
        } catch (CertificateException e) {
            if (Debug.ON)
                e.printStackTrace();
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_OCSP_CHAIN", e.toString()));
        } catch (TokenException e) {
            if (Debug.ON)
                e.printStackTrace();
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_OCSP_CHAIN", e.toString()));
        }
    }

    /**
     * Notifies this subsystem if owner is in running mode.
     */
    public void startup() throws EBaseException {
        try {
            if (mDefStore != null)
                mDefStore.startup();
        } catch (EBaseException e) {
            if (CMS.isPreOpMode()) {
                return;
            } else
                throw e;
        } catch (Exception e) {
        }
    }

    /**
     * Process OCSPRequest.
     */
    public OCSPResponse validate(OCSPRequest request)
            throws EBaseException {
        long startTime = (CMS.getCurrentDate()).getTime();
        OCSPResponse response = mDefStore.validate(request);
        long endTime = (CMS.getCurrentDate()).getTime();

        mServedTime = mServedTime + (endTime - startTime);
        return response;
    }

    public boolean arraysEqual(byte[] bytes, byte[] ints) {
        if (bytes == null || ints == null) {
            return false;
        }

        if (bytes.length != ints.length) {
            return false;
        }

        for (int i = 0; i < bytes.length; i++) {
            if (bytes[i] != ints[i]) {
                return false;
            }
        }
        return true;
    }

    /**
     * Stops this system. The owner may call shutdown
     * anytime after initialization.
     * <P>
     */
    public void shutdown() {
    }

    /**
     * Returns the root configuration storage of this system.
     * <P>
     *
     * @return configuration store of this subsystem
     */
    public IConfigStore getConfigStore() {
        return mConfig;
    }

    public String getDefaultAlgorithm() {
        return mSigningUnit.getDefaultAlgorithm();
    }

    /**
     * logs a message in the CA area.
     *
     * @param level the debug level.
     * @param msg the message to debug.
     */
    public void log(int event, int level, String msg) {
        mLogger.log(event, ILogger.S_OCSP,
                level, msg);
    }

    public void log(int level, String msg) {
        mLogger.log(ILogger.EV_SYSTEM, ILogger.S_OCSP,
                level, msg);
    }

    public void setDefaultAlgorithm(String algorithm)
            throws EBaseException {
        mSigningUnit.setDefaultAlgorithm(algorithm);
    }

    /**
     * Signs the Response Data.
     */
    public BasicOCSPResponse sign(ResponseData rd)
            throws EBaseException {
        try (DerOutputStream out = new DerOutputStream()) {
            DerOutputStream tmp = new DerOutputStream();

            String algname = mSigningUnit.getDefaultAlgorithm();

            byte rd_data[] = ASN1Util.encode(rd);
            if (rd_data != null) {
                mTotalData += rd_data.length;
            }
            rd.encode(tmp);
            AlgorithmId.get(algname).encode(tmp);
            CMS.debug("adding signature");
            byte[] signature = mSigningUnit.sign(rd_data, algname);

            tmp.putBitString(signature);
            // XXX - optional, put the certificate chains in also

            DerOutputStream tmpChain = new DerOutputStream();
            DerOutputStream tmp1 = new DerOutputStream();
            java.security.cert.X509Certificate chains[] =
                    mCertChain.getChain();

            for (int i = 0; i < chains.length; i++) {
                tmpChain.putDerValue(new DerValue(chains[i].getEncoded()));
            }
            tmp1.write(DerValue.tag_Sequence, tmpChain);
            tmp.write(DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte) 0),
                    tmp1);

            out.write(DerValue.tag_Sequence, tmp);

            BasicOCSPResponse response = new BasicOCSPResponse(out.toByteArray());

            return response;
        } catch (Exception e) {
            e.printStackTrace();
            // error e
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_OCSP_SIGN_RESPONSE", e.toString()));
            return null;
        }

    }

    /**
     * Returns default signing unit used by this CA
     * <P>
     *
     * @return request identifier
     */
    public ISigningUnit getSigningUnit() {
        return mSigningUnit;
    }

    /**
     * Retrieves the request queue for the Authority.
     * <P>
     *
     * @return the request queue.
     */
    public IRequestQueue getRequestQueue() {
        return null;
    }

    /**
     * Registers request completed class.
     */
    public void registerRequestListener(IRequestListener listener) {
    }

    /**
     * Registers pending request class.
     */
    public void registerPendingListener(IRequestListener listener) {
    }

    /**
     * nickname of signing (id) cert
     */
    public String getNickname() {
        return mNickname;
    }

    public String getNewNickName() throws EBaseException {
        return mConfig.getString(PROP_NEW_NICKNAME, "");
    }

    public void setNewNickName(String name) {
        mConfig.putString(PROP_NEW_NICKNAME, name);
    }

    public void setNickname(String str) {
        mConfig.putString(PROP_NICKNAME, str);
    }

    /**
     * return official product name.
     */
    public String getOfficialName() {
        return "ocsp";
    }

    /**
     * Utility functions for processing OCSP request.
     */

    /**
     * public OCSPResponse processOCSPRequest(OCSPRequest req, OCSPReqProcessor p)
     * throws EBaseException
     * {
     * try {
     * log(ILogger.LL_INFO, "start OCSP request");
     * TBSRequest tbsReq = request.getTBSRequest();
     *
     * Vector singleResponses = new Vector();
     * for (int i = 0; i < tbsReq.getRequestCount(); i++)
     * {
     * com.netscape.certsrv.ocsp.asn1.Request req =
     * tbsReq.getRequestAt(i);
     * CertID cid = req.getCertID();
     * SingleResponse sr = p.process(cid);
     * singleResponses.addElement(sr);
     * }
     *
     *
     * SingleResponse res[] = new SingleResponse[singleResponses.size()];
     * singleResponses.copyInto(res);
     *
     * X500Name name = getName();
     * Name.Template nameTemplate = new Name.Template();
     * NameID rid = new NameID((Name)nameTemplate.decode(
     * new ByteArrayInputStream(name.getEncoded())));
     * ResponseData rd = new ResponseData(rid, new GeneralizedTime(
     * CMS.getCurrentDate()), res);
     *
     * BasicOCSPResponse basicRes = sign(rd);
     *
     * OCSPResponse response = new OCSPResponse(
     * OCSPResponseStatus.SUCCESSFUL,
     * new ResponseBytes(ResponseBytes.OCSP_BASIC,
     * new OCTET_STRING(ASN1Util.encode(basicRes))));
     *
     * log(ILogger.LL_INFO, "done OCSP request");
     * return response;
     * } catch (Exception e) {
     * log(ILogger.LL_FAILURE, "request processing failure " + e);
     * return null;
     * }
     * }
     **/

    /**
     * Returns the in-memory count of the processed OCSP requests.
     *
     * @return number of processed OCSP requests in memory
     */
    public long getNumOCSPRequest() {
        return mNumOCSPRequest;
    }

    /**
     * Returns the in-memory time (in mini-second) of
     * the processed time for OCSP requests.
     *
     * @return processed times for OCSP requests
     */
    public long getOCSPRequestTotalTime() {
        return mTotalTime;
    }

    /**
     * Returns the in-memory time (in mini-second) of
     * the signing time for OCSP requests.
     *
     * @return processed times for OCSP requests
     */
    public long getOCSPTotalSignTime() {
        return mSignTime;
    }

    public long getOCSPTotalLookupTime() {
        return mLookupTime;
    }

    /**
     * Returns the total data signed
     * for OCSP requests.
     *
     * @return processed times for OCSP requests
     */
    public long getOCSPTotalData() {
        return mTotalData;
    }

    public void incTotalTime(long inc) {
        mTotalTime += inc;
    }

    public void incSignTime(long inc) {
        mSignTime += inc;
    }

    public void incLookupTime(long inc) {
        mLookupTime += inc;
    }

    public void incNumOCSPRequest(long inc) {
        mNumOCSPRequest += inc;
    }
}
