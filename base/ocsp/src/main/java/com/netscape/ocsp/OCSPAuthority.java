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
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateParsingException;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import org.dogtagpki.server.ocsp.OCSPConfig;
import org.dogtagpki.server.ocsp.OCSPEngine;
import org.dogtagpki.server.ocsp.OCSPEngineConfig;
import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.GeneralizedTime;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.netscape.security.util.DerOutputStream;
import org.mozilla.jss.netscape.security.util.DerValue;
import org.mozilla.jss.netscape.security.x509.AlgorithmId;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509Key;
import org.mozilla.jss.pkix.cert.Extension;
import org.mozilla.jss.pkix.primitive.Name;

import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.OCSPSigningInfoEvent;
import com.netscape.certsrv.ocsp.IDefStore;
import com.netscape.certsrv.ocsp.IOCSPAuthority;
import com.netscape.certsrv.ocsp.IOCSPService;
import com.netscape.certsrv.ocsp.IOCSPStore;
import com.netscape.certsrv.request.IRequestListener;
import com.netscape.certsrv.security.SigningUnit;
import com.netscape.certsrv.util.IStatsSubsystem;
import com.netscape.cms.logging.Logger;
import com.netscape.cms.logging.SignedAuditLogger;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.dbs.DBSubsystem;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.ocsp.BasicOCSPResponse;
import com.netscape.cmsutil.ocsp.KeyHashID;
import com.netscape.cmsutil.ocsp.NameID;
import com.netscape.cmsutil.ocsp.OCSPRequest;
import com.netscape.cmsutil.ocsp.OCSPResponse;
import com.netscape.cmsutil.ocsp.OCSPResponseStatus;
import com.netscape.cmsutil.ocsp.Request;
import com.netscape.cmsutil.ocsp.ResponderID;
import com.netscape.cmsutil.ocsp.ResponseBytes;
import com.netscape.cmsutil.ocsp.ResponseData;
import com.netscape.cmsutil.ocsp.SingleResponse;
import com.netscape.cmsutil.ocsp.TBSRequest;

/**
 * A class represents a Certificate Authority that is
 * responsible for certificate specific operations.
 * <P>
 *
 * @author lhsiao
 * @version $Revision$, $Date$
 */
public class OCSPAuthority implements IOCSPAuthority, IOCSPService, IAuthority {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(OCSPAuthority.class);
    private static final Logger signedAuditLogger = SignedAuditLogger.getLogger();

    private long mServedTime = 0;

    public final static OBJECT_IDENTIFIER OCSP_NONCE = new OBJECT_IDENTIFIER("1.3.6.1.5.5.7.48.1.2");

    private Hashtable<String, IOCSPStore> mStores = new Hashtable<>();
    private String mId = "ocsp";
    private OCSPConfig mConfig;
    private OCSPSigningUnit mSigningUnit;

    private String[] mOCSPSigningAlgorithms = null;
    private IOCSPStore mDefStore = null;

    public long mNumOCSPRequest = 0;
    public long mTotalTime = 0;
    public long mTotalData = 0;
    public long mSignTime = 0;
    public long mLookupTime = 0;

    /**
     * Retrieves the name of this subsystem.
     */
    @Override
    public String getId() {
        return mId;
    }

    /**
     * Sets specific to this subsystem.
     */
    @Override
    public void setId(String id) throws EBaseException {
        mId = id;
    }

    /**
     * Initializes this subsystem with the given configuration
     * store.
     * <P>
     * @param config configuration store
     *
     * @exception EBaseException failed to initialize
     */
    @Override
    public void init(IConfigStore config)
            throws EBaseException {

        OCSPEngine engine = OCSPEngine.getInstance();
        OCSPEngineConfig engineConfig = engine.getConfig();
        DBSubsystem dbSubsystem = engine.getDBSubsystem();

        try {
            mConfig = engineConfig.getOCSPConfig();

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
                    IOCSPStore store = (IOCSPStore) Class.forName(className).getDeclaredConstructor().newInstance();
                    IConfigStore cfg = mConfig.getSubStore(PROP_STORE + "." + id);

                    store.init(cfg, dbSubsystem);

                    mStores.put(id, store);
                    if (id.equals(defStoreId)) {
                        mDefStore = store;
                    }
                }

            } catch (Exception e) {
                logger.warn(CMS.getLogMessage("CMSCORE_OCSP_SIGNING_UNIT", e.toString()), e);
            }

        } catch (EBaseException e) {
            logger.error("OCSPAuthority: " + e.getMessage(), e);
            throw e;
        }

        try {
            String ocspSigningSKI = CryptoUtil.getSKIString(mSigningUnit.getCertImpl());
            signedAuditLogger.log(OCSPSigningInfoEvent.createSuccessEvent(ILogger.SYSTEM_UID, ocspSigningSKI));

        } catch (IOException e) {
            throw new EBaseException(e);
        }
    }

    /**
     * This method retrieves the OCSP store given its name.
     * <P>
     *
     * @param id the string representation of an OCSP store
     * @return IOCSPStore an instance of an OCSP store object
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
            logger.warn(CMS.getLogMessage("CMSCORE_OCSP_CLASSPATH", id, e.toString()), e);
            return null;
        }
    }

    @Override
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

    @Override
    public ResponderID getResponderIDByHash() {

        /*
         KeyHash ::= OCTET STRING --SHA-256 hash of responder's public key
         --(excluding the tag and length fields)
         */
        PublicKey publicKey = getSigningUnit().getPublicKey();
        MessageDigest md = null;

        try {
            md = MessageDigest.getInstance("SHA256");
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
    @Override
    public String[] getOCSPSigningAlgorithms() {
        if (mOCSPSigningAlgorithms != null) {
            return mOCSPSigningAlgorithms;
        }

        X509CertImpl certImpl = mSigningUnit.getCertImpl();
        if (certImpl == null) {
            return null; // CA not inited yet.
        }

        X509Key caPubKey = null;

        try {
            caPubKey = (X509Key) certImpl.get(X509CertImpl.PUBLIC_KEY);
        } catch (CertificateParsingException e) {
            logger.warn(CMS.getLogMessage("CMSCORE_OCSP_RETRIEVE_KEY", e.toString()), e);
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
            logger.debug("OCSP - no signing algorithms for " + alg.getName());
        } else {
            logger.debug("OCSP First signing algorithm ");
        }
        return mOCSPSigningAlgorithms;
    }

    /**
     * Retrieves the name of this OCSP server.
     */
    @Override
    public X500Name getName() {
        X509CertImpl certImpl = mSigningUnit.getCertImpl();
        return (X500Name) certImpl.getSubjectDN();
    }

    /**
     * This method retrieves the default OCSP store
     * (i. e. - information from the internal database).
     * <P>
     *
     * @return DefStore an instance of the default OCSP store
     */
    public IDefStore getDefaultStore() {
        return (IDefStore) mDefStore;
    }

    private void initSigUnit() throws EBaseException {

        logger.info("OCSPAuthority: Initializing OCSP signing unit");

        mSigningUnit = new OCSPSigningUnit();
        mSigningUnit.init(mConfig.getSubStore(PROP_SIGNING_SUBSTORE));

        getOCSPSigningAlgorithms();
    }

    /**
     * Notifies this subsystem if owner is in running mode.
     */
    @Override
    public void startup() throws EBaseException {
        OCSPEngine engine = OCSPEngine.getInstance();
        try {
            if (mDefStore != null)
                mDefStore.startup();

        } catch (EBaseException e) {
            logger.warn("OCSPAuthority: " + e.getMessage(), e);
            if (engine.isPreOpMode()) {
                logger.warn("OCSPAuthority.init(): Swallow exception in pre-op mode");
                return;
            }
            throw e;

        } catch (Exception e) {
            logger.warn("OCSPAuthority: " + e.getMessage(), e);
        }
    }

    /**
     * This method validates the information associated with the specified
     * OCSP request and returns an OCSP response.
     * <P>
     *
     * @param request an OCSP request
     * @return OCSPResponse the OCSP response associated with the specified
     *         OCSP request
     * @exception EBaseException an error associated with the inability to
     *                process the supplied OCSP request
     */
    @Override
    public OCSPResponse validate(OCSPRequest request) throws EBaseException {

        logger.info("OCSPAuthority: Validating OCSP request");

        TBSRequest tbsReq = request.getTBSRequest();
        if (tbsReq.getRequestCount() == 0) {
            logger.error("OCSPAuthority: No request found");
            logger.error(CMS.getLogMessage("OCSP_REQUEST_FAILURE", "No Request Found"));
            throw new EBaseException("OCSP request is empty");
        }

        OCSPEngine engine = OCSPEngine.getInstance();
        IStatsSubsystem statsSub = (IStatsSubsystem) engine.getSubsystem(IStatsSubsystem.ID);

        incNumOCSPRequest(1);
        long startTime = new Date().getTime();

        logger.info("OCSPAuthority: Start OCSP request");

        OCSPResponse response;

        try {
            // (3) look into database to check the certificate's status
            Vector<SingleResponse> singleResponses = new Vector<>();

            if (statsSub != null) {
                statsSub.startTiming("lookup");
            }

            long lookupStartTime = new Date().getTime();

            for (int i = 0; i < tbsReq.getRequestCount(); i++) {
                Request req = tbsReq.getRequestAt(i);
                SingleResponse sr = mDefStore.processRequest(req);
                singleResponses.addElement(sr);
            }

            long lookupEndTime = new Date().getTime();
            incLookupTime(lookupEndTime - lookupStartTime);

            if (statsSub != null) {
                statsSub.endTiming("lookup");
            }

            if (statsSub != null) {
                statsSub.startTiming("build_response");
            }

            SingleResponse res[] = new SingleResponse[singleResponses.size()];
            singleResponses.copyInto(res);

            ResponderID rid = null;

            if (mDefStore.isByName()) {
                rid = getResponderIDByName();
            } else {
                rid = getResponderIDByHash();
            }

            Extension nonce[] = null;

            for (int j = 0; j < tbsReq.getExtensionsCount(); j++) {
                Extension thisExt = tbsReq.getRequestExtensionAt(j);

                if (thisExt.getExtnId().equals(IOCSPAuthority.OCSP_NONCE)) {
                    nonce = new Extension[1];
                    nonce[0] = thisExt;
                }
            }

            ResponseData rd = new ResponseData(rid,
                    new GeneralizedTime(new Date()), res, nonce);

            if (statsSub != null) {
                statsSub.endTiming("build_response");
            }

            if (statsSub != null) {
                statsSub.startTiming("signing");
            }

            long signStartTime = new Date().getTime();

            BasicOCSPResponse basicRes = sign(rd);

            long signEndTime = new Date().getTime();
            incSignTime(signEndTime - signStartTime);

            if (statsSub != null) {
                statsSub.endTiming("signing");
            }

            response = new OCSPResponse(
                    OCSPResponseStatus.SUCCESSFUL,
                    new ResponseBytes(ResponseBytes.OCSP_BASIC,
                            new OCTET_STRING(ASN1Util.encode(basicRes))));

        } catch (EBaseException e) {
            logger.error(CMS.getLogMessage("OCSP_REQUEST_FAILURE", e.toString()), e);
            throw e;

        } catch (Exception e) {
            logger.error(CMS.getLogMessage("OCSP_REQUEST_FAILURE", e.toString()), e);
            throw new EBaseException(e);
        }

        logger.info("OCSPAuthority: Done validating OCSP request");

        long endTime = new Date().getTime();
        incTotalTime(endTime - startTime);

        mServedTime = mServedTime + (endTime - startTime);

        return response;
    }

    /**
     * Stops this system. The owner may call shutdown
     * anytime after initialization.
     * <P>
     */
    @Override
    public void shutdown() {
    }

    /**
     * Returns the root configuration storage of this system.
     * <P>
     *
     * @return configuration store of this subsystem
     */
    @Override
    public OCSPConfig getConfigStore() {
        return mConfig;
    }

    @Override
    public String getDefaultAlgorithm() {
        return mSigningUnit.getDefaultAlgorithm();
    }

    public void log(int level, String msg) {
    }

    @Override
    public void setDefaultAlgorithm(String algorithm)
            throws EBaseException {
        mSigningUnit.setDefaultAlgorithm(algorithm);
    }

    /**
     * Signs the Response Data.
     */
    @Override
    public BasicOCSPResponse sign(ResponseData rd)
            throws EBaseException {

        OCSPEngine engine = OCSPEngine.getInstance();

        try (DerOutputStream out = new DerOutputStream()) {
            DerOutputStream tmp = new DerOutputStream();

            String algname = mSigningUnit.getDefaultAlgorithm();

            byte rd_data[] = ASN1Util.encode(rd);
            if (rd_data != null) {
                mTotalData += rd_data.length;
            }

            rd.encode(tmp);
            AlgorithmId.get(algname).encode(tmp);

            logger.debug("OCSPAuthority: adding signature");
            byte[] signature = mSigningUnit.sign(rd_data, algname);

            tmp.putBitString(signature);
            // XXX - optional, put the certificate chains in also

            DerOutputStream tmpChain = new DerOutputStream();
            DerOutputStream tmp1 = new DerOutputStream();
            java.security.cert.X509Certificate chains[] = mSigningUnit.getCertChain().getChain();

            for (int i = 0; i < chains.length; i++) {
                tmpChain.putDerValue(new DerValue(chains[i].getEncoded()));
            }

            tmp1.write(DerValue.tag_Sequence, tmpChain);
            tmp.write(DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte) 0),
                    tmp1);

            out.write(DerValue.tag_Sequence, tmp);

            BasicOCSPResponse response = new BasicOCSPResponse(out.toByteArray());

            return response;

        } catch (NoSuchAlgorithmException e) {
            logger.error(CMS.getLogMessage("OPERATION_ERROR", e.toString()), e);
            throw new EOCSPException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", e.toString()), e);

        } catch (TokenException e) {
            // from get signature context or from initSign
            logger.error(CMS.getLogMessage("OPERATION_ERROR", e.toString()), e);
            throw new EOCSPException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", e.toString()), e);

        } catch (InvalidKeyException e) {
            logger.error(CMS.getLogMessage("OPERATION_ERROR", e.toString()), e);
            throw new EOCSPException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", e.toString()), e);

        } catch (SignatureException e) {
            logger.error(CMS.getLogMessage("OPERATION_ERROR", e.toString()), e);
            engine.checkForAndAutoShutdown();
            throw new EOCSPException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", e.toString()), e);

        } catch (Exception e) {
            logger.error(CMS.getLogMessage("CMSCORE_OCSP_SIGN_RESPONSE", e.toString()), e);
            throw new EBaseException(e);
        }
    }

    /**
     * Returns default signing unit used by this CA
     * <P>
     *
     * @return request identifier
     */
    @Override
    public SigningUnit getSigningUnit() {
        return mSigningUnit;
    }

    /**
     * Registers request completed class.
     */
    @Override
    public void registerRequestListener(IRequestListener listener) {
    }

    /**
     * Registers pending request class.
     */
    @Override
    public void registerPendingListener(IRequestListener listener) {
    }

    /**
     * nickname of signing (id) cert
     */
    @Override
    public String getNickname() {
        return mSigningUnit.getNickname();
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
    @Override
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
     * logger.info("start OCSP request");
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
     * new Date()), res);
     *
     * BasicOCSPResponse basicRes = sign(rd);
     *
     * OCSPResponse response = new OCSPResponse(
     * OCSPResponseStatus.SUCCESSFUL,
     * new ResponseBytes(ResponseBytes.OCSP_BASIC,
     * new OCTET_STRING(ASN1Util.encode(basicRes))));
     *
     * logger.info("done OCSP request");
     * return response;
     * } catch (Exception e) {
     * logger.warn("request processing failure: " + e.getMessage(), e);
     * return null;
     * }
     * }
     **/

    /**
     * Returns the in-memory count of the processed OCSP requests.
     *
     * @return number of processed OCSP requests in memory
     */
    @Override
    public long getNumOCSPRequest() {
        return mNumOCSPRequest;
    }

    /**
     * Returns the in-memory time (in mini-second) of
     * the processed time for OCSP requests.
     *
     * @return processed times for OCSP requests
     */
    @Override
    public long getOCSPRequestTotalTime() {
        return mTotalTime;
    }

    /**
     * Returns the in-memory time (in mini-second) of
     * the signing time for OCSP requests.
     *
     * @return processed times for OCSP requests
     */
    @Override
    public long getOCSPTotalSignTime() {
        return mSignTime;
    }

    @Override
    public long getOCSPTotalLookupTime() {
        return mLookupTime;
    }

    /**
     * Returns the total data signed
     * for OCSP requests.
     *
     * @return processed times for OCSP requests
     */
    @Override
    public long getOCSPTotalData() {
        return mTotalData;
    }

    @Override
    public void incTotalTime(long inc) {
        mTotalTime += inc;
    }

    @Override
    public void incSignTime(long inc) {
        mSignTime += inc;
    }

    @Override
    public void incLookupTime(long inc) {
        mLookupTime += inc;
    }

    @Override
    public void incNumOCSPRequest(long inc) {
        mNumOCSPRequest += inc;
    }
}
