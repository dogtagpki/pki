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
package com.netscape.cms.profile.input;

import java.util.Enumeration;
import java.util.Locale;
import java.util.Map;
import java.util.Vector;

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.CAEngineConfig;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.pkix.crmf.CertReqMsg;
import org.mozilla.jss.pkix.crmf.ProofOfPossession;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.cms.profile.common.EnrollProfile;
import com.netscape.cms.profile.common.Profile;
import com.netscape.cms.profile.common.ProfileInput;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.cmscore.request.Request;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * This class implements the base enrollment input.
 *
 * @version $Revision$, $Date$
 */
public abstract class EnrollInput extends ProfileInput {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(EnrollInput.class);

    protected ConfigStore mConfig;
    protected Vector<String> mValueNames = new Vector<>();
    protected Vector<String> mConfigNames = new Vector<>();
    protected Profile mProfile = null;

    /**
     * Initializes this default policy.
     */
    public void init(Profile profile, ConfigStore config)
            throws EProfileException {
        mConfig = config;
        mProfile = profile;
    }

    @Override
    public ConfigStore getConfigStore() {
        return mConfig;
    }

    /**
     * Populates the request with this policy default.
     *
     * @param ctx profile context
     * @param request request
     * @exception Exception failed to populate
     */
    @Override
    public abstract void populate(Map<String, String> ctx, Request request) throws Exception;

    /**
     * Retrieves the localizable name of this policy.
     *
     * @param locale user locale
     * @return localized input name
     */
    @Override
    public abstract String getName(Locale locale);

    /**
     * Retrieves the localizable description of this policy.
     *
     * @param locale user locale
     * @return localized input description
     */
    @Override
    public abstract String getText(Locale locale);

    /**
     * Retrieves the descriptor of the given value
     * property by name.
     *
     * @param locale user locale
     * @param name property name
     * @return descriptor of the property
     */
    @Override
    public abstract IDescriptor getValueDescriptor(Locale locale, String name);

    public void addValueName(String name) {
        mValueNames.addElement(name);
    }

    /**
     * Retrieves a list of names of the value parameter.
     */
    @Override
    public Enumeration<String> getValueNames() {
        return mValueNames.elements();
    }

    public void addConfigName(String name) {
        mConfigNames.addElement(name);
    }

    @Override
    public Enumeration<String> getConfigNames() {
        return mConfigNames.elements();
    }

    @Override
    public void setConfig(String name, String value)
            throws EPropertyException {
        if (mConfig.getSubStore("params") == null) {
            //
        } else {
            mConfig.getSubStore("params").putString(name, value);
        }
    }

    @Override
    public String getConfig(String name) {
        try {
            if (mConfig == null) {
                return null;
            }
            if (mConfig.getSubStore("params") != null) {
                return mConfig.getSubStore("params").getString(name);
            }
        } catch (EBaseException e) {
        }
        return "";
    }

    public String getDefaultConfig(String name) {
        return null;
    }

    @Override
    public String getValue(String name, Locale locale, Request request)
            throws EProfileException {
        return request.getExtDataInString(name);
    }

    /**
     * Sets the value of the given value parameter by name.
     */
    @Override
    public void setValue(String name, Locale locale, Request request,
            String value) throws EPropertyException {
        request.setExtData(name, value);
    }

    public Locale getLocale(Request request) {
        Locale locale = null;
        String language = request.getExtDataInString(
                EnrollProfile.REQUEST_LOCALE);
        if (language != null) {
            locale = new Locale(language);
        }
        return locale;
    }

    @Override
    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        return null;
    }

    public void verifyPOP(Locale locale, CertReqMsg certReqMsg)
            throws EProfileException {
        String method = "EnrollInput: verifyPOP: ";
        logger.debug("EnrollInput ::in verifyPOP");

        CAEngine engine = CAEngine.getInstance();

        Auditor auditor = engine.getAuditor();
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        if (!certReqMsg.hasPop()) {
            logger.debug(method + "CertReqMsg has not POP, return");
            return;
        }
        ProofOfPossession pop = certReqMsg.getPop();
        ProofOfPossession.Type popType = pop.getType();

        if (popType != ProofOfPossession.SIGNATURE) {
            logger.debug(method + "not POP SIGNATURE, return");
            return;
        }

        CAEngineConfig cs = engine.getConfig();

        try {
            if (cs.getBoolean("cms.skipPOPVerify", false)) {
                logger.debug(method + "skipPOPVerify on, return");
                return;
            }
            logger.debug("POP verification begins:");
            CryptoManager cm = CryptoManager.getInstance();

            CryptoToken verifyToken = null;
            String tokenName = cs.getString("ca.requestVerify.token", CryptoUtil.INTERNAL_TOKEN_NAME);
            if (CryptoUtil.isInternalToken(tokenName)) {
                logger.debug(method + "POP verification using internal token");
                certReqMsg.verify();
            } else {
                logger.debug(method + "POP verification using token:" + tokenName);
                verifyToken = CryptoUtil.getCryptoToken(tokenName);
                certReqMsg.verify(verifyToken);
            }

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                    AuditEvent.PROOF_OF_POSSESSION,
                    auditSubjectID,
                    ILogger.SUCCESS,
                    "method="+method);
            auditor.log(auditMessage);
        } catch (Exception e) {

            logger.error(method + "Failed POP verify! " + e.getMessage(), e);

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                    AuditEvent.PROOF_OF_POSSESSION,
                    auditSubjectID,
                    ILogger.FAILURE,
                    method + e.toString());

            auditor.log(auditMessage);

            throw new EProfileException(CMS.getUserMessage(locale,
                        "CMS_POP_VERIFICATION_ERROR"));
        }
    }

    /**
     * Signed Audit Log Subject ID
     *
     * This method is inherited by all extended "CMSServlet"s,
     * and is called to obtain the "SubjectID" for
     * a signed audit log message.
     * <P>
     *
     * @return id string containing the signed audit log message SubjectID
     */
    protected String auditSubjectID() {

        String subjectID = null;

        // Initialize subjectID
        SessionContext auditContext = SessionContext.getExistingContext();

        if (auditContext != null) {
            subjectID = (String)
                    auditContext.get(SessionContext.USER_ID);

            if (subjectID != null) {
                subjectID = subjectID.trim();
            } else {
                subjectID = ILogger.NONROLEUSER;
            }
        } else {
            subjectID = ILogger.UNIDENTIFIED;
        }

        return subjectID;
    }
}
