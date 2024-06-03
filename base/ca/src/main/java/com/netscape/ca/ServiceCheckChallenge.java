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
package com.netscape.ca;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.util.Utils;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.MetaInfo;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.dbs.RecordPagedList;
import com.netscape.cmscore.request.Request;

class ServiceCheckChallenge implements IServant {

    public static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ServiceCheckChallenge.class);

    private MessageDigest mSHADigest = null;

    public ServiceCheckChallenge(CAService service) {
        try {
            mSHADigest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            logger.warn(CMS.getLogMessage("OPERATION_ERROR", e.toString()), e);
        }
    }

    @Override
    public boolean service(Request request)
            throws EBaseException {
        // note: some request attributes used below are set in
        // authentication/ChallengePhraseAuthentication.java :(
        BigInteger serialno = request.getExtDataInBigInteger("serialNumber");
        String pwd = request.getExtDataInString(
                CAService.CHALLENGE_PHRASE);

        CAEngine engine = CAEngine.getInstance();
        CertificateRepository certDB = engine.getCertificateRepository();
        ArrayList<BigInteger> ida = new ArrayList<>();

        if (serialno != null) {
            CertRecord certRecord = null;
            try {
                certRecord = certDB.readCertificateRecord(serialno);
            } catch (EBaseException ee) {
                logger.warn(ee.toString());
            }
            if (certRecord != null) {
                String status = certRecord.getStatus();
                if (status.equals("VALID")) {
                    boolean samepwd = compareChallengePassword(certRecord, pwd);
                    if (samepwd) {
                        ida.add(certRecord.getSerialNumber());
                    }
                }
            }
        } else {
            String subjectName = request.getExtDataInString("subjectName");

            if (subjectName != null) {
                String filter = "(&(x509cert.subject=" + subjectName + ")(certStatus=VALID))";
                RecordPagedList<CertRecord> list = certDB.findPagedCertRecords(filter, null, null);
                for(CertRecord cRec: list) {
                    boolean samepwd = compareChallengePassword(cRec, pwd);
                    if (samepwd) {
                        BigInteger id = cRec.getSerialNumber();
                        ida.add(id);
                    }
                }
            }
        }
        BigInteger[] bigIntArray = ida.toArray(new BigInteger[0]);
        request.setExtData(CAService.SERIALNO_ARRAY, bigIntArray);
        return true;
    }

    private boolean compareChallengePassword(CertRecord certRecord, String pwd)
            throws EBaseException {
        MetaInfo metaInfo = (MetaInfo) certRecord.get(CertRecord.ATTR_META_INFO);

        if (metaInfo == null) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTRIBUTE", "metaInfo"));
        }

        String hashpwd = hashPassword(pwd);

        // got metaInfo
        String challengeString =
                (String) metaInfo.get(CertRecord.META_CHALLENGE_PHRASE);

        return challengeString.equals(hashpwd);
    }

    private String hashPassword(String pwd) {
        String salt = "lala123";
        byte[] pwdDigest = mSHADigest.digest((salt + pwd).getBytes());
        String b64E = Utils.base64encode(pwdDigest, true);

        return "{SHA-256}" + b64E;
    }
}
