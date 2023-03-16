package com.netscape.ca;

import java.math.BigInteger;

import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.Subsystem;
import com.netscape.certsrv.ca.EErrorPublishCRL;
import com.netscape.certsrv.request.RequestListener;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.request.Request;

public class RevocationRequestListener extends RequestListener {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(RevocationRequestListener.class);

    private CRLIssuingPoint crlIssuingPoint;

    public RevocationRequestListener(CRLIssuingPoint crlIssuingPoint) {
        this.crlIssuingPoint = crlIssuingPoint;
    }

    @Override
    public void init(Subsystem sys, ConfigStore config) throws EBaseException {
    }

    @Override
    public void set(String name, String val) {
    }

    @Override
    public void accept(Request r) {
        String requestType = r.getRequestType();

        if (!(requestType.equals(Request.REVOCATION_REQUEST) ||
                requestType.equals(Request.UNREVOCATION_REQUEST) ||
                requestType.equals(Request.CLA_CERT4CRL_REQUEST) ||
                requestType.equals(Request.CLA_UNCERT4CRL_REQUEST))) {
            return;
        }

        logger.info("RevocationRequestListener: Received revocation request " + r.getRequestId().toHexString());

        // check if serial number is in begin/end range if set.
        if (crlIssuingPoint.mBeginSerial != null || crlIssuingPoint.mEndSerial != null) {

            BigInteger[] serialNumbers = r.getExtDataInBigIntegerArray(Request.OLD_SERIALS);
            if (serialNumbers == null || serialNumbers.length == 0) {

                X509CertImpl oldCerts[] = r.getExtDataInCertArray(Request.OLD_CERTS);
                if (oldCerts == null || oldCerts.length == 0) {
                    return;
                }

                serialNumbers = new BigInteger[oldCerts.length];
                for (int i = 0; i < oldCerts.length; i++) {
                    serialNumbers[i] = oldCerts[i].getSerialNumber();
                }
            }

            logger.debug("RevocationRequestListener: Checking serial numbers:");
            boolean inRange = false;

            for (int i = 0; i < serialNumbers.length; i++) {
                BigInteger serialNumber = serialNumbers[i];
                logger.debug("RevocationRequestListener: - serial number: " + serialNumber);
                if ((crlIssuingPoint.mBeginSerial == null || serialNumber.compareTo(crlIssuingPoint.mBeginSerial) >= 0)
                        && (crlIssuingPoint.mEndSerial == null || serialNumber.compareTo(crlIssuingPoint.mEndSerial) <= 0)) {
                    inRange = true;
                }
            }

            logger.debug("RevocationRequestListener: Serial numbers in range: " + inRange);
            if (!inRange) {
                return;
            }
        }

        if (crlIssuingPoint.mAlwaysUpdate) {

            logger.info("RevocationRequestListener: Updating CRL in " + crlIssuingPoint.getId());

            try {
                crlIssuingPoint.updateCRLNow();
                r.setExtData(crlIssuingPoint.mCrlUpdateStatus, Request.RES_SUCCESS);
                if (crlIssuingPoint.mPublisherProcessor != null) {
                    r.setExtData(crlIssuingPoint.mCrlPublishStatus, Request.RES_SUCCESS);
                }

            } catch (EErrorPublishCRL e) {
                // error already logged in updateCRLNow();
                r.setExtData(crlIssuingPoint.mCrlUpdateStatus, Request.RES_SUCCESS);
                if (crlIssuingPoint.mPublisherProcessor != null) {
                    r.setExtData(crlIssuingPoint.mCrlPublishStatus, Request.RES_ERROR);
                    r.setExtData(crlIssuingPoint.mCrlPublishError, e);
                }

            } catch (EBaseException e) {
                logger.warn(CMS.getLogMessage("CMSCORE_CA_ISSUING_UPDATE_CRL", e.toString()), e);
                r.setExtData(crlIssuingPoint.mCrlUpdateStatus, Request.RES_ERROR);
                r.setExtData(crlIssuingPoint.mCrlUpdateError, e);

            } catch (Exception e) {
                String message = CMS.getLogMessage("CMSCORE_CA_ISSUING_UPDATE_CRL", e.toString());
                logger.warn(message, e);
                r.setExtData(crlIssuingPoint.mCrlUpdateStatus, Request.RES_ERROR);
                r.setExtData(crlIssuingPoint.mCrlUpdateError,
                        new EBaseException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", e.toString())));
            }
        }
    }
}
