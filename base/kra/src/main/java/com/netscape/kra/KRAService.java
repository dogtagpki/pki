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
package com.netscape.kra;

import java.util.Hashtable;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.request.IService;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.request.Request;

/**
 * A class represents a KRA request queue service. This
 * is the service object that is registered with
 * the request queue. And it acts as a broker to
 * distribute request into different KRA specific
 * services. This service registration allows us to support
 * new request easier.
 * <P>
 *
 * @author thomask
 * @version $Revision$, $Date$
 */
public class KRAService implements IService {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(KRAService.class);

    public final static String ENROLLMENT = Request.ENROLLMENT_REQUEST;
    public final static String RECOVERY = Request.KEYRECOVERY_REQUEST;
    public final static String NETKEY_KEYGEN = Request.NETKEY_KEYGEN_REQUEST;
    public final static String NETKEY_KEYRECOVERY = Request.NETKEY_KEYRECOVERY_REQUEST;
    public final static String SECURITY_DATA_ENROLLMENT = Request.SECURITY_DATA_ENROLLMENT_REQUEST;
    public final static String SECURITY_DATA_RECOVERY = Request.SECURITY_DATA_RECOVERY_REQUEST;
    public final static String SYMKEY_GENERATION = Request.SYMKEY_GENERATION_REQUEST;
    public final static String ASYMKEY_GENERATION = Request.ASYMKEY_GENERATION_REQUEST;


    // private variables
    private Hashtable<String, IService> mServices = new Hashtable<>();

    /**
     * Constructs KRA service.
     */
    public KRAService(KeyRecoveryAuthority kra) {
        mServices.put(ENROLLMENT, new EnrollmentService(kra));
        mServices.put(RECOVERY, new RecoveryService(kra));
        mServices.put(NETKEY_KEYGEN, new NetkeyKeygenService(kra));
        mServices.put(NETKEY_KEYRECOVERY, new TokenKeyRecoveryService(kra));
        mServices.put(SECURITY_DATA_ENROLLMENT, new SecurityDataService(kra));
        mServices.put(SECURITY_DATA_RECOVERY, new SecurityDataRecoveryService(kra));
        mServices.put(SYMKEY_GENERATION, new SymKeyGenService(kra));
        mServices.put(ASYMKEY_GENERATION, new AsymKeyGenService(kra));
    }

    /**
     * Processes a KRA request. This method is invoked by
     * request subsystem.
     *
     * @param r request from request subsystem
     * @exception EBaseException failed to serve
     */
    @Override
    public boolean serviceRequest(Request r) throws EBaseException {

        logger.info("KRAService: Processing request " + r.getRequestId().toHexString());

        String type = r.getRequestType();
        logger.info("KRAService: - type: " + type);

        IService s = mServices.get(type);
        logger.info("KRAService: - service: " + s);

        if (s == null) {
            logger.error("KRAService: Unable to find service " + type);
            r.setExtData(Request.RESULT, Request.RES_ERROR);
            r.setExtData(Request.ERROR, new EBaseException(
                    CMS.getUserMessage("CMS_BASE_INVALID_OPERATION")));
            return true;
        }

        logger.info("KRAService: - service class: " + s.getClass().getSimpleName());

        try {
            return s.serviceRequest(r);
        } catch (EBaseException e) {
            logger.error("KRAService: Unable to process request: " + e.getMessage(), e);
            r.setExtData(Request.RESULT, Request.RES_ERROR);
            r.setExtData(Request.ERROR, e);
            if ((e.getMessage()).equals(CMS.getUserMessage("CMS_KRA_INVALID_TRANSPORT_CERT"))) {
                r.setRequestStatus(RequestStatus.REJECTED);
                return true;
            }
            // return true;
            // #546508
            return false;
        }
    }
}
