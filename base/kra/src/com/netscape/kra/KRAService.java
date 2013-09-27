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

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.kra.IKeyRecoveryAuthority;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IService;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cmscore.util.Debug;

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

    public final static String ENROLLMENT =
            IRequest.ENROLLMENT_REQUEST;
    public final static String RECOVERY = IRequest.KEYRECOVERY_REQUEST;
    public final static String NETKEY_KEYGEN = IRequest.NETKEY_KEYGEN_REQUEST;
    public final static String NETKEY_KEYRECOVERY = IRequest.NETKEY_KEYRECOVERY_REQUEST;
    public final static String SECURITY_DATA_ENROLLMENT = IRequest.SECURITY_DATA_ENROLLMENT_REQUEST;
    public final static String SECURITY_DATA_RECOVERY = IRequest.SECURITY_DATA_RECOVERY_REQUEST;


    // private variables
    private IKeyRecoveryAuthority mKRA = null;
    private Hashtable<String, IService> mServices = new Hashtable<String, IService>();

    /**
     * Constructs KRA service.
     */
    public KRAService(IKeyRecoveryAuthority kra) {
        mKRA = kra;
        mServices.put(ENROLLMENT, new EnrollmentService(kra));
        mServices.put(RECOVERY, new RecoveryService(kra));
        mServices.put(NETKEY_KEYGEN, new NetkeyKeygenService(kra));
        mServices.put(NETKEY_KEYRECOVERY, new TokenKeyRecoveryService(kra));
        mServices.put(SECURITY_DATA_ENROLLMENT, new SecurityDataService(kra));
        mServices.put(SECURITY_DATA_RECOVERY, new SecurityDataRecoveryService(kra));
    }

    /**
     * Processes a KRA request. This method is invoked by
     * request subsystem.
     *
     * @param r request from request subsystem
     * @exception EBaseException failed to serve
     */
    public boolean serviceRequest(IRequest r) throws EBaseException {
        if (Debug.ON)
            Debug.trace("KRA services request " +
                    r.getRequestId().toString());
        mKRA.log(ILogger.LL_INFO, "KRA services request " +
                r.getRequestId().toString());
        IService s = mServices.get(r.getRequestType());

        if (s == null) {
            r.setExtData(IRequest.RESULT, IRequest.RES_ERROR);
            r.setExtData(IRequest.ERROR, new EBaseException(
                    CMS.getUserMessage("CMS_BASE_INVALID_OPERATION")));
            return true;
        }
        try {
            return s.serviceRequest(r);
        } catch (EBaseException e) {
            r.setExtData(IRequest.RESULT, IRequest.RES_ERROR);
            r.setExtData(IRequest.ERROR, e);
            CMS.debug("KRAService serviceRequest EBaseException:" + e.getMessage());
            if ((e.getMessage()).equals(CMS.getUserMessage("CMS_KRA_INVALID_TRANSPORT_CERT"))) {
                r.setRequestStatus(RequestStatus.REJECTED);
                return true;
            } else {
                // return true;
                // #546508
                return false;
            }
        }
    }
}
