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
package com.netscape.certsrv.publish;


import netscape.security.x509.X509CRLImpl;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;


/**
 * This interface represents a CRL publisher that is
 * invoked when CRL publishing is requested by CMS.
 * Note that CMS, by default, shipped with a LDAP-based 
 * CRL publisher that can be configured via 
 * Certificiate Manager/LDAP Publishing panel. This
 * interface provides administrator additional capability 
 * of publishing CRL to different destinations.
 *
 * The CRL publishing frequency is configured via
 * Netscape Certificate Server Console's 
 * Certificate Manager/Revocation List panel.
 * The CRL publishing may occur either everytime a 
 * certificate is revoked or at a pre-defined interval.
 * 
 * To try out this new CRL publisher mechanism, do
 * the following:
 * (1) Write a sample CRL publisher class that implements
 *     ICRLPublisher interface. For example,
 * 
 * <code>
 * public class CRLPublisher implements ICRLPublisher
 * {
 * 	public void init(ISubsystem owner, IConfigStore config) 
 *		throws EBaseException
 * 	{
 *		log(ILogger.LL_DEBUG, "CRLPublisher: Initialized");
 * 	}
 *
 *	public void publish(String issuingPointId, X509CRLImpl crl) 
 * 		throws EBaseException 
 *      {
 * 		log(ILogger.LL_DEBUG, "CRLPublisher: " + issuingPointId + 
 *                " crl=" + crl);
 * 	}
 *
 *      public void log(int level, String msg)
 *      {
 *              Logger.getLogger().log(ILogger.EV_SYSTEM, 
 *                      null, ILogger.S_OTHER, level,
 *                      msg);
 *      }
 * }
 * </code>
 *
 * (2) Compile the class and place the class into 
 *     <server-root>\bin\cert\classes directory. 
 * (3) Add the following parameter to CMS.cfg
 *       ca.crlPublisher.class=<implementation class>
 *     For example,
 *       ca.crlPublisher.class=myCRLPublisher
 *
 * @version $Revision$, $Date$
 */
public interface ICRLPublisher {

    /**
     * Initializes this CRL publisher.
     * 
     * @param owner parent of the publisher. An object of type 
     *        CertificateAuthority.
     * @param config config store for this publisher. If this
     *        publisher requires configuration parameters for
     *        initialization, the parameters should be placed
     *        in CMS.cfg as ca.crlPublisher.<paramType>=<paramValue>
     * @exception EBaseException failed to initialize this publisher
     */
    public void init(ISubsystem owner, IConfigStore config) 
        throws EBaseException;

    /**
     * Publishes CRL. This method is invoked by CMS based
     * on the configured CRL publishing frequency.
     *
     * @param issuingPointId CRL issuing point identifier 
     *          (i.e. MasterCRL)
     * @param crl CRL that is publishing
     * @exception EBaseException failed to publish
     */
    public void publish(String issuingPointId, X509CRLImpl crl) 
        throws EBaseException;
} 
