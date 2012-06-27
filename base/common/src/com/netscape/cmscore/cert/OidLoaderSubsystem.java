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
package com.netscape.cmscore.cert;

import java.security.cert.CertificateException;
import java.util.Enumeration;

import netscape.security.extensions.CertificateRenewalWindowExtension;
import netscape.security.extensions.CertificateScopeOfUseExtension;
import netscape.security.extensions.NSCertTypeExtension;
import netscape.security.util.ObjectIdentifier;
import netscape.security.x509.DeltaCRLIndicatorExtension;
import netscape.security.x509.FreshestCRLExtension;
import netscape.security.x509.HoldInstructionExtension;
import netscape.security.x509.InvalidityDateExtension;
import netscape.security.x509.IssuingDistributionPointExtension;
import netscape.security.x509.OIDMap;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.cmscore.util.Debug;

/**
 *
 * @author stevep
 * @version $Revision
 */
public class OidLoaderSubsystem implements ISubsystem {

    private IConfigStore mConfig = null;
    public static final String ID = "oidmap";
    private String mId = ID;

    private static final String PROP_OID = "oid";
    private static final String PROP_CLASS = "class";

    /**
     *
     */
    private OidLoaderSubsystem() {
    }

    /**
     * Retrieves subsystem identifier.
     */
    public String getId() {
        return mId;
    }

    public void setId(String id) throws EBaseException {
        mId = id;
    }

    // singleton enforcement

    private static OidLoaderSubsystem mInstance = new OidLoaderSubsystem();

    public static OidLoaderSubsystem getInstance() {
        return mInstance;
    }

    private static final int CertType_data[] = { 2, 16, 840, 1, 113730, 1, 1 };

    /**
     * Identifies the particular public key used to sign the certificate.
     */
    public static final ObjectIdentifier CertType_Id = new
            ObjectIdentifier(CertType_data);

    private static final String[][] oidMapEntries = new String[][] {
            { NSCertTypeExtension.class.getName(),
                    CertType_Id.toString(),
                    NSCertTypeExtension.NAME },
            { CertificateRenewalWindowExtension.class.getName(),
                    CertificateRenewalWindowExtension.ID.toString(),
                    CertificateRenewalWindowExtension.NAME },
            { CertificateScopeOfUseExtension.class.getName(),
                    CertificateScopeOfUseExtension.ID.toString(),
                    CertificateScopeOfUseExtension.NAME },
            { DeltaCRLIndicatorExtension.class.getName(),
                    DeltaCRLIndicatorExtension.OID,
                    DeltaCRLIndicatorExtension.NAME },
            { HoldInstructionExtension.class.getName(),
                    HoldInstructionExtension.OID,
                    HoldInstructionExtension.NAME },
            { InvalidityDateExtension.class.getName(),
                    InvalidityDateExtension.OID,
                    InvalidityDateExtension.NAME },
            { IssuingDistributionPointExtension.class.getName(),
                    IssuingDistributionPointExtension.OID,
                    IssuingDistributionPointExtension.NAME },
            { FreshestCRLExtension.class.getName(),
                    FreshestCRLExtension.OID,
                    FreshestCRLExtension.NAME },
        };

    /**
     * Initializes this subsystem with the given
     * configuration store.
     * It first initializes resident subsystems,
     * and it loads and initializes loadable
     * subsystem specified in the configuration
     * store.
     * <P>
     * Note that individual subsystem should be initialized in a separated thread if it has dependency on the
     * initialization of other subsystems.
     * <P>
     *
     * @param owner owner of this subsystem
     * @param config configuration store
     */
    public synchronized void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {
        if (Debug.ON) {
            Debug.trace("OIDLoaderSubsystem started");
        }
        mConfig = config;

        Enumeration<String> names = mConfig.getSubStoreNames();

        // load static (build-in) extensions

        for (int i = 0; i < oidMapEntries.length; i++) {
            try {
                OIDMap.addAttribute(oidMapEntries[i][0],
                        oidMapEntries[i][1],
                        oidMapEntries[i][2]);
            } catch (Exception e) {
            }
        }

        // load dynamic extensions

        while (names.hasMoreElements()) {
            String substorename = names.nextElement();
            IConfigStore substore = mConfig.getSubStore(substorename);

            try {
                String oidname = substore.getString(PROP_OID);
                String classname = substore.getString(PROP_CLASS);

                OIDMap.addAttribute(classname,
                        oidname,
                        substorename);
            } catch (EPropertyNotFound e) {
                // Log error
            } catch (CertificateException e) {
                // log error
            }
        }
    }

    public void startup() throws EBaseException {
    }

    /**
     * Stops this system.
     */
    public synchronized void shutdown() {
    }

    /*
     * Returns the root configuration storage of this system.
     * <P>
     *
     * @return configuration store of this subsystem
     */
    public synchronized IConfigStore getConfigStore() {
        return mConfig;
    }

}
