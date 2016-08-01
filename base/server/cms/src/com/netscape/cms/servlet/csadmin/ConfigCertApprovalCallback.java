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

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.ssl.SSLCertificateApprovalCallback;

import com.netscape.certsrv.apps.CMS;

public class ConfigCertApprovalCallback
        implements SSLCertificateApprovalCallback {

    public Set<Integer> ignoredErrors = new HashSet<Integer>();

    public ConfigCertApprovalCallback() {
    }

    public void ignoreError(int error) {
        ignoredErrors.add(error);
    }

    public String getErrorDescription(int reason) {

        // iterate through all constants in ValidityStatus
        for (Field f : ValidityStatus.class.getDeclaredFields()) {
            int mod = f.getModifiers();
            if (Modifier.isPublic(mod) &&
                Modifier.isFinal(mod) &&
                Modifier.isStatic(mod)) {

                try {
                    int value = f.getInt(null);

                    // if value matches the reason, return the name
                    if (value == reason) {
                        return f.getName();
                    }

                } catch (IllegalAccessException e) {
                    return "ERROR #" + reason;
                }
            }
        }

        return "UNKNOWN_ERROR";
    }

    public boolean approve(X509Certificate cert,
            SSLCertificateApprovalCallback.ValidityStatus status) {

        CMS.debug("Server certificate:");
        CMS.debug(" - subject: " + cert.getSubjectDN());
        CMS.debug(" - issuer: " + cert.getIssuerDN());

        Enumeration<?> errors = status.getReasons();
        boolean result = true;

        while (errors.hasMoreElements()) {
            SSLCertificateApprovalCallback.ValidityItem item = (SSLCertificateApprovalCallback.ValidityItem) errors.nextElement();
            int reason = item.getReason();
            String description = getErrorDescription(reason);

            if (ignoredErrors.contains(reason)) {
                CMS.debug("WARNING: " + description);
            } else {
                CMS.debug("ERROR: " + description);
                result = false;
            }
        }

        return result;
    }
}
