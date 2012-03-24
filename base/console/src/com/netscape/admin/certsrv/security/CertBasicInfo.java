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
package com.netscape.admin.certsrv.security;

import java.util.*;

import com.netscape.management.client.util.ResourceSet;

class CertBasicInfo {
    String _certName;
    String _certType;
    String _certExpiration;

    String _certNameLabel;
    String _certTypeLabel;
    String _certExpirationLabel;

    public CertBasicInfo(String certName, String certType,
            String certExpiration) {
        _certName = certName;
        _certType = certType;
        _certExpiration = certExpiration;

        ResourceSet resource = new ResourceSet("com.netscape.admin.certsrv.security.CertManagementResource");
        _certNameLabel = resource.getString("CertBasicInfo", "labelName");
        _certTypeLabel = resource.getString("CertBasicInfo", "lableType");
        _certExpirationLabel = resource.getString("CertBasicInfo", "labelExpire");
    }

    public String getCertName() {
        return _certName;
    }

    public String getCertType() {
        return _certType;
    }

    public String getCertExpiration() {
        return _certExpiration;
    }


    public String getCertInfo(String headerIndex) {
        String nReturn = "";

        if (headerIndex.equals(_certNameLabel)) {
            nReturn = getCertName();
        } else if (headerIndex.equals(_certTypeLabel)) {
            nReturn = getCertType();
        } else if (headerIndex.equals(_certExpirationLabel)) {
            nReturn = getCertExpiration();
        }

        return nReturn;
    }

    static public Vector getCertTitleLabels() {
        Vector title = new Vector();

        ResourceSet resource = new ResourceSet("com.netscape.admin.certsrv.security.CertManagementResource");
        title.addElement(resource.getString("CertBasicInfo", "labelName"));
        title.addElement(resource.getString("CertBasicInfo", "lableType"));
        title.addElement(resource.getString("CertBasicInfo", "labelExpire"));

        return title;
    }
}

