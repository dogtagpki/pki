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
// (C) 2015 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.certsrv.authentication;

import java.math.BigInteger;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;

import org.apache.catalina.realm.GenericPrincipal;

import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.usrgrp.Certificates;


/**
 * Authentication token that wraps an externally authenticated
 * principal to return.
 */
public class ExternalAuthToken implements IAuthToken {

    protected GenericPrincipal principal;

    public ExternalAuthToken(GenericPrincipal principal) {
        this.principal = principal;
    }

    public Principal getPrincipal() {
        return principal;
    }

    public Enumeration<String> getElements() {
        ArrayList<String> keys = new ArrayList<>();
        keys.add(GROUPS);
        keys.add(TOKEN_AUTHMGR_INST_NAME);
        keys.add(UID);
        keys.add(USER_ID);
        return Collections.enumeration(keys);
    }

    public Object get(String k) {
        return null;
    }

    public boolean set(String k, String v) {
        return false;
    }

    public String getInString(String k) {
        if (k == null)
            return null;
        if (k.equals(USER_ID) || k.equals(UID))
            return principal.getName();
        if (k.equals(TOKEN_AUTHMGR_INST_NAME))
            return "external";
        return null;
    }

    public boolean set(String k, byte[] v) {
        return false;
    }

    public byte[] getInByteArray(String k) {
        return null;
    }

    public boolean set(String k, Integer v) {
        return false;
    }

    public Integer getInInteger(String k) {
        return null;
    }

    public boolean set(String k, BigInteger[] v) {
        return false;
    }

    public BigInteger[] getInBigIntegerArray(String k) {
        return null;
    }

    public boolean set(String k, Date v) {
        return false;
    }

    public Date getInDate(String k) {
        return null;
    }

    public boolean set(String k, String[] v) {
        return false;
    }

    public String[] getInStringArray(String k) {
        if (k == null)
            return null;
        if (k.equals(GROUPS))
            return principal.getRoles();
        return null;
    }

    public boolean set(String k, X509CertImpl v) {
        return false;
    }

    public X509CertImpl getInCert(String k) {
        return null;
    }

    public boolean set(String k, CertificateExtensions v) {
        return false;
    }

    public CertificateExtensions getInCertExts(String k) {
        return null;
    }

    public boolean set(String k, Certificates v) {
        return false;
    }

    public Certificates getInCertificates(String k) {
        return null;
    }

    public boolean set(String k, byte[][] v) {
        return false;
    }

    public byte[][] getInByteArrayArray(String k) {
        return null;
    }
}
