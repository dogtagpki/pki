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
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.dogtagpki.server.tks.servlet;

//Simple class used to hold scp03 related settings in TKS keyset config block
// Ex: tks.defKeySet.prot3.divers=emv
//     tks.defKeySet.prot3.diversVer1Keys=emv

// Will probably be extended to allow params for future tokens

public class GPParams {

    public static final String DIVER_EMV = "emv";
    public static final String DIVER_NONE = "none";
    public static final String DIVER_VISA2 = "visa2";
    public static final String DIVER_GPKMC = "gpkmc";
    public static final String NIST_SP800 = "nistsp_800";
    public static final String AES = "AES";
    public static final String DES3 ="DES3";

    protected GPParams() {
    }

    // Diversification scheme for all keysets after 1
    private String diversificationScheme;
    //Diversification scheme for just version one or developer keys
    private String version1DiversificationScheme;

    private String devKeyType;
    private String masterKeyType;

    public String getDevKeyType() {
        return devKeyType;
    }

    public String getMasterKeyType() {
        return masterKeyType;
    }

    public void setDevKeyType(String newType) {
        devKeyType = newType;
    }

    public void setMasterKeyType(String newType) {
        masterKeyType = newType;
    }

    public boolean isDiversGPKMC() {
        return DIVER_GPKMC.equalsIgnoreCase(diversificationScheme);
    }

    public boolean isDiversEmv() {
        return DIVER_EMV.equalsIgnoreCase(diversificationScheme);
    }

    public boolean isDiversVisa2() {
        return DIVER_VISA2.equalsIgnoreCase(diversificationScheme);
    }

    public boolean isDiversNone() {
        return DIVER_NONE.equalsIgnoreCase(diversificationScheme);
    }

    public boolean isVer1DiversGPKMC() {
        return DIVER_GPKMC.equalsIgnoreCase(version1DiversificationScheme);
    }

    public boolean isVer1DiversEmv() {
        return DIVER_EMV.equalsIgnoreCase(version1DiversificationScheme);
    }

    public boolean isVer1DiversVisa2() {
        return DIVER_VISA2.equalsIgnoreCase(version1DiversificationScheme);

    }

    public boolean isVer1DiversNone() {
        return DIVER_NONE.equalsIgnoreCase(version1DiversificationScheme);
    }

    public void setDiversificationScheme(String scheme) {
        diversificationScheme = scheme;
    }

    public String getDiversificationScheme() {
        return diversificationScheme;
    }

    public String getVersion1DiversificationScheme() {
        return version1DiversificationScheme;
    }

    public void setVersion1DiversificationScheme(String version1DiversificationScheme) {
        this.version1DiversificationScheme = version1DiversificationScheme;
    }

    @Override
    public String toString() {
        return " Version1 Diversification Scheme: " + version1DiversificationScheme + " All other versions : "
                + diversificationScheme;
    }

}
