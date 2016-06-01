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
package com.netscape.cms.servlet.tks;


//Simple class used to hold scp03 related settings in TKS keyset config block
// Ex: tks.defKeySet.prot3.divers=emv
//     tks.defKeySet.prot3.diversVer1Keys=emv

// Will probably be extended to allow params for future tokens

public class GPParams {

    public static String DIVER_EMV = "emv";
    public static String DIVER_NONE = "none";
    public static String DIVER_VISA2 = "visa2";
    public static String NIST_SP800 = "nistsp_800";

    public GPParams() {
    }

    // Diversification scheme for all keysets after 1
    private String diversificationScheme;
    //Diversification scheme for just version one or developer keys
    private String version1DiversificationScheme;

    public boolean isDiversEmv() {
        if (DIVER_EMV.equalsIgnoreCase(diversificationScheme))
            return true;
        else
            return false;
    }

    public boolean isDiversVisa2() {
        if (DIVER_VISA2.equalsIgnoreCase(diversificationScheme))
            return true;
        else
            return false;
    }

    public boolean isDiversNone() {
        if (DIVER_NONE.equalsIgnoreCase(diversificationScheme))
            return true;
        else
            return false;
    }

    public boolean isVer1DiversEmv() {
        if (DIVER_EMV.equalsIgnoreCase(version1DiversificationScheme))
            return true;
        else
            return false;
    }

    public boolean isVer1DiversVisa2() {
        if (DIVER_VISA2.equalsIgnoreCase(version1DiversificationScheme))
            return true;
        else
            return false;

    }

    public boolean isVer1DiversNone() {
        if (DIVER_NONE.equalsIgnoreCase(version1DiversificationScheme))
            return true;
        else
            return false;
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

    public String toString() {
        String output = " Version1 Diversification Scheme: " + version1DiversificationScheme + " All other versions : "
                + diversificationScheme;

        return output;
    }

}
