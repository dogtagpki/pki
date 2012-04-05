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
package com.netscape.certsrv.policy;

/**
 * Class that can be used to form general names from configuration file.
 * Used by policies and extension commands.
 * <P>
 *
 * <PRE>
 * NOTE:  The Policy Framework has been replaced by the Profile Framework.
 * </PRE>
 * <P>
 *
 * @deprecated
 * @version $Revision$, $Date$
 */
public interface IGeneralNameUtil {

    public static final String PROP_NUM_GENERALNAMES = "numGeneralNames";
    public static final String PROP_GENERALNAME = "generalName";
    public static final String PROP_GENNAME_CHOICE = "generalNameChoice";
    public static final String PROP_GENNAME_VALUE = "generalNameValue";
    public static final String GENNAME_CHOICE_RFC822NAME = "rfc822Name";
    public static final String GENNAME_CHOICE_DIRECTORYNAME = "directoryName";
    public static final String GENNAME_CHOICE_DNSNAME = "dNSName";
    public static final String GENNAME_CHOICE_X400ADDRESS = "x400Address";
    public static final String GENNAME_CHOICE_EDIPARTYNAME = "ediPartyName";
    public static final String GENNAME_CHOICE_URL = "URL";
    public static final String GENNAME_CHOICE_IPADDRESS = "iPAddress";
    public static final String GENNAME_CHOICE_REGISTEREDID = "OID";
    public static final String GENNAME_CHOICE_OTHERNAME = "otherName";

    /**
     * Default number of general names.
     */
    public static final int DEF_NUM_GENERALNAMES = 8;

    /**
     * Default extended plugin info.
     */
    public static String NUM_GENERALNAMES_INFO =
            "number;The total number of alternative names or identities permitted in the extension.";
    public static String GENNAME_CHOICE_INFO =
            "choice(" +
                    IGeneralNameUtil.GENNAME_CHOICE_RFC822NAME + "," +
                    IGeneralNameUtil.GENNAME_CHOICE_DIRECTORYNAME + "," +
                    IGeneralNameUtil.GENNAME_CHOICE_DNSNAME + "," +
                    IGeneralNameUtil.GENNAME_CHOICE_EDIPARTYNAME + "," +
                    IGeneralNameUtil.GENNAME_CHOICE_URL + "," +
                    IGeneralNameUtil.GENNAME_CHOICE_IPADDRESS + "," +
                    IGeneralNameUtil.GENNAME_CHOICE_REGISTEREDID + "," +
                    IGeneralNameUtil.GENNAME_CHOICE_OTHERNAME + ");" +
                    "GeneralName choice. See RFC 2459 appendix B2 on GeneralName.";
    public static String GENNAME_VALUE_INFO =
            "string;Value according to the GeneralName choice.";

    public static String PROP_NUM_GENERALNAMES_INFO = PROP_NUM_GENERALNAMES + ";" + NUM_GENERALNAMES_INFO;
    public static String PROP_GENNAME_CHOICE_INFO = PROP_GENNAME_CHOICE + ";" + GENNAME_CHOICE_INFO;
    public static String PROP_GENNAME_VALUE_INFO = PROP_GENNAME_VALUE + ";" + GENNAME_VALUE_INFO;

}
