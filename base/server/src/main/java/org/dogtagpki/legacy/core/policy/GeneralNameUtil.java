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
package org.dogtagpki.legacy.core.policy;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.StringTokenizer;

import org.dogtagpki.legacy.policy.IGeneralNameUtil;
import org.mozilla.jss.netscape.security.util.DerValue;
import org.mozilla.jss.netscape.security.util.ObjectIdentifier;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.DNSName;
import org.mozilla.jss.netscape.security.x509.EDIPartyName;
import org.mozilla.jss.netscape.security.x509.GeneralName;
import org.mozilla.jss.netscape.security.x509.GeneralNameInterface;
import org.mozilla.jss.netscape.security.x509.IPAddressName;
import org.mozilla.jss.netscape.security.x509.InvalidIPAddressException;
import org.mozilla.jss.netscape.security.x509.OIDName;
import org.mozilla.jss.netscape.security.x509.RFC822Name;
import org.mozilla.jss.netscape.security.x509.URIName;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.apps.CMS;

/**
 * Class that can be used to form general names from configuration file.
 * Used by policies and extension commands.
 */
public class GeneralNameUtil implements IGeneralNameUtil {

    public static Logger logger = LoggerFactory.getLogger(GeneralNameUtil.class);
    static final String DOT = ".";

    /**
     * GeneralName can be used in the context of Constraints. Examples
     * are NameConstraints, CertificateScopeOfUse extensions. In such
     * cases, IPAddress may contain netmask component.
     */
    static public GeneralName
            form_GeneralNameAsConstraints(String generalNameChoice, String value)
                    throws EBaseException {
        try {
            if (generalNameChoice.equalsIgnoreCase(GENNAME_CHOICE_IPADDRESS)) {
                StringTokenizer st = new StringTokenizer(value, ",");
                String ip = st.nextToken();
                String netmask = null;

                if (st.hasMoreTokens()) {
                    netmask = st.nextToken();
                }
                return new GeneralName(new IPAddressName(ip, netmask));
            } else {
                return form_GeneralName(generalNameChoice, value);
            }
        } catch (InvalidIPAddressException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_IP_ADDR", value));
        }
    }

    /**
     * Form a General Name from a General Name choice and value.
     * The General Name choice must be one of the General Name Choice Strings
     * defined in this class.
     *
     * @param generalNameChoice General Name choice. Must be one of the General
     *            Name choices defined in this class.
     * @param value String value of the general name to form.
     */
    static public GeneralName
            form_GeneralName(String generalNameChoice, String value)
                    throws EBaseException {
        GeneralNameInterface generalNameI = null;
        DerValue derVal = null;
        GeneralName generalName = null;

        try {
            if (generalNameChoice.equalsIgnoreCase(GENNAME_CHOICE_OTHERNAME)) {
                byte[] val = Utils.base64decode(value);

                derVal = new DerValue(new ByteArrayInputStream(val));
                logger.trace("otherName formed");
            } else if (generalNameChoice.equalsIgnoreCase(GENNAME_CHOICE_RFC822NAME)) {
                generalNameI = new RFC822Name(value);
                logger.trace("rfc822Name formed ");
            } else if (generalNameChoice.equalsIgnoreCase(GENNAME_CHOICE_DNSNAME)) {
                generalNameI = new DNSName(value);
                logger.trace("dnsName formed");
            }/**
             * not supported -- no sun class
             * else if (generalNameChoice.equalsIgnoreCase(GENNAME_CHOICE_X400ADDRESS)) {
             * }
             **/
            else if (generalNameChoice.equalsIgnoreCase(GENNAME_CHOICE_DIRECTORYNAME)) {
                generalNameI = new X500Name(value);
                logger.trace("X500Name formed");
            } else if (generalNameChoice.equalsIgnoreCase(GENNAME_CHOICE_EDIPARTYNAME)) {
                generalNameI = new EDIPartyName(value);
                logger.trace("ediPartyName formed");
            } else if (generalNameChoice.equalsIgnoreCase(GENNAME_CHOICE_URL)) {
                generalNameI = new URIName(value);
                logger.trace("url formed");
            } else if (generalNameChoice.equalsIgnoreCase(GENNAME_CHOICE_IPADDRESS)) {
                generalNameI = new IPAddressName(value);
                logger.trace("ipaddress formed");
            } else if (generalNameChoice.equalsIgnoreCase(GENNAME_CHOICE_REGISTEREDID)) {
                ObjectIdentifier oid;

                try {
                    oid = new ObjectIdentifier(value);
                } catch (Exception e) {
                    throw new EBaseException(
                            CMS.getUserMessage("CMS_BASE_INVALID_VALUE_FOR_TYPE",
                                    generalNameChoice,
                                    "value must be a valid OID in the form n.n.n.n"));
                }
                generalNameI = new OIDName(oid);
                logger.trace("oidname formed");
            } else {
                throw new EBaseException(
                        CMS.getUserMessage("CMS_BASE_INVALID_ATTR_VALUE",
                                new String[] {
                                        PROP_GENNAME_CHOICE,
                                        "value must be one of: " +
                                                GENNAME_CHOICE_OTHERNAME + ", " +
                                                GENNAME_CHOICE_RFC822NAME + ", " +
                                                GENNAME_CHOICE_DNSNAME + ", " +

                                                /* GENNAME_CHOICE_X400ADDRESS +", "+ */
                                                GENNAME_CHOICE_DIRECTORYNAME + ", " +
                                                GENNAME_CHOICE_EDIPARTYNAME + ", " +
                                                GENNAME_CHOICE_URL + ", " +
                                                GENNAME_CHOICE_IPADDRESS + ", or " +
                                                GENNAME_CHOICE_REGISTEREDID + "."
                            }
                                ));
            }
        } catch (IOException e) {
            logger.error("GeneralNameUtil: " + e.getMessage(), e);
            throw new EBaseException(
                    CMS.getUserMessage("CMS_BASE_INVALID_VALUE_FOR_TYPE",
                            generalNameChoice, e.toString()));
        } catch (InvalidIPAddressException e) {
            logger.error("GeneralNameUtil: " + e.getMessage(), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_IP_ADDR", value));
        } catch (RuntimeException e) {
            logger.error("GeneralNameUtil: " + e.getMessage(), e);
            throw e;
        }

        try {
            if (generalNameI != null)
                generalName = new GeneralName(generalNameI);
            else
                generalName = new GeneralName(derVal);
            logger.trace("general name formed");
            return generalName;
        } catch (IOException e) {
            logger.error("GeneralNameUtil: " + e.getMessage(), e);
            throw new EBaseException(
                    CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", "Could not form GeneralName. Error: " + e));
        }
    }

    /**
     * Checks if given string is a valid General Name choice and returns
     * the actual string that can be passed into form_GeneralName().
     *
     * @param generalNameChoice a General Name choice string.
     * @return one of General Name choices defined in this class that can be
     *         passed into form_GeneralName().
     */
    static public String check_GeneralNameChoice(String generalNameChoice)
            throws EBaseException {
        String theGeneralNameChoice = null;

        if (generalNameChoice.equalsIgnoreCase(GENNAME_CHOICE_OTHERNAME))
            theGeneralNameChoice = GENNAME_CHOICE_OTHERNAME;
        else if (generalNameChoice.equalsIgnoreCase(GENNAME_CHOICE_RFC822NAME))
            theGeneralNameChoice = GENNAME_CHOICE_RFC822NAME;
        else if (generalNameChoice.equalsIgnoreCase(GENNAME_CHOICE_DNSNAME))
            theGeneralNameChoice = GENNAME_CHOICE_DNSNAME;

        /* X400Address not supported.
         else if (generalNameChoice.equalsIgnoreCase(GENNAME_CHOICE_X400ADDRESS))
         theGeneralNameChoice = GENNAME_CHOICE_X400ADDRESS;
         */
        else if (generalNameChoice.equalsIgnoreCase(GENNAME_CHOICE_DIRECTORYNAME))
            theGeneralNameChoice = GENNAME_CHOICE_DIRECTORYNAME;
        else if (generalNameChoice.equalsIgnoreCase(GENNAME_CHOICE_EDIPARTYNAME))
            theGeneralNameChoice = GENNAME_CHOICE_EDIPARTYNAME;
        else if (generalNameChoice.equalsIgnoreCase(GENNAME_CHOICE_URL))
            theGeneralNameChoice = GENNAME_CHOICE_URL;
        else if (generalNameChoice.equalsIgnoreCase(GENNAME_CHOICE_IPADDRESS))
            theGeneralNameChoice = GENNAME_CHOICE_IPADDRESS;
        else if (generalNameChoice.equalsIgnoreCase(GENNAME_CHOICE_REGISTEREDID))
            theGeneralNameChoice = GENNAME_CHOICE_REGISTEREDID;
        else {
            throw new EBaseException(
                    CMS.getUserMessage("CMS_BASE_INVALID_ATTR_VALUE",
                            new String[] {
                                    PROP_GENNAME_CHOICE + "=" + generalNameChoice,
                                    "value must be one of: " +
                                            GENNAME_CHOICE_OTHERNAME + ", " +
                                            GENNAME_CHOICE_RFC822NAME + ", " +
                                            GENNAME_CHOICE_DNSNAME + ", " +

                                            /* GENNAME_CHOICE_X400ADDRESS +", "+ */
                                            GENNAME_CHOICE_DIRECTORYNAME + ", " +
                                            GENNAME_CHOICE_EDIPARTYNAME + ", " +
                                            GENNAME_CHOICE_URL + ", " +
                                            GENNAME_CHOICE_IPADDRESS + ", " +
                                            GENNAME_CHOICE_REGISTEREDID + "."
                        }
                            ));
        }
        return theGeneralNameChoice;
    }
}
