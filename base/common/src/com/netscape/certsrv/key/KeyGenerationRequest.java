//--- BEGIN COPYRIGHT BLOCK ---
//This program is free software; you can redistribute it and/or modify
//it under the terms of the GNU General Public License as published by
//the Free Software Foundation; version 2 of the License.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License along
//with this program; if not, write to the Free Software Foundation, Inc.,
//51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
//(C) 2014 Red Hat, Inc.
//All rights reserved.
//--- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.key;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.lang.StringUtils;

import com.netscape.certsrv.base.ResourceMessage;

/**
 * Class to define the common attributes and methods used by
 * SymKeyGenerationRequest and AsymKeyGenerationRequest
 * @author akoneru
 *
 */
public class KeyGenerationRequest extends ResourceMessage{

    protected static final String CLIENT_KEY_ID = "clientKeyID";
    protected static final String KEY_SIZE = "keySize";
    protected static final String KEY_ALGORITHM = "keyAlgorithm";
    protected static final String KEY_USAGE = "keyUsage";
    protected static final String TRANS_WRAPPED_SESSION_KEY = "transWrappedSessionKey";
    protected static final String REALM = "realm";


    public List<String> getUsages() {
        String usageString = attributes.get(KEY_USAGE);
        if (!StringUtils.isBlank(usageString)) {
            return new ArrayList<String>(Arrays.asList(usageString.split(",")));
        }
        return new ArrayList<String>();
    }

    public void setUsages(List<String> usages) {
        attributes.put(KEY_USAGE, StringUtils.join(usages, ","));
    }

    public void addUsage(String usage) {
        List<String> usages = getUsages();
        for (String u : usages) {
            if (u.equals(usage))
                return;
        }
        usages.add(usage);
        setUsages(usages);
    }

    /**
     * @return the clientKeyId
     */
    public String getClientKeyId() {
        return attributes.get(CLIENT_KEY_ID);
    }

    /**
     * @param clientKeyId the clientKeyId to set
     */
    public void setClientKeyId(String clientKeyId) {
        attributes.put(CLIENT_KEY_ID, clientKeyId);
    }

    /**
     * @return the keySize
     */
    public Integer getKeySize() {
        try {
            return new Integer(attributes.get(KEY_SIZE));
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /**
     * @param keySize the key size to set
     */
    public void setKeySize(Integer keySize) {
        attributes.put(KEY_SIZE, keySize.toString());
    }

    /**
     * @return the keyAlgorithm
     */
    public String getKeyAlgorithm() {
        return attributes.get(KEY_ALGORITHM);
    }

    /**
     * @param keyAlgorithm the key algorithm to set
     */
    public void setKeyAlgorithm(String keyAlgorithm) {
        attributes.put(KEY_ALGORITHM, keyAlgorithm);
    }

    /**
     * @return the transWrappedSessionKey
     */
    public String getTransWrappedSessionKey() {
        return attributes.get(TRANS_WRAPPED_SESSION_KEY);
    }

    /**
     * @param transWrappedSessionKey the wrapped seesion key to set
     */
    public void setTransWrappedSessionKey(String transWrappedSessionKey) {
        attributes.put(TRANS_WRAPPED_SESSION_KEY, transWrappedSessionKey);
    }

    /**
     * @return the realm
     */
    public String getRealm() {
        return attributes.get(REALM);
    }

    /**
     * @param realm - authorization realm to set
     */
    public void setRealm(String realm) {
        if (realm != null) {
            attributes.put(REALM, realm);
        } else {
            attributes.remove(REALM);
        }
    }
}
