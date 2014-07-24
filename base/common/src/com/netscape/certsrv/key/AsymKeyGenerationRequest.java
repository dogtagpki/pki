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

import javax.ws.rs.core.MultivaluedMap;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

import org.apache.commons.lang.StringUtils;

import com.netscape.certsrv.base.ResourceMessage;

@XmlRootElement(name = "AsymKeyGenerationRequest")
@XmlAccessorType(XmlAccessType.FIELD)
public class AsymKeyGenerationRequest extends KeyGenerationRequest {

    // Asymmetric Key Usages
    public static final String ENCRYPT = "encrypt";
    public static final String DECRYPT = "decrypt";
    public static final String SIGN = "sign";
    public static final String SIGN_RECOVER = "sign_recover";
    public static final String VERIFY = "verify";
    public static final String VERIFY_RECOVER = "verify_recover";
    public static final String WRAP = "wrap";
    public static final String UNWRAP = "unwrap";
    public static final String DERIVE = "derive";

    public AsymKeyGenerationRequest() {
        // required for JAXB (defaults)
        setClassName(getClass().getName());
    }

    public AsymKeyGenerationRequest(MultivaluedMap<String, String> form) {
        attributes.put(CLIENT_KEY_ID, form.getFirst(CLIENT_KEY_ID));
        attributes.put(KEY_SIZE, form.getFirst(KEY_SIZE));
        attributes.put(KEY_ALGORITHM, form.getFirst(KEY_ALGORITHM));
        attributes.put(KEY_USAGE, form.getFirst(KEY_USAGE));
        attributes.put(TRANS_WRAPPED_SESSION_KEY, form.getFirst(TRANS_WRAPPED_SESSION_KEY));

        String usageString = attributes.get(KEY_USAGE);
        if (!StringUtils.isBlank(usageString)) {
            setUsages(new ArrayList<String>(Arrays.asList(usageString.split(","))));
        }
        setClassName(getClass().getName());
    }

    public AsymKeyGenerationRequest(ResourceMessage data) {
        attributes.putAll(data.getAttributes());
        setClassName(getClass().getName());
    }

    public String toString() {
        try {
            return ResourceMessage.marshal(this, AsymKeyGenerationRequest.class);
        } catch (Exception e) {
            return super.toString();
        }
    }

    public static AsymKeyGenerationRequest valueOf(String string) throws Exception {
        try {
            return ResourceMessage.unmarshal(string, AsymKeyGenerationRequest.class);
        } catch (Exception e) {
            return null;
        }
    }

    public static List<String> getValidUsagesList() {
        List<String> list = new ArrayList<String>();
        list.add(DERIVE);
        list.add(SIGN);
        list.add(DECRYPT);
        list.add(ENCRYPT);
        list.add(WRAP);
        list.add(UNWRAP);
        list.add(SIGN_RECOVER);
        list.add(VERIFY);
        list.add(VERIFY_RECOVER);

        return list;
    }

    public static void main(String[] args) {
        AsymKeyGenerationRequest request = new AsymKeyGenerationRequest();
        request.setKeyAlgorithm(KeyRequestResource.RSA_ALGORITHM);
        request.setKeySize(1024);
        request.setClientKeyId("vek12345");
        List<String> usages = new ArrayList<String>();
        usages.add(AsymKeyGenerationRequest.ENCRYPT);
        usages.add(AsymKeyGenerationRequest.DECRYPT);
        request.setUsages(usages);

        System.out.println(request.toString());
    }
}
