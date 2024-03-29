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
package com.netscape.cmscore.connector;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.OptionalDataException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.NoSuchElementException;
import java.util.Vector;

import com.netscape.certsrv.connector.IHttpPKIMessage;
import com.netscape.cmscore.request.Request;

/**
 * simple name/value pair message.
 */
public class HttpPKIMessage implements IHttpPKIMessage {

    private static final long serialVersionUID = -3378261119472034953L;

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(HttpPKIMessage.class);

    // initialized to "" because nulls don't serialize well.
    public String reqType = "";
    public String reqId = "";
    protected String reqStatus = "";
    protected String reqRealm = "";
    protected Vector<Object> mNameVals = new Vector<>(); // sequence of name/vals.

    public HttpPKIMessage() {
    }

    @Override
    public String getReqStatus() {
        return reqStatus;
    }

    @Override
    public String getReqType() {
        return reqType;
    }

    @Override
    public String getReqId() {
        return reqId;
    }

    @Override
    public String getReqRealm() {
        return reqRealm;
    }

    /**
     * copy contents of request to make a simple name/value message.
     */
    @Override
    public void fromRequest(Request r) {
        // actually don't need to copy source id since
        reqType = r.getRequestType();
        reqId = r.getRequestId().toString();
        reqStatus = r.getRequestStatus().toString();
        reqRealm = r.getRealm();

        logger.debug("HttpPKIMessage.fromRequest: requestId="
                + r.getRequestId().toString() + " requestStatus=" + reqStatus + " instance=" + r);

        String attrs[] = RequestTransfer.getTransferAttributes(r);
        String[] names = attrs;
        Object value = null;

        for (int i = 0; i < attrs.length; i++) {
            String key = names[i];
            if (r.isSimpleExtDataValue(key)) {
                value = r.getExtDataInString(key);
            } else {
                value = r.getExtDataInHashtable(key);
            }
            if (value != null) {
                mNameVals.addElement(key);
                mNameVals.addElement(value);
            }
        }
    }

    /**
     * copy contents to request.
     */
    @Override
    @SuppressWarnings("unchecked")
    public void toRequest(Request r) {
        // id, type and status
        // type had to have been set in instantiation.
        // id is checked but not reset.
        // request status cannot be set, but can be looked at.
        reqStatus = r.getRequestStatus().toString();
        logger.debug("HttpPKMessage.toRequest: requestStatus=" + reqStatus);

        String key;
        Object value;
        Enumeration<Object> enum1 = mNameVals.elements();

        while (enum1.hasMoreElements()) {
            key = (String) enum1.nextElement();
            try {
                value = enum1.nextElement();
                if (value instanceof String) {
                    r.setExtData(key, (String) value);
                } else if (value instanceof Hashtable) {
                    r.setExtData(key, (Hashtable<String, String>) value);
                } else {
                    logger.warn("HttpPKIMessage.toRequest(): key: " + key +
                            " has unexpected type " + value.getClass().toString());
                }
            } catch (NoSuchElementException e) {
                logger.warn("Incorrect pairing of name/value for " + key);
            }
        }
    }

    private void writeObject(java.io.ObjectOutputStream out)
            throws IOException {
        logger.debug("writeObject");
        out.writeObject(reqType);
        logger.trace("read object req type " + reqType);
        out.writeObject(reqId);
        logger.trace("read object req id " + reqId);
        out.writeObject(reqStatus);
        logger.trace("read object req source status " + reqStatus);
        out.writeObject(reqRealm);
        logger.trace("read object req realm " + reqRealm);
        Enumeration<Object> enum1 = mNameVals.elements();

        while (enum1.hasMoreElements()) {
            Object key = null;
            Object val = null;
            key = enum1.nextElement();
            try {
                val = enum1.nextElement();
                // test if key and value are serializable
                ObjectOutputStream os =
                        new ObjectOutputStream(new ByteArrayOutputStream());
                os.writeObject(key);
                os.writeObject(val);

                // ok, if we dont have problem serializing the objects,
                // then write the objects into the real object stream
                out.writeObject(key);
                out.writeObject(val);
            } catch (Exception e) {
                // skip not serialiable attribute in DRM
                // DRM does not need to store the enrollment request anymore
                logger.warn("HttpPKIMessage:skipped key=" +
                        key.getClass().getName());
                if (val == null) {
                    logger.warn("HttpPKIMessage:skipped val= null");
                } else {
                    logger.warn("HttpPKIMessage:skipped val=" +
                            val.getClass().getName());
                }
            }
        }
    }

    private void readObject(java.io.ObjectInputStream in)
            throws IOException, ClassNotFoundException, OptionalDataException {
        reqType = (String) in.readObject();
        reqId = (String) in.readObject();
        reqStatus = (String) in.readObject();
        reqRealm = (String) in.readObject();
        mNameVals = new Vector<>();
        Object keyorval = null;

        try {
            boolean iskey = true;

            while (true) {
                boolean skipped = false;
                try {
                    keyorval = in.readObject();
                } catch (OptionalDataException e) {
                    throw e;
                } catch (IOException e) {
                    // just skipped parameter
                    logger.warn("skipped attribute in request e=" + e);
                    if (!iskey) {
                        int s = mNameVals.size();
                        if (s > 0) {
                            // remove previous key if this is value
                            mNameVals.removeElementAt(s - 1);
                            skipped = true;
                            keyorval = "";
                        }
                    }
                }
                if (iskey) {
                    logger.trace("read key " + keyorval);
                    iskey = false;
                } else {
                    logger.trace("read val " + keyorval);
                    iskey = true;
                }
                logger.trace("read " + keyorval);
                if (!skipped) {
                    if (keyorval == null)
                        break;
                    mNameVals.addElement(keyorval);
                }
            }
        } catch (OptionalDataException e) {
            if (e.eof == true) {
                logger.trace("end of stream");
            } else {
                logger.trace(" " + e.length);
                throw e;
            }
        }
    }
}
