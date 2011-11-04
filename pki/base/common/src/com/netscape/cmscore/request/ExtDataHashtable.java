package com.netscape.cmscore.request;

import java.util.Hashtable;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

/**
 * Subclass of Hashtable returned by IRequest.getExtDataInHashtable.  Its
 * purpose is to hide the fact that LDAP doesn't preserve the case of keys.
 * It does this by lowercasing all keys used to access the Hashtable.
 */
public class ExtDataHashtable extends Hashtable {

    public ExtDataHashtable() {
        super();
    }

    public ExtDataHashtable(int i) {
        super(i);
    }

    public ExtDataHashtable(int i, float v) {
        super(i, v);
    }

    public ExtDataHashtable(Map map) {
        // the super constructor seems to call putAll, but I can't
        // rely on that behaviour
        super();
        putAll(map);
    }

    public boolean containsKey(Object o) {
        if (o instanceof String) {
            String key = (String)o;
            return super.containsKey(key.toLowerCase());
        }
        return super.containsKey(o);
    }

    public Object get(Object o) {
        if (o instanceof String) {
            String key = (String)o;
            return super.get(key.toLowerCase());
        }
        return super.get(o);
    }

    public Object put(Object oKey, Object val) {
        if (oKey instanceof String) {
            String key = (String)oKey;
            return super.put(key.toLowerCase(), val);
        }
        return super.put(oKey, val);
    }

    public void putAll(Map map) {
        Set keys = map.keySet();
        for (Iterator i = keys.iterator();
             i.hasNext();) {
            Object key = i.next();
            put(key, map.get(key));
        }
    }

    public Object remove(Object o) {
        if (o instanceof String) {
            String key = (String)o;
            return super.remove(key.toLowerCase());
        }
        return super.remove(o);
    }
}
