package com.netscape.cmscore.dbs;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Enumeration;
import java.util.Vector;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.IDBObj;

public class DBRecord implements IDBObj {

    private static final long serialVersionUID = 1L;

    @Override
    public void set(String name, Object value) throws EBaseException {
        try {
            // find setter
            String setter = "set" + Character.toUpperCase(name.charAt(0)) + name.substring(1);
            for (Method method : getClass().getMethods()) {
                if (!method.getName().equals(setter)) continue;

                // invoke setter
                method.invoke(this, value);
                return;
            }

            // if setter not available, set field directly
            Field field = getClass().getField(name);
            field.set(this, value);

        } catch (InvocationTargetException|NoSuchFieldException|IllegalAccessException e) {
            throw new EBaseException(e.getMessage(), e);
        }
    }

    @Override
    public Object get(String name) throws EBaseException {
        try {
            // find getter
            String getter = "get" + Character.toUpperCase(name.charAt(0)) + name.substring(1);
            for (Method method : getClass().getMethods()) {
                if (!method.getName().equals(getter)) continue;

                // invoke getter
                return method.invoke(this);
            }

            // if getter not available, get field directly
            Field field = getClass().getField(name);
            return field.get(this);

        } catch (InvocationTargetException|NoSuchFieldException|IllegalAccessException e) {
            throw new EBaseException(e.getMessage(), e);
        }
    }

    @Override
    public void delete(String name) throws EBaseException {
        set(name, null);
    }

    @Override
    public Enumeration<String> getElements() {
        return getSerializableAttrNames();
    }

    @Override
    public Enumeration<String> getSerializableAttrNames() {
        Vector<String> list = new Vector<String>();

        // get attributes defined in setters/getters
        for (Method method : getClass().getMethods()) {
            DBAttribute dbAttribute = method.getAnnotation(DBAttribute.class);
            if (dbAttribute == null) continue;

            String name = method.getName();
            if (!name.matches("^set.+") && !name.matches("^get.+")) continue;

            // get attribute name from method name
            name = Character.toLowerCase(name.charAt(3)) + name.substring(4);
            list.add(name);
        }

        // get attributes defined in fields
        for (Field field : getClass().getFields()) {
            DBAttribute dbAttribute = field.getAnnotation(DBAttribute.class);
            if (dbAttribute == null) continue;

            String name = field.getName();
            list.add(name);
        }

        return list.elements();
    }

}