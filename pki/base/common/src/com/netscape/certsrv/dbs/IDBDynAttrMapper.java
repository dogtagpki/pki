package com.netscape.certsrv.dbs;

/**
 * An interface representing a dynamic attribute mapper.
 * A dynamic mapper has knowledge on how to convert a set of dynamically
 * assigned db attribute into zero or more dynamically assigned LDAP
 * attributes, and vice versa.
 * <P>
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public interface IDBDynAttrMapper extends IDBAttrMapper {

    /**
     * Returns true if the LDAP attribute can be mapped by this
     * dynamic mapper.
     *
     * @param attrName LDAP attribute name to check
     * @return a list of supported attribute names
     */
    public boolean supportsLDAPAttributeName(String attrName);
}
