/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*-
 */
/** BEGIN COPYRIGHT BLOCK
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301  USA 
 * 
 * Copyright (C) 2007 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK **/

#ifndef __PRESENCE_SERVER_IMPL_H__
#define __PRESENCE_SERVER_IMPL_H__

#ifdef HAVE_CONFIG_H
#ifndef AUTOTOOLS_CONFIG_H
#define AUTOTOOLS_CONFIG_H

/* Eliminate warnings when using Autotools */
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#include <config.h>
#endif /* AUTOTOOLS_CONFIG_H */
#endif /* HAVE_CONFIG_H */

class PSUser;

/**
 * PresenceServerImpl.h	1.000 04/30/2002
 * 
 * Interface for WASP implementation of presence service
 *
 * @author  Rob Weltman
 * @author  Surendra Rajam
 * @version 1.000, 04/30/2002
 */

class EXPORT_DECL PresenceServerImpl:public PresenceServiceImpl {
public:
    PresenceServerImpl() {}
    virtual ~PresenceServerImpl() {}
    virtual int getAllGroups (ArrayOfstring *& groups);
    virtual int getAllUsers (WASP_String * group, ArrayOfstring *& users);
    virtual int removeGroup (WASP_String * group);
    virtual int getUsersByFilter (WASP_String * group, WASP_String * filter, int nAttributes, ArrayOfstring * attributes, ArrayOfPresenceUser *& users);
    virtual int getMultipleUserStatus (WASP_String * group,
									   int nUsers,
									   ArrayOfstring * names,
									   int nAttributes,
									   ArrayOfstring * attributes,
									   ArrayOfPresenceUser *& users);
    virtual int removeUser (WASP_String * group, WASP_String * name);
    virtual int getUserStatus (WASP_String * group, WASP_String * name, int nAttributes, ArrayOfstring * attributes, PresenceUser *& user);
    /** 
     * Gets the number of users who are online or offline in a group
     * 
     * @param group Name of group to query; NULL or empty for all groups
     * @param bOnline true to return the count of online users, false for offline
     * @return Number of users, or a negative error code on failure 
     *
     * Error Code(s):
     * PS_UNKOWN_GROUP 
     */ 
    virtual int getUserCount( WASP_String* group, int bOnline );
    virtual int addUsers (WASP_String * group, int nUsers, ArrayOfPresenceUser * users);
    virtual int addGroup (WASP_String * group, int nAttributes, ArrayOfstring * attributes);
    virtual int getSearchableAttributes (WASP_String * group, ArrayOfstring *& attributes);
    virtual int addUser (WASP_String * group, WASP_String * name, int nAttributes, ArrayOfUserAttribute * attributes);
    virtual int getSortedUsersByFilter (WASP_String * group,
										WASP_String * filter,
										WASP_String * sortKey,
										int sortKeyType,
										int nAttributes,
										ArrayOfstring * attributes,
										ArrayOfPresenceUser *& users);
    virtual int removeUsers (WASP_String * group, int nUsers, ArrayOfstring * names);
protected:
    void doLog(const char *func, int status);
    static int parseUsers(int nUsers, PSUser** tusers,
                          ArrayOfPresenceUser*& users);
    /**
     * Decodes an array of Unicode strings from a WASP string array object;
     * the result should be freed by deleting the individual strings as well as
     * the array itself; nStrings is set to 0 if wStrings is NULL
     *
     * @param attributes WASP string array object to convert
     * @param nAttributes Number of strings to process
     * @return Array of strings
     */
    char **DecodeStringArrayObject( ArrayOfstring* wStrings,
                                    int& nStrings );
};

#endif // __PRESENCE_SERVER_IMPL_H__


