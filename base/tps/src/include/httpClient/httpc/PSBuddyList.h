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

#ifndef __PS_BUDDY_LIST_H__
#define __PS_BUDDY_LIST_H__

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

/**
 * PSBuddyList.h	1.000 05/21/2002
 * 
 * This class maintains users information which are set for 
 * online status tracking. The online status of users are updated 
 * through a PSBuddyListener interface implemented by this class. 
 *
 * @author  Surendra Rajam
 * @version 1.000, 05/21/2002
 */
class PSBuddyList : 
    public PSBuddyListener
{
private:

	/**
	 * Constructor
	 */
	PSBuddyList();

	/**
	 * Destructor
	 */
	virtual ~PSBuddyList();

public:

	/**
	 * Gets an instance of the class
	 */
	static PSBuddyList* GetBuddyList();

	public:

	/**
	 * Save the users maintain by an instance of presence server 
	 * to a local file in the BLT format
	 *
	 * @return 0 on succcess, negative error code otherwise
	 */
	int SaveBuddyList();

	/**
	 * Loads the users into an instance of presence server 
	 * from a local file
	 *
	 * @return 0 on succcess, negative error code otherwise
	 */
	int LoadBuddyList();

	/**
	 * Sets a service provider. We currently support only one service
	 * provider in a presence server instance.
	 *
	 * @return 0 on succcess, negative error code otherwise
	 */
	int RegisterService(PSBuddyService* service);

	/** 
	 * Gets the online status of a user along with the 
	 * requested additional attributes
	 * 
	 * @param     group       group name to which the user belongs 
	 * @param     name        the screen name of the user to query status for 
	 * @param     nAttributes number of attributes 
	 * @param     attributes  the names of the attributes of the user to return 
	 * @param     user        upon return, filled with user attributes 
	 * @return                0 on success, a negative error code on failure 
	 */ 
	int GetUserStatus( const char* group, 
					   const char* name, 
					   int nAttributes, 
					   char** attributes, 
					   PSUser** user );

	/** 
	 * Gets the online status of multiple users along with the requested
	 * additional attributes
	 * 
	 * @param     group       group name to which the user belongs 
	 * @param     nUsers      the number of screen names to status query for
	 * @param     names       the screen names of the users to query status for 
	 * @param     nAttributes number of attributes 
	 * @param     attributes  the names of the attributes of the user to return 
	 * @param     user        upon return, filled with user attributes 
	 * @return                0 on success, a negative error code on failure 
	 */ 
	int GetMultipleUserStatus( const char* group,
							   int nUsers,
							   char** names,
							   int nAttributes,
							   char** attributes,
							   PSUser*** users );

	/** 
	 * Gets the screen names and attributes of users that match 
	 * certain search criteria
	 * 
	 * @param     group       group name to query from 
	 * @param     filter      an LDAP-like search expression on 
	 *						  presence status attributes 
	 * @param     nAttrbiutes number of attributes 
	 * @param     attributes  the names of the attributes of the user to return 
	 * @param     user        upon return, an array of users with 
	 *						  requested attributes 
	 * @return                number of users returned, or a negative error code 
	 */ 
	int GetUsersByFilter( const char* group, 
						  const char* filter, 
						  int nAttributes, 
						  char** attributes, 
						  PSUser*** users );

	/** 
	 * Gets the screen names and attributes of users that match certain search
	 * criteria and sorts the results (currently only by entryId)
	 * 
	 * @param     group       group name to query from 
	 * @param     filter      an LDAP-like search expression on presence status
	 *                        attributes 
	 * @param     sortKey     name of attribute to sort on
	 * @param     sortKeyType 1 for numeric, 2 for string
	 * @param     nAttributes number of attributes 
	 * @param     attributes  the names of the attributes of the user to return 
	 * @param     user        upon return, an array of users with requested
	 *                        attributes 
	 * @return                number of users returned, or a negative error code 
	 */ 
	int GetSortedUsersByFilter(	const char* group, 
								const char* filter, 
								const char *sortKey, 
								int sortKeyType, 
								int nAttributes, 
								char** attributes, 
								PSUser*** users	);

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
	int GetBuddyCount( const char* group, int bOnline );

	/** 
	 * Add a new group 
	 * 
	 * @param     group       name of the new group 
	 * @param     nAttributes number of attributes 
	 * @param     attributes  attributes the group will support 
	 * @return                0 on success, a negative error code on failure 
	 */ 
	int AddGroup( const char* group, int nAttributes, char** attributes	); 

	/** 
	 * Adds a user to be tracked. 
	 * 
	 * @param     group       name of the group to add the user in 
	 * @param     name        screen name of the user to track 
	 * @param     nAttributes number of attributes 
	 * @param     attributes  the attributes of the users to be stored 
	 * @return                on success, 0 or an error code 
	 */
	int AddUser( const char* group, 
				 const char* name, 
				 int nAttributes, 
				 PSAttribute** attributes );

	/** 
	 * Adds a number of users to track. 
	 * 
	 * @param     group       name of the group to which the users belong 
	 * @param     nUsers      number of users 
	 * @param     users       names and attributes of users to track 
	 * @return                number of users added on success, 
							  or a negative error code on failure 
	 */ 
	int AddUsers( const char* group, 
				  int nUsers, 
				  PSUser** users );

	/** 
	 * Removes a user to be tracked. 
	 * 
	 * @param     group       name of the group to which the user belongs 
	 * @param     name        screen name of the user to be removed 
	 * @return                0 on success, or a negative error code on failure 
	 */ 
	int RemoveUser(	const char* group, const char* name	);

	/** 
	 * Removes a number of users to be tracked. 
	 * 
	 * @param     group       name of the group to which the users belong 
	 * @param     nUsers      number of users 
	 * @param     names       screen name of the users to be removed 
	 * @return                number of users removed on success, 
	 *						or a negative error code on failure 
	 */ 
	int RemoveUsers( const char* group, int nUsers, char** names );

	/** 
	 * Removes a group. 
	 * 
	 * @param     group       name of the group to be removed 
	 * @return                number of users removed on success, 
	 *						or a negative error code on failure 
	 * 
	 * Error Code(s):
	 * PS_UNKNOWN_GROUP 
	 */ 
	int RemoveGroup(const char* group); 

	/** 
	 * Gets the list of groups. 
	 * 
	 * @param     groups      upon return, array containing group names 
	 * @return                number of groups or 0 if no group present 
	 * 
	 * Error Code(s):
	 * PS_NO_GROUPS
	 */ 
	int GetAllGroups(char*** groups);

	/** 
	 * Gets the users in a group(s). 
	 * 
	 * @param     group       name of the group to query 
	 * @param     users       upon return, array of User objects 
	 * @return                number of users returned, 
	 *						 or a negative error code on failure 
	 */ 
	int GetAllUsers( const char* group, PSUser*** users	); 

	/** 
	 * Gets the attributes supported by a group(s)
	 * 
	 * @param     group			name of the group
	 * @param	  attributes	upon return, array of attributes
	 * @return					number of users removed on success, 
	 *							or a negative error code on failure 
	 */ 
	int GetSearchableAttributes( const char* group, char*** attributes );

	// PSBuddyListener interface
	/**
	 * Callback to notify buddy changes
	 *
	 * @param	service	the reporting buddy service
	 * @param	buddy	buddy object containing online status attributes
	 * @return			0 on success
	 */
	int OnBuddyChanged(PSBuddyService* service, PSBuddy* buddy);

	/**
	 * Callback to refresh the list of screen names to the buddy queue 
	 *
	 * @param	the reporting buddy service
	 * @return 0 on success
	 */
	int OnRefreshList(PSBuddyService* service);

	/** 
	 * Removes a user from a group based on its entry Id
	 * 
	 * @param	group		name of the group
	 * @param	entryId		user's entry id
	 * @return	0
	 */ 
	int RemoveUserByEntryId(const char* group, char* entryId);

protected:

	/** 
	 * Gets the max number of search results to return
	 * 
	 * @return The max number of search results to return
	 */ 
	int GetMaxSearchResults();

private:

	/**
	 * Parses the LDAP like filter and create a map object containing
	 * filter in the form of name-value pair
	 *
	 * @param	filter	LDAP like filter
	 * @param	map		array containing break up of filter into name-value pair
	 * @return 0 on success
	 */
	int ParseFilter(const char* filter, PSAttribute*** map);

	/**
	 * Checks whether a given string is NULL or ""
	 *
	 * @param	value	a string to be tested for NULL or ""
	 * @return  true if NULL, false otherwise
	 */
	bool IsNull(const char* value);

	/**
	 * Prints buddy information
	 *
	 * @param	buddy	a buddy object containing online status attributes
	 * @return 0 on success
	 */
	int DumpBuddy(PSBuddy* buddy);

	/**
	 * Sorts a list of users based on a "entryId"
	 *
	 * @param	users	array of users to be sorted
	 * @param	nUsers	number of users in the array
	 * @return 0 on success
	 */
	int SortUsersByEntryId(PSUser** users, int nUsers);

private:    
	PSBuddyCache*	m_buddies;
	PSGroupCache*	m_groups;
	PSBuddyService*	m_service;

	/* flag indicating if buddy list is loaded from the disk */
	bool m_loadedList;	
};

#endif // __PS_BUDDY_LIST_H__


