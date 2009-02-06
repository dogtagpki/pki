// --- BEGIN COPYRIGHT BLOCK ---
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation;
// version 2.1 of the License.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor,
// Boston, MA  02110-1301  USA 
// 
// Copyright (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

#include <stdio.h>
#include <string.h>
#include "prmem.h"
#include "prsystem.h"
#include "plstr.h"
#include "prio.h"
#include "prprf.h"
#include "main/ConfigStore.h"
#include "main/Memory.h"
#include "main/Util.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

#ifdef XP_WIN32
#define TOKENDB_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TOKENDB_PUBLIC
#endif /* !XP_WIN32 */

#ifdef __cplusplus
extern "C"
{
#endif

static PR_CALLBACK void*
_AllocTable(void* pool, PRSize size)
{
    return PR_MALLOC(size);
}

static PR_CALLBACK void
_FreeTable(void* pool, void* item)
{
    PR_DELETE(item);
}

static PR_CALLBACK PLHashEntry*
_AllocEntry(void* pool, const void* key)
{
    return PR_NEW(PLHashEntry);
}

static PR_CALLBACK void
_FreeEntry(void* pool, PLHashEntry* he, PRUintn flag)
{
    if( he == NULL ) {
        return;
    }

    if (flag == HT_FREE_VALUE) {
        if( he->value != NULL ) {
            PL_strfree( (char*) he->value );
            he->value = NULL;
        }
    } else if (flag == HT_FREE_ENTRY) {
        if( he->key != NULL ) {
            PL_strfree( (char*) he->key );
            he->key = NULL;
        }
        if( he->value != NULL ) {
            PL_strfree( (char*) he->value );
            he->value = NULL;
        }
        PR_DELETE(he);
    }
}

static PLHashAllocOps _AllocOps = {
    _AllocTable,
    _FreeTable,
    _AllocEntry,
    _FreeEntry
};

#ifdef __cplusplus
}
#endif

///// ConfigStoreRoot

ConfigStoreRoot::ConfigStoreRoot()
{ 
	m_set = PL_NewHashTable(3, PL_HashString, 
			PL_CompareStrings, PL_CompareValues, 
			&_AllocOps, NULL);

	m_set_refcount = 0;
}

// If the ConfigStoreRoot goes out of scope, we can't destroy
// the Hashtable because others maybe depending on the values
// inside. 
ConfigStoreRoot::~ConfigStoreRoot ()
{
    if( m_set != NULL ) { 
		if (m_set_refcount==0) {
        	PL_HashTableDestroy( m_set );
        	m_set = NULL;
		}
    }
}

void ConfigStoreRoot::addref()
{
	m_set_refcount++;
}

void ConfigStoreRoot::release()
{
	m_set_refcount--;
}

PLHashTable *ConfigStoreRoot::getSet()
{
	return m_set;
}


// ConfigureStore

ConfigStore::ConfigStore(ConfigStoreRoot* root, const char *subStoreName)
{ 
	m_substore_name = PL_strdup(subStoreName);
	m_root = root;
	root->addref();
}

ConfigStore::~ConfigStore ()
{ 
	if (m_substore_name != NULL) {
		PR_Free(m_substore_name);
	}
	m_root->release();
        delete m_root;
}



/*
ConfigStore::ConfigStore(const ConfigStore &X)
{
	m_substore_name = X.m_substore_name;
	m_root = X.m_root;
	m_root.addref();
}

*/



ConfigStore ConfigStore::GetSubStore(const char *substore)
{
	char *newname=NULL;
	const char *name = m_substore_name;
	if (strlen(name)==0) {	  // this is the root
		newname = PL_strdup(substore);
	} else {
		newname = PR_smprintf("%s.%s",name,substore);
	}
	return ConfigStore(m_root,newname);
}


/**
 * Reads configuration file and puts name value
 * pair into the global hashtable.
 */
static int ReadLine(PRFileDesc *f, char *buf, int buf_len, int *removed_return)
{
       char *cur = buf;
       int sum = 0;
       PRInt32 rc;

       *removed_return = 0;
       while (1) {
         rc = PR_Read(f, cur, 1);
         if (rc == -1 || rc == 0)
             break;
         if (*cur == '\r') {
             continue;
         }
         if (*cur == '\n') {
             *cur = '\0';
             *removed_return = 1;
             break;
         }
         sum++;
         cur++;
       }
       return sum;
}

#define MAX_CFG_LINE_LEN 4096

ConfigStore *ConfigStore::CreateFromConfigFile(const char *cfg_path)
{
        PRFileDesc *f = NULL;
        int removed_return;
        char line[MAX_CFG_LINE_LEN];
		ConfigStoreRoot *root = NULL;
		ConfigStore *cfg = NULL;

        f = PR_Open(cfg_path, PR_RDWR, 00400|00200);
        if (f == NULL)
                goto loser;

		root = new ConfigStoreRoot();
		cfg = new ConfigStore(root,"");

        while (1) {
                int n = ReadLine(f, line, MAX_CFG_LINE_LEN, &removed_return);
                if (n > 0) {
                        if (line[0] == '#')  // handle comment line
                                continue;
                        int c = 0;
                        while ((c < n) && (line[c] != '=')) {
                                c++;
                        }
                        if (c < n) {
                                line[c] = '\0';
                        } else {
                                continue; /* no '=', skip this line */
                        }
                        cfg->Add(line, &line[c+1]);
                } else if (n == 0 && removed_return == 1) {
                        continue; /* skip empty line */
                } else {
                        break;
                }
        }
        if( f != NULL ) {
            PR_Close( f );
            f = NULL;
        }

loser:
        return cfg;
}

/**
 * Parses string of format "n1=v1&n2=v2..."
 * into a ConfigStore.
 */
ConfigStore *ConfigStore::Parse(const char *s, const char *separator)
{
	char *pair;
	char *line = NULL;
	int i;
        int len;
	char *lasts = NULL;

	if (s == NULL)
		return NULL;
	ConfigStoreRoot *root = new ConfigStoreRoot();
	ConfigStore *set= new ConfigStore(root,"");

	line = PL_strdup(s);
	pair = PL_strtok_r(line, separator, &lasts);
	while (pair != NULL) {
                len = strlen(pair);
	        i = 0;
		while (1) {
                        if (i >= len) {
				goto skip;
                        }
			if (pair[i] == '\0') {
				goto skip;
			}
			if (pair[i] == '=') {
				pair[i] = '\0';
				break;
			}
			i++;
		}
                set->Add(&pair[0], &pair[i+1]);
skip:
		pair = PL_strtok_r(NULL, separator, &lasts);
	}
    if( line != NULL ) {
        PL_strfree( line );
        line = NULL;
    }
	return set;
} 

typedef struct {
	int index;
	char *key;
} Criteria;

#ifdef __cplusplus
extern "C"
{
#endif

static PRIntn CountLoop(PLHashEntry *he, PRIntn index, void *arg)
{
        Criteria *criteria = (Criteria *)arg;
	criteria->index++;
        return HT_ENUMERATE_NEXT;
}

static PRIntn Loop(PLHashEntry *he, PRIntn index, void *arg)
{
    Criteria *criteria = (Criteria *)arg;
    if (criteria != NULL && index == criteria->index) {
	    criteria->key = (char *)he->key;
            return HT_ENUMERATE_STOP;
    } else {
            return HT_ENUMERATE_NEXT;
    }
}

#ifdef __cplusplus
}
#endif

int ConfigStore::Size()
{
        Criteria criteria;
	criteria.index = 0;
	criteria.key = NULL;
	PL_HashTableEnumerateEntries(m_root->getSet(), &CountLoop, &criteria);
	return criteria.index;
}

const char *ConfigStore::GetNameAt(int pos)
{
        Criteria criteria;
	criteria.index = pos;
	criteria.key = NULL;
	PL_HashTableEnumerateEntries(m_root->getSet(), &Loop, &criteria);
	return criteria.key;
}

/**
 * Checks if a key is defined. 
 */
int ConfigStore::IsNameDefined(const char *name)
{ 
	if (m_root->getSet()!= NULL) {
	  if (GetConfig(name) != NULL)
		return 1;
	}
	return 0; 
}

void ConfigStore::Add(const char *name, const char *value)
{
	if (IsNameDefined(name)) {
	  PL_HashTableRemove(m_root->getSet(), name);
	  PL_HashTableAdd(m_root->getSet(), PL_strdup(name), PL_strdup(value));
	} else {
	  PL_HashTableAdd(m_root->getSet(), PL_strdup(name), PL_strdup(value));
	}
}

const char *ConfigStore::GetConfig(const char *name)
{ 
	char buf[256];
	if (m_root->getSet() ==NULL) {
		return NULL;
	}
	if (PL_strlen(m_substore_name) == 0) {
		PL_strncpy(buf,name,256);
	} else {
		PR_snprintf(buf,256,"%s.%s",m_substore_name,name);
	}
	return (char *)PL_HashTableLookupConst(m_root->getSet(), buf);
}

/**
 * Retrieves configuration value as integer.
 */
int ConfigStore::GetConfigAsInt(const char *name)
{
        char *value = NULL;

        value = (char *)GetConfig(name);
        if (value == NULL)
          return 0;
        return atoi(value);
}

/**
 * Retrieves configuration value as integer. If name is
 * not defined, default value is returned.
 */
TPS_PUBLIC int ConfigStore::GetConfigAsInt(const char *name, int def)
{
        char *value = NULL;

        value = (char *)GetConfig(name);
        if (value == NULL)
          return def;
        return atoi(value);
}


/**
 * Retrieves configuration value as unsigned integer.
 */
unsigned int ConfigStore::GetConfigAsUnsignedInt(const char *name)
{
        char *value = NULL;
		int i = 0;

        value = (char *)GetConfig(name);
        if (value == NULL) {
          return 0;
        }

        i = atoi(value);
        if (i < 0) {
          return 0;
        }
        return i;
}

/**
 * Retrieves configuration value as unsigned integer. If name is
 * not defined, default value is returned.
 */
TPS_PUBLIC unsigned int ConfigStore::GetConfigAsUnsignedInt(const char *name, unsigned int def)
{
        char *value = NULL;
		int i = 0;

        value = (char *)GetConfig(name);
        if (value == NULL) {
          return def;
        }

        i = atoi(value);
        if (i < 0) {
          return def;
        }
        return i;
}


/**
 * Retrieves configuration value as boolean.
 */
bool ConfigStore::GetConfigAsBool(const char *name)
{
        char *value = NULL;

        value = (char *)GetConfig(name);
        if (value == NULL)
          return false;
        if (PL_CompareStrings("true", value) != 0)
          return true;
        else
          return false;
}

/**
 * Retrieves configuration value as boolean. If name is
 * not defined, default value is returned.
 */
TPS_PUBLIC bool ConfigStore::GetConfigAsBool(const char *name, bool def)
{
        char *value = NULL;

        value = (char *)GetConfig(name);
        if (value == NULL)
                return def;

        if (PL_CompareStrings("true", value) != 0)
          return true;
	else if (PL_CompareStrings("false", value) != 0)
	  return false;
	else
	  return def;
}

/**
 * Retrieves configuration value as string. If key is
 * not defined, default value is returned.
 */
TOKENDB_PUBLIC const char *ConfigStore::GetConfigAsString(const char *name, const char *def)
{
        char *value = NULL;

        value = (char *)GetConfig(name);
        if (value == NULL)
                return def;
        return value;
}

/**
 * Retrieves configuration value as string.
 */
TPS_PUBLIC const char *ConfigStore::GetConfigAsString(const char *name)
{
        return (char *)GetConfig(name);
}


/**
 * Allow operator[] overloading for retrieval of config strings
 */
const char* ConfigStore::operator[](const char*name)
{
	return GetConfigAsString(name);
}


Buffer *ConfigStore::GetConfigAsBuffer(const char *key)
{
        return GetConfigAsBuffer(key, NULL);
}

Buffer *ConfigStore::GetConfigAsBuffer(const char *key, const char *def)
{
        const char *value = NULL;

        value = (char *)GetConfig(key);
        if (value == NULL) {
                if (def == NULL) {
                        return NULL;
                } else {
                  return Util::Str2Buf(def);
                }
        } else {
                return Util::Str2Buf(value);
        }
}

