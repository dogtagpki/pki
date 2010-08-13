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
#include <regex.h>
#include "prmem.h"
#include "prsystem.h"
#include "plstr.h"
#include "prio.h"
#include "prprf.h"
#include "main/ConfigStore.h"
#include "main/Memory.h"
#include "main/Util.h"
#include "engine/RA.h"

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
        m_lock = PR_NewLock();
}

ConfigStore::~ConfigStore ()
{ 
	if (m_substore_name != NULL) {
		PR_Free(m_substore_name);
	}
        if (m_cfg_file_path != NULL) {
        	PR_Free(m_cfg_file_path);
        }
	m_root->release();
        delete m_root;
    
        if (m_lock != NULL ) 
            PR_DestroyLock(m_lock);
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
        cfg->SetFilePath(cfg_path);

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

typedef struct {
    PRCList list;
    char *key;
} OrderedEntry_t;

typedef struct {
    regex_t *regex;
    ConfigStore *store;
} PatternEntry_t;

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

/**
 * Called from PL_HashTableEnumerateEntries
 * A pointer to a PRCList (circular linked list) is passed in. 
 * Once enumeration is complete, the PRCList will contain a lexically
 * ordered list of a copy of the keys in the hash.  
 * The caller needs to free the copies
 */ 
static PRIntn OrderLoop(PLHashEntry *he, PRIntn index, void *arg)
{
    PRCList *qp = (PRCList *)arg;
    OrderedEntry_t *entry;

    if (he != NULL) {
        entry = (OrderedEntry_t *) PR_Malloc(sizeof(OrderedEntry_t));
        entry->key = PL_strdup((char *) he->key);
        if (index ==0) {
            PR_APPEND_LINK((PRCList *)entry, qp);
            return HT_ENUMERATE_NEXT;
        }
        PRCList *head = PR_LIST_HEAD(qp);
        PRCList *next;
        while (head != qp) {
            OrderedEntry_t *current = (OrderedEntry_t *) head;
            if (strcmp((char *) he->key, (char *) current->key) <=0) 
                break;
            next = PR_NEXT_LINK(head);
            head = next;
        }
        PR_INSERT_BEFORE((PRCList*) entry, head);
        return HT_ENUMERATE_NEXT;
    } else {
        return HT_ENUMERATE_STOP;
    }
}

/**
 * Called from PL_HashTableEnumerateEntries
 * A pointer to a PatternEntry is passed in.  A PatternEntry consists of 
 * a pointer a regex_t and a pointer to a new config store. 
 * Once enumeration is complete, the new config store will contain 
 * all the parameters (key and values) whose keys match the regex.
 */ 
static PRIntn PatternLoop(PLHashEntry *he, PRIntn index, void *arg)
{
    PatternEntry_t *entry = (PatternEntry_t *) arg;

    if (entry == NULL) {
        return HT_ENUMERATE_STOP;
    }

    regex_t *r = entry->regex;
    ConfigStore *store = entry->store;

    if ((r == NULL) || (store == NULL)) {
        return HT_ENUMERATE_STOP;
    }

    size_t no_sub = r->re_nsub+1; 
    regmatch_t *result = NULL;

    result = (regmatch_t *) PR_Malloc(sizeof(regmatch_t) * no_sub);
 
    if ((he != NULL) && (he->key != NULL) && (he->value != NULL)) {
        if (regexec(r, (char *) he->key, no_sub, result, 0)==0) {
            // Found a match 
            store->Add((const char*) he->key, (const char *) he->value);
        }
    }  else {
        return HT_ENUMERATE_STOP;
    }
    
    if (result != NULL) PR_Free(result);
    return HT_ENUMERATE_NEXT;
}

#ifdef __cplusplus
}
#endif

int ConfigStore::Size()
{
        Criteria criteria;
	criteria.index = 0;
	criteria.key = NULL;

        PR_Lock(m_lock);
	PL_HashTableEnumerateEntries(m_root->getSet(), &CountLoop, &criteria);
        PR_Unlock(m_lock);

	return criteria.index;
}

const char *ConfigStore::GetNameAt(int pos)
{
        Criteria criteria;
	criteria.index = pos;
	criteria.key = NULL;

        PR_Lock(m_lock);
	PL_HashTableEnumerateEntries(m_root->getSet(), &Loop, &criteria);
        PR_Unlock(m_lock);

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

void ConfigStore::SetFilePath(const char* cfg_file_path) 
{
    m_cfg_file_path = PL_strdup(cfg_file_path);
}

void ConfigStore::Add(const char *name, const char *value)
{
	if (IsNameDefined(name)) {
          PR_Lock(m_lock);
	  PL_HashTableRemove(m_root->getSet(), name);
	  PL_HashTableAdd(m_root->getSet(), PL_strdup(name), PL_strdup(value));
          PR_Unlock(m_lock);
	} else {
          PR_Lock(m_lock);
	  PL_HashTableAdd(m_root->getSet(), PL_strdup(name), PL_strdup(value));
          PR_Unlock(m_lock);
	}
}

void ConfigStore::Remove(const char *name)
{
	if (IsNameDefined(name)) {
          PR_Lock(m_lock);
	  PL_HashTableRemove(m_root->getSet(), name);
          PR_Unlock(m_lock);
	} 
}

const char *ConfigStore::GetConfig(const char *name)
{ 
	char buf[256];
        char *ret;
	if (m_root->getSet() ==NULL) {
		return NULL;
	}
	if (PL_strlen(m_substore_name) == 0) {
		PL_strncpy(buf,name,256);
	} else {
		PR_snprintf(buf,256,"%s.%s",m_substore_name,name);
	}

        PR_Lock(m_lock);
        ret = (char *)PL_HashTableLookupConst(m_root->getSet(), buf);
        PR_Unlock(m_lock);

	return ret;
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

/**
 * returns a string containing all the parameters in the ConfigStore hash set in the 
 * format key1=value1&&key2=value2&& ...
 * The list will be lexically ordered by parameter key values.
 * The string needs to be freed by the caller.
 **/
TPS_PUBLIC const char* ConfigStore::GetOrderedList()
{
    char *outstr = NULL;
    char *new_string = NULL;
    PRCList order_list;
    PR_INIT_CLIST(&order_list);

    PR_Lock(m_lock);
    PL_HashTableEnumerateEntries(m_root->getSet(), &OrderLoop, &order_list);
    PR_Unlock(m_lock);

    PRCList *current = PR_LIST_HEAD(&order_list);
    PRCList *next;

    outstr = (char*) PR_Malloc(128);
    int allocated = 128;
    int needed = 0;
    PR_snprintf(outstr, 128, "");

    while (current != &order_list) {
        OrderedEntry_t *entry = (OrderedEntry_t *) current;
        const char *value = GetConfigAsString(entry->key, "");

        if ((entry != NULL) && (entry->key != NULL)) {
            needed = PL_strlen(outstr) + PL_strlen(entry->key) + PL_strlen(value) + 4;
            if (allocated <= needed) {
                while (allocated <= needed) {
                    allocated = allocated * 2;
                }
                new_string = (char *)PR_Malloc(allocated);
                PR_snprintf(new_string, allocated, "%s", outstr);
                PR_Free(outstr);
                outstr = new_string;
            } 
                
            PL_strcat(outstr, entry->key);
            PL_strcat(outstr, "=");
            PL_strcat(outstr, value);

            // free the memory for the Ordered Entry
            PL_strfree(entry->key);
        }

        next = PR_NEXT_LINK(current);
        PR_REMOVE_AND_INIT_LINK(current);
        if (current != NULL) {
            PR_Free(current);
        }
        current = next;

        if (current != &order_list) PL_strcat(outstr, "&&");
    }
    return outstr;
}

/**
 * Commits changes to the config file
 */
TPS_PUBLIC int ConfigStore::Commit(const bool backup)
{
    char name_tmp[256], cdate[256], name_bak[256], bak_dir[256];
    char basename[256], dirname[256];
    PRFileDesc *ftmp  = NULL;
    PRExplodedTime time;
    PRTime now;

    if (m_cfg_file_path == NULL) 
        return 1;

    if (strrchr(m_cfg_file_path, '/') != NULL) {
        PR_snprintf((char *) basename, 256, "%s", strrchr(m_cfg_file_path, '/') +1);
        PR_snprintf((char *) dirname, PL_strlen(m_cfg_file_path) - PL_strlen(basename), "%s", m_cfg_file_path);
        PL_strcat(dirname, '\0');
    } else {
        PR_snprintf((char *) basename, 256, "%s", m_cfg_file_path);
        PR_snprintf((char *) dirname, 256, ".");
    }
    PR_snprintf(bak_dir, 256, "%s/bak", dirname); 

    now = PR_Now();
    PR_ExplodeTime(now, PR_LocalTimeParameters, &time);
    PR_snprintf(cdate, 16, "%04d%02d%02d%02d%02d%02dZ",
        time.tm_year, (time.tm_month + 1), time.tm_mday,
        time.tm_hour, time.tm_min, time.tm_sec);
    PR_snprintf(name_tmp, 256, "%s.%s.tmp", m_cfg_file_path,cdate);
    PR_snprintf(name_bak, 256, "%s/%s.%s", bak_dir, basename, cdate);

    ftmp = PR_Open(name_tmp, PR_WRONLY| PR_CREATE_FILE, 00400|00200);
    if (ftmp == NULL) {
        // unable to create temporary config file 
        return 1;
    }

    PRCList order_list;
    PR_INIT_CLIST(&order_list);

    PR_Lock(m_lock);
    PL_HashTableEnumerateEntries(m_root->getSet(), &OrderLoop, &order_list);
    PR_Unlock(m_lock);

    PRCList *current = PR_LIST_HEAD(&order_list);
    PRCList *next;

    while (current != &order_list) {
        OrderedEntry_t *entry = (OrderedEntry_t *) current;
        PR_Write(ftmp, entry->key, PL_strlen(entry->key));
        PR_Write(ftmp, "=", 1);
        const char *value = GetConfigAsString(entry->key, "");
        PR_Write(ftmp, value, PL_strlen(value));
        PR_Write(ftmp, "\n", 1);

        // free the memory for the Ordered Entry
        if (entry->key != NULL)  PL_strfree(entry->key);

        next = PR_NEXT_LINK(current);
        PR_REMOVE_AND_INIT_LINK(current);
        if (current != NULL) {
            PR_Free(current);
        }
        current = next;
    }

    PR_Close(ftmp);

    if (backup) { 
        // create the backup directory if it does not exist
        if (PR_Access(bak_dir, PR_ACCESS_EXISTS) != PR_SUCCESS) {
            PR_MkDir(bak_dir, 00770);
        } 
        PR_Rename(m_cfg_file_path, name_bak);
    }
    PR_Rename(name_tmp, m_cfg_file_path);

    return 0;
}

/**
 * Takes in a string containing a regular expression.
 * Returns a new ConfigStore which contains only those parameters whose
 * keys match the pattern.
 * The new Configstore must of course be freed by the caller.
 **/
ConfigStore *ConfigStore::GetPatternSubStore(const char *pattern)
{

    ConfigStoreRoot *root = NULL;
    ConfigStore *ret = NULL;
    PatternEntry_t entry;
    regex_t *regex = NULL;
    int err_no=0; /* For regerror() */

    regex = (regex_t *) malloc(sizeof(regex_t));
    memset(regex, 0, sizeof(regex_t));

    if((err_no=regcomp(regex, pattern, 0))!=0) /* Compile the regex */
    {
      // Error in computing the regex
      size_t length; 
      char *buffer;
      length = regerror (err_no, regex, NULL, 0);
      buffer = (char *) PR_Malloc(length);
      regerror (err_no, regex, buffer, length);
      // PR_fprintf(m_dump_f, "%s\n", buffer); /* Print the error */
      PR_Free(buffer);
      regfree(regex);
      return NULL;
    }

    entry.regex = regex;
    root = new ConfigStoreRoot();
    ret = new ConfigStore(root, "");
    entry.store = ret;

    PR_Lock(m_lock);
    PL_HashTableEnumerateEntries(m_root->getSet(), &PatternLoop, &entry);
    PR_Unlock(m_lock);

    /* cleanup */
    //regfree(entry.regex);
    //entry.store = NULL;

    ret->SetFilePath("");
    return ret;
}

