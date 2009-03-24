/* --- BEGIN COPYRIGHT BLOCK ---
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
 * --- END COPYRIGHT BLOCK ---
 */

#ifndef CONFIG_STORE_H
#define CONFIG_STORE_H

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

#include "plhash.h"
#include "main/Buffer.h"

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

class ConfigStoreRoot;

class ConfigStore
{
  public:
	  ConfigStore(ConfigStoreRoot* root, const char *subStoreName);
      //ConfigStore::ConfigStore(const ConfigStore &X);

	  ~ConfigStore();
	  static ConfigStore *Parse(const char *s, const char *separator);
	  static ConfigStore *CreateFromConfigFile(const char *cfg_path);

	  int                 IsNameDefined(const char *name);
          void                SetFilePath(const char* cfg_file_path);
	  void                Add(const char *name, const char *value);
	  const char *        GetConfig(const char *name);
	  int                 Size();
	  const char *        GetNameAt(int pos);
	  ConfigStore         GetSubStore(const char*name);

	// Retrieve config parameters
      Buffer *         GetConfigAsBuffer(const char *key);
      Buffer *         GetConfigAsBuffer(const char *key, const char *def);
	  int              GetConfigAsInt(const char *key);
	  TPS_PUBLIC int GetConfigAsInt(const char *key, int def); 
	  unsigned int     GetConfigAsUnsignedInt(const char *key);
	  TPS_PUBLIC unsigned int GetConfigAsUnsignedInt(const char *key,
                                                       unsigned int def); 
      bool              GetConfigAsBool(const char *key);
      TPS_PUBLIC bool GetConfigAsBool(const char *key, bool def); 
      TOKENDB_PUBLIC const char *GetConfigAsString(const char *key, const char *def);  
      TPS_PUBLIC int Commit(const bool backup);
      TPS_PUBLIC const char *GetConfigAsString(const char *key);
	  /**
	   * operator[] is used to look up config strings in the ConfigStore.
	   * For example:
	   * <PRE>
	   *   const char *param = cfg["filename"];           // equivalent
	   *   const char *param = cfg.GetConfig("filename"); // equivalent
	   * </PRE>
	   */
      const char *      operator[](const char*key);

  private: 
	  char      *m_substore_name;
	  ConfigStoreRoot *m_root;
          char      *m_cfg_file_path;
          PRLock *m_lock;
};

class ConfigStoreRoot
{
	  friend class ConfigStore;
    public:
	  ConfigStoreRoot();
	  ~ConfigStoreRoot();
	  void addref();
	  void release();
	
	private:
	  PLHashTable* getSet();
	  PLHashTable *m_set;
	  int          m_set_refcount;

};



#endif /* CONFIG_STORE_H */
