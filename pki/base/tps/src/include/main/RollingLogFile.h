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
// Copyright (C) 2010 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

#ifndef ROLLINGLOGFILE_H
#define ROLLINGLOGFILE_H

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

#include <stdio.h>

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

#include "main/LogFile.h"

class RollingLogFile: public LogFile {
  private:
    size_t m_max_file_size;
    volatile int m_rollover_interval;
    volatile int m_expiration_time;
    int m_expiration_sleep_time;
    volatile bool m_rotation_needed;
    PRThread* m_rollover_thread;
    PRThread* m_expiration_thread;

  public: 
    static const char *CFG_MAX_FILE_SIZE;
    static const char *CFG_ROLLOVER_INTERVAL;
    static const char *CFG_EXPIRATION_INTERVAL;
    static const int MAX_SLEEP;

  public:
    TPS_PUBLIC RollingLogFile();
    TPS_PUBLIC ~RollingLogFile() {} 

    int startup(RA_Context *ctx, const char* prefix, const char *fname, bool sign_audit);
    void shutdown();
    void child_init();
    int write(char *msg);
    void rotate();

    /* accessors and mutators */
    void set_rollover_interval(int interval);
    int get_rollover_interval();
    void set_expiration_time(int interval);
    int get_expiration_time();
    void set_rotation_needed(bool val);
    bool get_rotation_needed();

  private:
    static void start_rollover_thread(void *args);
    void run_rollover_thread();

    static void start_expiration_thread(void *args); 
    void run_expiration_thread();
    void expire();

};

#endif
