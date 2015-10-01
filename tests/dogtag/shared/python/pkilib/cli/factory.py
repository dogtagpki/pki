#!/usr/bin/python
import rpm
import subprocess
import os
import shlex
import shutil
import ldap
import ldap.modlist as modlist
from ldap.ldapobject import SimpleLDAPObject
import ldap.sasl
import ldif
import sys

class PkiFactory:
    def run_cmd(cls,cmd,stdin=None,capture_output=True):
        p_in = None
        p_out = None
        p_err = None
        if stdin:
            p_in = subprocess.PIPE
        else:
            p_out = subprocess.PIPE
            p_err = subprocess.PIPE    	
    
        args = shlex.split(cmd)
        p = subprocess.Popen(args, stdin=p_in, stdout=p_out, stderr=p_err, close_fds=True)
        stdout, stderr = p.communicate(stdin)
        stdout, stderr = str(stdout), str(stderr)
        if capture_output:
            return stdout, stderr, p.returncode
        else:
            return stderr, p.returncode

 

    def setup_ds(cls,dsInfFile):
        cmd = "setup-ds.pl --silent --file=%s" % dsInfFile
        stdout, stderr, returncode = cls.run_cmd(cmd,capture_output=True)
        if returncode !=0:
            return stderr, returncode
        else:
            return stdout,returncode

    def remove_dsInstance(cls,InstanceName=None):
        cmd = "remove-ds.pl -i slapd-%s -d" % (InstanceName)
        print(cmd)
        stdout, stderrr, returncode = cls.run_cmd(cmd,capture_output=True)
        if returncode !=0:
            return stderr, returncode
        else:
            return stdout,returncode

    def setup_PkiInstance(cls,InstanceName=None,InstanceFile=None):
        cmd = "pkispawn -s %s -f %s -vv" % (InstanceName,InstanceFile)
        print(cmd)
        stdout,stderr,returncode = cls.run_cmd(cmd)
        if returncode !=0:
            return stderr, returncode
        else:
            return stdout,stderr,returncode

    def remove_subsystem(cls,subsystem=None,InstanceName=None):
        cmd = "pkidestroy -i %s -s %s" % (InstanceName, subsystem)
        stdout,stderr,returncode = cls.run_cmd(cmd,capture_output=True)
        if returncode !=0:
            return stderr, returncode
        else:
            return stdout,stderr,returncode

