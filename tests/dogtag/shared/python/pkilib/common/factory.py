#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
This module implements generic functions for py.test framework. 
"""
import subprocess
import copy
import os

class PkiTools:
    '''
        PkiTools consists of functions related to Operating system tasks
        that are used regularly.
    '''
    @classmethod
    def Execute(self, args, stdin=None, capture_output=True, raiseonerr=False, env=None, cwd=None):
        """
        Execute a command and return stdout, stderr and return code

        :param str args: List of arguments for the command
        :param str stdin: Optional input 
        :param bool capture_output: Capture output of the command (default True)
        :param bool raiseonerr: Raise exception if command fails
        :param str env: Environment variables to be set before the command is run
        :param str cwd: Current working Directory

        :return stdout, stderr and returncode: if command return code is 0 else raises exception if raiseonerr is True
        """
        p_in = None
        p_out = None
        p_err = None
        if env is None:
            env = copy.deepcopy(os.environ)
        if capture_output:
            p_out = subprocess.PIPE
            p_err = subprocess.PIPE
        try:
            proc = subprocess.Popen(args, stdin=p_in, stdout=p_out, stderr=p_err,
                    close_fds=True, env=env, cwd=cwd)
            stdout, stderr = proc.communicate(stdin)
        except KeyboardInterrupt:
            proc.wait()
            raise
	if proc.returncode !=0 and raiseonerr:
            raise subprocess.CalledProcessError(proc.returncode, args, stdout)
        else:
            return (stdout, stderr, proc.returncode)
