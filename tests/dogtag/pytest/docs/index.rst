.. CS(pki) QE Test documentation master file, created by
   sphinx-quickstart on Wed Sep 02 18:52:16 2015.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

IDM QE CS PyTest Documentation
===========================================
* CS Pytest is a project designed to provide test suites for Red Hat Certificate Services and Dogtag PKI.
  These tests are written in python using pytest framework. There will be primarily 3 types of tests

        * UI tests which rely on `selenium's webdrive <http://docs.seleniumhq.org/projects/webdriver/>`_.[Todo]
        * CLI tests which rely on `python-multihost plugin  <https://fedorahosted.org/python-pytest-multihost/>`_.[Todo]
        * Legacy tests which rely on `Requests <http://www.python-requests.org/en/latest/>`_.[Todo]


Contents:

.. toctree::
   :maxdepth: 2

   Install
   running
   layout
   multihost
   examples
   conftest
   api
   

Additional Information
======================
.. [#] `Python Pytest Multihost plugin <https://fedorahosted.org/python-pytest-multihost/>`_.

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
