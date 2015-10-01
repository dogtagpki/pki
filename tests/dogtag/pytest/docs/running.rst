Running Tests
=======

Prerequisites
-------------
* Functional Tests mostly written for Certificate services require multiple hosts. General naming used in this regard are:

        * master(m): Node on which we have all the subsystems installed like CA (Root), kra, ocsp, tks, tps
        * clone(r): Which has clone of all the subsystems installed on Master or subca
        * client(c): System from which we run pki commands 
        * mrc: topology with master, clone, client
        * mrr: topology with master, clone, clone
        * m : topology with only master
        * mc: topology with only master and client


config
-------

 * To run multihosts tests, pickup a multihost template to use. Template files can be found in /etc/pkilib directory, They are named based on topology they represent. Naming scheme is mh_cfg_<topology>.yaml

    Example config file::

        root_password: 'redhat'
        domains:
          - name: testrelm.test
            type: cs
            hosts:
              - name: hostname1
                ip: 192.168.122.1
                role: master
              - name: hostname2
                ip: 192.168.122.2
                role: clone

    Edit the config file and replace **hostname1** and **hostname2** with actual hostname. Hostname should be Fully qualified domain name.

    Set the root password of the systems under parameter **root_password**

Executing Tests
---------------
* To execute existing tests clone pki-tests repo and run py.test against any specific test suite directory.

   * On RHEL7.2::

     $ git clone git://git.app.eng.bos.redhat.com/pki-tests.git
     $ cd pki-tests/dogtag/pytest
     $ py.test --multihost-config=<multihost-template> <test-suite-directory>
    
   * On Fedora 22::

     $ git clone git://git.fedorahosted.org/pki.git
     $ cd tests/dogtag/pytest
     $ py.test --multihost-config=<multihost-template> <test-suite-directory>
    
* Before executing any tests, it's required to create a config file as specified in `config` section. 

        * Executing test suite::

                $ cd pki-tests/dogtag/pytest/
                $ py.test --junit-xml=/tmp/junit.xml \
                        --multihost-config=mh_cfg.yaml \
                        -v <test_suite_dir>

        * Executing Individual Test sub-suite (module)::
                
                $ cd pki-tests/dogtag/pytest/
                $ py.test --junit-xml=/tmp/junit.xml \
                        --multihost-config=mh_cfg.yaml \
                        -v <test_suite_dir/test_module.py>

        * Executing individual Test cases.::
                
                $ cd pki-tests/dogtag/pytest/

                $ py.test --junit.xml=/tmp/junit.xml \
                        --multihosts-config=mh_cfg.yaml \
                        -v <test_suite_dir>/<test_module>.py::<TestClass>::<test_case>

        * Example 1: Running Installation test suite::
                
                $ cd pki-tests/dogtag/pytest/installation
                
                $ py.test --junit.xml=/tmp/junit.xml \
                        --multihosts-config=mh_cfg.yaml \
                        -v installation
