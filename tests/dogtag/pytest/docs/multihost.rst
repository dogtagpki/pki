Multihost Plugin
================

plugin setup and use
---------------------
This doc explains how to setup a config for pytest multihost plugin for Certificate Services. This plugin takes
a description of available infrastructure and provides as a fixture to tests written in pytest. Each of hosts
in the infrastructure have certain attributes:

        * Role : Master/Clone/Replica/Slave/Root/Client
        * Shortname: Shortname of the host
        * Hostname: Current hostname of the system
        * External Hostname: External Hostname of the system
        * IP-Address: IP Address
        * Domain: DNS Domain under which these systems fall under

* Example1::

   root_password: 'redhat'
   domains:
     - name: testrelm.test
       type: pki
       hosts:
         - name: pki2
           external_hostname: pki2.testrelm.test
           role: master
         - name: pki3
           external_hostname: pki3.testrelm.test
           role: clone

* Fields:

        root_password: Root password of the systems , Instead of root password ssh keys can also be used. 
        
        domains: DNS Domain name of the systems

        type: Can be of any name, 

        name: DNS Name of the domain

        external_hostname: hostname used to connect to this host
        
        role: Role played by the specific host

* Example2::
   
        root_password: 'redhat'
        domains:
          - name: example.org
            type: cs
            hosts:
              - name: pki3
                ip: 192.168.122.103
                role: master

In the above example only single host `pki3.example.org` is defined which is playing the role of master

* Example3::

        root_password: 'redhat'
        domains:
          - name: testrelm.test
            type: pki
            hosts:
              - name: pki1.testrelm.test
                external_hostname: rhel7-1.example.org
                ip: 192.168.122.101
                role: master
              - name: pki2.testrelm.test
                external_hostname: rhel7-2.example.org
                ip: 192.168.122.102
                role: clone
              - name: pki3.testrelm.test
                external_hostname: rhel7-3.example.org
                ip: 192.168.122.103
                role: client

The above is an example of 3 hosts 


fixtures
--------

To use the above infrastructure create fixtures specifying what is required to run the tests. For example, if the 
infrastructure provides 2 clones and 2 masters, but for specific test/test suite requires 1 clone and 1 master, we create
fixture specifying the requirement. 

Example::

        import pytest
        from pytest_multihost import make_multihost_fixture

        @pytest.fixture(scope='class')
        def multihost(request):
                mh = make_multihost_fixture(
                        request, description=
                        [
                            {
                                'type': 'pki'
                                'hosts': {
                                        'master':1,
                                        'clone':1
                                          }
                             },
                        ],
                        config_class=QeConfig)
                #we are requesting first domain
                mh.domain = mh.config.domains[0]
                [mh.master] = mh.domain.hosts_by_role('master')
                [mh.clone] = mh.domain.hosts_by_role('clone')
                return mh

        #use the fixture in tests
        
        def test1(multihost):
            multihost.master.run_command(['ls', '-l'])
            multihost.clone.run_command(['ls', '-l'])
 
                 


