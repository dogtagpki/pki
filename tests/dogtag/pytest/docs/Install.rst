Install
=======
* Certificate Services test suite uses Pytest-Multihost-plugin and shared library called `pkilib` to run the tests

Dependencies
------------
        
        1. python-pytest-multihost
        2. pkilib-0.1
        3. Pytest
        
        * Note: pkilib is only required to use any of the shared functions that have been written for Certificate Services. 
          currently pkilib contains classes which configure directory services. Look at the pkilib docs for more information
        
Required Hosts
--------------
* Red Hat Certificate Services tests are mostly multihosts tests, At a bare minimum you require 2 systems, where 1 system could be your
laptop/jenkins slave which contains all the necessary rpm's mentioned above, while other system would be the actual host where tests would run. 

Note: The actual system where test suite will run should have Certificate System/dogtag PKI Repos already available. 

RHEL7.2
-------

* Packages mentioned above can be installed from `idmqe-extras <http://cosmos.lab.eng.pnq.redhat.com/idmqe-extras/rhel/7Server/x86_64/>`_.  repo.::

    $ wget -O /etc/yum.repos.d/idmqe-extras-rhel.repo \
    <url to repo>/idmqe-extras-rhel.repo
    $ yum install pkilib pytest
   
Fedora 22
---------

* On fedora 22, all the packages mentioned above except pkilib is available on base Fedora Channel, 
Download the pkilib for Fedora 22 from `here <https://mrniranjan.fedorapeople.org/pkilib-0.1-1.fc22.noarch.rpm>_.` repo::

   $ wget https://mrniranjan.fedorapeople.org/pkilib-0.1-1.fc22.noarch.rpm
   $ dnf install pkilib-0.1.noarch.f22.rpm
   $ dnf install pytest
