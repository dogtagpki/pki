# Installing CA, KRA, OCSP, TKS and TPS instances in containers.

# Allocate ip address to the containers.
#cd /root/dogtag/
cd /root/dogtagpki/
docker run --name pki1 --cap-add=NET_ADMIN -v /root/dogtagpki/pki:/root/pki -dit pki /bin/sh -c "/sbin/ip addr add 172.17.0.07 dev eth0; bash"
docker run --name pki2 --cap-add=NET_ADMIN -v /root/dogtagpki/pki:/root/pki -dit pki /bin/sh -c "/sbin/ip addr add 172.17.0.08 dev eth0; bash"

# Installing Directory server and CA instances in the container.
docker exec -d pki1 /usr/sbin/setup-ds.pl /root/pki/tests/ci/topology-02/ca_ldap.cfg
docker exec -d pki1 /usr/sbin/pkispawn /root/pki/tests/ci/topolgoy-02/ca.cfg

# Installing Directory server and KRA instances in the container.
#docker exec -d pki1 /usr/bin/setup-ds.pl /root/pki/tests/ci/topology-02/kra_ldap.cfg
docker exec -d pki1 /usr/bin/pkispawn /root/pki/tests/ci/topology-02/kra.cfg

# Installing Directory server and OCSP instances in the container.
#docker exec -d pki1 /usr/bin/setup-ds.pl /root/pki/tests/ci/topology-02/ocsp_ldap.cfg
docker exec -d pki1 /usr/bin/pkispawn /root/pki/tests/ci/topology-02/ocsp.cfg

# Installing Directory server and TKS instances in the container.
#docker exec -d pki1 /usr/bin/setup-ds.pl /root/pki/tests/ci/topology-02/tks_ldap.cfg
docker exec -d pki1 /usr/bin/pkispawn /root/pki/tests/ci/topology-02/tks.cfg

# Installing Directory server and TPS instances in the container.
#docker exec -d pki1 /usr/bin/setup-ds.pl /root/pki/tests/ci/topology-02/tps_ldap.cfg
docker exec -d pki1 /usr/bin/pkispawn /root/pki/tests/ci/topology-02/tps.cfg

docker exec -d pki1 /usr/bin/pkidaemon stats

docker logs pki1
