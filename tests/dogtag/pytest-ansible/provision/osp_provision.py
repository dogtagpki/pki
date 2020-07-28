import os
import random
import sys

import click
import openstack


OS_AUTH_URL = os.getenv('OS_AUTH_URL')
OS_PROJECT_NAME = os.getenv('OS_PROJECT_NAME')
OS_USERNAME = os.getenv('OS_USERNAME')
OS_REGION_NAME = os.getenv('OS_REGION_NAME')
OS_KEYPAIR_NAME = os.getenv('OS_KEYPAIR_NAME')
CI_FLAVOR_NAME = os.getenv('CI_FLAVOR_NAME')
DOMAIN_NAME = os.getenv('DOMAIN_NAME')
OS_PASSWORD = os.getenv('OS_PASSWORD')
OS_NETWORK_ID = os.getenv('OS_NETWORK_ID').split(',')
# OS_NETWORK_ID = random.choice(OS_NETWORK_ID)

inventory_file = "ansible_inventory"
instance_record = '/tmp/instance_record.txt'


def create_connection(auth_url, region, project_name, username, password):
    return openstack.connect(auth_url=auth_url,
                             project_name=project_name,
                             username=username,
                             password=password,
                             user_domain_name=DOMAIN_NAME,
                             project_domain_name=DOMAIN_NAME,
                             region_name=region)


def spawn_server(conn, image_name, server_type='master'):
    """
    This method spawns a server for provided image.
    The method looks for available network and also sets an inventory which is used in teardown state.
    """

    print("Spawning server: ")
    set_available_network(conn)

    if server_type == 'master':
        server_name = 'OSP_API_Master_{}'.format(random.randint(999, 99999))
    else:
        server_name = 'OSP_API_Client_{}'.format(random.randint(999, 99999))
    image = conn.compute.find_image(image_name)
    flavor = conn.compute.find_flavor(CI_FLAVOR_NAME)
    try:
        server = conn.compute.create_server(name=server_name, image_id=image.id,
                                            flavor_id=flavor.id, networks=[{"uuid": OS_NETWORK_ID}],
                                            key_name=OS_KEYPAIR_NAME)


        # Writing server details in the inventory file which is used at the time of teardown.
        if os.path.isfile(instance_record):
            with open(instance_record, 'a') as f:
                f.write('{}\n'.format(server.name))
        else:
            with open(instance_record, 'w') as f:
                f.write('{}\n'.format(server.name))

        # Wait time for VM to come active is 10 min
        server = conn.compute.wait_for_server(server, status='ACTIVE', failures='ERROR', interval=2, wait=600)
        return server
    except Exception as e:
        print(e)
        sys.exit(1)


def delete_server(conn, server_name):
    print("Removing Server")
    server = conn.compute.find_server(server_name)
    conn.compute.delete_server(server)


def list_images(conn, name):
    print("List Images:")
    image_list = []
    for image in conn.image.images():
        if ("latest" in image.name and image.name.startswith(name)) or (name in image.name):
            image_list.append(image.name)
            print("Found Image: {}".format(image.name))
    return image_list


def set_available_network(conn):
    """
    This method searches for network with available IPs.
    And sets the network for server spawining.
    """
    print('Getting network availability')
    global OS_NETWORK_ID
    for net_id in OS_NETWORK_ID:
        print net_id
        used_ips = conn.network.get_network_ip_availability('60cacaff-86a6-4f88-82a4-ed3023724df1').used_ips
        total_ips = conn.network.get_network_ip_availability('60cacaff-86a6-4f88-82a4-ed3023724df1').total_ips
        print(used_ips)
        print(total_ips)
        if total_ips - used_ips > 10:
            OS_NETWORK_ID = net_id
            print('Using network : {} \n Available IPs : {}'.format(net_id, str(total_ips - used_ips)))
            break


@click.group()
def cli():
    pass


@cli.command()
@click.option('--image', default='Fedora-Cloud-Base-32', help="Image to provision.")
@click.option('--inventory', default='/root/host', help='Generate inventory file.')
@click.option('--image-type', type=click.Choice(['nightly', 'production']), default='nightly',
              help="Image type (nightly, production)")
@click.option('--server-type', type=click.Choice(['master', 'client']), default='server',
              help="Machine type (master, client)")
@click.option('-v', '--verbose', is_flag=True, help="Verbose")
def up(inventory, image, image_type, server_type, verbose):

    python_interpreter = ''
    if not image:
        image_name = 'Fedora 31'
    else:
        image_name = image

    if verbose:
        openstack.enable_logging(True, stream=sys.stdout)

    conn = create_connection(OS_AUTH_URL, OS_REGION_NAME,
                             OS_PROJECT_NAME, OS_USERNAME,
                             OS_PASSWORD)
    print(image)
    image_list = list_images(conn, image)

    network = None
    if image_name in image_list:
        print("Using Image: {}".format(image_name))
        server = spawn_server(conn, image_name, server_type=server_type)
        print(server)
        if server:
            for key in server.addresses.keys():
                network = server.addresses[key][0]
                print("OSP Machine name: {}".format(server.name))
                print("Server ip: {}".format(network['addr']))

            data = ["[all]\n"]
            if os.path.isfile(inventory):
                with open(inventory, 'r') as f:
                    data = f.readlines()

            data = [i.strip() for i in data]
            index = data.index("[all]")
            data.insert(index + 1, "{} hostname={} {}".format(network['addr'], network['addr'],
                                                              python_interpreter))
            if "[{}]".format(server_type) in data:
                index = data.index("[{}]".format(server_type))
                data.insert(index + 1, "{} hostname={} {}".format(network['addr'], network['addr'],
                                                                  python_interpreter))
            else:
                data.extend(["\n[{}]".format(server_type),
                             "{} hostname={} {}".format(network['addr'], network['addr'],
                                                        python_interpreter)])
            with open(inventory, 'w') as f:
                print(data)
                file_data = "\n".join(data)
                f.write(file_data)
        else:
            print("ERROR: Unable to provision machine")
            sys.exit(1)

    else:
        print("ERROR: No image found.")
        sys.exit(1)


@cli.command()
@click.option('--inventory', default='ansible_inventory', help='Inventory file path')
def down(inventory):
    name = None
    if not inventory:
        inventory = inventory_file
    if os.path.isfile(instance_record):
        conn = create_connection(OS_AUTH_URL, OS_REGION_NAME,
                                 OS_PROJECT_NAME, OS_USERNAME,
                                 OS_PASSWORD)
        vm_list = open(instance_record, 'r').read()
        for record in vm_list.split("\n"):
            if record.strip():
                name = record.split()[0].strip()
                print("Removing Machine: {}".format(name))
                delete_server(conn, name)
            print("Removed Machine: {}".format(name))
    else:
        print("ERROR: No record file found. Delete instances manually.")
    print("Removed record.")
    os.remove(instance_record)
    print("Removed inventory.")
    os.remove(inventory)


cli.add_command(up)
cli.add_command(down)

if __name__ == '__main__':
    cli()
