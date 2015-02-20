# Ansible module for OpenVZ
YA Ansible Openvz module

## Documentation

### Summary
This module, called "openvz" will allow you to create / update / delete OpenVZ containers. One of the primary goal is to keep the "idempotent" behavior of Ansible, using the "state" option.

More precisely :

* if state = present
    * either the VZ doesn't exists, and it's created according to the option you've entered
    * or it's already created, and it's only updated (if needed)
* if state = absent, then the VZ will be deleted

### Requirements

You'll need a "recent" OpenVZ kernel. By recent, I mean "able to deal with ploop", as it's the only layout supported at the moment.
You'll also need "vzctl" and "vzlist" command available.

### Options

| Name | Description | Required |
|------|-------------|----------|
| veid | This is the ID for the OpenVZ Container | yes |
| name | Name of the container | no |
| hostname | Hostname of the container | no |
| diskspace | Size of the disk for the container. You can use a value in bytes or a value using units such as B, K, M, G, T or P (lowercase are also supported). You can also provide a integer value, but in this case, the value is in KiB (Kibibytes) | no |
| ram | Size of the ram for the container. You can use a value in bytes or a value using units such as B, K, M, G, T or P (lowercase are also supported). You can also provide a integer value, but in this case, the value is in bytes. | no |
| swap | Size of the swap for the container. You can use a value in bytes or a value using units such as B, K, M, G, T or P (lowercase are also supported). You can also provide a integer value, but in this case, the value is in bytes. | no |
| ostemplate | Template used to create the container. This template must be installed on your hypervisor, or it will failed | no |
| ips | You can set one or several IPs in this field. You can either set the IP directly as a string, or several IPs using a list. The module will automatically add or remove IPs according to the information you'll provide. Please see the example section. | no |
| onboot | If the container will automatically start at the boot of the hypervisor. Choices : 'on', 'yes', True, 'off', 'no', False. | no |
| nameserver | Set one or multiple nameserver on the container. You can provide either a single string as a nameserver, or a list of nameserver. Please see the example section. | no |
| searchdomain | Set one or multiple search domains on the container. You can provide either a single string as a search domain, or a list of search domains. Please see the example section. | no |

## Examples

### Create or update a container, ID 123
```YAML
- openvz:
    veid: 123
    state: present
```

### Delete a container ID 123
```YAML
- openvz:
    veid: 123
    state: absent
```

### Set a single nameserver, search domain and IP on the container 123
```YAML
- openvz:
    veid: 123
    state: present
    nameserver: "172.16.0.1"
    searchdomain : "example.com"
    ips: "172.16.10.100
```

### Set multiple nameserver, search domains and IPs on the container 123
```YAML
- openvz:
    veid: 123
    state: present
    nameserver:
        - "172.16.0.1"
        - "172.16.0.2"
    searchdomain:
        - "example.com"
        - "inside.example.com"
    ips:
        - "172.16.10.100"
        - "172.16.10.101"
```

### Update a diskspace to 20 GB, ram to 2GB and swap to 500 MB
```YAML
- openvz
    veid: 123
    state: present
    diskspace: 20G
    ram: 2G
    swap: 500000000
```

## Known issues

* Only one layout managed : ploop.
* If you try to delete a container that is not stopped, the module will fail.
