# Ansible module for OpenVZ
YA Ansible Openvz module

## Documentation

### Summary
This module, called "openvz" will allow you to create / update / delete OpenVZ containers. One of the primary goal is to keep the "idempotent" behavior of Ansible, using the "state" option.

More precisely :

* if state = present
** either the VZ doesn't exists, and it's created according to the option you've entered
** or it's already created, and it's only updated (if needed)
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
