# whois42d
Whois server for the dn42 registry.

Based original on whoisd from the dn42 monotone registry written by welterde.

## Installation

1. Install a go compiler (like apt-get install go)
2. Setup Go Workspace:

        $ mkdir ~/go && export GOPATH=~/go

3. Download and install the daemon

        $ go get github.com/Mic92/whois42d

## Usage

    root> ~/go/bin/whois42d -registry /path/to/registry


## Run without root

By default root privileges are required to run whois42d to be able to bind port 43.
However you can use one of the following options to run whois42d without beeing root.

1. Use setcap on file:

        $ setcap 'cap_net_bind_service=+ep' ./whois42d

2. Use a supervisor supporting socket activation, for example systemd:

        $ cp whois42d.service whois42d.socket /etc/systemd/system
        $ install -D -m755 ~/go/bin/whois42d /usr/local/bin/

Edit whois42d.service to point to your monotone registry path, then enable it with

    $ systemctl enable whois42d.socket
    $ systemctl start whois42d.socket

**NOTE**: Do not start whois42d.service directly (`systemctl start whois42d`),
it run as user nobody, who cannot bind to port 43 itself.

## Supported Queries

- mntner: `$ whois -h <server> HAX404-MNT`
- person: `$ whois -h <server> HAX404-DN42`
- aut-num: `$ whois -h <server> AS4242420429`
- dns: `$ whois -h <server> hax404.dn42`
- inetnum: `$ whois -h <server> 172.23.136.0/23` or `$ whois -h <server> 172.23.136.1`
- inet6num: `$ whois -h <server> fd58:eb75:347d::/48`
- route: `$ whois -h <server> 172.23.136.0/23`
- route6: `$ whois -h <server> fdec:1:1:dead::/64`
- schema: `$ whois -h <server> PERSON-SCHEMA`
- organisation: `$ whois -h <server> ORG-C3D2`
- tinc-keyset: `$ whois -h <server> SET-1-DN42-TINC`
- tinc-key: `$ whois -h <server> AS4242422703`
- as-set: `$ whois -h <server> 4242420000_4242423999`
- as-block: `$ whois -h <server> AS-FREIFUNK`
- route-set: `$ whois -h <server> RS-DN42-NATIVE`
- version: `$ whois -h <server> -q version`
- sources: `$ whois -h <server> -q sources`
- types: `$ whois -h <server> -q types`


## TODO

- [ ] Match multiple objects by inverse index
