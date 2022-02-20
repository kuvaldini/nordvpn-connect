NordVPN-connect
===============
I do not trust Official NordVPN, it is not open-source,
and does more that it is asked for. Giving root access to this
app is extremely dangerous for Secure Systems. 
Configuring nordvpnd to work without root is hard, if it is ever possible.

So I desided to spend a couple of hours to write a script to connect to nordvpn.


INSTALLATION
---------------
This is beta version and has no cool installation procedure.
Just clone the repo and create a link in your `$PATH`.

```sh
umask u=rw
git clone https://github.com/kuvaldini/nordvpn-connect /path/to/home/user/sofware/nordvpn-connect --single-branch -b master
chmod -R go= nordvpn-connect  ## Restrict access, only user-ovener may read and run
ln -s $PWD/nordvpn-connect/nordvpn-connect.sh /usr/local/bin/nordvpn-connect  ## root required
```
Rootless link `ln -s $PWD/nordvpn-connect/nordvpn-connect.sh ~/.local/bin/`. 
Ensure it is in the `$PATH`.

UPDATE/UPGRADE
--------------
```
git -C /path/to/nordvpn-connect pull -Xtheirs --ff
chmod -R go= /path/to/nordvpn-connect
```


USAGE
-----
```
nordvpn-connect version undefined
Calls openvpn command to connect to selected NordVPN server.
USAGE:
   nordvpn-connect <COUNTRY|serverspec> [PROTOCOL]
   nordvpn-connect --help
COUNTRY: al ar at au ba be bg br ca ch cl cr cy cz de dk ee es fi fr ge gr hk hr hu id ie il in is it jp kr lt lu lv md mk mx my nl no nz pl pt ro rs se sg si sk th tr tw ua uk us vn za 
SERVER: may specify any letters correponding to the begining of server address
PROTOCOLS: tcp, udp
OPTIONS:
   -c|--countries List available countries
   -s|--servers   List available servers with given serverspec, default=all
   -h|--help      Show this help
   -V|--version   Show version
   -n|--dry-run   Dry run, not execute but echo openvpn command
   -x|--trace     Trace as bash -x
SITE: https://github.com/kuvaldini/nordvpn-connect
```

### store credentials
It is important to have credentials Login:Password stored somewhere, 
not to be asked every time. And moreover that should be secure.
That is why I added a stupid encryption for credentials utilizing GnuPG.

Login:Password are stored in `$HOME/.config/nordvpn-connect.auth`. 
First time user creates it in open form
```
login
password
```
After first call `nordvpn-connect` will encrypt that file.
Password is optional, if not set openvpn will ask each time.

The encryption is vulnerable because password is stored in script,
but that is better than nothing.  
I have a future plan to encrypt assimetrically with key from user's 
GPG keychain. 


Lifehacks
---------
### Connecting without sudo
Someone could want to connect as regular user without root priveliges (i.e. no sudo):
```
sudo chmod 500 $(which openvpn)
sudo setcap 'CAP_NET_ADMIN=ep' $(which openvpn)
```
Then `openvpn` should become able to configure tun/tap interfaces and create routes.

### Get direct URLs to OpenVPN configs from official site nordvpn.com

    curl https://nordvpn.com/ovpn/ | 
       htmlq -a href a | grep -F .ovpn

### Request servers via API
Server restrics the rate of requests hard, cannot use for scripting, cache required

    curl https://api.nordvpn.com/server -fsSLv >servers.json \
        -H"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:97.0) Gecko/20100101 Firefox/97.0"

File size is about 4MB, reduce it to 500KB

    jq 'map({name,domain,ip_address}) |sort_by(.domain)' <servers.json >servers.short.json

Select/filter servers by country

    jq <server.short.json '.[]|select(.name|contains("Ukraine"))'


## LINKS
- https://community.openvpn.net/openvpn/wiki/IgnoreRedirectGateway


## ToDo 
- stabilize connection after sleep
- systemd config to connect at startup
- optional killswitch by unrouting all
- suggest adguard-dnsserver on localhost
- protect from server's routes https://community.openvpn.net/openvpn/wiki/IgnoreRedirectGateway
- protect from server's dns
- notify desktop
- integrate with NetworkManager
- encrypt/decrypt with master trusted key using assimmetric algorithm
- version
- test for a fastest server, cache the value

```
Firewall: enabled
KillSwitch: disabled
Obfuscate: disabled
CyberSec: disabled
DNS: 
IPv6: disabled
Notify: enabled
Auto-connect: disabled
```
