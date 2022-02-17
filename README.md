NordVPN-connect
===============
I do not trust Official NordVPN, it is not open-source,
and does more that it is asked for. Giving root access to this
app is extremely dangerous for Secure Systems. 
Configuring nordvpnd to work without root is hard, if it is ever possible.

So I desided to spend a couple of hours to write a script to connect to nordvpn.


INSTALLATION
---------------
This is alpha version and has no cool installation procedure.
Just clone the repo and create a link in your `$PATH`.

```sh
umask u=rw
git clone https://github.com/kuvaldini/nordvpn-connect
chmod -R go= nordvpn-connect
ln -s $PWD/nordvpn-connect/nordvpn-connect.sh /usr/local/bin/nordvpn-connect
```


USAGE
-----
```
nordvpn-connect <contry_code> [tcp|udp]
```
Use `--help`.

### credentials
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

The encryption is vulnerable because password is stored in script,
but that is better than nothing.  
I have a future plan to encrypt assimetrically with key from user's 
GPG keychain. 


### Get config from official site nordvpn.com

    curl https://nordvpn.com/ovpn/ | 
       htmlq -a href a | grep -F .ovpn

### Request servers via API
Server restrics the rate of requests hard, cannot use for scripting, cache required

    curl https://api.nordvpn.com/server -fsSLv >servers.json \
        -H"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:97.0) Gecko/20100101 Firefox/97.0"

File size is about 4MB, reduce it to 500KB

    jq 'map({name,domain,ip_address}) |sort_by(.domain)' <servers.json >servers.short.json


## LINKS
- https://community.openvpn.net/openvpn/wiki/IgnoreRedirectGateway


## ToDo 
- systemd config to connect at startup
- optional killswitch by unrouting all
- suggrest adguard-dnsserver on localhost
- protect from server routes
- protect from server dns
- notify desktop

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
