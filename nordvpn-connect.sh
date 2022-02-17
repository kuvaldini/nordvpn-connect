#!/usr/bin/env bash
set -euo pipefail
# shopt -s inherit_errexit
# shopt -s lastpipe
shopt -s expand_aliases

readonly VERSION=undefined
readonly VERSION_NPM=2.x.x

readonly DIR=$(realpath $(dirname "${BASH_SOURCE[0]}"))

function echomsg      { echo $'\e[1;37m'"$@"$'\e[0m'; }
function echodbg  { >&2 echo $'\e[0;36m'"$@"$'\e[0m'; }
function echowarn { >&2 echo $'\e[0;33m'WARNING$'\e[0m' "$@"; }
function echoerr  { >&2 echo $'\e[0;31m'ERROR$'\e[0m' "$@"; }
function fatalerr { >&2 echoerr "$@"; exit 1; }


--help(){
   cat <<END
nordvpn-connect version $VERSION
Calls openvpn command to connect to selected NordVPN server.
USAGE:
   nordvpn-connect <COUNTRY> [PROTOCOL] 
   nordvpn-connect --help
COUNTRIES: $(cat COUNTRIES.txt | tr '\n' ' ')
PROTOCOLS: tcp, udp
END
   awk '/^\s*## BUILDSPEC ARGUMENTS/,/^\s*## END BUILDSPEC ARGUMENTS/ ' $0 | sed -n 's,).*,,gp' | sed -E 's,^ +,   ,'
}

protocol=tcp

while [[ $# > 0 ]] ;do
   if cc=$(grep -iFo -- "$1" $DIR/COUNTRIES.txt) ;then
      CountryCode=$cc
   else
      case "$1" in
         ## ARGUMENTS
         tcp|udp) protocol=$1 ;;
         -h|--help) ## Show this help
            --help
            exit 0
            ;;
         ## END ARGUMENTS
         \#*)
            break  ## stop parsing arguments
         ;;
         *) fatalerr "Unknown argument $(printf %q "$1")" ;;
      esac
   fi
   shift
done

if [[ $protocol = udp ]]
then port=1194
else port=443
fi
host="$(grep "^$CountryCode" "$DIR"/SERVERS.txt | shuf -n1)"
USR="${SUDO_USER:-$USER}"
user_home="$(bash -c "cd ~$(printf %q "${SUDO_USER:-$USER}") && pwd")"
auth_file="$user_home/.config/nordvpn-connect.auth"

umask u=rw

gpgp(){
   echo 'ABraCaDabra Shvabra ;)' | 
         gpg --passphrase-fd 0 --batch --yes "$@"
}

if test -s "$auth_file" ;then
   ls -l "$auth_file" | grep -E "^...------- [^ ]+ $USR $USR" || 
      fatalerr 'Access to auth file is to open, restrict it by' \
               '`'"chown $USR:$USR $auth_file && chmod 400 $auth_file"

   if ( set +o pipefail;
         gpgp --decrypt "$auth_file" 2>&1 | 
         grep -q 'gpg: no valid OpenPGP data found.' )
   then
      echowarn "Auth file is not encrypted! Fixing this..."
      ## ToDo use own master key from keychain
      gpgp -o "$auth_file.x" --symmetric "$auth_file"
      chmod 400 "$auth_file.x"
      mv "$auth_file"{.x,}
   fi

   ## Decrypt auth data to file. ToDo use fifo with root
   open_auth=$(mktemp )
   # mknod -m600 $open_auth p ## One-time readable. Become empty after openvpn reads it
   # exec 7<>$open_auth
   gpgp --decrypt "$auth_file" >$open_auth
   # (sleep 2 && rm -f $open_auth) &  ## Let openvpn read this, then remove
else
   open_auth=
fi

[[ "`id -u`" != 0 ]] &&
   echowarn 'OpenVPN usually requires root'

echomsg "Connecting to $host:$port via $protocol"

openvpn \
   --config <(echo remote $host $port $protocol) \
   --config $DIR/nordvpn.base.ovpn \
   --config <(echo auth-user-pass $open_auth) \
