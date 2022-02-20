#!/usr/bin/env bash
set -eEuo pipefail
shopt -s inherit_errexit
shopt -s lastpipe
shopt -s expand_aliases

readonly VERSION=$(git describe --tags 2>/dev/null || echo undefined)
readonly VERSION_NPM=2.x.x

readonly DIR=$(realpath $(dirname "${BASH_SOURCE[0]}"))

function echomsg      { echo $'\e[1;37m'"$@"$'\e[0m'; }
function echodbg  { >&2 echo $'\e[0;36m'"$@"$'\e[0m'; }
function echowarn { >&2 echo $'\e[0;33m'WARNING$'\e[0m' "$@"; }
function echoerr  { >&2 echo $'\e[0;31m'ERROR$'\e[0m' "$@"; }
function fatalerr { >&2 echoerr "$@"; exit 1; }

--version(){
   cat <<END
nordvpn-connect version $VERSION
END
}
--countries(){
   cat SERVERS.txt | cut -c-2  | uniq | tr '\n' ' '
}
--help(){
   --version
   cat <<END
Calls openvpn command to connect to selected NordVPN server.
USAGE:
   nordvpn-connect <COUNTRY|serverspec> [PROTOCOL]
   nordvpn-connect --help
COUNTRY: $(--countries)
SERVER: may specify any letters correponding to the begining of server address
PROTOCOLS: tcp, udp
OPTIONS:
END
   awk '/^\s*## ARGUMENTS/,/^\s*## END ARGUMENTS/ ' ${BASH_SOURCE[0]} | 
      sed -En 's,^( +)(.*)\)( +)## (.*),   \2\3\4,gp'
   cat <<END
SITE: https://github.com/kuvaldini/nordvpn-connect
END
}

protocol=tcp

while [[ $# > 0 ]] ;do
      case "$1" in
         ## ARGUMENTS
         tcp|udp) protocol=$1 ;;
         -c|--countries) ## List available countries
            --countries
            exit 0
            ;;
         -s|--servers)   ## List available servers with given serverspec, default=all
            v="${serverspec:-}" awk 'index($0, ENVIRON["v"])==1' $DIR/SERVERS.txt
            exit 0
            ;;
         -h|--help)      ## Show this help
            --help
            exit 0
            ;;
         -V|--version)   ## Show version
            --version
            exit 0
            ;;
         -n|--dry-run)   ## Dry run, not execute but echo openvpn command
            DryRun=y
            ;;
         -x|--trace)     ## Trace as bash -x
            set -x
            ;;
         ## END ARGUMENTS
         \#*)
            break  ## stop parsing arguments
         ;;
         *)
            serverspec="$1"
            h=$(v="$1" awk 'index($0, ENVIRON["v"])==1' $DIR/SERVERS.txt | shuf -n1)
            if [[ ${h:-x} = x ]] ;then
               fatalerr "No server begins with such name." 
            else
               host=$h
            fi
            ;;
      esac
   shift
done

if [[ $protocol = udp ]]
then port=1194
else port=443
fi

USR="${SUDO_USER:-$USER}"
user_home="$(bash -c "cd ~$(printf %q "${SUDO_USER:-$USER}") && pwd")"
auth_file="$user_home/.config/nordvpn-connect.auth"

umask u=rw

gpgp(){
   echo 'ABraCaDabra Shvabra ;)' | 
         gpg --passphrase-fd 0 --batch --yes "$@" 2>/dev/null
}

if test -s "$auth_file" ;then
   ls -l "$auth_file" | grep -qE "^...------- [^ ]+ $USR $USR" || 
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

if [[ $(getcap $(which openvpn)) != *'openvpn cap_net_admin=ep' ]] ;then
   [[ "`id -u`" != 0 ]] &&
      echowarn 'OpenVPN usually requires root'
fi

echomsg "Connecting to $host:$port via $protocol"

$( [[ $DryRun = y ]] && echo echo || echo exec ) \
   openvpn \
   --config <(echo remote $host $port $protocol) \
   --config $DIR/nordvpn.base.ovpn \
   --config <(echo auth-user-pass $open_auth) \
