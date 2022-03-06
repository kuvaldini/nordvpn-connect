#!/usr/bin/env bash
set -eEuo pipefail
shopt -s inherit_errexit
shopt -s lastpipe
shopt -s expand_aliases

readonly VERSION=$(git describe --tags 2>/dev/null || echo undefined)
readonly VERSION_NPM=2.x.x

readonly DIR=$(realpath $(dirname $(realpath "${BASH_SOURCE[0]}")))

function echomsg      { echo $'\e[1;37m'"$@"$'\e[0m'; }
function echodbg  { >&2 echo $'\e[0;36m'"$@"$'\e[0m'; }
function echowarn { >&2 echo $'\e[0;33m'WARNING$'\e[0m' "$@"; }
function echoerr  { >&2 echo $'\e[0;31m'ERROR$'\e[0m' "$@"; }
function fatalerr { >&2 echoerr "$@"; exit 1; }

[[ "$DIR" = *' '* ]] && fatalerr "Program expects to be located without at path WITHOUT spaces."
cd "$DIR"

--version(){
   cat <<END
nordvpn-connect version $VERSION
END
}
--countries(){
   # cat SERVERS.txt | cut -c-2  | uniq | tr '\n' ' '
   cat "$DIR"/server.csv | cut -c-2  | sort -u | tr '\n' ' '
}
--help(){
   cat <<END
Calls openvpn command to connect to selected NordVPN server.
USAGE:
   nordvpn-connect [country_code] [protocol]
   nordvpn-connect [server_fuzzy_name] [protocol]
   nordvpn-connect --help
Where:
   country_code: $(--countries)
   server_fuzzy_name: country name and/or server number for fuzzy search. i.e: Ukraine, albaia21
   protocol: tcp, udp
OPTIONS:
END
   awk '/^\s*## ARGUMENTS/,/^\s*## END ARGUMENTS/ ' ${BASH_SOURCE[0]} | 
      sed -En 's,^( +)(.*)\)( +)## (.*),   \2\3\4,gp'
   cat <<END
SITE: https://github.com/kuvaldini/nordvpn-connect
END
}

exit_if_last_arg(){
   ## Exit if this is last argument and serverspec was not set
   if test $1 = 1 -a "${serverspec:-}" = '' ;then
      exit ${2:-}
   fi
}

readonly sameline=$'\e[2K\r'
protocol=tcp
DryRun=n
declare -i use_fastest=0
readonly latency_unknown=98767
do_actions= ## ToDo arrange actions in defined order to be executed later (not while parsing), deduplicate

if ! test -s server.user.json ;then
   cp server.{short,user}.json
fi
if ! test -s server.user.json ;then
   cp server.{short,user}.json
fi

while [[ $# > 0 ]] ;do
   case "$1" in
      ## ARGUMENTS
      tcp|udp) protocol=$1 ;;
      -c|--countries)                 ## List available countries
         #test "" = "${do_action:-}" && do_action=--countries || echowarn "do_action already set to '$do_action'"
         echo -n "Countries available: "; --countries
         echo
         exit 0
         ;;
      -l|--list|--list-servers)       ## List available servers with given serverspec, default=all
         test "" = "${do_action:-}" && do_action=--list-servers || echowarn "do_action already set to '$do_action'"
         ;;
      -f|--args-from)                 ## Take arguments from file, drop rest
         set -- tobeshifted $(sed '/^[ \t]*#/d' "$2" | xargs)
         ;;
      -a|--auth-file)                 ## Provide path to authorization file
         test "" = "${auth_file:-}" && auth_file="$2" || echowarn "auth_file already set to '$auth_file'"
         shift
         ;;
      -u|--update|--update-servers)   ## Update servers list
         set +e
         (
            set -Eeuo pipefail
            cd $DIR
            echo >&2 "Updating servers list..."
            curl https://api.nordvpn.com/server -fsSL >server.full.temp.json \
               -H"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:97.0) Gecko/20100101 Firefox/97.0"  \
               && mv -f server.full.{temp,}.json \
               || { rm -f server.full.temp.json
                  errmsg="Failed to get server.full.json from NordVPN API."
               }
            if test -s server.full.json ;then
               if test "${errmsg:-}" != "" ;then
                  echowarn "$errmsg" "Going ahead with previous server.full.json"
               fi
            else
               fatalerr "$errmsg" "No cached server.full.json"
            fi
            ## Merge updated servers list, removed servers stay removed
            jq 'INDEX(.domain) as $u |
                reduce ($full[][] | {domain,ip_address,name}) as $i (
                   []; . + [ $i | .ping_latency=( $u[$i.domain].ping_latency//98767 ) ]
                  )' \
                --slurpfile full server.full.json <server.user.json >server.user.temp.json
            function json_tsv { jq -r 'sort_by(.domain)|.[]|[.domain,.ip_address,.name]|@tsv'; }
            diff --old-line-format=`tput setaf 3`'- %L'$'\e[0m' --new-line-format=`tput setaf 2`'+ %L'$'\e[0m' --unchanged-line-format= \
               <(json_tsv<server.user.json) <(json_tsv<server.user.temp.json) \
               && echo >&2 "Updated with no changes."
            mv -f server.user{.temp,}.json
            jq <server.user.json ".[] | [.domain,.ip_address,.ping_latency//$latency_unknown,.name] | @tsv" --raw-output >server.csv
            echomsg "Servers database updated. Use --reindex-fastest to update latencies."
         )
         exit_if_last_arg $# $?
         set -e
         ;;
      -r|--reindex-fastest)           ## Detect optimal servers (lowest ping), ToDo make longer test with iperf or ookla speedtest
         echo >&2 "Checking ping delay to servers. Make sure your are not connected to any proxy or VPN. This takes a while (about 10 min)..."
         fastest_server=`mktemp` #rm -f fastest_server.csv
         latencies_json=latencies.json #`mktemp`
         echo '{' >$latencies_json
         readonly pingjobsMAX=24
         declare -i i=1 max=`wc -l <server.csv`
         shuf $DIR/server.csv | while read domain ipaddr oldpingavg name ;do
            echo -n "${sameline}Checking server $i/$max $domain $ipaddr..."
            ping -q -c3 -w10 -i.7 -l2 $ipaddr | tail -1 | 
               sed -nE 's,^rtt min.*(.*)/(.*)/(.*)/(.*) ms.*,\2,p;tx;q1;:x' | {
                  read pingavg || echo "Failed to read ping time for server $domain $ipaddr: keep old $oldpingavg"
                  echo -e "$domain\t$ipaddr\t${pingavg:-$oldpingavg}\t$name" >>$fastest_server
                  echo "\"$domain\":{ \"ping_latency\":${pingavg:-$oldpingavg} }," >>$latencies_json
               } & sleep .1
            if test `jobs -rp | wc -l` -ge $pingjobsMAX ;then
               wait -fn #|| true
               sleep .1
            fi
            ((++i))
         done
         wait; sleep 1
         echo ' Done.'
         <$fastest_server sort --numeric-sort --key=3 >server.csv
         sed -i '${s/,$/\n\}/}'  $latencies_json  ## remove last comma and add closing bracket
         jq '(map({ (.domain) : {ip_address,name,ping_latency} }) | add) * $lat[0] | to_entries | map(.value.ping_latency//='$latency_unknown') |
                sort_by(.value.ping_latency) | map({"domain":.key}+.value)' \
               <server.user.json --slurpfile lat $latencies_json >server.user.temp.json 
         mv -f server.user{.temp,}.json
         rm -f $latencies_json
         exit_if_last_arg $#
         ;;
      --fastest)                      ## Use server with lowest ping among 50 instead of random
         use_fastest=50
         ;;
      --fastest=*)                    ## Use server with lowest ping among N instead of random
         declare -i use_fastest=${1#*=}
         test $use_fastest -eq $use_fastest 2>&- || fatalerr "fastest must be a number"
         ;;
      -g|--genconfig|--gen-config)    ## Generate OpenVPN configuration file to stdout
         test "" = "${do_action:-}" && do_action=--gen-config || echowarn "do_action already set to '$do_action'"
         ;;
      -U|--upgrade|--upgrade-script)  ## Upgrade the script and repo
         exec git -C $DIR pull origin master --rebase -X ours
         ;;
      -h|--help)                      ## Show this help
         --help
         exit 0
         ;;
      -V|--version)                   ## Show version
         --version
         exit 0
         ;;
      -n|--dry-run)                   ## Dry run, not execute but echo openvpn command
         DryRun=y
         ;;
      -x|--trace)                     ## Trace as bash -x
         set -x
         ;;
      ## END ARGUMENTS
      -?)  ## one char - unknown
         fatalerr "Unknown short option '$1'"
         ;;
      --*)
         fatalerr "Unknown option '$1'"
         ;;
      -*)  ## multiple chars -> unwrap multiple flags
         echo -n "${1#-}" | while read -n1 C; do
            args+="-$C "
         done
         shift
         set tobeshifted $args "$@"
         ;;
      # \#*)
      #    break  ## stop parsing arguments
      #    ;;
      *)
         test "" = "${serverspec:-}" && serverspec="$1" || fatalerr "serverspec cannot be set twice"
         ;;
   esac
   shift
done

## Show version first
--version >&2
echo >&2 "This simple script gathers no data not about hardware nor about user."\
        "Sends nothing nowhere. Just VPN."

--list-servers(){
   ## Extract from test file contains names line ua57.nordvpn.com
   # h=$(v="$1" awk 'index($0, ENVIRON["v"])==1' $DIR/SERVERS.txt | shuf -n1)
   ## Extract from JSON file
   # h=$(jq -r <$DIR/server.short.json --arg x "$1" '.[]|select(.domain|startswith($x))| .domain +" "+ .ip_address + " " +.name' )
   ## Extract from CSV file
   # awk -F$'\t' -vIGNORECASE=1 -vv="$(printf %q ${serverspec:-})"  'index($0, v)==1 || $3 ~ v' $DIR/server.csv | 
   #    tee >( test $(wc -l) != 0 || fatalerr "No server begins with such name '${serverspec:-}'."; )
   # awk -F$'\t' -vIGNORECASE=1 -vS="$(printf %q ${serverspec:-})"  'index($1, S)==1' $DIR/server.csv | 
   #    tee >( test $(wc -l) != 0 ||
   if test "${serverspec:-}" = '' ;then
      cat "$DIR"/server.csv
   elif [[ "${serverspec:-}" != ??* ]] ;then
      fatalerr "serverspec must be longer than 2"
   else
      grep -i "^$serverspec" $DIR/server.csv ||
         {
            if echo "$serverspec" | grep -qEo '^[[:alpha:]]{2}[[:digit:]]*$' ;then
               fatalerr "No server name begins with '$serverspec'"; 
            elif fzf --version &>/dev/null ;then
               fzf --filter="${serverspec:-}" --no-sort <$DIR/server.csv
            else
               echowarn "fzf is not installed or not in PATH, using grep instead."
               grep -i '.*\t.*'"${serverspec:-}" <$DIR/server.csv
            fi
         } ||
         fatalerr "No server begins with such name '${serverspec:-}', no fuzzy corresponding to server name"; 
   fi
}

case "${do_action:-}" in
   '')  : ;;
   --gen-config)  : ;;
   *) "$do_action"
      exit 0
      ;;
esac

if [[ $use_fastest > 0 ]] ;then
   select_server(){
      # sort --numeric-sort --key=3 | grep -v '^.*\s.*\s0' | head -n100 | shuf -n1
      ## Expects sorted input
      { grep -v "^.*\s.*\s$latency_unknown" || 
         fatalerr "No latency information provided, use --reindex-fastest first or remove flag --fastest"; } | 
            sed -n 1,${use_fastest}p | shuf -n1
   }
else
   select_server(){
      shuf -n1
   }
fi

--list-servers | select_server | read hostname serverip pingavg servername || 
   fatalerr 'Failed to select server.'
if [[ $protocol = udp ]]
then port=1194
else port=443
fi

case "${do_action:-}" in
   --gen-config)
      cat <<END
remote $serverip $port $protocol
$(cat $DIR/nordvpn.base.ovpn)
auth-user-pass ${open_auth:-/tmp/nordvpn-auth.txt}
END
      exit 0;
      ;; 
esac

USR="${SUDO_USER:-$USER}"
user_home="$(bash -c "cd ~$(printf %q "${SUDO_USER:-$USER}") && pwd")"
auth_file=${auth_file:-"$user_home/.config/nordvpn-connect.auth"}

umask u=rw

gpgp(){
   echo 'ABraCaDabra Shvabra ;)' | 
         gpg --passphrase-fd 0 --batch --yes "$@" #2>/dev/null
}

if test -s "$auth_file" ;then
   ls -l "$auth_file" | grep -qE "^...------- [^ ]+ $USR $USR" || {
      # fatalerr 'Access to auth file is to open, restrict it by' \
      #          '`'"chown $USR:$USR $auth_file && chmod 400 $auth_file"
      echowarn 'Access to auth file is to open, restricting.'
      chown $USR:$USR "$auth_file" && chmod 400 "$auth_file"
   }
   if ( set +o pipefail;
         gpgp --decrypt "$auth_file" 2>&1 | 
         grep -q 'gpg: no valid OpenPGP data found.' )
   then
      echowarn "Auth file is not encrypted! Fixing this."
      ## ToDo use own master key from keychain
      gpgp -o "$auth_file.x" --symmetric "$auth_file"
      chmod 400 "$auth_file.x"
      mv -f "$auth_file"{.x,}
   fi
else
   ## ToDo detect is_interactive
   echomsg "Auth_file '$auth_file' does not exist. "\
         "Enter username and password (optional) to store in encrypted file. "\
         "Leave empty, then OpenVPN will ask you every time directly."
   read  -rp "Username: " vpnuser || fatalerr "Failed to read vpnuser"
   read -rsp "Password: " vpnpass || fatalerr "Failed to read vpnpassword"
   gpgp -o "$auth_file" --symmetric <( echo "$vpnuser"; echo "$vpnpass"; )
   chmod 400 "$auth_file"
fi
## Decrypt auth data to file. ToDo be able to use fifo with root
open_auth=$(mktemp )
# mknod -m600 $open_auth p ## One-time readable. Become empty after openvpn reads it, but does not work
# exec 7<>$open_auth
gpgp --decrypt "$auth_file" >$open_auth
(sleep 2 && rm -f $open_auth) &  ## Let openvpn read this, then remove

if [[ $(getcap $(which openvpn)) != *'openvpn cap_net_admin=ep' ]] ;then
   [[ "`id -u`" != 0 ]] &&
      echowarn 'OpenVPN usually requires root or cap_net_admin'
fi

if test "$pingavg" = $latency_unknown ;then pingavg=unknown; else pingavg=${pingavg}ms ;fi
echomsg "Connecting to $servername -- $serverip:$port ($hostname) via $protocol, latency ${pingavg}"


$( [[ $DryRun = y ]] && echo echo || echo exec ) \
   openvpn \
   --config <(echo remote $serverip $port $protocol) \
   --config $DIR/nordvpn.base.ovpn \
   --config <(echo auth-user-pass $open_auth) \
| tee /dev/tty | tail -10 | if grep -qF "AUTH_FAILED" ;then
      echomsg "Authentication failed. Removing auth file '$auth_file'. Next do: "\
            "a) rerun nordvpn-connect to be asked for user/pass, or b) create file with user/pass then rerun to be non-interactive."
      rm -f "$auth_file"
      exit 1
   fi
