#!/usr/bin/env bash
set -euo pipefail
DIR=$(realpath $(dirname "${BASH_SOURCE[0]}"))
cd ovpn
curl https://nordvpn.com/ovpn/ | 
   htmlq -a href a | grep -F .ovpn |
   tee $OLDPWD/LIST.txt |
   while read addr; do
      filename="$(basename $addr)"
      if test -s "$filename"
      then echo EXIST "$filename"
      else echo wget $addr
      fi
   done
