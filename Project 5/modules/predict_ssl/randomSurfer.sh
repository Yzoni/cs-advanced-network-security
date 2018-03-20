#!/bin/bash
domain=$1
nexturl=$domain

for i in `seq 1 5`; do
   echo "Getting $nexturl"
   sleep 3
   lynx -dump "https://$domain" > q
   nexturl=`cat q | sed -e '1,/^References/d' | egrep -e " +[0-9]*\. .*" -o | grep "https://$domain.*" -o | sort | uniq | shuf -n 1`
done
