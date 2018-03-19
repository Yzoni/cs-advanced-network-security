#!/bin/bash
domain=$1
nexturl=$domain

for i in `seq 1 10`; do
   echo "Getting $nexturl"
   lynx -dump "https://$domain" > q
   nexturl=`cat q | sed -e '1,/^References/d' | egrep -e " +[0-9]*\. .*" -o | grep "https://$domain.*" -o | sort | uniq | shuf -n 1`
   sleep 5
done
