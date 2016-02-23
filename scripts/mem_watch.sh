#!/usr/bin/env bash


while true
do
    pid=`ps -C client -o pid --no-headers | awk '{print $1}'`

    if [ $? == 0 ];
    then
        watch -n 1 -d cat /proc/$pid/status
    fi
    sleep 1
done
