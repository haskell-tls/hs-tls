#! /bin/sh

for i in `yes | head -n 1000`       
do              
  dist/build/spec/spec -a 1 -m "TLS 1.3 0RTT -> PSK" +RTS -N4
  if [ $? -ne 0 ]; then
     exit
  fi
done
