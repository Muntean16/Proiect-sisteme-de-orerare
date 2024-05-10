#!/bin/bash

file=$1
#echo "$file"
chmod 444 $file

nrLinii=$(wc -l < "$file")
nrCaractere=$(wc -c < "$file")
nrCuvinte=$(wc -w < "$file")

suspect=0
# <3 linii & >1000 cuv &  >2000 char
if [ $nrLinii -lt 3 ] || [ $nrCuvinte -gt 1000 ] || [ $nrCaractere -gt 2000 ]; then
    suspect=1
fi


if grep -qE 'corrupted|dangerous|risk|attack|malware|malicious' "$file";  then
    suspect=1
fi

if grep -qP "[^\x00-\x7F]" "$file"; then
    suspect=1
fi

if [ $suspect -eq 1 ]; then
   {  
    chmod 000 $file  
    echo "$file"
    #mv "$1" "$2"
    exit 1
   }
else
   chmod 000 $file 
   echo "SAFE"
   exit 1
fi
