#!/bin/bash
/usr/local/bin/tshark -r $2 -R "not vrrp and not ans and not msnlb" -w  $2-filtered.pcap
if [ -f "$2-filtered.pcapout" ]
then
rm -rf $2-filtered.pcapout
fi
python $1FlowParserv1.5.py $2-filtered.pcap
rm -rf $2-filtered.pcap
var1=`cat $2-filtered.pcapout | head -1 | awk '{print $2}'`
var2=`cat $2-filtered.pcapout | tail -1 | awk '{print $2}'`
var="$var1 $var2"
/home/inlay/opentsdb-2.0.0RC2/build/tsdb mkmetric bytes.uploaded
/home/inlay/opentsdb-2.0.0RC2/build/tsdb import  $2-filtered.pcapout
echo $var
