#!/bin/bash
cat << EOF | mysql -uroot 
CREATE DATABASE logs_db
EOF

cat << EOF | mysql -uroot logs_db
CREATE TABLE dhcp (ip_decimal INT(10) UNSIGNED NOT NULL, mac_string VARCHAR(20) NOT NULL, pc_name VARCHAR(20) 
NOT NULL, transaction VARCHAR(12) NOT NULL, timestamp TIMESTAMP NOT NULL, PRIMARY KEY (ip_decimal, mac_string, timestamp));
EOF

cat << EOF | mysql -uroot logs_db
CREATE TABLE radacct (timestamp timestamp NOT NULL, username VARCHAR(64) NOT NULL, 
FramedIPAddress VARCHAR(15) NOT NULL, AcctStatusType VARCHAR(15) NOT NULL, CallingStationId VARCHAR(50) NOT NULL);
EOF

cat << EOF | mysql -uroot logs_db
CREATE TABLE contactinfo (mac_string VARCHAR(20) NOT NULL, contact VARCHAR(20) NOT NULL, PRIMARY KEY(mac_string));
EOF
