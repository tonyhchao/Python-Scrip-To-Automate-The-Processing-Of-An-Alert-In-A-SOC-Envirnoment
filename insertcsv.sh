echo "Inserting Contact infoi\n"
mysql -uroot --local_infile=1 logs_db -e "LOAD DATA LOCAL INFILE '<INSERT PATH TO CONTACT INFO CSV FILE HERE>' INTO TABLE contactinfo FIELDS TERMINATED BY ',' LINES TERMINATED BY '\n'";

echo "Inserting RADIUS logs\n"
mysql -uroot --local_infile=1 logs_db -e "LOAD DATA LOCAL INFILE '<INSERT PATH TO CONTACT INFO CSV FILE HERE>' INTO TABLE radacct FIELDS TERMINATED BY ',' LINES TERMINATED BY '\n'";

echo "Inserting DHCP logs\n"
mysql -uroot --local_infile=1 logs_db -e "LOAD DATA LOCAL INFILE '<INSERT PATH TO CONTACT INFO CSV FILE HERE>' INTO TABLE dhcp FIELDS TERMINATED BY ',' LINES TERMINATED BY '\n'";
