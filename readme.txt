Dependencies:
mysql.connector: Will allow us to connect to our database
sys: Will allow us to get arguments
os: Will allow us to go through directories
xml.etree.ElementTree: XML parsing
datetime import datetime, timedelta: This will facilitate the adding and subtracting of dates ( +- 10 mins )
subprocess: Will allow us to get the commands running (zgrep / grep) to search in the nat.csv archive
netaddr import IPAddress: Easy way to transform IPs into their decimal values.

Running the code:
Before executing the python script, you need to edit the login credentials within the automator.py provided with your own login credentials to access your own MySQL database. 
I was able to connect to my own MySQL database using a user name of 'root' and a password of 'pass123' and execute the python script without any issue.
The code runs casually as any python script. We just need to run the command:
python3 automator.py Desktop/../testcases (specify the directory which contains all the files for testing)
If the nat.csv. ... file isn't found while doing the zgrep command the output will be: "No file found" 
If there is no log within +/- 10 mins, the output will be "No file found"
If there is no match in the radius logs with out timestamp and preNATIP, this will be considered as "False Positive"
if we find no user attached to a MAC Address the output will be "No such user"
If everything goes well, the output will be: "Username: %username"
A line will be printed before going to the next notice.

Assumptions:
Sometimes getting the MAC Address from the database returns multiple values. Since it wasn't precise, we may get different MAC values while defining a 
specific time + ip decimal. We presumed that any of those values will be good and we didn't do a second check (get the value with the closest timestamp). 
And same goes for the Radius Logs. 

Other information:
Subprocess returns a byte array, so in order to make it a string, we need to decode it with utf-8.

Timedate allows us to add, subtract, get absolute value and compare between dates. This is very useful to get the closest date and to get the +/- 10 mins from a date and to change timezone.

When looking for an element in an XML tree, we need to add the xmlns value to it. 
Example: If we want to look for <Source> we need to look for {http://www.acns.net/ACNS}Source
