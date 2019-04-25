import mysql.connector
import sys, os, calendar
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
import subprocess
from netaddr import IPAddress

# Contains functions to convert nat logs timestamps from Eastern Time to Zulu Time
class Time:
	def __init__(self, string, tz = "ZULU"):
		tmp = string.split("T")
		tmpa = tmp[0].split("-")
		year = int(tmpa[0])
		month = int(tmpa[1])
		day = int(tmpa[2])
		tmpb = tmp[1].split(":")
		hour = int(tmpb[0])
		minute = int(tmpb[1])
		if "Z" in tmpb[2]:
			second = int(tmpb[2][:-1].split(".")[0])
		else:
			second = int(tmpb[2].split(".")[0])
		self.date = datetime(year, month, day, hour, minute, second)
		if tz == "ZULU":
			self.date -= timedelta(seconds = 4*3600)

	def str(self):
		tmpdates = []
		tmpdates.append(self.date)
		tmpdates.append(self.date + timedelta(seconds = 600))
		tmpdates.append(self.date - timedelta(seconds = 600))

		output = []
		for item in tmpdates:
			tmpitem = item + timedelta(seconds= 3600)
			strm = twodigits(str(tmpitem.month))
			strd = twodigits(str(tmpitem.day))
			strh = twodigits(str(tmpitem.hour))
			output.append([date_to_str1(item), str(tmpitem.year) + strm + strd + strh])
		return output

def twodigits(strn):
	return strn if len(strn) == 2 else '0' + strn

# Convert the information found in a specific format 1 from logs to a string
def date_to_str1(tmpdate):
	strm = twodigits(str(tmpdate.month))
	strd = twodigits(str(tmpdate.day))
	strh = twodigits(str(tmpdate.hour))
	strmi = twodigits(str(tmpdate.minute))[0]
	return str(tmpdate.year) + "-" + strm + "-" + strd + "T" + strh + ":" + strmi

# Convert the information found in a specific format 2 from logs to a string
def date_to_str2(tmpdate):
	strm = twodigits(str(tmpdate.month))
	strd = twodigits(str(tmpdate.day))
	strh = twodigits(str(tmpdate.hour))
	strmi = twodigits(str(tmpdate.minute))[0]
	return str(tmpdate.year) + "-" + strm + "-" + strd + " " + strh + ":"

# Get the required information to make a connection to the database
def getdb(host, user, passwd, database):
	return mysql.connector.connect(host=host
		,user=user
		,passwd=passwd
		,database= database)

# Parse the xml file in order to read the file
def read_notice(file_name):
	with open(file_name, 'r') as file:
		lines= file.readlines()
	xml = ""
	xmlns = "{http://www.acns.net/ACNS}"

	for line in lines:
		strippedline = line.strip()
		if len(strippedline)!=0 and strippedline[0] == '<':
				xml += line

	tree = ET.fromstring(xml)
	source = tree.find(xmlns + 'Source')
	time = source.find(xmlns + 'TimeStamp')
	ip = source.find(xmlns + 'IP_Address')
	port = source.find(xmlns + 'Port')

	return time.text, ip.text, port.text

# Search and select the MAC Address
def get_contactinfo(mycursor, mac):
	mycursor.execute("SELECT * FROM contactinfo WHERE mac_string = '" + mac + "';")
	return mycursor.fetchall()

# Get the MAC Address of the device using the IP Address and timestamp
def get_MACaddr(mycursor, time, ipdecimal):
	cmd = "SELECT * FROM dhcp WHERE ip_decimal= " + str(ipdecimal) + " AND timestamp LIKE '" + date_to_str2(time) + "%';"
	# print(cmd)
	mycursor.execute(cmd)
	return mycursor.fetchall()

# Retrieve the required information from Radius Logs
def get_RADIUS(mycursor, time, ip):
	cmd = "SELECT * FROM radacct WHERE FramedIPAddress= '" + ip + "' AND timestamp LIKE '" + date_to_str2(time) + "%';"
	# print(cmd)
	mycursor.execute(cmd)
	return mycursor.fetchall()

# Select the closest time if there are muitple entries based on the timestamp from the notice
def closestresp(columns, t):
	times = [Time(column[0], tz = "EASTERN") for column in columns]
	i = -1
	mini = timedelta(seconds = 600)
	for j in range(len(times)):
		diff = abs(t- times[j].date)
		if mini >= diff:
			mini = diff
			i = j
	return i

def main():
	# Store the directory path containing the files for testing into notices_path
	notices_path = sys.argv[1]
	notices = os.listdir(notices_path)
	tests = []
	for notice in notices:
		time, ip, port = read_notice(os.path.join(notices_path, notice))
		tests.append({"time": time, "ip": ip, "port": port})

	# Connect to the database by specifying all the required information
	try:
		mydb = getdb("localhost", "root", "", "logs_db")
		mycursor = mydb.cursor()
	except mysql.connector.errors.ProgrammingError as e:
		print("A Database Error Has Occurred:")
		print(e)

	# Processing the alert 
	for item in tests:
		t = Time(item["time"])

		times = t.str()
		resps = []
		# Print(item["time"])
		for time in times:
			filename = "nat_logs/nat.csv." + time[1] + ".csv.gz"
			# Print(time[0])
			# Print("filename: ", filename)
			ps = subprocess.Popen(("zgrep", time[0], filename), stdout= subprocess.PIPE, stderr = subprocess.STDOUT)
			try:
				output = subprocess.check_output(("grep", item["ip"]+ "," + item["port"]), stdin = ps.stdout)
				ps.wait()
				for line in output.split():
					resps.append(line.decode("utf-8"))
			except subprocess.CalledProcessError as e:
				pass
		# Print(item["time"])
		if len(resps) == 0:
			print("No file found")
		else:
			# Print(resps)
			columns = [[x for x in resp.split(",")] for resp in resps ]
			index = closestresp(columns, t.date)
			if index == -1:
				print("No file found")
			else:
				column = columns[index]
				PreNATIP = column[2]
				PreNATIPDecimal = int(IPAddress(PreNATIP))
				# PreNATPort = column[3]
				MACs = get_MACaddr(mycursor,t.date,PreNATIPDecimal)
				# Pick any of those 
				MAC = MACs[0][1]
				# Print(MAC)
				# Print(PreNATIP)
				if PreNATIP.startswith("172.19."):
					Radiuses = get_RADIUS(mycursor, t.date, PreNATIP)
					if len(Radiuses) == 0:
						print("False Positive")
					else:
						# Pick any of those 
						Radius = Radiuses[0]
						if Radius[-1] == MAC:
							username = Radius[1]
							print("Username: " + username)
						else:
							print("Sanity Check Unsuccessful")
				else:
					contacts = get_contactinfo(mycursor, MAC)
					if len(contacts) == 0:
						print("No such user")
					else: 
						contact = contacts[0]
						username = contact[1]
						print("Username: " + username)

		print("______________________")

if __name__ == '__main__':
	main()
