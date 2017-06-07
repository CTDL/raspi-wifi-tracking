# probemon.py
# Written by Colin Monroe, New Mexico Highlands University, SSD Program 2017

# reads wireless communications probes and registers them to an internal
# dictionary, along with first and final read times of said probes. Program
# then outputs this data to an external file, which it can then send to a client
# email directly, or to a database (which can send an email as well).

# Extra features include the ability to register extra long probe readings
# as exemptions (accounting for exhibits or employees), and being able to count
# returning guests (who might leave for lunch and then return later in the day)
# as a new guest.

# PLEASE NOTE: This version depends on the client turning off power to the pi
# at the end of the work day. The pi will shut itself off 15 minutes after the
# designated close time (see pr_config.py), and will require a power cycle
# externally in order to boot up again. Once rebooted, the program will start
# automatically thanks to an external script (probescript) that is called via
# a service located in the pi's systemd folder.

# THIS VERSION DOES NOT ACCOUNT FOR LEAVING THE PI ON 24/7. THAT FEATURE IS
# STILL IN DEVELOPMENT.

# Original sniffer code thanks to Nik Harris
# nikharris.com/tracking-people
# https://github.com/nikharris0/probemon/

# database php code thanks to Eli Seifert - see sendToDB() for his code,
# and all database php code on external computer (not this program or pi) is his.

#!/usr/bin/python

import time
import datetime
import argparse
import netaddr
import sys
import logging
import os
import smtplib

import requests #for DB PHP call

from scapy.all import *
from pprint import pprint
from logging.handlers import RotatingFileHandler
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

#load in control variables from external file
from pr_config import (
        max_t,
        min_thresh,
        max_thresh,
        re_entry_thresh,
        open_time_h,
        open_time_m,
        close_time_h,
        close_time_m,
        power_off_toggle,
        sending_email,
        sending_pass,
        receiving_email,
        database_IP
)

MAX_TIME = max_t
MIN_THRESHOLD = min_thresh
MAX_THRESHOLD = max_thresh
RE_THRESHOLD = re_entry_thresh
POWER_OFF = power_off_toggle
EMAIL_FROM = sending_email
EMAIL_PASS = sending_pass
EMAIL_TO = receiving_email
DB_IP = database_IP


time.sleep(20) #give the program 20 seconds for wireless to connect

#boolean used to check to see if program should be reading probes
stopReading = False

NAME = 'probemon'
DESCRIPTION = "a command line tool for logging 802.11 probe request frames"

DEBUG = False

#time variable keeps track of when device is booted up
startTime = int(time.time())

#dictionary variable that will keep track of addresses and times
macDict = {}

#create exemptions file if it doesn't exist
exFile = open("/home/pi/Probemon/exemptions.txt","a")
exFile.close()

def build_packet_callback(time_fmt, logger, delimiter, mac_info, ssid, rssi):
        def packet_callback(packet):
                
                if not packet.haslayer(Dot11):
                        return

                # we are looking for management frames with a probe subtype
                # if neither match we are done here
                if packet.type != 0 or packet.subtype != 0x04:
                        return

                # list of output fields
                fields = []

                # determine preferred time format 
                log_time = str(int(time.time()))
                if time_fmt == 'iso':
                        log_time = datetime.datetime.now().isoformat()

                fields.append(log_time)

                # append the mac address itself
                #fields.append(packet.addr2)
                fields.append("MAC") #Changed for security

                # parse mac address and look up the organization from the vendor octets
                if mac_info:
                        try:
                                parsed_mac = netaddr.EUI(packet.addr2)
                                fields.append(parsed_mac.oui.registration().org)
                        #except netaddr.core.NotRegisteredError, e:
                        except netaddr.core.NotRegisteredError:
                                fields.append('UNKNOWN')

                # include the SSID in the probe frame
                if ssid:
                        #fields.append(packet.info)
                        fields.append('SSID')
                        
                if rssi:
                        rssi_val = -(256-ord(packet.notdecoded[-4:-3]))
                        #fields.append(str(rssi_val))
                        fields.append(str('RSSI'))


                #important variables:
                #log_time : the time of the ping in yyyy-mm-ddThh:mm:ss.ssssss format
                #packet.addr2 : the mac address information read from the ping

                #check to see what time it is. Take closing actions if closed, or opening action if open
                areWeOpenOrClosed()

                #put information from probe into dictionary if flag allows
                global stopReading
                if stopReading == False:
                        loadDictionary(log_time,packet.addr2)

                logger.info(delimiter.join(fields))

                #time variable keeps track of current time as an integer
                currentTime = int(time.time())

                #register local variable as global
                global startTime
                
                #if MAX_TIME amount of time has passed and flag allows, print to document
                if (currentTime - startTime >= MAX_TIME) and stopReading == False:
                        startTime = currentTime
                        printToDoc()
                        
        return packet_callback

#function converts a HH:MM:SS time format into seconds and returns them
def timeConverter(time):
        timeArray = time.split(":")
        hoursToSeconds = int(timeArray[0]) * 3600
        minutesToSeconds = int(timeArray[1]) * 60
        seconds = int(timeArray[2])
        totalSeconds = hoursToSeconds + minutesToSeconds + seconds

        return totalSeconds

#function converts iso time format (YYYY-MM-DDTHH:MM:SS.SSSSSS) to YYYYMMDD for file naming
def getDate():
        currentTime = datetime.datetime.now().isoformat()       #YYYY-MM-DDTHH:MM:SS.SSSSSS
        tempArray = currentTime.split("T")                      
        date = tempArray[0]                                     #YYYY-MM-DD
        dateArray = date.split("-")
        dateString = str(dateArray[0])+str(dateArray[1])+str(dateArray[2])

        return dateString

#function converts iso time format (YYYY-MM-DDTHH:MM:SS.SSSSSS) to [HH,MM] time array for time calculations
def getTime():
        currentTime = datetime.datetime.now().isoformat()       #YYYY-MM-DDTHH:MM:SS.SSSSSS
        tempArray = currentTime.split("T")
        time = tempArray[1]                                     #HH:MM:SS.SSSSSS
        hmsArray = time.split(".")
        hms = hmsArray[0]                                       #HH:MM:SS
        hmArray = hms.split(":")
        hours = hmArray[0]                                      #HH
        minutes = hmArray[1]                                    #MM
        timeArray = [ hours, minutes ]

        return timeArray

#function adds a specified key to exemption list
def addToExemptions(key):
        #boolean will flag to keep variable from being added 
        #if it is already on the exemption list. Starts as
        #TRUE and is changed if variable is found on list
        needsAdding = True
        
        exFile = open("/home/pi/Probemon/exemptions.txt","r")     #r = reading (default)-pointer starts at beginning of document
        for item in exFile:
                if key == item:                         #if exemption key is found,
                        needsAdding = False             #flag boolean,
                        break                           #then exit for loop,
        exFile.close()                                  #and close file stream

        #if the check for existing exemptions has not flagged false, add the key to the file
        if needsAdding == True:
                exFile = open("/home/pi/Probemon/exemptions.txt","a")           #reopen file stream in appending mode, so it starts at the end of the file
                exFile.write(key+"\n") #write key to end of document with a new line
                exFile.close() #then close the file stream

#function counts number of exemptions in exemption file
def getExemptions():
        exemptions = 0
        exFile = open("/home/pi/Probemon/exemptions.txt","r")
        for number in exFile:
                exemptions = exemptions + 1
        exFile.close()

        return exemptions
        
        

#function loads data into the dictionary.
#should be called whenever a scan is made
def loadDictionary(time, macAddr):
        #Dictonary reminder- KEY : VALUE
        #goal variable - macAddr: [t_in, t_out]
        
        keyUpdated = False; #boolean variable keeps track if a key has been updated

        #first, scan the dictionary for an existing mac address
        #(reminder: for statements iterate through keys here)
        for key in macDict:                             #iterate through mac address dictionary
                if macAddr == key:                      #if an incoming mac address matches an existing key...

                        time_array = time.split("T")
                        current_time = time_array[1]
                        current_time_array = time_array[1].split(".")
                        current_time_no_seconds = current_time_array[0]

                        mac_array = macDict[macAddr][1].split("T")
                        mac_time = mac_array[1]
                        mac_time_array = mac_array[1].split(".")
                        mac_time_no_seconds = mac_time_array[0]

# Re-entry Threshold Check
                        #if incoming time minus current time registered in dictionary
                        #is greater than or equal to the re_entry threshold...
                        if int(timeConverter(current_time_no_seconds)) - int(timeConverter(mac_time_no_seconds)) >= RE_THRESHOLD:
                                macDict[str(time)] = macDict[macAddr]   #create a new entry in the dictionary
                                                                        #using the current time as a key (this
                                                                        #ensures uniqueness) and copy original
                                                                        #values into it
                                del macDict[macAddr]    #delete dictionary entry for original entry
                                                        #original time survives as the new entry with time as key.
                                                        #program continues with keyUpdated flag set as false
                        else:   #otherwise, if threshold is within limit of new scan...
                                macDict[macAddr][1] = time      #set index 1 of macDict list value to new time
                                keyUpdated = True               #key updated, flag set to true
                        

        if keyUpdated == False:                 #if no key was updated, then it means a new mac address was detected
                macDict[macAddr] = [time, time] #create a new dict entry, with a 2 length list of time-
                                                #[time in, time out]. First entry has both times set as the same
        

#display start time in 24hr format - mostly for debugging purposes
curTime = getTime()
curHour = curTime[0]
curMin = curTime[1]
print("program started at:", curHour,":", curMin)

#function to print data from dictionary to document.
#This should be called at the end of the designated time period (i.e the end of the business day)
def printToDoc():
        
        print("Printing to document")
        #create a data stream to a file. File name is NS_YYYYMMDD.txt
        #NS means 'NOT SENT' and is an indicator that the file has not been sent to database/client yet.
        #Program will change the file name after successful sending (removing the NS_)
        #"w" parameter means that it will create a new file if none exists, or overwrite an existing file by that name
        textFile = open( "/home/pi/Probemon/logs/NS_"+str(getDate())+".txt", "w")
        
        
        guestNum = 1 #integer variable to keep track of guest numbers for writing to text file
        passerbyNum = 0 #integer keeps track of passerby (mac addresses that fall below minimum value needed)
        

        #write to text file from dictionary
        for key in macDict:
                #boolean flag for use of exemptions found
                keyIsExempt = False
                #split date data up for first index of list value of macDict key (time IN)
                tempArray_IN = macDict[key][0].split("T")
                date_IN = tempArray_IN[0]
                timeArray_IN = tempArray_IN[1].split(".")
                time_IN = timeArray_IN[0]
                #split date data up for second index of list value of macDict key (time OUT)
                tempArray_OUT = macDict[key][1].split("T")
                date_OUT = tempArray_OUT[0]
                timeArray_OUT = tempArray_OUT[1].split(".")
                time_OUT = timeArray_OUT[0]

                
                exFile = open("/home/pi/Probemon/exemptions.txt","r")     #r = reading (default)-pointer starts at beginning of document
                #check key against exepmtion list
                for item in exFile:
                        if key == item:                         #if exemption key is found,
                                keyIsExempt = True              #flag boolean,
                                break                           #exit for loop
                #close exemption file stream
                exFile.close()
                        
                #if key is not on exemption list, continue with operation
                if keyIsExempt == False:
                        #if time value is below minimum, it is not written to file
                        if int(timeConverter(time_OUT)) - int(timeConverter(time_IN)) <= MIN_THRESHOLD:
                                passerbyNum = passerbyNum + 1
                        #if time value is above maximum, add it to exemption list
                        elif int(timeConverter(time_OUT)) - int(timeConverter(time_IN)) >= MAX_THRESHOLD:
                                addToExemptions(key)    #attempt to add file to exemption list
                                
                        #if time value is within acceptable parameters, create string and write to file
                        else:
                                stringForFile = "GUEST"+str(guestNum).zfill(5)+","+str(date_OUT)+","+str(time_IN)+","+str(time_OUT)+"\n"
                                textFile.write(stringForFile)
                        
                guestNum = guestNum+1 #increment guestNum counter integer

        #debug statements print passerby and exemptions
        print("Passerby: ",passerbyNum)
        print("Exemptions: ",str(getExemptions())) 
        #close file stream
        textFile.close()

        #DEBUGGING - TESTING EMAIL SENDING CAPABILITY
        #switchMode('managed') #mode switching only needed for RPi2!
        #sendEmail()     #send email to client

        #DEBUGGING - TESTING DATABASE SEND CAPABILITY
        #switchMode('managed') #mode switching only needed for RPi2!
        #sendToDB(DB_IP) 



#function checks if it is at or past close time
def areWeOpenOrClosed():
        #convert closing time to HH:MM:SS to be run through converter function
        closing_time = str(close_time_h).zfill(2) + ':' + str(close_time_m).zfill(2) + ':00' 
        #convert closing time to seconds past midnight.
        close_time_in_seconds = timeConverter(closing_time)
        #convert opening time to HH:MM:SS to be run through converter function
        opening_time = str(open_time_h).zfill(2) + ':' + str(open_time_m).zfill(2) + ':00' 
        #convert closing time to seconds past midnight.
        open_time_in_seconds = timeConverter(opening_time)

        date_time = datetime.datetime.now().isoformat()
        time_array = date_time.split("T")
        current_time = time_array[1]
        current_time_array = time_array[1].split(".")
        current_time_no_seconds = current_time_array[0]
        
        #get current time in seconds
        current_time_in_seconds = timeConverter(current_time_no_seconds)

        #compare current time to open time.
        #If current time is 15 minutes or more past close time...
        if current_time_in_seconds - close_time_in_seconds >= 900:
                wereClosed()    #call closing function
        #if the current time is not past close, and the business is open...
        elif current_time_in_seconds >= open_time_in_seconds:
                wereOpen()    #call opening function

#function deals with what to do when the business opens.
#This function therefore assumes that the POWER_OFF reading is 1 and the business will NOT be
#shutting down the pi at the end of the day.
def wereOpen():
        global stopReading
        #set global tag to false if the business should be open
        if stopReading == True:
                stopReading = false


#function deals with what to do when the business closes.
#What function it performs is dependant on the POWER_OFF variable.
def wereClosed():
        global stopReading
        #switchMode('managed')   #mode switching only needed for RPi2!
        #sendEmail()     #send email to client directly
        sendToDB(DB_IP)  #send email to client via database
        
        #Turn off pi
        if POWER_OFF == 0:
                os.system("sudo poweroff")
        #if its time to close up and the pi does not need to turn itself off, reboot to refresh connection
        #CKM: This is for 24/7 setups
        elif POWER_OFF == 1:
                stopReading = True

#function sends an email to specified address, from a specified gmail address: both in config file.
#function also renames file; both removing the NS flag (to show that the file has been sent) and also
#renaming the file to CSV format for client use.
def sendEmail():
        print ("sending email...")
        #set variables from config file to local variables
        toEmail = EMAIL_TO
        fromEmail = EMAIL_FROM
        password = EMAIL_PASS

        #set up message fields
        msg = MIMEMultipart()
        msg['From'] = fromEmail
        msg['To'] = toEmail
        msg['Subject'] = ( 'Probemon report for: %s' %getDate() )
        body = 'Please see included attachment.'
        content = MIMEText(body,'plain')
        #attach message content
        msg.attach(content)

        #rename file, removing the NS to indicate that file has been sent
        oldNameWithPath = "/home/pi/Probemon/logs/NS_"+str(getDate())+".txt"
        newNameWithPath = "/home/pi/Probemon/logs/"+str(getDate())+".csv"       #rename .txt file to .csv
        osString = "sudo mv %s %s"  % (oldNameWithPath, newNameWithPath)        #rename old file to new file name
        fileName = str(getDate())+".csv"
        os.system(osString)

        #create attachment for email, using newly renamed file
        attachment = open(newNameWithPath, 'rb')

        #set up, encode, and then attach the attachment to the message
        part = MIMEBase('application','octet-stream')
        part.set_payload((attachment).read())
        encoders.encode_base64(part)
        part.add_header('Content-Disposition',"attachment; filename= %s" % fileName )
        msg.attach(part)

        #set up server details for sending email from
        #note that this is set up for using a gmail account with 'less secure apps' enabled as of May 2017
        server = smtplib.SMTP('smtp.gmail.com',587)
        server.starttls()
        server.login(fromEmail,password)
        text = msg.as_string()
        server.sendmail(fromEmail, toEmail, text)       #email is sent on this line
        server.quit()

        time.sleep(20)
        print("email sent!")
        
        
#function switches dongle between modes
#modes = monitor or managed
#current reason: to send email
def switchMode(mode):
        print("switching mode to %s" %mode)
        os.system("sudo ifconfig wlan1 down")
        time.sleep(20)   #pause execution of program for 20 seconds
        os.system("sudo iwconfig wlan1 mode %s" %mode)
        time.sleep(20)   
        os.system("sudo ifconfig wlan1 up")
        time.sleep(20)   
        print("mode switched!")

#function sends file to database via a PHP script call
def sendToDB(dBIP):

        print("sending to DB...")
        
        #specify absolute path for file to be sent to DB
        nameWithPath = "/home/pi/Probemon/logs/NS_"+str(getDate())+".txt"

        #open file for sending
        payload = {'datafile':open( nameWithPath, 'r')}
        
        #set up script call location
        dbAddress = ("http://%s/crct/crct.php" %dBIP)
        #make request
        r = requests.post( dbAddress, files=payload)
        print(r.text)
        #allow 20 seconds for data to send, if necessary
        time.sleep(20)

        #rename file, removing the NS to indicate that file has been sent
        oldNameWithPath = "/home/pi/Probemon/logs/NS_"+str(getDate())+".txt"
        newNameWithPath = "/home/pi/Probemon/logs/"+str(getDate())+".txt"       #rename .txt file. Note that this doesnt change extension!
        osString = "sudo mv %s %s"  % (oldNameWithPath, newNameWithPath)        #rename old file to new file name
        os.system(osString)
                
def main():
        parser = argparse.ArgumentParser(description=DESCRIPTION)
        parser.add_argument('-i', '--interface', default="wlan1", help="capture interface")
        parser.add_argument('-t', '--time', default='iso', help="output time format (unix, iso)")
        parser.add_argument('-o', '--output', default='/home/pi/Probemon/logs/allprobes.log', help="logging output location")
        parser.add_argument('-b', '--max-bytes', default=5000000, help="maximum log size in bytes before rotating")
        parser.add_argument('-c', '--max-backups', default=99999, help="maximum number of log files to keep")
        parser.add_argument('-d', '--delimiter', default='\t', help="output field delimiter")
        parser.add_argument('-f', '--mac-info', action='store_true', help="include MAC address manufacturer")
        parser.add_argument('-s', '--ssid', action='store_true', help="include probe SSID in output")
        parser.add_argument('-r', '--rssi', action='store_true', help="include rssi in output")
        parser.add_argument('-D', '--debug', action='store_true', help="enable debug output")
        parser.add_argument('-l', '--log', action='store_true', help="enable scrolling live view of the logfile")
        args = parser.parse_args()

        if not args.interface:
                print ("error: capture interface not given, try --help")
                sys.exit(-1)
        
        DEBUG = args.debug

        # setup our rotating logger
        logger = logging.getLogger(NAME)
        logger.setLevel(logging.INFO)
        
        handler = RotatingFileHandler(args.output, maxBytes=args.max_bytes, backupCount=args.max_backups)

        logger.addHandler(handler)
        
        if args.log:
                logger.addHandler(logging.StreamHandler(sys.stdout))
        built_packet_cb = build_packet_callback(args.time, logger, args.delimiter, args.mac_info, args.ssid, args.rssi)
        sniff(iface=args.interface, prn=built_packet_cb, store=0)

        
        

if __name__ == '__main__':
        main()
