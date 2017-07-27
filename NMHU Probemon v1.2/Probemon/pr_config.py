# pr_config.py
# holds configuration settings for probemon program
# written by Colin Monroe,
# New Mexico Highlands University, SSD Program 2017

#max_time
# keeps track of maximum time frame to run program
# before saving to file from program dictionary
# number is in SECONDS
max_t = 3600     #3600 seconds = 1 hour

#FOR DEBUGGING
#max_t = 1800    #1800 seconds = 30 minutes
#max_t = 1200    #1200 seconds = 20 minutes
#max_t = 600     #600 seconds = 10 minutes
#max_t = 300     #300 seconds = 5 min
#max_t = 60

#min_threshold
# keeps track of minimum time frame to read pings
# any time frame of less than this time will be
# registered as a passerby and not counted
min_thresh = 900     #900 seconds = 15 minutes

#FOR DEBUGGING
#min_thresh = 300
#min_thresh = 120

#max_threshold
# keeps track of maximum threshold to read pings
# any time frame of more than this time will be
# registered as an exception and not counted
max_thresh = 25200   #25200 seconds = 7 hours

#re_entry_threshold
# keeps track of time frame that must elapse
# before a single mac is registered as a new visitor.
# pings detected after this threshold has passed will
# trigger a new visitor
re_entry_thresh = 5400  #5400 seconds = 1.5 hours

#open_time
# keeps track of opening time for business
# using h:m format (24 hour). Default is 9:00
open_time_h = 9     
open_time_m = 0

#close_time
# keeps track of closing time for business
# using h:m format (24 hour). Default is 17:00, or 5:00pm
close_time_h = 17
close_time_m = 0

#power_off_toggle
# determines if the pi will turn itself off after close
# 0 will make the pi turn itself off at a specified time.
# 1 will keep the pi on 24/7
power_off_toggle = 1

#send_toggle
# determines if the pi will send emails itself, or use a database
# to send data to a client
# 0 means the pi will not use a database
# 1 means the pi will use a database
send_toggle = 0

#EMAIL OPTIONS - USE IF send_toggle IS SET TO 0 #######################
#sending_email
# put email address to send emails FROM here
# please note that the program is set up for a GMAIL address.
# the account used must also enable 'less secure apps' from the google
# account settings page at myaccount.google.com/lesssecureapps
# default address is NMHUProbemon@gmail.com
sending_email = 'NMHUProbemon@gmail.com'

#sending_pass
# password for sending email's account goes here
sending_pass = 'raspberry'

#receiving_email
# put email address to send emails TO here
receiving_email = 'cmonroe1@live.nmhu.edu'
#######################################################################

#DATABASE OPTIONS - USE IF send_toggle IS SET TO 1 ####################
#database IP address
# put IP address here for database on local network
# IP will need to be statically set
database_IP = ''
#######################################################################
