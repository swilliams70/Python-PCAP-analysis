from scapy.all import *
import sys, getopt
import statistics
import matplotlib
import matplotlib.dates as mpd
#from matplotlib.dates import DateFormatter
import datetime, time
import pandas as pd
import ipaddress


def main(argv):

  pcapfile = ''
  whitelistfile = ''
  try:
    opts, args = getopt.getopt(argv,"hp:w:",["pfile=","wfile="])
  except getopt.GetoptError:
    print('pcap_analysis_parse.py -p <pcapfile> -o <whitelistfile>')
    sys.exit()
  for opt, arg in opts:
    if opt == '-h':
      print('pcap_analysis_parse.py -p <pcapfile> -w <whitelistfile>')
      sys.exit()
    elif opt in ("-p", "--pfile"):
      pcapfile = arg
    elif opt in ("-w", "--wfile"):
      whitelistfile = arg
  
  #init key variable
  pkts = rdpcap(pcapfile)
  whitelist = open(whitelistfile, "r")
  whitelist = whitelist.read().splitlines()
  input_data = list()


  #loop through each packet in pcap
  for pkt in pkts:
    #check for IP protocol
    if IP in pkt:
      #set variables from packet
      dstIP = pkt[IP].dst

      #set time from packet
      pktTime = int(pkt.time/1000)    #works with attack1.pcapng
      #pktTime = int(pkt.time)          #works with foo.pcap  
      
      #create a network object from dstIP for comparison to whitelist
      dstIPnet = ipaddress.ip_network(dstIP)
      
      #send the whitelist and dstIPnet for comparison
      excluded = compare_networks(dstIPnet,whitelist)
      
      #if it's not in the whitelist, add dstIP and pktTime to our list
      if excluded == False:
        try:
          input_data.append([dstIP, pktTime])
        except:
          pass
  #pass the data list and plot it
  plot_traffic(input_data)


def compare_networks(dstIPnet, whitelist):
  #loop through each network in whitelist
  for entry in whitelist: 
    #compare query network to whitelist entry
    excluded = ipaddress.ip_network(entry) 
    #return boolean, true if a match else false
    if dstIPnet.subnet_of(excluded) == True:
      return True
    else:
      pass
  return False

def plot_traffic(input_data):
  output = dict()
  count = 0
  list_of_things = []


  for i in range(0,len(input_data)):
      var_ip = input_data[i][0]
      var_dt = datetime.datetime.fromtimestamp(input_data[i][1])
      #var_dt = (input_data[i][1])
      #print(var_dt.strftime("%m-%d %H:%M:%S"))
      if var_ip not in output:
          output[var_ip]=count
          count += 1
      
      ip2int = output.get(var_ip)
      #data = ([var_dt.strftime("%H:%M:%S.%f"),var_ip,mpd.date2num(var_dt),ip2int])
      data = ([var_dt.strftime("%m-%d %H:%M:%S"),var_ip,mpd.date2num(var_dt),ip2int])
      list_of_things.append(data)

  df = pd.DataFrame(list_of_things,columns = list('DAXY'))
  ax = df.plot.scatter(x = 'X',y = 'Y',s = 1,figsize = (14,6))
  ax.set_xticklabels(df['D'])
  ax.set_yticklabels(df['A'])
  #ax.set_xticks(df['X'])
  ax.set_yticks(df['Y'])
  ax.set_xlabel('Time')
  ax.set_ylabel('Destination IP')

  #date_form = mpd.DateFormatter("%H:%M:%S.%f")
  #ax.xaxis.set_major_formatter(date_form)

  plt.show()

if __name__ == "__main__":
  main(sys.argv[1:])


  
