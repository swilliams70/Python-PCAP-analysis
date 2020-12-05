from scapy.all import *
from prettytable import PrettyTable
from collections import Counter
import ipaddress


def main():
  #init key variable
  pkts = rdpcap("attack1.pcapng")
  whitelist = open("attack1_wl.txt", "r")
  whitelist = whitelist.read().splitlines()
  input_data = list()

  #Read and append
  dstIP=[]
  for pkt in pkts:
    if IP in pkt:
      #set variables from packet
      cmpip = pkt[IP].dst

      #create a network object from dstIP for comparison to whitelist
      dstIPnet = ipaddress.ip_network(cmpip)
      
      #send the whitelist and dstIPnet for comparison
      excluded = compare_networks(dstIPnet,whitelist)
      
      #if it's not in the whitelist, add dstIPto our list
      if excluded == False:
        try:
          dstIP.append(pkt[IP].dst)
        except:
          pass


  #Count
  cnt=Counter()
  for ip in dstIP:
    cnt[ip] += 1

  #Table and Print
  table= PrettyTable(["IP", "Count"])
  for ip, count in cnt.most_common():
    table.add_row([ip, count])
  print(table)

  #Add Lists
  xData=[]
  yData=[]

  for ip, count in cnt.most_common():
    xData.append(ip)
    yData.append(count)


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


if __name__ == "__main__":
  main()


  
