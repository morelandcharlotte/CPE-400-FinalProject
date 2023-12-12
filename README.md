# CPE-400-FinalProject

# Name: Charlotte Moreland
# Class: CPE 400
# Assignment: Final Project
# Description:
  This script takes a pcap file as an argument and analyzes it for IP Addresses, DNS Lookups, and packet size. 
  Dictionaries were used for IP Addresses and DNS Queries so that it would be simpler to store and pull out data. Packet sizes
  were stored in a list. The analyzeNetworkTraffic funtion reads the pcap file for packets then iterates through them first for
  IP Addresses which are stored in itemCounts and then DNS Queries also stored in itemCounts. Packet sizes are appended in a list
  as they are iterated through. The IP Addresses and DNS Queries are plotted using the plotItemCounts function which uses the 
  matplotlib library to plot a bar graph, this is also done for packet sizes with the plotPacketSizes function which is histogram.
  Libraries used: Scapy, Matplotlib, argparse (standard library)
