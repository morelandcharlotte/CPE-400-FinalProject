# Name: Charlotte Moreland
# Class: CPE 400
# Assignment: Final Project Script
# Description: This script takes a pcap file as an argument and analyzes it for IP Addresses, DNS Lookups, and packet size. 
# Dictionaries were used for IP Addresses and DNS Queries so that it would be simpler to store and pull out data. Packet sizes
# were stored in a list. The analyzeNetworkTraffic funtion reads the pcap file for packets then iterates through them first for
# IP Addresses which are stored in itemCounts and then DNS Queries also stored in itemCounts. Packet sizes are appended in a list
# as they are iterated through. The IP Addresses and DNS Queries are plotted using the plotItemCounts function which uses the 
# matplotlib library to plot a bar graph, this is also done for packet sizes with the plotPacketSizes function which is histogram.
# Libraries used: Scapy, Matplotlib, argparse (standard library)

import scapy.all as scapy
import matplotlib.pyplot as plt
import argparse

def analyzeNetworkTraffic(pcapFile):

    # Dictionary to store counts for each item (IP address or DNS query) and
    # list for packet sizes
    itemCounts = {'ipAddresses': {}, 'dnsQueries': {}}
    packetSizes = []

    # Use the Scapy library to load the PCAP file
    packets = scapy.rdpcap(pcapFile)

    # For loop to analyze each packet in the capture
    for packet in packets:

        # Get source and destination IP addresses
        if "IP" in packet:
            srcIp = packet["IP"].src
            dstIp = packet["IP"].dst

            # increment count for source/destination IP
            itemCounts['ipAddresses'][srcIp] = itemCounts['ipAddresses'].get(srcIp, 0) + 1
            itemCounts['ipAddresses'][dstIp] = itemCounts['ipAddresses'].get(dstIp, 0) + 1

        # Check if the packet has a DNS layer
        if "DNS" in packet and packet["DNS"].qd:

            # If the packet has a DNS layer, add the DNS query to the dictionary
            # Convert the DNS Query to a string and maintain a count of how many unique queries show up
            for qname in packet["DNS"].qd:

                dnsQuery = str(qname.qname, 'utf-8')
                itemCounts['dnsQueries'][dnsQuery] = itemCounts['dnsQueries'].get(dnsQuery, 0) + 1

        # Track packet sizes
        packetSizes.append(len(packet))

    return itemCounts, packetSizes

def plotItemCounts(labels, dataName, counts, title, fileName):

    # Noticed the columns getting squished so this adjusts figure size based on the number of items
    if len(labels) > 10:
        figureSize = (15, 10)
    else:
        figureSize = (10, 6)

    # Plot bar chart with counts
    plt.figure(figsize=figureSize)
    plt.bar(range(len(labels)), counts, tick_label=labels)
    plt.xlabel(str(dataName))
    plt.ylabel('Count')
    plt.title(title)
    plt.xticks(rotation=90)  # Rotate x-labels vertically
    plt.tight_layout()  # So the the graph doesn't get squished
    plt.savefig(fileName) 
    plt.show()

def plotPacketSizes(packetSizes, fileName='packetSizesPlot.png'):

    # Plot histogram of packet sizes
    plt.figure(figsize=(10, 6))
    plt.hist(packetSizes, bins=50, color='blue', alpha=0.7)
    plt.xlabel('Packet Size (bytes)')
    plt.ylabel('Frequency')
    plt.title('Distribution of Packet Sizes in Network Traffic')
    plt.tight_layout()  # Adjust layout to prevent image getting squished
    plt.savefig(fileName) 
    plt.show()

def main():

    # Create argument parser and get CLI argument for the pcap file
    parser = argparse.ArgumentParser()
    parser.add_argument('pcapFile', type=str)
    args = parser.parse_args()

    # Analyze network traffic and plot counts for IP addresses and DNS queries
    itemCounts, packetSizes = analyzeNetworkTraffic(args.pcapFile)
    ipAddressesKeys = list(itemCounts['ipAddresses'].keys())
    ipAddressesVals = list(itemCounts['ipAddresses'].values())
    dnsKeys = list(itemCounts['dnsQueries'].keys())
    dnsVals = list(itemCounts['dnsQueries'].values())

    plotItemCounts(ipAddressesKeys, "IP Addresses", ipAddressesVals, 'IP Address Counts in Network Traffic', 'ipAddressCountsPlot.png')
    plotItemCounts(dnsKeys, "DNS Queries", dnsVals, 'DNS Lookups in Network Traffic', 'dnsQueryCountsPlot.png')
    plotPacketSizes(packetSizes, 'packetSizesPlot.png')

if __name__ == "__main__":
    main()

