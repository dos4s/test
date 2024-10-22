---
title: ISP Router Replacement
date: 2022-01-11
categories: [Networking]
tags: [ ppoe, router ]
author: dos4s
---

# ISP Router Replacement

## Introduction 
Most commercial ISPs provide low-budget routers with domestic internet subscriptions, offering limited features due to hardware or software constraints.
* What can’t you do with an ISP-provided router?
	-   Access via SSH, unless you hack it or convince the ISP to give you the credentials (which is unlikely).
	-     Assign a large number of static IP addresses; these routers typically have a limit on the number of entries.
	-     Create multiple ESSIDs (wireless networks).
	-     Customize the built-in Linux firewall (iptables).
	-     Subnet your network with multiple DHCP configurations.
	-     Add or configure advanced protocols beyond basic ones like UPnP, QoS, and SMB.
	-     Manage VLANs (Virtual Local Area Networks).
	-     Other features that may be restricted or undiscovered yet.

* What can you do with an ISP-provided router?

  -  Toast a sandwich! (In other words, not much in terms of advanced functionality.)

## ISP Network Topologies for regular customers

With that out of the way, let’s look at some typical ISP network topologies that you may find on home routers 

### CGNAT (Carrier-Grade NAT)

Some ISPs use CGNAT, which assigns private IP addresses to multiple customers' routers. This means your home network shares a public IP address with others, preventing you from doing anything that requires port forwarding or public IP access.

There are rumors that some ISPs will remove you from CGNAT if requested, but this isn’t always guaranteed.

### NEBA

Other ISPs, like those using the NEBA network architecture, provide unique PPPoE connections per customer. In this setup, each customer's router gets a unique public IP, allowing full control over port forwarding and other features.

However, this also exposes your router directly to the internet, which, if not configured properly, will increase the risk of getting compromised

Whatever service you have, you can always replace the stock router with a more capable one.

## Replacing the ISP Router

First, you’ll need to obtain your PPPoE credentials. The process varies depending on your ISP's topology (CGNAT, NEBA, etc.), but let’s start with how to extract those credentials.

### Obtaining PPPoE Credentials

The ISP-provided router stores PPPoE credentials and, shortly after booting, authenticates with the ISP's server by sending these credentials in plaintext.

To capture these credentials, one method is to perform a MITM (Man-in-the-Middle) attack by setting up port mirroring from the WAN port to a LAN port and capturing network traffic on a connected computer. However, many stock routers don't allow port mirroring, so this might not be an option.

An alternative method is setting up a rogue PPPoE server to trick the router into authenticating against it. By capturing the traffic during this process, the PPPoE credentials can be revealed in plaintext.

You can either do this manually or use this [script](https://github.com/rdaton/BAdpppoe), which automates the process to make it easier.

### Setting Up the New Router

Once you’ve obtained the credentials, it's time to set up the new router.

Access the router's management interface (usually via a web browser) and configure the WAN interface to use the PPPoE protocol. Input the credentials you extracted earlier.

### Troubleshooting

If the connection fails, the problem is likely due to VLAN settings. ISPs use specific VLAN IDs to separate different types of traffic (e.g., internet data, IPTV, VoIP) or to differentiate between ISPs.

You’ll need to know which VLAN IDs your ISP uses in order to configure the correct VLANs  on the WAN interface for successful PPPoE authentication. 


