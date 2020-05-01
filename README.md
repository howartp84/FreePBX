![](https://raw.githubusercontent.com/Colorado4Wheeler/WikiDocs/master/FreePBX/freepbx-logo-250.png)

# FreePBX

This plugin for the [Indigo Domotics](http://www.indigodomo.com/) home automation platform that interacts with your [FreePBX](http://www.freepbx.org/) telephone system to allow you to control your PBX and extensions via Indigo.

## Requirements

You must install the RestAPI module from the FreePBX modules admin and enable the module for this plugin to work.  This has been tested on FreePBX version 13.  The API module is available on 14 and should work fine but may not on version 15.  Once I upgrade to 15 I'll add support for the new API structure added in that version.

This plugin requires Indigo 7 or greater.

## Basic Instructions

Once the RestAPI module is installed, open it to get the Token and Token Key, then create a PBX Server device in Indigo with this information and the IP address of your PBX.  Once complete you can create PBX Extension devices in Indigo for each extension you wish to control and use Indigo Actions to manipulate the extensions

## Supports

Currently this supports:

* Do Not Disturb (Enabling/disabling for any extension, showing status)
* Call Forwarding (Enabling/disabling for any extension, showing status)
* Call Waiting (Showing status)
* Call Flow - aka Day/Night ((Enabling/disabling any flow, showing status)
