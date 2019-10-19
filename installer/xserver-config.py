#!/usr/bin/env python
####################################################################################################
# @file xserver-config.py
#
# Perform configuration of X server.
#
# @author ayegorov@
# @author owner is alexg@
#
# Copyright (c) 1999-2016 Parallels International GmbH.
# All rights reserved.
# http://www.parallels.com
####################################################################################################

import os
import sys
import re
import shutil

####################################################################################################
# Implementation of X.Org server configuration function
####################################################################################################

# Definition of Parallels X server identifiers
prl_ids = {
	"mouse":     "Parallels Mouse",
	"video":     "Parallels Video",
	"monitor":   "Parallels Monitor",
	"screen":    "Parallels Screen",
}


# Definition of default Parallels mouse device
prl_ddevice = "/dev/input/mice"
prl_mdevice = ""

# Definition of default identifier for ServerFlags section
prl_dsfid = "DefaultFlags"

# Definition of default identifier for ServerLayout section
prl_dslid = "DefaultLayout"

# Definition of default input devices' atributes
prl_dmid  = "Void Mouse"
prl_dkid  = "Generic Keyboard"
# Void driver name will allow us to avoid unwanted mouse driver loading
# We can skip Generic Mouse InputDevice at all, but some old Linuxes (Fedora 8)
# very very want it.
prl_dmdrv = "void"
prl_dkdrv = "kbd"

# Default Depth line
prl_depth_line = '\t\tDepth\t24\n'

orig_default_screen_lines = []


# Returns true if Vt-d video card is present in guest system
def is_vtd_video_enabled():
	pci_devs_path = '/sys/bus/pci/devices'
	video_class = 0x30000 # display controller class
	prl_video_vendor_id = \
		[
			0xaaaa,	# old
			0x1ab8	# new
		]
	prl_video_dev_id = 0x4005

	pci_devs = os.listdir(pci_devs_path)
	for dev in pci_devs:
		class_file = os.path.join(pci_devs_path, dev, 'class')
		vendor_file = os.path.join(pci_devs_path, dev, 'vendor')
		device_file = os.path.join(pci_devs_path, dev, 'device')
		try:
			f = open(class_file, 'r')
			dev_class = f.read()
			f.close()

			f = open(vendor_file, 'r')
			dev_vendor = f.read()
			f.close()

			f = open(device_file, 'r')
			dev_id = f.read()
			f.close()

			dev_class = int(dev_class.strip(), 16)
			dev_vendor = int(dev_vendor.strip(), 16)
			dev_id = int(dev_id.strip(), 16)
		except:
			print('Error: cannot read info for device "%s"' % dev)
			return False
		if video_class == (dev_class & 0xFF0000) and \
				not (dev_vendor in prl_video_vendor_id and prl_video_dev_id == dev_id):
			# Videoadapter was found and it is not Parallels Video
			# so it is Vt-d video card
			return True
	return False

# Check... is this Parallels' section
def is_prl_section(name):
	for key in prl_ids.keys():
		if re.compile("\s*%s\s*" % prl_ids[key], re.IGNORECASE).match(name):
			return True
	return False


# Add Display subsection
def add_display_subsection(sextra):
	sextra.append("\tSubSection\t\"Display\"\n")
	sextra.append(prl_depth_line)
	sextra.append("\t\tModes\t\"1024x768\" \"800x600\" \"640x480\"\n")
	sextra.append("\tEndSubSection\n")

# Add default Display modes
def add_display_modes(sextra):
	ret = []
	for line in sextra:
		if line.find("EndSubSection") != -1:
			ret.append("\t\tModes\t\"1024x768\" \"800x600\" \"640x480\"\n")
		ret.append(line)
	return ret

# Print out Parallels' section
def print_prl_section(fout, sname, key, sextra = []):

	global prl_mdevice
	global prl_ddevice

	fout.write("\n# %s section\n" % prl_ids[key])
	fout.write("Section \"%s\"\n" % sname)
	fout.write("\tIdentifier\t\"%s\"\n" % prl_ids[key])

	# Print out section specific information
	if key == "mouse":
		if prl_mdevice == "":
			prl_mdevice = prl_ddevice
		fout.write("\tDriver\t\"prlmouse\"\n")
		fout.write("\tOption\t\"Device\"\t\"%s\"\n" % prl_mdevice)
		fout.write("\tOption\t\"Protocol\"\t\"auto\"\n")
	elif key == "video":
		fout.write("\tDriver\t\"prlvideo\"\n")
	elif key == "monitor":
		fout.write("\tVendorName\t\"Parallels Inc.\"\n")
		fout.write("\tModelName\t\"%s\"\n" % prl_ids["monitor"])
	elif key == "screen":
		fout.write("\tDevice\t\"%s\"\n" % prl_ids["video"])
		fout.write("\tMonitor\t\"%s\"\n" % prl_ids["monitor"])
		fout.write("\tOption\t\"NoMTRR\"\n")

	# Print out extra section information
	for line in sextra:
		fout.write(line)

	fout.write("EndSection\n")


# Print out extra sections
def print_extra_section(fout, sname, idname, sextra = [], add_aei = False):

	fout.write("\n# %s section\n" % idname)
	fout.write("Section \"%s\"\n" % sname)

	lsname = sname.lower()

	# Print out section specific information
	if lsname == "serverlayout":
		fout.write("\tIdentifier\t\"%s\"\n" % idname)
		if is_vtd_video_enabled():
			fout.write("\t#Screen\t\"%s\"\n" % prl_ids["screen"])
			for line in orig_default_screen_lines:
				fout.write("%s\n" % line)
		else:
			fout.write("\tScreen\t\"%s\"\n" % prl_ids["screen"])
	elif lsname == "inputdevice":
		if idname == prl_dmid:
			fout.write("\tIdentifier\t\"%s\"\n" % prl_dmid)
			fout.write("\tDriver\t\"%s\"\n" % prl_dmdrv)
		elif idname == prl_dkid:
			fout.write("\tIdentifier\t\"%s\"\n" % prl_dkid)
			fout.write("\tDriver\t\"%s\"\n" % prl_dkdrv)
			fout.write("\tOption\t\"XkbModel\"\t\"pc105\"\n")
			fout.write("\tOption\t\"XkbLayout\"\t\"us\"\n")
			fout.write("\tOption\t\"XkbOptions\"\t\"grp:alt_shift_toggle\"\n")
	elif lsname == "serverflags" and add_aei:
		fout.write("\tOption\t\"AllowEmptyInput\"\t\"yes\"\n")
		fout.write("\tOption\t\"AutoAddDevices\"\t\"yes\"\n")

	# Print out extra section information
	for line in sextra:
		fout.write(line)

	fout.write("EndSection\n")


def configure_xorg(xtype, xversion, fin, fout):

	global prl_mdevice
	global prl_ddevice
	global orig_default_screen_lines

	add_aei = False # flag showing if we need to add AllowEmpyInput option
	add_voidmouse = False
	add_inputdevices = True
	xversion = xversion.split('.')
	if len(xversion) < 3:
		xversion += ['0', '0']
	xver_maj = int(xversion[0])
	xver_min = int(xversion[1])
	xver_patch = int(xversion[2])

	if xver_maj >= 6:
	# Must discount major version,
	# because XOrg changes versioning logic since 7.3 (7.3 -> 1.3)
		xver_maj = xver_maj - 6
	xversion_int = xver_maj * 1000000 + xver_min * 1000 + xver_patch

	if xversion_int >= 1004000:
	# Starting from XServer 1.4 we are must configure udev,
	# to properly init input devices, in this purposes we will add
	# AllowEmpyInput/AutoAddDevices option for xserver
		add_aei = True

	if xversion_int < 1004000:
	# For older XServer's, must add stub mouse section, to disable
	# loading of standard mouse_drv driver
		add_voidmouse = True

	if xversion_int >= 1010000:
	# For new XServer's releases we drop old style InputDevices configuration entries
	# and will use udev only
		add_inputdevices = False

	re_section_start = re.compile("\s*Section\s*\"(\w+)\".*$", re.IGNORECASE)
	re_section_end = re.compile("\s*EndSection\s*.*$", re.IGNORECASE)

	re_id_name = re.compile("\s*Identifier\s*\"([^\"]+)\".*$", re.IGNORECASE)
	re_device_name = re.compile("\s*Device\s*\"([^\"]+)\".*$", re.IGNORECASE)
	re_monitor_name = re.compile("\s*Monitor\s*\"([^\"]+)\".*$", re.IGNORECASE)
	re_screen_name = re.compile("\s*Screen\s*[?0-9]*\s*\"([^\"]+)\".*$", re.IGNORECASE)
	re_idevice_name = re.compile("\s*InputDevice\s*\"([^\"]+)\".*$", re.IGNORECASE)
	re_device_name = re.compile("\s*Option\s*\"Device\"\s*\"([^\"]+)\".*$", re.IGNORECASE)
	re_driver_name = re.compile("\s*Driver\s*\"([^\"]+)\".*$", re.IGNORECASE)
	re_core_pointer = re.compile("\s*Option\s*\"CorePointer\".*$", re.IGNORECASE)
	re_send_core_events = re.compile("\s*Option\s*\"SendCoreEvents\".*$", re.IGNORECASE)

	re_kbd = re.compile(".*(keyboard|kbd).*", re.IGNORECASE)

	print("Generating X.Org server configuration file (version %d)" % xversion_int)

	# Add header
	fout.write("#\n")
	fout.write("# X.Org server configuration file generated by Parallels Guest Tools.\n")
	fout.write("#\n")

	################################################################################################
	# Read input configuration line-by-line and generate X.Org configuration file for
	# Parallels Guest Tools.
	################################################################################################

	# Comment whole section
	def comment_section(f, s):
		for l in s:
			f.write("# %s" % l)

	# Print out whole section
	def print_section(f, s):
		for l in s:
			f.write(l)

	ssection = {}
	mname = []
	iname = []

	is_section = False
	section = []
	idname = ""
	sname = ""

	is_video   = False
	is_monitor = False
	is_screen  = False

	if fin:

		for line in fin.readlines():

			if is_section:
				####################################################################################
				# Parse section
				####################################################################################

				# Add section's line into array
				section.append(line)

				if not re_section_end.match(line):
					if re_id_name.match(line):
						idname = re_id_name.findall(line)[0]
					continue

				if not is_prl_section(idname):

					# Lower-case version of section name
					lsname = sname.lower()

					if lsname == "inputdevice" or lsname == "pointer":
						############################################################################
						# Parse InputDevice or Pointer section
						############################################################################

						comment_section(fout, section)

					elif lsname == "device":
						############################################################################
						# Parse Device section
						############################################################################

						print_section(fout, section)

						if not is_video:
							is_video = True
							print_prl_section(fout, sname, "video")

					elif lsname == "monitor":
						############################################################################
						# Parse Monitor section
						############################################################################

						print_section(fout, section)

						if not is_monitor:
							is_monitor = True
							print_prl_section(fout, sname, "monitor")

					elif lsname == "screen":
						############################################################################
						# Parse Screen section
						############################################################################

						print_section(fout, section)

						esection = []

						if not is_screen:

							re_defdepth = re.compile("\s*DefaultDepth\s*[0-9]+\s*.*$", re.IGNORECASE)
							re_depth = re.compile("\s*Depth\s*[0-9]+\s*.*$", re.IGNORECASE)
							re_display_start = re.compile("\s*SubSection\s*\"Display\".*$", re.IGNORECASE)
							re_modes_option = re.compile("\s*Modes.*(\d*x\d*|default)", re.IGNORECASE)
							re_display_end = re.compile("\s*EndSubSection\s*.*$", re.IGNORECASE)

							is_section = False
							is_modes_option = False
							is_display_section = False

							# Add extra lines into section
							for line in section:
								if is_section:
									if not re_modes_option.match(line) and \
										not re_depth.match(line):
										esection.append(line)
									if re_display_end.match(line):
										is_section = False
								elif re_display_start.match(line):
									esection.append(line)
									# Depth for our display must be 24 only.
									# Original settings will be dropped.
									esection.append(prl_depth_line)
									is_section = True
									is_display_section = True
								elif re_defdepth.match(line):
									esection.append(line)
								elif re_modes_option.match(line):
									is_modes_option = True
								else:
									continue

							if not is_display_section:
								add_display_subsection(esection)
							elif not is_modes_option:
								esection = add_display_modes(esection)

							is_screen = True
							print_prl_section(fout, sname, "screen", esection)

					elif lsname == "serverlayout":
						############################################################################
						# Parse ServerLayout section
						############################################################################

						comment_section(fout, section)

					else:
						############################################################################
						# Print out whole section as it is
						############################################################################

						print_section(fout, section)

				else:
					################################################################################
					# Comment whole section due to ID conflict
					################################################################################

					print("\"%s\" ID conflict - commented" % idname)

					comment_section(fout, section)

				is_section = False
				section = []
				idname = ""
				sname = ""

			elif re_section_start.match(line):
				####################################################################################
				# Detect section
				####################################################################################

				# Start adding of section's lines into array
				section = [line]
				is_section = True

				# Set section name
				sname = re_section_start.findall(line)[0]

			else:
				####################################################################################
				# Print out line as it is
				####################################################################################

				fout.write(line)

	################################################################################################
	# Check... are all required sections printed out
	################################################################################################

	# Generic Keyboard
	if add_inputdevices:
		mname.append(prl_dkid)
		print_extra_section(fout, "InputDevice", prl_dkid)

	# Void Mouse
	if add_voidmouse:
		mname.append(prl_dmid)
		print_extra_section(fout, "InputDevice", prl_dmid)

	# Parallels Mouse
	if add_inputdevices:
		mname.append(prl_ids["mouse"])
		print_prl_section(fout, "InputDevice", "mouse")

	if not is_video:
		print_prl_section(fout, "Device", "video")

	if not is_monitor:
		print_prl_section(fout, "Monitor", "monitor")

	if not is_screen:
		section = []
		add_display_subsection(section)
		print_prl_section(fout, "Screen", "screen", section)

	################################################################################################
	# Print out "ServerFlags" section
	################################################################################################

	print_extra_section(fout, "ServerFlags", prl_dsfid, add_aei = add_aei)

	################################################################################################
	# Print out "ServerLayout" section
	################################################################################################

	print("Add the following InputDevice into ServerLayout section")

	section = []
	for m in mname:
		is_section = False
		for i in iname:
			if i == m:
				# Input device is already in section
				is_section = True
				break
		if not is_section:
			# Add InputDevice into ServerLayout section
			print("+ \"%s\"" % m)
			if re_kbd.match(m):
				section.append("\tInputDevice\t\"%s\"\t\"CoreKeyboard\"\n" % m)
			elif prl_ids["mouse"] == m:
				section.append("\tInputDevice\t\"%s\"\t\"CorePointer\"\n" % m)
			else:
				section.append("\tInputDevice\t\"%s\"\n" % m)

	# Print out ServerLayout section
	print_extra_section(fout, "ServerLayout", prl_dslid, section)

	################################################################################################
	# X.Org server is configured now
	################################################################################################

	print("X.Org server was configured")

	return True

####################################################################################################
# Implementation of XFree86 server configuration function
####################################################################################################

def configure_xfree(xtype, xversion, fin, fout):

	print("Error: XFree86 server is not supported now")

	return False

####################################################################################################
# Default X server configuration routine
####################################################################################################

def configure_invalid(xtype, xversion, fin, fout):

	print("Error: invalid X server [%s] type" % xtype)

	return False

####################################################################################################
# Perform configuration of X server
####################################################################################################

# Dictionary of X server configuration routines for all supported server types
configure = {
	# X.Org server
	"xorg": configure_xorg,

	# XFree86 server
	"xfree": configure_xfree,
}

def main():

	################################################################################################
	# Check number of input parameters
	################################################################################################

	n = len(sys.argv)

	if n != 5:
		print("Error: wrong number [%d] of input parameters" % n)
		print("Usage:")
		print("       %s <X server type> <X server version> <Original X config file> <New X config file>" % sys.argv[0])
		return False

	################################################################################################
	# Configure X server
	################################################################################################

	fin = None
	fout = None

	# Open input and output configuration files
	if sys.argv[3] != "":
		fin = open(sys.argv[3])
	fout = open(sys.argv[4], "w")

	xtype = sys.argv[1]
	xversion = sys.argv[2]

	print('Configuring X server (%s, %s)' % (xtype, xversion))

	status = False
	# Use 'configure_invalid' function as default action
	status = configure.get(xtype, configure_invalid)(xtype, xversion, fin, fout)

	if fin:
		fin.close()

	if fout:
		fout.close()

	################################################################################################
	# Check X server configuration status
	################################################################################################

	if status:
		print("Configuring of X server was finished successfully")
	else:
		print("Error: configuring of X server failed")

	return status


if __name__ == "__main__":

	if not main():
		sys.exit(1)

	sys.exit(0)
