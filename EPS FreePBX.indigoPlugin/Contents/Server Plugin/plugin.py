#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""plugin.py: FreePBX Plugin."""

__version__ 	= "1.0.0-b1"

__modname__		= "Indigo FreePBX"
__author__ 		= "ColoradoFourWheeler"
__copyright__ 	= "Copyright 2018, ColoradoFourWheeler & EPS"
__credits__ 	= ["ColoradoFourWheeler"]
__license__ 	= "GPL"
__maintainer__ 	= "ColoradoFourWheeler"
__email__ 		= "Indigo Forums"
__status__ 		= "Production"

# Python Modules
import logging
import sys
import os
import hashlib
import hmac
from random import randint
import requests
from requests.auth import HTTPBasicAuth
from requests.auth import HTTPDigestAuth
import json
import base64
import thread
import time

# Third Party Modules
import indigo

# Package Modules
from lib.eps import ex
from lib.eps import version

class Plugin(indigo.PluginBase):

	################################################################################
	# CLASS HANDLERS
	################################################################################

	###
	def __init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs):
		indigo.PluginBase.__init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs)
		self.EXT_TIMERS = []

	###
	def __del__(self):
		indigo.PluginBase.__del__(self)


	###
	def deviceStartComm (self, dev):
		self.debugLog(u"device start comm called")
		dev.stateListOrDisplayStateIdChanged() # Commit any state changes

		#self.dnd_status(dev)
		#if dev.deviceTypeId == 'Extension': self.dnd_on(dev)

		if dev.deviceTypeId == 'Server':
			#self.get_server_extensions(dev)
			self.update_address(dev) # Update address

			if not str(dev.id) in self.EXT_TIMERS:
				thread.start_new_thread (self.timer_update_extension_status, (dev.id,))
				self.EXT_TIMERS.append(str(dev.id))

		elif dev.deviceTypeId == 'Extension':
			#self.timer_update_extension_status()
			pass


	###
	def actionControlDimmerRelay (self, action, dev):
		try:
			if dev.deviceTypeId == 'CallFlow': return self.device_control_flow (action, dev)

		except Exception as e:
			self.logger.error (ex.stack_trace(e))

	###
	def startup(self):
		self.debugLog(u"startup called")

		#server = indigo.devices[1644005444] # "PBX - House"
		for s in indigo.devices.iter("self.Server"):
			server = s #Assuming there's only one server, pick it

		try:
			#result = self.invoke_api(server, 'timeconditions', '2', '', '')
			result = self.invoke_api(server, 'findmefollow', '101', '')
			if result:
				indigo.server.log(unicode(result))
		except UnboundLocalError:
			self.errorLog("Please create a FreePBX Server device then restart the plugin")

	###
	def shutdown(self):
		self.debugLog(u"shutdown called")

	###
	def runConcurrentThread(self):
		try:
			while True:
					#self.processTimer()
					self.sleep(1)
		except self.StopThread:
			pass


	################################################################################
	# EXTENSION FORM
	################################################################################

	###
	def list_extensions (self, filter="", valuesDict=None, typeId="", targetId=0):
		"""
		Return a custom list of extensions - will not include extensions that don't have a userman account so it may be incomplete.
		"""

		try:
			listData = [("default", "No data")]
			if not 'server' in valuesDict: return listData
			if valuesDict['server'] == '': return listData

			server = indigo.devices[int(valuesDict['server'])]
			result = self.invoke_api(server, 'userman', '', '', 'extensions')
			if result:
				listData = []
				for extension_num, userman in result.iteritems():
					listData.append ((extension_num, extension_num))

		except Exception as e:
			self.logger.error (ex.stack_trace(e))

		return listData

	################################################################################
	# CALL FLOW / DAY NIGHT
	################################################################################

	###
	def device_control_flow (self, action, dev):
		try:
			keyValueList = []

			dev = indigo.devices[action.deviceId]
			server = int(dev.pluginProps["server"])
			if not server in indigo.devices:
				self.logger.error (u"PBX Server {} is not in the Indigo device list, was it removed?  {} action cannot complete".format(server, dev.name))
				return

			server = indigo.devices[server]
			params = {}

			forceState = ''

			if action.deviceAction == indigo.kDimmerRelayAction.Toggle:
				if dev.onState:
					forceState = 'off'
				else:
					forceState = 'on'

			if action.deviceAction == indigo.kDimmerRelayAction.TurnOn or forceState == 'on':
				params["state"] = 'NIGHT'
				keyValueList.append({'key':'onOff_State', 'value':True})
			elif action.deviceAction == indigo.kDimmerRelayAction.TurnOff or forceState == 'off':
				params["state"] = 'DAY'
				keyValueList.append({'key':'onOff_State', 'value':False})
			elif unicode(action.deviceAction) == u'RequestStatus':
				self.update_call_flow_status (dev)
				return
			else:
				indigo.server.error (u'Unknown Call Flow action {}'.format(action.deviceAction))
				return

			result = self.invoke_api(server, 'daynight', dev.pluginProps['callflow'], json.dumps(params), '')

			self.update_call_flow_status (dev)

			if keyValueList: dev.updateStatesOnServer(keyValueList)

		except Exception as e:
			self.logger.error (ex.stack_trace(e))

	###
	def update_call_flow_status (self, dev):
		try:
			keyValueList = []

			server = int(dev.pluginProps["server"])
			if not server in indigo.devices:
				self.logger.error (u"PBX Server {} is not in the Indigo device list, was it removed?  {} action cannot complete".format(server, dev.name))
				return

			result = self.invoke_api(indigo.devices[server], 'daynight', dev.pluginProps['callflow'], '', '')
			if result:
				#indigo.server.log(unicode(result))

				if result['state'] == 'DAY':
					keyValueList.append({'key':'onOff_State', 'value':False, 'uiValue':'DAY'})
					dev.updateStateImageOnServer(indigo.kStateImageSel.TimerOff)
				else:
					keyValueList.append({'key':'onOff_State', 'value':True, 'uiValue':'NIGHT'})
					dev.updateStateImageOnServer(indigo.kStateImageSel.TimerOn)

			if keyValueList: dev.updateStatesOnServer(keyValueList)

			self.update_address (dev)

		except Exception as e:
			self.logger.error (ex.stack_trace(e))

	###
	def list_call_flows (self, filter="", valuesDict=None, typeId="", targetId=0):
		"""
		Build a custom list based on the information in the filter field.
		"""

		try:
			listData = [("default", "No data")]
			if not 'server' in valuesDict: return listData
			if valuesDict['server'] == '': return listData

			server = indigo.devices[int(valuesDict['server'])]
			result = self.invoke_api(server, 'daynight', '', '', '')
			if result:
				listData = []
				for r in result:
					listData.append ((r['ext'], r['dest']))

		except Exception as e:
			self.logger.error (ex.stack_trace(e))

		return listData

	###
	def device_field_changed (self, valuesDict, typeId, devId):
		"""
		Callback method invoked on device forms, primary method.
		"""

		try:
			errorsDict = indigo.Dict()

		except Exception as e:
			self.logger.error (ex.stack_trace(e))

		return (valuesDict, errorsDict)

	################################################################################
	# MISC
	################################################################################

	###
	def timer_update_extension_status (self, serverId):
		try:
			delay = int(indigo.devices[serverId].pluginProps['frequency'])

			while True:
				for dev in indigo.devices.iter(self.pluginId):
					if dev.deviceTypeId == 'Extension' and dev.pluginProps['server'] == str(serverId):
						self.update_extension_status (dev)

					elif dev.deviceTypeId == 'CallFlow':
						self.update_call_flow_status (dev)

				time.sleep(delay)
				#self.timer_update_extension_status()

		except self.StopThread:
			pass

		except Exception as e:
			self.logger.error (ex.stack_trace(e))


	###
	def update_extension_status (self, dev):
		try:
			keyValueList = []

			result = self.get_status(dev, 'callforward')
			if result:
				#indigo.server.log(unicode(result))

				if not result['CF']:
					keyValueList.append({'key':'cfunconditional', 'value':'disabled'})
					keyValueList.append({'key':'cfunconditionalNumber', 'value':''})
				else:
					keyValueList.append({'key':'cfunconditional', 'value':'enabled'})
					keyValueList.append({'key':'cfunconditionalNumber', 'value':result['CF']})

				if not result['CFB']:
					keyValueList.append({'key':'cfbusy', 'value':'disabled'})
					keyValueList.append({'key':'cfbusyNumber', 'value':''})
				else:
					keyValueList.append({'key':'cfbusy', 'value':'enabled'})
					keyValueList.append({'key':'cfbusyNumber', 'value':result['CFB']})

				if not result['CFU']:
					keyValueList.append({'key':'cfunavailable', 'value':'disabled'})
					keyValueList.append({'key':'cfunavailableNumber', 'value':''})
				else:
					keyValueList.append({'key':'cfunavailable', 'value':'enabled'})
					keyValueList.append({'key':'cfunavailableNumber', 'value':result['CFU']})

			result = self.get_status(dev, 'donotdisturb')
			if result:
				#indigo.server.log(unicode(result))

				if result["status"] == "enabled" or result["status"] == "YES": # YES when this is turned on via a phone
					keyValueList.append({'key':'dnd', 'value':'enabled'})
				else:
					keyValueList.append({'key':'dnd', 'value':'disabled'})


			result = self.get_status(dev, 'callwaiting')
			if result:
				#indigo.server.log(unicode(result))

				if result[0] == "ENABLED":
					keyValueList.append({'key':'callwaiting', 'value':'enabled'})
				else:
					keyValueList.append({'key':'callwaiting', 'value':'disabled'})


			if keyValueList: dev.updateStatesOnServer(keyValueList)

			self.update_address (dev)

		except Exception as e:
			self.logger.error (ex.stack_trace(e))

	###
	def update_address (self, dev):
		try:
			if dev.deviceTypeId == 'Server':
				props = dev.pluginProps
				props['address'] = props['ipaddress']
				dev.replacePluginPropsOnServer (props)

			if dev.deviceTypeId == 'CallFlow':
				server = int(dev.pluginProps["server"])
				if not server in indigo.devices:
					self.logger.error (u"PBX Server {} is not in the Indigo device list, was it removed?  {} action cannot complete".format(server, dev.name))
					return
				server = indigo.devices[server]

				props = dev.pluginProps
				props['address'] = server.name
				dev.replacePluginPropsOnServer (props)

			if dev.deviceTypeId == 'Extension':
				server = int(dev.pluginProps["server"])
				if not server in indigo.devices:
					self.logger.error (u"PBX Server {} is not in the Indigo device list, was it removed?  {} action cannot complete".format(server, dev.name))
					return
				server = indigo.devices[server]

				props = dev.pluginProps

				if props['method'] == 'ext':
					props['address'] = u'Ext {} on {}'.format(props['extension'], server.name)

				elif props['method'] == 'status':
					props['address'] = self.update_address_status(dev)

				elif props['method'] == 'fwd':
					status = self.update_address_status(dev)
					if 'CF ' in status:
						status = u'CF to {}'.format(dev.states['cfunconditionalNumber'])
					elif 'CFU ' in status:
						status = u'CFU to {}'.format(dev.states['cfunavailableNumber'])
					elif 'CFB ' in status:
						status = u'CFB to {}'.format(dev.states['cfbusyNumber'])

					props['address'] = status

				dev.replacePluginPropsOnServer (props)

				self.update_state (dev)

		except Exception as e:
			self.logger.error (ex.stack_trace(e))

	###
	def update_state (self, dev):
		try:
			status = self.update_address_status(dev)
			keyValueList = []
			onOff_State = True # Assume on until decided otherwise

			# Only analyze conditions that will set the onstate to off
			if dev.pluginProps['ison'] == 'notready' and status == 'Ready':
				onOff_State = False
			elif dev.pluginProps['ison'] == 'ready' and status != 'Ready':
				onOff_State = False
			elif dev.pluginProps['ison'] == 'dnd' and 'DND ' not in status:
				onOff_State = False
			elif dev.pluginProps['ison'] == 'notdnd' and 'DND ' in status:
				onOff_State = False
			elif dev.pluginProps['ison'] == 'cf' and 'CF ' not in status:
				onOff_State = False
			elif dev.pluginProps['ison'] == 'notcf' and 'CF ' in status:
				onOff_State = False
			elif dev.pluginProps['ison'] == 'cfu' and 'CFU ' not in status:
				onOff_State = False
			elif dev.pluginProps['ison'] == 'notcfu' and 'CFU ' in status:
				onOff_State = False
			elif dev.pluginProps['ison'] == 'cfb' and 'CFB ' not in status:
				onOff_State = False
			elif dev.pluginProps['ison'] == 'notcfb' and 'CFB ' in status:
				onOff_State = False

			keyValueList.append({'key':'onOff_State', 'value':onOff_State})
			dev.updateStatesOnServer(keyValueList)

		except Exception as e:
			self.logger.error (ex.stack_trace(e))

	###
	def update_address_status (self, dev):
		"""
		Determine the phone status and return it.
		"""

		try:
			status = ''

			if dev.states['dnd.enabled']: status += 'DND '
			if dev.states['cfunconditional.enabled']: status += 'CF '
			if dev.states['cfbusy.enabled']: status += 'CFB '
			if dev.states['cfunavailable.enabled']: status += 'CFU '

			if status == '': status = 'Ready'

			return status

		except Exception as e:
			self.logger.error (ex.stack_trace(e))



	################################################################################
	# ACTIONS
	################################################################################

	###
	def action_cf (self, action):
		try:
			method = 'callforward'

			dev = indigo.devices[action.deviceId]
			server = int(dev.pluginProps["server"])
			if not server in indigo.devices:
				self.logger.error (u"PBX Server {} is not in the Indigo device list, was it removed?  {} action cannot complete".format(server, dev.name))
				return

			server = indigo.devices[server]
			params = {}

			if action.pluginTypeId == 'callForwarding':
				if action.props['cfenabled']: params['CF'] = int(action.props['cfnumber'])
				if action.props['cfuenabled']: params['CFU'] = int(action.props['cfunumber'])
				if action.props['cfuenabled']: params['CFB'] = int(action.props['cfbnumber'])
			elif action.pluginTypeId == 'cfDisableAll':
				params['CF'] = False
				params['CFB'] = False
				params['CFU'] = False
			elif action.pluginTypeId == 'cfDisableUC':
				params['CF'] = False
			elif action.pluginTypeId == 'cfDisableBusy':
				params['CFB'] = False
			elif action.pluginTypeId == 'cfDisableUA':
				params['CFU'] = False

			#indigo.server.log(unicode(json.dumps(params)))

			result = self.invoke_api(server, method, dev.pluginProps["extension"], json.dumps(params))

			self.update_extension_status (dev)

		except Exception as e:
			self.logger.error (ex.stack_trace(e))

	###
	def action_dnd (self, action):
		try:
			method = 'donotdisturb'

			dev = indigo.devices[action.deviceId]
			server = int(dev.pluginProps["server"])
			if not server in indigo.devices:
				self.logger.error (u"PBX Server {} is not in the Indigo device list, was it removed?  {} action cannot complete".format(server, dev.name))
				return

			server = indigo.devices[server]
			params = {}

			if action.pluginTypeId == 'dndEnable':
				params["status"] = 'enabled'
			else:
				params["status"] = False

			result = self.invoke_api(server, method, dev.pluginProps["extension"], json.dumps(params))

			self.update_extension_status (dev)

		except Exception as e:
			self.logger.error (ex.stack_trace(e))


	################################################################################
	# API
	################################################################################

	###
	def get_server_extensions (self, dev):
		try:
			method = 'userman'
			params = {}

			extensions = self.invoke_api(dev, method)
			for e in extensions:
				for field, info in e.iteritems():
					indigo.server.log(unicode(u"{}: {}".format(field, info)))

		except Exception as e:
			self.logger.error (ex.stack_trace(e))

	###
	def get_status (self, dev, method):
		try:
			if dev.deviceTypeId == 'Server':
				result = self.invoke_api(dev, method)

			elif dev.deviceTypeId == 'Extension':
				server = int(dev.pluginProps["server"])
				if not server in indigo.devices:
					self.logger.error (u"PBX Server {} is not in the Indigo device list, was it removed?  {} action cannot complete".format(server, dev.name))
					return

				server = indigo.devices[server]
				result = self.invoke_api(server, method, dev.pluginProps["extension"])

				return result

		except Exception as e:
			self.logger.error (ex.stack_trace(e))

	###
	def invoke_api (self, dev, method, suffix = '', body = '', sub = 'users'):
		"""
		Calls the FreePBX API and returns the results.

		Arguments:
			dev				(device) the server device where the IP address will be used
			method			(string) the core API method to call
			suffix			(string) generally the extension or list ID if we want granular details
			body			(json dict) to execute or change an API call
			sub				(string) sub folder under the method to direct to
		"""

		try:
			if not suffix == '': suffix = '/' + suffix

			if body == '':
				verb = 'GET'
			else:
				verb = 'PUT'

			#url = 'http://{}/admin/rest.php/rest/donotdisturb/users'.format(dev.pluginProps["ipaddress"])
			url = '{}/restapi/rest.php/rest/{}/{}{}'.format(dev.pluginProps["ipaddress"], method, sub, suffix)
			token = dev.pluginProps["token"]
			key = dev.pluginProps["key"]
			#body = ''

			d = indigo.server.getTime()
			keyString = d.strftime("%Y-%m-%d %H:%M:%S %f") + str(randint(1000, 1000001))
			nonce = hashlib.sha1(keyString.encode('ascii', 'ignore')).digest().encode("hex")  # [0:16]

			keyString = '{}:{}'.format(url, verb.lower())
			hash_a = hashlib.sha256(keyString.encode('ascii', 'ignore')).digest().encode("hex")

			keyString = '{}:{}'.format(token, nonce)
			hash_b = hashlib.sha256(keyString.encode('ascii', 'ignore')).digest().encode("hex")


			#keyString = '{}'.format(body.encode('base64'))
			keyString = base64.b64encode(bytes(body))
			#indigo.server.log(u"Body Encode64: {}".format(keyString))
			#hash_c = hashlib.sha256(keyString.encode('ascii', 'ignore')).digest().encode("hex")
			hash_c = hashlib.sha256(keyString).digest().encode("hex")
			#hash_d = hashlib.sha256(body.encode('ascii', 'ignore')).digest().encode("hex")
			#indigo.server.log(u"Body C: {}".format(hash_c))
			#indigo.server.log(u"Body D: {}".format(hash_d))
			#return

			keyString = '{}:{}:{}'.format(hash_a, hash_b, hash_c)
			data = hashlib.sha256(keyString.encode('ascii', 'ignore')).digest().encode("hex")

			signature = hmac.new(str(key), str(data), hashlib.sha256).hexdigest() # Py 2.x, in Py 3.x we'll need to use bytes instead
			#signature = hmac.new(str(key), str(hash_c), hashlib.sha256).hexdigest()

			#indigo.server.log(u"Body C: {}".format(hash_c))
			#indigo.server.log(u"Token Key: {}".format(key))
			#indigo.server.log(u"Signature: {}".format(signature))
			#indigo.server.log(u"Nonce: {}".format(nonce))
			#indigo.server.log(u"Token: {}".format(token))

			if body == '':
				headers = {'Signature': signature, 'Nonce': nonce, 'Token': token}
				ret = requests.get(u"http://{}".format(url), headers=headers)
			else:
				headers = {'Signature': signature, 'Nonce': nonce, 'Token': token, 'Content-Type': 'application/json'}
				ret = requests.put(u"http://{}".format(url), data=body, headers=headers)
				#headers = {'Signature': signature, 'Nonce': nonce, 'Token': token}
				#ret = requests.put(u"http://{}".format(url), json=body, headers=headers)

			#ret = urlopen(Request(url, headers))
			#ret = requests.get(u"http://{}".format(url), headers=headers)
			#ret = requests.get(url, headers=headers, auth=HTTPBasicAuth('101','12345')) # change 12345 to the known 29 password
			#ret = requests.get(url, headers=headers, auth=HTTPDigestAuth('101','12345'))

			#indigo.server.log(url)

			if ret.status_code == 200:
				self.logger.debug (u"Success on FreePBX RestAPI on {}: {}".format(dev.name, ret.text))
				if not ret.text == '':
					results = json.loads(ret.text)
					return results
				else:
					return {'status': 'no response, successful operation'}

				#for r in results:
				#	for extension, status in r.iteritems():
				#		extdata = extension.split("/")
				#		indigo.server.log(unicode(extdata))

			elif ret.status_code == 403:
				self.logger.error (u"{} Access forbidden to FreePBX RestAPI on {}: {}".format(ret.status_code, dev.name, ret.text))
			elif ret.status_code == "404":
				self.logger.error (u"{} Invalid response to FreePBX RestAPI on {}: {}".format(ret.status_code, dev.name, ret.text))
			else:
				self.logger.error (u"{} Invalid response to FreePBX RestAPI on {}: {}".format(ret.status_code, dev.name, ret.text))


			#indigo.server.log(u"{}".format(ret))

		except Exception as e:
			self.logger.error (ex.stack_trace(e))

		return False





















