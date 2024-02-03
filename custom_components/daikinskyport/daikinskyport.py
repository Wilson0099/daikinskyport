''' Python Code for Communication with the Daikin Skyport Thermostat.  This is taken mostly from pyecobee, so much credit to those contributors'''
import requests
import json
import os
import logging
from time import sleep

from requests.exceptions import RequestException
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

from .const import DAIKIN_PERCENT_MULTIPLIER
from .const import DAIKIN_FANDEMAND_MULTIPLIER

logger = logging.getLogger('daikinskyport')

NEXT_SCHEDULE = 1

class ExpiredTokenError(Exception):
    """Raised when Daikin Skyport API returns a code indicating expired credentials."""

    pass

def config_from_file(filename, config=None):
    ''' Small configuration file management function'''
    if config:
        # We're writing configuration
        try:
            with open(filename, 'w') as fdesc:
                fdesc.write(json.dumps(config))
        except IOError as error:
            logger.exception(error)
            return False
        return True
    else:
        # We're reading config
        if os.path.isfile(filename):
            try:
                with open(filename, 'r') as fdesc:
                    return json.loads(fdesc.read())
            except IOError as error:
                return False
        else:
            return {}


class DaikinSkyport(object):
    ''' Class for storing Daikin Skyport Thermostats and Sensors '''

    def __init__(self, config_filename=None, user_email=None, user_password=None, config=None):
        self.thermostats = list()
        self.thermostatlist = list()
        self.authenticated = False

        if config is None:
            self.file_based_config = True
            if config_filename is None:
                if (user_email is None) or (user_password is None):
                    logger.error("Error. No user email or password was supplied.")
                    return
                jsonconfig = {"EMAIL": user_email, "PASSWORD": user_password}
                config_filename = 'daikinskyport.conf'
                config_from_file(config_filename, jsonconfig)
            config = config_from_file(config_filename)
        else:
            self.file_based_config = False
        if 'EMAIL' in config:
            self.user_email = config['EMAIL']
        else:
            logger.error("Email missing from config.")
        if 'PASSWORD' in config: # PASSWORD is only needed during first login
            self.user_password = config['PASSWORD']

        if 'ACCESS_TOKEN' in config:
            self.access_token = config['ACCESS_TOKEN']
        else:
            self.access_token = ''

        if 'REFRESH_TOKEN' in config:
            self.refresh_token = config['REFRESH_TOKEN']
        else:
            self.refresh_token = ''
#            self.request_tokens()
#            return

#        self.update()

    def request_tokens(self):
        ''' Method to request API tokens from skyport '''
        url = 'https://api.daikinskyport.com/users/auth/login'
        header = {'Accept': 'application/json',
                  'Content-Type': 'application/json'}
        data = {"email": self.user_email, "password": self.user_password}
        try:
            request = requests.post(url, headers=header, json=data)
        except RequestException as e:
            logger.error("Error connecting to Daikin Skyport.  Possible connectivity outage."
                        "Could not request token. %s", e)
            return False
        if request.status_code == requests.codes.ok:
            json_data = request.json()
            self.access_token = json_data['accessToken']
            self.refresh_token = json_data['refreshToken']
            if self.refresh_token is None:
                logger.error("Auth did not return a refresh token.")
            else:
                if self.file_based_config:
                    self.write_tokens_to_file()
                return json_data
        else:
            logger.error('Error while requesting tokens from daikinskyport.com.'
                        ' Status code: %s Message: %s', request.status_code, request.text)
            return

    def refresh_tokens(self):
        ''' Method to refresh API tokens from daikinskyport.com '''
        url = 'https://api.daikinskyport.com/users/auth/token'
        header = {'Accept': 'application/json',
                  'Content-Type': 'application/json'}
        data = {'email': self.user_email,
                  'refreshToken': self.refresh_token}
        request = requests.post(url, headers=header, json=data)
        if request.status_code == requests.codes.ok:
            json_data = request.json()
            self.access_token = json_data['accessToken']
            if self.file_based_config:
                self.write_tokens_to_file()
            return True
        else:
            logger.warn("Could not refresh tokens, Trying to re-request. Status code: %s Message: %s ", request.status_code, request.text)
            result = self.request_tokens()
            if result is not None:
                return True
            return False

    def get_thermostats(self):
        ''' Set self.thermostats to a json list of thermostats from daikinskyport.com '''
        url = 'https://api.daikinskyport.com/devices'
        header = {'Content-Type': 'application/json;charset=UTF-8',
                  'Authorization': 'Bearer ' + self.access_token}
        retry_strategy = Retry(total=8, backoff_factor=0.1)
        adapter = HTTPAdapter(max_retries=retry_strategy)
        http = requests.Session()
        http.mount("https://", adapter)
        http.mount("http://", adapter)

        try:
            request = http.get(url, headers=header)
        except RequestException as e:
            logger.warn("Error connecting to Daikin Skyport.  Possible connectivity outage: %s", e)
            return None
        if request.status_code == requests.codes.ok:
            self.authenticated = True
            self.thermostatlist = request.json()
            for thermostat in self.thermostatlist:
                overwrite = False
                thermostat_info = self.get_thermostat_info(thermostat['id'])
                if thermostat_info == None:
                    continue
                thermostat_info['name'] = thermostat['name']
                thermostat_info['id'] = thermostat['id']
                thermostat_info['model'] = thermostat['model']
                for index in range(len(self.thermostats)):
                    if thermostat['id'] == self.thermostats[index]['id']:
                        overwrite = True
                        self.thermostats[index] = thermostat_info
                if not overwrite:
                    self.thermostats.append(thermostat_info)
            return self.thermostats
        else:
            self.authenticated = False
            logger.debug("Error connecting to Daikin Skyport while attempting to get "
                        "thermostat data. Status code: %s Message: %s", request.status_code, request.text)
            raise ExpiredTokenError ("Daikin Skyport token expired")
            return None

    def get_thermostat_info(self, deviceid):
        ''' Retrieve the device info for the specific device '''
        url = 'https://api.daikinskyport.com/deviceData/' + deviceid
        header = {'Content-Type': 'application/json;charset=UTF-8',
                  'Authorization': 'Bearer ' + self.access_token}
        retry_strategy = Retry(total=8, backoff_factor=0.1)
        adapter = HTTPAdapter(max_retries=retry_strategy)
        http = requests.Session()
        http.mount("https://", adapter)
        http.mount("http://", adapter)

        try:
            request = http.get(url, headers=header)
            request.raise_for_status()
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 400 and e.response.json().get("message") == "DeviceOfflineException":
                logger.warn("Device is offline.")
                self.authenticated = True
                return None
            else:
                self.authenticated = False
            logger.debug("Error connecting to Daikin Skyport while attempting to get "
                        "thermostat data. Status code: %s Message: %s", request.status_code, request.text)
            raise ExpiredTokenError ("Daikin Skyport token expired")
            return None
        if request.status_code == requests.codes.ok:
            self.authenticated = True
            return request.json()
        else:
            self.authenticated = False
            logger.debug("Error connecting to Daikin Skyport while attempting to get "
                        "thermostat data. Status code: %s Message: %s", request.status_code, request.text)
            raise ExpiredTokenError ("Daikin Skyport token expired")
            return None

    def get_thermostat(self, index):
        ''' Return a single thermostat based on index '''
        return self.thermostats[index]

    def get_sensors(self, index):
        ''' Return sensors based on index '''
        sensors = list()
        thermostat = self.thermostats[index]
        name = thermostat['name']
        sensors.append({"name":  f"OutdoorTemperature", "value": thermostat['tempOutdoor'], "type": "temperature"})
        sensors.append({"name": f"OutdoorHumidity", "value": thermostat['humOutdoor'], "type": "humidity"})
        sensors.append({"name": f"{name} Outdoor fan", "value": round(thermostat['ctOutdoorFanRequestedDemandPercentage'] / DAIKIN_PERCENT_MULTIPLIER, 1), "type": "demand"})
        sensors.append({"name": f"{name} Outdoor heat pump", "value": round(thermostat['ctOutdoorHeatRequestedDemand'] / DAIKIN_PERCENT_MULTIPLIER, 1), "type": "demand"})
        sensors.append({"name": f"{name} Outdoor cooling", "value": round(thermostat['ctOutdoorCoolRequestedDemand'] / DAIKIN_PERCENT_MULTIPLIER, 1), "type": "demand"})
        sensors.append({"name": f"OutdoorPower", "value": thermostat['ctOutdoorPower'], "type": "power"})
        sensors.append({"name": f"{name} Outdoor", "value": round(thermostat['ctOutdoorFrequencyInPercent'] / DAIKIN_PERCENT_MULTIPLIER, 1), "type": "frequency_percent"})
        sensors.append({"name": f"{name} Indoor", "value": thermostat['tempIndoor'], "type": "temperature"})
        sensors.append({"name": f"{name} Indoor", "value": thermostat['humIndoor'], "type": "humidity"})
        sensors.append({"name": f"{name} Indoor fan", "value": round(thermostat['ctIFCFanRequestedDemandPercent'] / DAIKIN_PERCENT_MULTIPLIER, 1), "type": "demand"})
        sensors.append({"name": f"{name} Indoor fan", "value": round(thermostat['ctIFCCurrentFanActualStatus'] / DAIKIN_PERCENT_MULTIPLIER, 1), "type": "actual_status"})
        sensors.append({"name": f"{name} Indoor cooling", "value": round(thermostat['ctIFCCoolRequestedDemandPercent'] / DAIKIN_PERCENT_MULTIPLIER, 1), "type": "demand"})
        sensors.append({"name": f"{name} Indoor cooling", "value": round(thermostat['ctIFCCurrentCoolActualStatus'] / DAIKIN_PERCENT_MULTIPLIER, 1), "type": "actual_status"})
        sensors.append({"name": f"{name} Indoor furnace", "value": round(thermostat['ctIFCHeatRequestedDemandPercent'] / DAIKIN_PERCENT_MULTIPLIER, 1), "type": "demand"})
        sensors.append({"name": f"{name} Indoor furnace", "value": round(thermostat['ctIFCCurrentHeatActualStatus'] / DAIKIN_PERCENT_MULTIPLIER, 1), "type": "actual_status"})
        sensors.append({"name": f"{name} Indoor humidifier", "value": round(thermostat['ctIFCHumRequestedDemandPercent'] / DAIKIN_PERCENT_MULTIPLIER, 1), "type": "demand"})
        sensors.append({"name": f"{name} Indoor dehumidifier", "value": round(thermostat['ctIFCDehumRequestedDemandPercent'] / DAIKIN_PERCENT_MULTIPLIER, 1), "type": "demand"})
        sensors.append({"name": f"{name} Indoor", "value": thermostat['ctIndoorPower'], "type": "power"})
        sensors.append({"name": f"ctOutdoorFanRPM", "value": thermostat['ctOutdoorFanRPM'], "type": "number"})
        sensors.append({"name": f"ctTargetODFanRPM", "value": round(thermostat['ctTargetODFanRPM'] * DAIKIN_FANDEMAND_MULTIPLIER, 1), "type": "number"})
        sensors.append({"name": f"ctCurrentCompressorRPS", "value": thermostat['ctCurrentCompressorRPS'], "type": "number"})
        sensors.append({"name": f"ctTargetCompressorspeed", "value": thermostat['ctTargetCompressorspeed'], "type": "number"})
        sensors.append({"name": f"quietModeActive", "value": thermostat['quietModeActive'], "type": "number"})
        sensors.append({"name": f"ctOutdoorQuietModeEnabled", "value": thermostat['ctOutdoorQuietModeEnabled'], "type": "number"})
        sensors.append({"name": f"ctOutdoorNoiseDownLevel", "value": thermostat['ctOutdoorNoiseDownLevel'], "type": "number"})
        sensors.append({"name":  f"OutdoorTemperature_num", "value": thermostat['tempOutdoor'], "type": "number"})
        sensors.append({"name":  f"OutdoorTemperature_fanscaled", "value": (thermostat['tempOutdoor'] * DAIKIN_FANDEMAND_MULTIPLIER), "type": "number"})
        sensors.append({"name":  f"IndoorTemperature_num", "value": thermostat['tempIndoor'], "type": "number"})
        sensors.append({"name":  f"IndoorTemperature_fanscaled", "value": (thermostat['tempIndoor'] * DAIKIN_FANDEMAND_MULTIPLIER), "type": "number"})
        sensors.append({"name":  f"ctOutdoorMode", "value": sum((int(format(ord(x), 'b'),2)) for x in thermostat['ctOutdoorMode']), "type": "number"})
        if self.thermostats[index]['aqOutdoorAvailable']:
            sensors.append({"name": f"{name} Outdoor", "value": thermostat['aqOutdoorParticles'], "type": "particle"})
            sensors.append({"name": f"{name} Outdoor", "value": thermostat['aqOutdoorValue'], "type": "score"})
            sensors.append({"name": f"{name} Outdoor", "value": round(thermostat['aqOutdoorOzone'] * 1.96), "type": "ozone"})
        if self.thermostats[index]['aqIndoorAvailable']:
            sensors.append({"name": f"{name} Indoor", "value": thermostat['aqIndoorParticlesValue'], "type": "particle"})
            sensors.append({"name": f"{name} Indoor", "value": thermostat['aqIndoorValue'], "type": "score"})
            sensors.append({"name": f"{name} Indoor", "value": thermostat['aqIndoorVOCValue'], "type": "VOC"})
            
        return sensors

    def write_tokens_to_file(self):
        ''' Write api tokens to a file '''
        config = dict()
        config['ACCESS_TOKEN'] = self.access_token
        config['REFRESH_TOKEN'] = self.refresh_token
        config['EMAIL'] = self.user_email
        if self.file_based_config:
            config_from_file(self.config_filename, config)
        else:
            self.config = config

    def update(self):
        ''' Get new thermostat data from daikin skyport '''
        sleep(3)
        result = self.get_thermostats()
        return result

    def make_request(self, index, body, log_msg_action, *, retry_count=0):
        deviceID = self.thermostats[index]['id']
        url = 'https://api.daikinskyport.com/deviceData/' + deviceID
        header = {'Content-Type': 'application/json;charset=UTF-8',
                  'Authorization': 'Bearer ' + self.access_token}
        logger.debug("Make Request: %s, Device: %s, Body: %s", log_msg_action, deviceID, body)
        retry_strategy = Retry(total=8, backoff_factor=0.1,)
        adapter = HTTPAdapter(max_retries=retry_strategy)
        http = requests.Session()
        http.mount("https://", adapter)
        http.mount("http://", adapter)

        try:
            request = http.put(url, headers=header, json=body)
        except RequestException as e:
            logger.warn("Error connecting to Daikin Skyport.  Possible connectivity outage: %s", e)
            return None
        if request.status_code == requests.codes.ok:
            return request
        elif (request.status_code == 401 and retry_count == 0 and
              request.json()['error'] == 'authorization_expired'):
            if self.refresh_tokens():
                return self.make_request(body, deviceID, log_msg_action,
                                         retry_count=retry_count + 1)
        else:
            logger.warn(
                "Error fetching data from Daikin Skyport while attempting to %s: %s",
                log_msg_action, request.json())
            return None
