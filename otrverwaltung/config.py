# -*- coding: utf-8 -*-
# BEGIN LICENSE
# Copyright (C) 2010 Benjamin Elbers <elbersb@gmail.com>
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 3, as published
# by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranties of
# MERCHANTABILITY, SATISFACTORY QUALITY, or FITNESS FOR A PARTICULAR
# PURPOSE.  See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program.  If not, see <http://www.gnu.org/licenses/>.
# END LICENSE

try:
    import simplejson as json
except ImportError:
    import json
import os.path
import base64
import logging

from base64 import b64decode
from Crypto.Cipher import AES
from otrverwaltung import path


class Config:
    """ Loads and saves configuration fields from/to file. """

    def __init__(self, config_file, fields):
        """ """

        self.__config_file = config_file
        self.__fields = fields

        self.__callbacks = {}

    def connect(self, category, option, callback):
        self.__callbacks.setdefault(category, {})
        self.__callbacks[category].setdefault(option, []).append(callback)

    def set(self, category, option, value):
        if option in ['email', 'password']:
            logging.info("Set [%(category)s][%(option)s] to *****" % {"category": category, "option": option})
        else:
            logging.info("Set [%(category)s][%(option)s] to %(value)s" % {"category": category, "option": option, "value": value})

        try:
            for callback in self.__callbacks[category][option]:
                callback(value)
        except KeyError:
            pass

        self.__fields[category][option] = value

    def get(self, category, option):
        """ Gets a configuration option. """
        value = self.__fields[category][option]

        if option in ['email', 'password']:
            logging.info("Get [%(category)s][%(option)s]: *****" % {"category": category, "option": option})
        else:
            if type(value) is list:
                logging.info("Get [%(category)s][%(option)s]: %(value)s" % {"category": category, "option": option, "value": ''.join(value)})
            else:
                logging.info("Get [%(category)s][%(option)s]: %(value)s" % {"category": category, "option": option, "value": value})

        return value

    def save(self):
        """ Saves configuration to disk. """

        try:
            # make sure directories exist
            try:
                os.makedirs(os.path.dirname(self.__config_file))
            except OSError:
                pass

            config_file = open(self.__config_file, "w", encoding='utf_8')
            try:
                if len(str(self.__fields['general']['password'])) > 0:
                    # Encryption
                    pad = lambda s: s + (self.__fields['general']['aes_blocksize'] - len(s) % self.__fields['general']['aes_blocksize']) * self.__fields['general']['aes_padding']
                    EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
                    encryption_suite = AES.new(b64decode(self.__fields['general']['aes_key'].encode('utf-8')))
                    cipher_text = EncodeAES(encryption_suite, self.__fields['general']['password'])
                    self.__fields['general']['password'] = base64.b64encode(cipher_text).decode('utf-8')
            except ValueError:
                self.__fields['general']['password']=self.__fields['general']['password']

            json.dump(self.__fields, config_file, ensure_ascii=False, sort_keys=True, indent=4)
            config_file.close()
        except IOError as message:
            print("Config file not available. Dumping configuration:")
            print(json.dumps(self.__fields, sort_keys=True, indent=4))

    def load(self):
        """ Reads an existing configuration file. """

        try:
            config = open(self.__config_file, 'r')
            json_config = json.load(config)
            config.close()
        except IOError as message:
            print("Config file not available. Using default configuration.")
            json_config = {}

        for category, options in self.__fields.items():
            for option, value in options.items():
                try:
                    if category is 'general' and option is 'password':
                        try:
                            # Decryption
                            padding=json_config['general']['aes_padding']
                            DecodeAES = lambda c, e: (c.decrypt(base64.b64decode(e)).decode("utf-8")).rstrip(padding)
                            decryption_suite = AES.new(b64decode(json_config['general']['aes_key'].encode('utf-8')))
                            b = base64.b64decode(json_config[category][option])
                            plain_text = DecodeAES(decryption_suite, b)
                            self.set(category, option, plain_text)
                        except ValueError:
                            self.set(category, option, json_config[category][option])
                    else:
                        self.set(category, option, json_config[category][option])
                except KeyError:
                    self.set(category, option, value)

    def get_program(self, program):
        """ Returns the full calling string of a program 
            either the pure config value or the internal version, if the config value contains 'intern' """

        value = self.__fields['programs'][program]
        intern_program = path.get_tools_path(value)

        if 'intern-' in value:
            if os.path.isfile(intern_program):
                return intern_program

        return value
