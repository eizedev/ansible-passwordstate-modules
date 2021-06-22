#!/usr/bin/python3

""" PasswordState Ansible Module """

from ansible.module_utils.basic import *

import requests
from json.decoder import JSONDecodeError
from requests_ntlm import HttpNtlmAuth

class PasswordIdException(Exception):
    msg = 'Either the password id or the match ' \
          'field id and value must be configured'

class Password(object):
    """ Password """
    def __init__(self, api, password_list_id, matcher):
        self.api = api
        self.password_list_id = password_list_id
        if matcher['id'] != None:
            self.password_id = matcher['id']
        elif matcher['field'] != None and matcher['field_id'] != None:
            self.match_field = matcher['field']
            self.match_field_id = matcher['field_id']
        else:
            raise PasswordIdException()

    @property
    def password(self):
        """ fetch the password from the api """
        return self.api.get_password_fields(self)['Password']

    @property
    def username(self):
        """ fetch the password from the api """
        return self.api.get_password_fields(self)['UserName']

    @property
    def type(self):
        """ the method to uniquely identify the password """
        if hasattr(self, 'password_id'):
            return 'password_id'
        elif hasattr(self, 'match_field') and hasattr(self, 'match_field_id'):
            return 'match_field'
        raise PasswordIdException()

    def gather_facts(self, fact_name):
        """ gather facts """
        data = {}
        data[fact_name + '_password'] = self.password
        data[fact_name + '_username'] = self.username
        return data

class PasswordState(object):
    """ PasswordState """
    def __init__(self, module, url, api_key, api_username = None, api_password = None):
        self.module = module
        self.url = url
        self.api_key = api_key
        self.api_username = api_username
        self.api_password = api_password

    def get_password_fields(self, password):
        """ get the password fields """
        if password.type == 'password_id':
            return self._get_password_by_id(password.password_id)
        elif password.type == 'match_field':
            return self._get_password_by_field(password)

    def _get_password_by_id(self, password_id):
        """ get the password by the password id """
        passwords = self._request('passwords/' + str(password_id), 'GET')
        if len(passwords) == 0:
            self.module.fail_json(msg='Password not found')
            return None
        if len(passwords) > 1:
            self.module.fail_json(msg='Multiple matching passwords found')
            return None
        return passwords[0]

    def _get_password_by_field(self, password):
        """ get the password by a specific field """
        return self._get_password_by_id(self._get_password_id(password))

    def _get_password_id(self, password):
        """ get the password id by using a specific field """
        uri = 'passwords/' + password.password_list_id + '?QueryAll&ExcludePassword=true'
        passwords = self._request(uri, 'GET')
        passwords = PasswordState._filter_passwords(
            passwords,
            password.match_field,
            password.match_field_id
        )
        if len(passwords) == 0:
            self.module.fail_json(msg='Password not found')
            return None
        elif len(passwords) > 1:
            self.module.fail_json(msg='Multiple matching passwords found')
            return None

        return passwords[0]['PasswordID']

    def _request(self, uri, method, params=None):
        """ send a request to the api and return as json """
        request_methods = {
            'GET':  requests.get,
            'PUT':  requests.put,
            'POST': requests.post
        }

        try:
            if self.api_key != None:
                full_uri = self.url + '/api/' + uri
                headers = { 'APIKey': self.api_key }
                response = request_methods[method](full_uri, headers=headers, params=params)
            else:
                full_uri = self.url + '/winapi/' + uri
                winauth = HttpNtlmAuth(self.api_username, self.api_password)
                response = request_methods[method](full_uri, auth=winauth, params=params)
        except requests.exceptions.RequestException as inst:
            self.module.fail_json(msg="Failed: %s" % str(inst))
            return None

        if response.status_code > 204:
            self.module.fail_json(msg="Failed: %s" % str(response.json()))
            return None

        try:
            return response.json()
        except JSONDecodeError as inst:
            self.module.fail_json(msg="Failed: %s" % str(inst))
            return None

    @staticmethod
    def _filter_passwords(passwords, field, value):
        """ filter out passwords which does not match the specific field value """
        return [obj for i, obj in enumerate(passwords) if obj[field] == value]

def main():
    """ main """
    module = AnsibleModule(
        argument_spec = {
            'url': { 'required': True },
            'fact_name': { 'required': True },
            'api_key': { 'required': False },
            'api_username': { 'required': False },
            'api_password': { 'required': False },
            'password_list_id': { 'required': False },
            'match_field': { 'required': False },
            'match_field_id': { 'required': False },
            'password_id': { 'required': False }
        },
        supports_check_mode = False,
        mutually_exclusive = [('api_key', 'api_username')],
        required_one_of = [('api_key', 'api_username')],
        required_together = [('api_username', 'api_password')]
    )

    url = module.params['url']
    api_key = module.params['api_key']
    api_username = module.params['api_username']
    api_password = module.params['api_password']
    fact_name = module.params['fact_name']
    password_list_id = module.params['password_list_id']
    match_field = module.params['match_field']
    match_field_id = module.params['match_field_id']
    password_id = module.params['password_id']

    api = PasswordState(module, url, api_key, api_username, api_password)
    password = Password(api, password_list_id,
                        {"id": password_id, "field": match_field, "field_id": match_field_id})

    facts = password.gather_facts(fact_name)
    facts_result = { 'changed': False, 'ansible_facts': facts }
    module.exit_json(**facts_result)

if __name__ == '__main__':
    main()
