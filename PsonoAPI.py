import requests
import json
import nacl.encoding
import nacl.signing
import nacl.secret
from nacl.public import PrivateKey, PublicKey, Box
import binascii
import socket

class PsonoAPI(object):
    """docstring for PsonoAPI"""
    def __init__(self, config):
        super(PsonoAPI, self).__init__()
        self.config = config
        self.api_key_id = config['api_key_id']
        self.api_key_private_key = config['api_key_private_key']
        self.api_key_secret_key = config['api_key_secret_key']
        self.server_url = config['server_url']
        self.server_public_key = config['server_public_key']
        self.server_signature = config['server_signature']
        self.danger_disable_tls = config['danger_disable_tls']

    def get_device_description(self):
        """
        This info is later shown in the "Open sessions" overview in the client.
        Should be something so the user knows where this session is coming from.

        :return:
        :rtype:
        """
        return 'Console Client ' + socket.gethostname()

    def generate_client_login_info(self):
        """
        Generates and signs the login info
        Returns a tuple of the session private key and the login info

        :return:
        :rtype:
        """

        box = PrivateKey.generate()
        session_private_key = box.encode(encoder=nacl.encoding.HexEncoder).decode()
        session_public_key = box.public_key.encode(encoder=nacl.encoding.HexEncoder).decode()

        info = {
            'api_key_id': self.api_key_id,
            'session_public_key': session_public_key,
            'device_description': self.get_device_description(),
        }

        info = json.dumps(info)

        signing_box = nacl.signing.SigningKey(self.api_key_private_key, encoder=nacl.encoding.HexEncoder)

        # The first 128 chars (512 bits or 64 bytes) are the actual signature, the rest the binary encoded info
        signed = signing_box.sign(info.encode())
        signature = binascii.hexlify(signed.signature)

        return session_private_key, {
            'info': info,
            'signature': signature.decode(),
        }

    def decrypt_server_login_info(self, login_info_hex, login_info_nonce_hex, session_public_key, session_private_key):
        """
        Takes the login info and nonce together with the session public and private key.
        Will decrypt the login info and interpret it as json and return the json parsed object.
        :param login_info:
        :type login_info:
        :param login_info_nonce:
        :type login_info_nonce:
        :param session_public_key:
        :type session_public_key:
        :param session_private_key:
        :type session_private_key:

        :return:
        :rtype:
        """

        crypto_box = Box(PrivateKey(session_private_key, encoder=nacl.encoding.HexEncoder),
                         PublicKey(session_public_key, encoder=nacl.encoding.HexEncoder))

        login_info = nacl.encoding.HexEncoder.decode(login_info_hex)
        login_info_nonce = nacl.encoding.HexEncoder.decode(login_info_nonce_hex)

        login_info = json.loads(crypto_box.decrypt(login_info, login_info_nonce).decode())

        return login_info

    def verify_signature(self, login_info, login_info_signature):
        """
        Takes the login info and the provided signature and will validate it with the help of server_signature.

        Will raise an exception if it does not match.

        :param login_info:
        :type login_info:
        :param login_info_signature:
        :type login_info_signature:

        :return:
        :rtype:
        """

        verify_key = nacl.signing.VerifyKey(self.server_signature, encoder=nacl.encoding.HexEncoder)

        verify_key.verify(login_info.encode(), binascii.unhexlify(login_info_signature))


    def decrypt_symmetric(self, text_hex, nonce_hex, secret):
        """
        Decryts an encrypted text with nonce with the given secret

        :param text_hex:
        :type text_hex:
        :param nonce_hex:
        :type nonce_hex:
        :param secret:
        :type secret:
        :return:
        :rtype:
        """

        text = nacl.encoding.HexEncoder.decode(text_hex)
        nonce = nacl.encoding.HexEncoder.decode(nonce_hex)

        secret_box = nacl.secret.SecretBox(secret, encoder=nacl.encoding.HexEncoder)

        return secret_box.decrypt(text, nonce)

    def decrypt_with_api_secret_key(self, secret_hex, secret_nonce_hex):
        """
        take anything that is encrypted with the api keys secret and decrypts it. e.g. the users secret and private key

        :param secret_hex:
        :type secret_hex:
        :param secret_nonce_hex:
        :type secret_nonce_hex:

        :return:
        :rtype:
        """

        return self.decrypt_symmetric(secret_hex, secret_nonce_hex, self.api_key_secret_key)


    def api_request(self, method, endpoint, data = None, token = None, session_secret_key = None):
        """
        API Request helper that will also automatically decrypt the content if a session secret was provided.
        Will return the decrypted content.

        :param method:
        :type method:
        :param endpoint:
        :type endpoint:
        :param data:
        :type data:
        :param token:
        :type token:
        :param session_secret_key:
        :type session_secret_key:

        :return:
        :rtype:
        """

        if token:
            headers = {'content-type': 'application/json', 'authorization': 'Token ' + token}
        else:
            headers = {'content-type': 'application/json'}

        ssl_verify = (self.danger_disable_tls == False)

        r = requests.request(method, self.server_url + endpoint, data=data, headers=headers, verify=ssl_verify)

        if r.status_code != 200:
            r.raise_for_status()

        if not session_secret_key:
            return r.json()
        else:
            encrypted_content = r.json()
            decrypted_content = self.decrypt_symmetric(encrypted_content['text'], encrypted_content['nonce'], session_secret_key)
            return json.loads(decrypted_content)


    def api_login(self, client_login_info):
        """
        API Request: Sends the actual login

        :param client_login_info:
        :type client_login_info:

        :return:
        :rtype:
        """

        method = 'POST'
        endpoint = '/api-key/login/'
        data = json.dumps(client_login_info)

        return self.api_request(method, endpoint, data)


    def api_read_datastores(self, token, session_secret_key):
        """
        Reads all datastores

        :param token:
        :type token:
        :param session_secret_key:
        :type session_secret_key:
        :return:
        :rtype:
        """

        method = 'GET'
        endpoint = '/datastore/'

        return self.api_request(method, endpoint, token=token, session_secret_key=session_secret_key)


    def api_read_datastore(self, token, session_secret_key, datastore_id, user_secret_key):
        """
        Reads the content of a specific datastore
        """

        method = 'GET'
        endpoint = '/datastore/' + datastore_id + '/'

        datastore_read_result = self.api_request(method, endpoint, token=token, session_secret_key=session_secret_key)

        datastore_secret = self.decrypt_symmetric(
            datastore_read_result['secret_key'],
            datastore_read_result['secret_key_nonce'],
            user_secret_key
        )

        datastore_content = self.decrypt_symmetric(
            datastore_read_result['data'],
            datastore_read_result['data_nonce'],
            datastore_secret
        )

        return json.loads(datastore_content)


    def api_read_secret(self, token, session_secret_key, secret_id, secret_key):
        """
        Reads the content of a specific secret
        """

        method = 'GET'
        endpoint = f'/secret/{secret_id}/'
 
        encrypted_secret = self.api_request(method, endpoint, token=token, session_secret_key=session_secret_key)

        decrypted_secret = self.decrypt_symmetric(encrypted_secret['data'], encrypted_secret['data_nonce'], secret_key)

        return json.loads(decrypted_secret)