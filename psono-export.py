#!/usr/bin/env python

import argparse
import json
import os
import sys
import toml
from xdg import BaseDirectory

from PsonoAPI import PsonoAPI

def main(args):
    if not os.path.exists(args.config):
        print("Missing config file. Example:\n", """
danger_disable_tls = false

api_key_id = '9..f'
api_key_private_key = '2..5'
api_key_secret_key = 'b..0'
server_url = 'https://psono.contoso.com'
server_public_key = 'e..8'
server_signature = '5..6'
""")
        sys.exit(1)

    config = toml.load(args.config)
    psono = PsonoAPI(config)

    def verbose_print(*params):
        if args.verbose:
            print(*params)

    # 1. Generate the login info including the private key for PFS
    session_private_key, client_login_info = psono.generate_client_login_info()

    # 2. Send the login request and handle eventual exceptions, problems and so on ...
    json_response = psono.api_login(client_login_info)

    # 3. Verify the signature in order to proof that we are really communicating with the server
    # (or someone who is in the posession of the servers private key :D)
    psono.verify_signature(json_response['login_info'], json_response['login_info_signature'])

    # 4. Decrypt the actual login info with the token and session_secret_key for the transport encryption
    decrypted_sever_login_info = psono.decrypt_server_login_info(
        json_response['login_info'],
        json_response['login_info_nonce'],
        json_response['server_session_public_key'],
        session_private_key
    )

    token = decrypted_sever_login_info['token'] # Token that we have to send always as header
    session_secret_key = decrypted_sever_login_info['session_secret_key'] # symmetric secret for the transport encryption
    user_username = decrypted_sever_login_info['user']['username'] # The username
    user_public_key = decrypted_sever_login_info['user']['public_key'] # The user's public key

    if decrypted_sever_login_info['api_key_restrict_to_secrets']:
        print("api key is restricted. it should only be used to read specific secrets")
        return

    # if the api key is unrestricted then the request will also return the encrypted secret and private key
    # of the user, symmetric encrypted with the api secret key
    user_private_key = psono.decrypt_with_api_secret_key(
        decrypted_sever_login_info['user']['private_key'],
        decrypted_sever_login_info['user']['private_key_nonce']
    ) # The user's private key

    user_secret_key = psono.decrypt_with_api_secret_key(
        decrypted_sever_login_info['user']['secret_key'],
        decrypted_sever_login_info['user']['secret_key_nonce']
    ) # The user's secret key

    # 5. Now we can start actual reading the datastore and secrets e.g. to read the datastore:
    content = psono.api_read_datastores(token, session_secret_key)

    # 6. Read content of all password datastores
    for datastore in content['datastores']:
        if datastore['type'] != 'password':
            continue

        datastore_content = psono.api_read_datastore(token, session_secret_key, datastore['id'], user_secret_key)

        def recurse_folder(folder, path=["/"]):
            path_str = "".join(path)
            folder["path"] = f"{path_str}"
            verbose_print(path_str)
            if 'items' in folder:
                for item in folder['items']:
                    depth_str = " "*len(path_str)
                    item_name = item["name"]
                    item_deleted = 'deleted' in item and item['deleted']
                    item["path"] = f"{path_str}{item_name}"
                    verbose_print(f"{depth_str}{item_name}")

                    if args.decrypt and not item_deleted:
                        decrypted_secret = psono.api_read_secret(token, session_secret_key, item['secret_id'], item['secret_key'])
                        item['decrypted_secret'] = decrypted_secret

            if 'folders' in folder:
                for f in folder['folders']:
                    recurse_folder(f, path + [f["name"] + "/"])

        recurse_folder(datastore_content)

        if args.output == "-":
            print(json.dumps(datastore_content))
        else:
            with open(args.output, "w") as f:
                json.dump(datastore_content, f)

if __name__ == '__main__':
    default_config = os.path.join(BaseDirectory.save_config_path("psono-export"), "config.toml")
    parser = argparse.ArgumentParser(prog = 'psono-export', description = 'Reads all secrets from psono and exports to json struct')
    parser.add_argument('-c', '--config', action='store', help="Path to config file", default=default_config)
    parser.add_argument('-o', '--output', action='store', help="Output file", default="export.json")
    parser.add_argument('-d', '--decrypt', action='store_true', help="Decode secrets")
    parser.add_argument('-v', '--verbose', action='store_true', help="Print folders & items as they are parsed")
    args = parser.parse_args()
    main(args)
