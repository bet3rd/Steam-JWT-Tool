import time

import jwt


def verify_steam_jwt(refresh_token) -> int:
    """
    Verify whether the refresh token is alive.
    :return: -1 if the token is invalid, 0 if the token is valid, otherwise how long the token is valid in seconds.
    """
    try:
        decoded_jwt = jwt.decode(refresh_token, options={'verify_signature': False})
        print(decoded_jwt)
        if decoded_jwt.get('iss') != 'steam':
            return -1
        if 'client' not in decoded_jwt.get('aud'):
            return -1
        expires_in = decoded_jwt.get('exp') - time.time()
        if expires_in <= 0:
            print("Token has expired")
            return -1
        print(f"Token expires in {expires_in} seconds")
        return expires_in
    except Exception as e:
        print(f"Error verifying token: {e}")
        return False