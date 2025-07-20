from base64 import b64encode
from hashlib import md5, sha1
from json import dumps, loads
from os import remove, path
from random import sample
from string import ascii_letters, digits
import time
from urllib import parse
from aiofiles import open as aio_open

from logging import getLogger
_LOGGER = getLogger(__package__)


def get_random(length):
    return ''.join(sample(ascii_letters + digits, length))


class MiTokenStore:

    def __init__(self, token_path):
        self.token_path = token_path
        print("token_path: ", self.token_path)

    async def load_token(self):
        if path.isfile(self.token_path):
            try:
                async with aio_open(self.token_path) as f:
                    return loads(await f.read())
            except Exception as e:
                _LOGGER.exception("Exception on load token from %s: %s", self.token_path, e)
        return None

    async def save_token(self, token=None):
        if token:
            try:
                async with aio_open(self.token_path, 'w') as f:
                    await f.write(dumps(token, indent=2))
            except Exception as e:
                _LOGGER.exception("Exception on save token to %s: %s", self.token_path, e)
        elif path.isfile(self.token_path):
            remove(self.token_path)


class MiAccount:

    def __init__(self, session, username, password, token_store='.mi.token'):
        self._session = session
        self.username = username
        self.password = password
        self.token_store = MiTokenStore(token_store) if isinstance(token_store, str) else token_store
        self.token = None
        # 新增tgm
        self.verify = None
        self.identity_session = None

    def request(self, url, method='GET', **kwargs):
        if self._session:
            return self._session.request(method, url, **kwargs)

        class RequestContextManager:
            async def __aenter__(self):
                from aiohttp import ClientSession
                self.sess = ClientSession()
                self.resp = await self.sess.request(method, url, **kwargs)
                return self.resp

            async def __aexit__(self, exc_type, exc, tb):
                await self.resp.release()
                await self.sess.close()
        return RequestContextManager()

    async def login(self, sid):
        if not self.token:
            self.token = {'deviceId': get_random(16).upper()}
        try:
            resp = await self._serviceLogin(f'serviceLogin?sid={sid}&_json=true')
            if resp['code'] != 0:
                data = {
                    '_json': 'true',
                    'qs': resp['qs'],
                    'sid': resp['sid'],
                    '_sign': resp['_sign'],
                    'callback': resp['callback'],
                    'user': self.username,
                    'hash': md5(self.password.encode()).hexdigest().upper()
                }
                resp = await self._serviceLogin('serviceLoginAuth2', data)
                
                # 新增tgm
                self.verify = resp.get("notificationUrl")
                if self.verify[:4] != 'http':
                    self.verify = f'https://account.xiaomi.com{self.verify}'

                if not resp.get("location", ''):
                    return False
                
                if resp['code'] != 0:
                    raise Exception(resp)

            self.token['userId'] = resp['userId']
            self.token['passToken'] = resp['passToken']

            serviceToken = await self._securityTokenService(resp['location'], resp['nonce'], resp['ssecurity'])
            self.token[sid] = (resp['ssecurity'], serviceToken)
            if self.token_store:
                await self.token_store.save_token(self.token)
            return True

        except Exception as e:
            self.token = None
            if self.token_store:
                await self.token_store.save_token()
            _LOGGER.exception("Exception on login %s: %s", self.username, e)
            return False

    async def _serviceLogin(self, uri, data=None):
        headers = {'User-Agent': 'APP/com.xiaomi.mihome APPV/6.0.103 iosPassportSDK/3.9.0 iOS/14.4 miHSTS'}
        cookies = {'sdkVersion': '3.9', 'deviceId': self.token['deviceId']}
        if 'passToken' in self.token:
            cookies['userId'] = self.token['userId']
            cookies['passToken'] = self.token['passToken']
        url = 'https://account.xiaomi.com/pass/' + uri
        async with self.request(url, 'GET' if data is None else 'POST', data=data, cookies=cookies, headers=headers) as r:
            raw = await r.read()
            resp = loads(raw[11:])
            # _LOGGER.debug("%s: %s", uri, resp)
            return resp

    async def _securityTokenService(self, location, nonce, ssecurity):
        nsec = 'nonce=' + str(nonce) + '&' + ssecurity
        clientSign = b64encode(sha1(nsec.encode()).digest()).decode()
        async with self.request(location + '&clientSign=' + parse.quote(clientSign)) as r:
            serviceToken = r.cookies['serviceToken'].value
            if not serviceToken:
                raise Exception(await r.text())
            return serviceToken

    async def mi_request(self, sid, url, data, headers, relogin=True):
        if self.token is None and self.token_store is not None:
            self.token = await self.token_store.load_token()
        if (self.token and sid in self.token) or await self.do_login(sid):  # Ensure login
            cookies = {'userId': self.token['userId'], 'serviceToken': self.token[sid][1]}
            content = data(self.token, cookies) if callable(data) else data
            method = 'GET' if data is None else 'POST'
            # _LOGGER.debug("%s %s", url, content)
            async with self.request(url, method, data=content, cookies=cookies, headers=headers) as r:
                status = r.status
                if status == 200:
                    resp = await r.json(content_type=None)
                    code = resp['code']
                    if code == 0:
                        return resp
                    if 'auth' in resp.get('message', '').lower():
                        status = 401
                else:
                    resp = await r.text()
                if status == 401 and relogin:
                    _LOGGER.warning("Auth error on request %s %s, relogin...", url, resp)
                    self.token = None  # Auth error, reset login
                    if self.token_store:
                        await self.token_store.save_token()
                    return await self.mi_request(sid, url, data, headers, False)
        else:
            resp = "Login failed"
        raise Exception(f"Error {url}: {resp}")
    

    # 以下新增
    async def do_login(self, sid) -> bool:
        try:
            result = await self.login(sid)
            if not result:       
                if self.verify:
                    print("need verify: ", self.verify)
                    ticket = input("请输入验证码：")
                    resp = await self.verify_ticket(self.verify, ticket)
                    location = resp.get('location', '')
                    if location:
                        resp = await self.session.get(location, allow_redirects=True)
                        resp = await self._serviceLogin(f'serviceLogin?sid={sid}&_json=true')                       
                        location = data.get('location', '')

                        if not location:
                            if resp['code'] != 0:
                                data = {
                                    '_json': 'true',
                                    'qs': resp['qs'],
                                    'sid': resp['sid'],
                                    '_sign': resp['_sign'],
                                    'callback': resp['callback'],
                                    'user': self.username,
                                    'hash': md5(self.password.encode()).hexdigest().upper()
                                }
                                resp = await self._serviceLogin('serviceLoginAuth2', data)
                            if not resp.get('location', ''):
                                return False
                            location = resp["location"]
                                
                        self.token['userId'] = resp['userId']
                        self.token['passToken'] = resp['passToken']

                        serviceToken = await self._securityTokenService(resp['location'], resp['nonce'], resp['ssecurity'])
                        self.token[sid] = (resp['ssecurity'], serviceToken)
                        if self.token_store:
                            await self.token_store.save_token(self.token)
                        return True
                        
                return False
        
            return result
        except Exception as e:
            _LOGGER.exception(f"Can't login to Mi Cloud: {e}")
            return False
        
    async def check_identity_list(self, url, path='identity/authStart'):
        if path not in url:
            return None
        async with self.request(url.replace(path, 'identity/list'), "GET") as r:
            self.identity_session = r.cookies.get('identity_session')
            if not self.identity_session:
                return False
            raw = await r.read()
            resp = loads(raw[11:])            
            flag= resp.get('flag', 4)
            options = resp.get('options', [flag])
            return options

    async def verify_ticket(self, url, ticket):
        url = self.verify
        if not url:
            return False
        options = await self.check_identity_list(url) or []
        for flag in options:
            api = {
                4: 'https://account.xiaomi.com/identity/auth/verifyPhone',
                8: 'https://account.xiaomi.com/identity/auth/verifyEmail',
            }.get(flag)
            if not api:
                continue

            data={'_flag': flag, 'ticket': ticket, 'trust': 'true', '_json': 'true'}
            cookies={'identity_session': self.identity_session}
            headers={"User-Agent":'APP/com.xiaomi.mihome APPV/6.0.103 iosPassportSDK/3.9.0 iOS/14.4 miHSTS'}
            async with self.request(api + f"?_dc={int(time.time() * 1000)}", 'POST', data=data, cookies=cookies, headers=headers) as r:
                raw = await r.read()
                resp = loads(raw[11:])
                if resp.get('code') == 0:
                    self.identity_session = None
                    return resp
        return {}
