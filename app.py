import asyncio
import logging
import os
import sys
import time

from aiohttp import web
import mohawk
from mohawk.exc import HawkFail

NONCE_EXPIRE = 120

NOT_PROVIDED = 'Authentication credentials were not provided.'
INCORRECT = 'Incorrect authentication credentials.'
MISSING_CONTENT_TYPE = 'Content-Type header was not set. ' + \
                       'It must be set for authentication, even if as the empty string.'


async def run_application():
    app_logger = logging.getLogger(__name__)

    app_logger.debug('Examining environment...')
    port = os.environ['PORT']

    incoming_key_pairs = {
        key_id: secret_key
        for key_pair in os.environ['INCOMING_ACCESS_KEY_PAIRS'].split(',')
        for key_id, secret_key in [key_pair.split(':')]
    }
    ip_whitelist = os.environ['INCOMING_IP_WHITELIST'].split(',')

    await create_incoming_application(
        port, ip_whitelist, incoming_key_pairs,
    )


async def create_incoming_application(port, ip_whitelist, incoming_key_pairs):
    app_logger = logging.getLogger(__name__)

    def lookup_credentials(passed_access_key_id):
        if passed_access_key_id not in incoming_key_pairs:
            raise HawkFail(f'No Hawk ID of {passed_access_key_id}')

        return {
            'id': passed_access_key_id,
            'key': incoming_key_pairs[passed_access_key_id],
            'algorithm': 'sha256',
        }

    # This would need to be stored externally if this was ever to be load balanced,
    # otherwise replay attacks could succeed by hitting another instance
    seen_nonces = ExpiringSet(NONCE_EXPIRE)

    def seen_nonce(access_key_id, nonce, _):
        nonce_tuple = (access_key_id, nonce)
        seen = nonce_tuple in seen_nonces
        if not seen:
            seen_nonces.add(nonce_tuple)
        return seen

    async def raise_if_not_authentic(request):
        mohawk.Receiver(
            lookup_credentials,
            request.headers['Authorization'],
            str(request.url),
            request.method,
            content=await request.content.read(),
            content_type=request.headers['Content-Type'],
            seen_nonce=seen_nonce,
        )

    @web.middleware
    async def authenticate(request, handler):
        if 'X-Forwarded-For' not in request.headers:
            app_logger.warning(
                'Failed authentication: no X-Forwarded-For header passed'
            )
            return web.json_response({
                'details': INCORRECT,
            }, status=401)

        remote_address = request.headers['X-Forwarded-For'].split(',')[0].strip()

        if remote_address not in ip_whitelist:
            app_logger.warning(
                'Failed authentication: the X-Forwarded-For header did not '
                'start with an IP in the whitelist'
            )
            return web.json_response({
                'details': INCORRECT,
            }, status=401)

        if 'Authorization' not in request.headers:
            return web.json_response({
                'details': NOT_PROVIDED,
            }, status=401)

        if 'Content-Type' not in request.headers:
            return web.json_response({
                'details': MISSING_CONTENT_TYPE,
            }, status=401)

        try:
            await raise_if_not_authentic(request)
        except HawkFail as exception:
            app_logger.warning('Failed authentication %s', exception)
            return web.json_response({
                'details': INCORRECT,
            }, status=401)

        return await handler(request)

    async def handle(_):
        return web.json_response({'secret': 'to-be-hidden'})

    app_logger.debug('Creating listening web application...')
    app = web.Application(middlewares=[authenticate])
    app.add_routes([web.post('/', handle)])
    access_log_format = '%a %t "%r" %s %b "%{Referer}i" "%{User-Agent}i" %{X-Forwarded-For}i'

    runner = web.AppRunner(app, access_log_format=access_log_format)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', port)
    await site.start()
    app_logger.debug('Creating listening web application: done')


class ExpiringSet:

    def __init__(self, seconds):
        self._seconds = seconds
        self._expiries = {}

    def _remove_old_keys(self, now):
        now = int(time.time())
        self._expiries = {
            key: expires
            for key, expires in self._expiries.items()
            if expires > now
        }

    def add(self, item):
        now = int(time.time())
        self._remove_old_keys(now)
        self._expiries[item] = now + self._seconds

    def __contains__(self, item):
        now = int(time.time())
        self._remove_old_keys(now)
        return item in self._expiries


def setup_logging():
    stdout_handler = logging.StreamHandler(sys.stdout)
    aiohttp_log = logging.getLogger('aiohttp.access')
    aiohttp_log.setLevel(logging.DEBUG)
    aiohttp_log.addHandler(stdout_handler)

    app_logger = logging.getLogger(__name__)
    app_logger.setLevel(logging.DEBUG)
    app_logger.addHandler(stdout_handler)


if __name__ == '__main__':
    setup_logging()

    LOOP = asyncio.get_event_loop()
    asyncio.ensure_future(run_application(), loop=LOOP)
    LOOP.run_forever()
