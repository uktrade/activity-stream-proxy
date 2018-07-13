import asyncio
import hashlib
import hmac
import functools
import itertools
import logging
import os
import re
import secrets
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
    env = normalise_environment(os.environ)
    port = env['PORT']

    incoming_key_pairs_hawk = {
        key_pair['KEY_ID']: key_pair['SECRET_KEY']
        for key_pair in env['INCOMING_ACCESS_KEY_PAIRS_HAWK']
    }
    incoming_key_pairs_digest = {
        key_pair['KEY_ID']: key_pair['SECRET_KEY']
        for key_pair in env['INCOMING_ACCESS_KEY_PAIRS_DIGEST']
    }
    ip_whitelist = env['INCOMING_IP_WHITELIST']

    await create_incoming_application(
        port, ip_whitelist, incoming_key_pairs_hawk, incoming_key_pairs_digest,
    )


def lookup_credentials(incoming_key_pairs, passed_access_key_id):
    if passed_access_key_id not in incoming_key_pairs:
        raise HawkFail(f'No Hawk ID of {passed_access_key_id}')

    return {
        'id': passed_access_key_id,
        'key': incoming_key_pairs[passed_access_key_id],
        'algorithm': 'sha256',
    }


def seen_nonce(seen_nonces, access_key_id, nonce, _):
    nonce_tuple = (access_key_id, nonce)
    seen = nonce_tuple in seen_nonces
    if not seen:
        seen_nonces.add(nonce_tuple)
    return seen


def authenticate_by_ip(ip_whitelist):
    app_logger = logging.getLogger(__name__)

    @web.middleware
    async def _authenticate_by_ip(request, handler):
        if 'X-Forwarded-For' not in request.headers:
            app_logger.warning(
                'Failed authentication: no X-Forwarded-For header passed'
            )
            return web.json_response({
                'details': INCORRECT,
            }, status=401)

        # PaaS appends 2 IPs, where the IP connected from is the first of the two
        ip_addesses = request.headers['X-Forwarded-For'].split(',')
        if len(ip_addesses) < 2:
            app_logger.warning(
                'Failed authentication: the X-Forwarded-For header does not '
                'contain enough IP addresses'
            )
            return web.json_response({
                'details': INCORRECT,
            }, status=401)

        remote_address = ip_addesses[-2].strip()

        if remote_address not in ip_whitelist:
            app_logger.warning(
                'Failed authentication: the X-Forwarded-For header did not '
                'start with an IP in the whitelist'
            )
            return web.json_response({
                'details': INCORRECT,
            }, status=401)

        return await handler(request)
    return _authenticate_by_ip


def authenticate_by_hawk(incoming_key_pairs):
    app_logger = logging.getLogger(__name__)

    # This would need to be stored externally if this was ever to be load balanced,
    # otherwise replay attacks could succeed by hitting another instance
    seen_nonces = ExpiringSet(NONCE_EXPIRE)

    async def raise_if_not_authentic(request):
        mohawk.Receiver(
            functools.partial(lookup_credentials, incoming_key_pairs),
            request.headers['Authorization'],
            str(request.url),
            request.method,
            content=await request.content.read(),
            content_type=request.headers['Content-Type'],
            seen_nonce=functools.partial(seen_nonce, seen_nonces),
        )

    @web.middleware
    async def _authenticate_by_hawk(request, handler):
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
    return _authenticate_by_hawk


def authenticate_by_digest(incoming_key_pairs):
    app_logger = logging.getLogger(__name__)

    # This would need to be stored externally if this was ever to be load balanced,
    # otherwise replay attacks could succeed by hitting another instance
    server_nonces_generated = ExpiringSet(NONCE_EXPIRE)
    server_nonces_used = ExpiringSet(NONCE_EXPIRE)
    client_nonces_used = ExpiringSet(NONCE_EXPIRE)

    correct_realm = 'activity-stream'
    correct_qop = 'auth-int'

    def secure_compare(val_a, val_b):
        return hmac.compare_digest(val_a, val_b)

    def www_authenticate_401():
        nonce = secrets.token_hex(64)
        server_nonces_generated.add(nonce)
        www_authenticate = f'Digest ' + \
                           f'realm="{correct_realm}", ' + \
                           f'qop="{correct_qop}", ' + \
                           f'algorithm=SHA-256, ' + \
                           f'nonce="{nonce}", '

        return web.json_response({
            'details': INCORRECT,
        }, headers={
            'WWW-Authenticate': www_authenticate,
        }, status=401)

    @web.middleware
    async def _authenticate_by_digest(request, handler):
        if 'Authorization' not in request.headers:
            return www_authenticate_401()

        header = request.headers['Authorization']
        components = dict(re.findall(r'([a-z]+)="([^"]+)"', header))

        bad_nonce = \
            components['nonce'] not in server_nonces_generated or \
            components['nonce'] in server_nonces_used or \
            components['cnonce'] in client_nonces_used
        if bad_nonce:
            app_logger.warning('bad nonce')
            return www_authenticate_401()

        matching_pairs = [
            (key_id, secret_key)
            for (key_id, secret_key) in incoming_key_pairs.items()
            if secure_compare(components['username'], key_id)
        ]

        if not matching_pairs:
            app_logger.warning('Username of %s not found', components['username'])
            return www_authenticate_401()

        correct_username, correct_password = matching_pairs[0]

        def hex_hash(string):
            return hashlib.sha256(string.encode('utf-8')).hexdigest()

        hmac_body_hash = hex_hash((await request.read()).decode('utf-8'))
        hmac_data_hash = hex_hash(
            f'{request.method}:{request.url.path}:{hmac_body_hash}')
        hmac_secret_hash = hex_hash(
            f'{correct_username}:{correct_realm}:{correct_password}')

        nonce_c = '00000001'  # We only allow cnonce to be used once
        hmac_value = hex_hash(
            f'{hmac_secret_hash}:{components["nonce"]}:'
            f'{nonce_c}:{components["cnonce"]}:{correct_qop}:'
            f'{hmac_data_hash}')

        if not secure_compare(components['response'], hmac_value):
            app_logger.warning('Response incorrect')
            return www_authenticate_401()

        server_nonces_used.add(components['nonce'])
        client_nonces_used.add(components['cnonce'])

        return await handler(request)

    return _authenticate_by_digest


async def create_incoming_application(port, ip_whitelist,
                                      incoming_key_pairs_hawk, incoming_key_pairs_digest):
    app_logger = logging.getLogger(__name__)

    async def handle(_):
        return web.json_response({'secret': 'to-be-hidden'})

    app_logger.debug('Creating listening web application...')
    app = web.Application(middlewares=[authenticate_by_ip(ip_whitelist)])

    hawk_app = web.Application(middlewares=[authenticate_by_hawk(incoming_key_pairs_hawk)])
    hawk_app.add_routes([web.get('/', handle)])
    app.add_subapp('/hawk/', hawk_app)

    digest_app = web.Application(middlewares=[authenticate_by_digest(incoming_key_pairs_digest)])
    digest_app.add_routes([web.get('/', handle)])
    app.add_subapp('/digest/', digest_app)

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


def normalise_environment(key_values):
    ''' Converts denormalised dict of (string -> string) pairs, where the first string
        is treated as a path into a nested list/dictionary structure

        {
            "FOO__1__BAR": "setting-1",
            "FOO__1__BAZ": "setting-2",
            "FOO__2__FOO": "setting-3",
            "FOO__2__BAR": "setting-4",
            "FIZZ": "setting-5",
        }

        to the nested structure that this represents

        {
            "FOO": [{
                "BAR": "setting-1",
                "BAZ": "setting-2",
            }, {
                "BAR": "setting-1",
                "BAZ": "setting-2",
            }],
            "FIZZ": "setting-5",
        }

        If all the keys for that level parse as integers, then its treated as a list
        with the actual keys only used for sorting

        This function is recursive, but it would be extremely difficult to hit a stack
        limit, and this function would typically by called once at the start of a
        program, so efficiency isn't too much of a concern.
    '''

    # Separator is chosen to
    # - show the structure of variables fairly easily;
    # - avoid problems, since underscores are usual in environment variables
    separator = '__'

    def get_first_component(key):
        return key.split(separator)[0]

    def get_later_components(key):
        return separator.join(key.split(separator)[1:])

    without_more_components = {
        key: value
        for key, value in key_values.items()
        if not get_later_components(key)
    }

    with_more_components = {
        key: value
        for key, value in key_values.items()
        if get_later_components(key)
    }

    def grouped_by_first_component(items):
        def by_first_component(item):
            return get_first_component(item[0])

        # groupby requires the items to be sorted by the grouping key
        return itertools.groupby(
            sorted(items, key=by_first_component),
            by_first_component,
        )

    def items_with_first_component(items, first_component):
        return {
            get_later_components(key): value
            for key, value in items
            if get_first_component(key) == first_component
        }

    nested_structured_dict = {
        **without_more_components, **{
            first_component: normalise_environment(
                items_with_first_component(items, first_component))
            for first_component, items in grouped_by_first_component(with_more_components.items())
        }}

    def all_keys_are_ints():
        def is_int(string):
            try:
                int(string)
                return True
            except ValueError:
                return False

        return all([is_int(key) for key, value in nested_structured_dict.items()])

    def list_sorted_by_int_key():
        return [
            value
            for key, value in sorted(
                nested_structured_dict.items(),
                key=lambda key_value: int(key_value[0])
            )
        ]

    return \
        list_sorted_by_int_key() if all_keys_are_ints() else \
        nested_structured_dict


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
