import asyncio
import datetime
import os
from subprocess import Popen, check_output
import sys
import unittest
from unittest.mock import patch

import aiohttp
from freezegun import freeze_time
import mohawk

from app import run_application


class TestBase(unittest.TestCase):

    def setup_manual(self):
        ''' Test setUp function that can be customised on a per-test basis '''

        self.os_environ_patcher = patch.dict(os.environ, {
            **mock_env(),
        })
        self.os_environ_patcher.start()
        self.loop = asyncio.get_event_loop()

        original_app_runner = aiohttp.web.AppRunner

        def wrapped_app_runner(*args, **kwargs):
            self.app_runner = original_app_runner(*args, **kwargs)
            return self.app_runner

        self.app_runner_patcher = patch('aiohttp.web.AppRunner', wraps=wrapped_app_runner)
        self.app_runner_patcher.start()

    def tearDown(self):
        for task in asyncio.Task.all_tasks():
            task.cancel()
        self.loop = asyncio.get_event_loop()
        self.loop.run_until_complete(self.app_runner.cleanup())
        self.app_runner_patcher.stop()
        self.os_environ_patcher.stop()


class TestConnection(TestBase):

    def test_application_accepts_http(self):
        self.setup_manual()
        asyncio.ensure_future(run_application(), loop=self.loop)
        self.assertTrue(is_http_accepted_eventually())


class TestDigestAuthentication(TestBase):

    def test_happy_path(self):
        self.setup_manual()

        asyncio.ensure_future(run_application(), loop=self.loop)
        is_http_accepted_eventually()

        command = [
            'curl', '-D', '-',
            '--digest', '-u', 'incoming-some-id-1:incoming-some-secret-1',
            'http://127.0.0.1:8080/digest/',
            '--header', 'X-Forwarded-For: 1.2.3.4, 0.0.0.0'
        ]

        async def fetch():
            return await asyncio.get_event_loop().run_in_executor(None, check_output, command)

        response = self.loop.run_until_complete(asyncio.ensure_future(fetch()))
        self.assertIn(b'{"secret": "to-be-hidden"}', response)

    def test_bad_signature(self):
        self.setup_manual()

        asyncio.ensure_future(run_application(), loop=self.loop)
        is_http_accepted_eventually()

        command = [
            'curl', '-D', '-',
            '--digest', '-u', 'incoming-some-id-1:incoming-some-secret-1-incorrect',
            'http://127.0.0.1:8080/digest/',
            '--header', 'X-Forwarded-For: 1.2.3.4, 0.0.0.0'
        ]

        async def fetch():
            return await asyncio.get_event_loop().run_in_executor(None, check_output, command)

        response = self.loop.run_until_complete(asyncio.ensure_future(fetch()))
        self.assertIn(b'HTTP/1.1 401', response)
        self.assertNotIn(b'HTTP/1.1 200', response)
        self.assertNotIn(b'{"secret": "to-be-hidden"}', response)


class TestHawkAuthentication(TestBase):

    def test_no_auth_then_401(self):
        self.setup_manual()

        asyncio.ensure_future(run_application(), loop=self.loop)
        is_http_accepted_eventually()

        url = 'http://127.0.0.1:8080/hawk/'
        text, status, _ = self.loop.run_until_complete(get_text_no_auth(url, '1.2.3.4, 4.4.4.4'))
        self.assertEqual(status, 401)
        self.assertEqual(text, '{"details": "Authentication credentials were not provided."}')

    def test_bad_id_then_401(self):
        self.setup_manual()

        asyncio.ensure_future(run_application(), loop=self.loop)
        is_http_accepted_eventually()

        url = 'http://127.0.0.1:8080/hawk/'
        auth = auth_header(
            'incoming-some-id-incorrect', 'incoming-some-secret-1', url, 'GET', '', '',
        )
        x_forwarded_for = '1.2.3.4, 4.4.4.4'
        text, status, _ = self.loop.run_until_complete(get_text(url, auth, x_forwarded_for))
        self.assertEqual(status, 401)
        self.assertEqual(text, '{"details": "Incorrect authentication credentials."}')

    def test_bad_secret_then_401(self):
        self.setup_manual()

        asyncio.ensure_future(run_application(), loop=self.loop)
        is_http_accepted_eventually()

        url = 'http://127.0.0.1:8080/hawk/'
        auth = auth_header(
            'incoming-some-id-1', 'incoming-some-secret-2', url, 'GET', '', '',
        )
        x_forwarded_for = '1.2.3.4, 4.4.4.4'
        text, status, _ = self.loop.run_until_complete(get_text(url, auth, x_forwarded_for))
        self.assertEqual(status, 401)
        self.assertEqual(text, '{"details": "Incorrect authentication credentials."}')

    def test_bad_method_then_401(self):
        self.setup_manual()

        asyncio.ensure_future(run_application(), loop=self.loop)
        is_http_accepted_eventually()

        url = 'http://127.0.0.1:8080/hawk/'
        auth = auth_header(
            'incoming-some-id-1', 'incoming-some-secret-1', url, 'POST', '', '',
        )
        x_forwarded_for = '1.2.3.4, 4.4.4.4'
        text, status, _ = self.loop.run_until_complete(get_text(url, auth, x_forwarded_for))
        self.assertEqual(status, 401)
        self.assertEqual(text, '{"details": "Incorrect authentication credentials."}')

    def test_bad_content_then_401(self):
        self.setup_manual()

        asyncio.ensure_future(run_application(), loop=self.loop)
        is_http_accepted_eventually()

        url = 'http://127.0.0.1:8080/hawk/'
        auth = auth_header(
            'incoming-some-id-1', 'incoming-some-secret-1', url, 'GET', 'content', '',
        )
        x_forwarded_for = '1.2.3.4, 4.4.4.4'
        text, status, _ = self.loop.run_until_complete(get_text(url, auth, x_forwarded_for))
        self.assertEqual(status, 401)
        self.assertEqual(text, '{"details": "Incorrect authentication credentials."}')

    def test_bad_content_type_then_401(self):
        self.setup_manual()

        asyncio.ensure_future(run_application(), loop=self.loop)
        is_http_accepted_eventually()

        url = 'http://127.0.0.1:8080/hawk/'
        auth = auth_header(
            'incoming-some-id-1', 'incoming-some-secret-1', url, 'GET', '', 'some-type',
        )
        x_forwarded_for = '1.2.3.4, 4.4.4.4'
        text, status, _ = self.loop.run_until_complete(get_text(url, auth, x_forwarded_for))
        self.assertEqual(status, 401)
        self.assertEqual(text, '{"details": "Incorrect authentication credentials."}')

    def test_no_content_type_then_401(self):
        self.setup_manual()

        asyncio.ensure_future(run_application(), loop=self.loop)
        is_http_accepted_eventually()

        url = 'http://127.0.0.1:8080/hawk/'
        auth = auth_header(
            'incoming-some-id-1', 'incoming-some-secret-1', url, 'GET', '', 'some-type',
        )
        x_forwarded_for = '1.2.3.4, 4.4.4.4'
        _, status, _ = self.loop.run_until_complete(
            get_text_no_content_type(url, auth, x_forwarded_for))
        self.assertEqual(status, 401)

    def test_time_skew_then_401(self):
        self.setup_manual()

        asyncio.ensure_future(run_application(), loop=self.loop)
        is_http_accepted_eventually()

        url = 'http://127.0.0.1:8080/hawk/'
        past = datetime.datetime.now() + datetime.timedelta(seconds=-61)
        with freeze_time(past):
            auth = auth_header(
                'incoming-some-id-1', 'incoming-some-secret-1', url, 'GET', '', '',
            )
        x_forwarded_for = '1.2.3.4, 4.4.4.4'
        text, status, _ = self.loop.run_until_complete(get_text(url, auth, x_forwarded_for))
        self.assertEqual(status, 401)
        self.assertEqual(text, '{"details": "Incorrect authentication credentials."}')

    def test_repeat_auth_then_401(self):
        self.setup_manual()

        asyncio.ensure_future(run_application(), loop=self.loop)
        is_http_accepted_eventually()

        url = 'http://127.0.0.1:8080/hawk/'
        auth = auth_header(
            'incoming-some-id-1', 'incoming-some-secret-1', url, 'GET', '', '',
        )
        x_forwarded_for = '1.2.3.4, 4.4.4.4'
        _, status_1, _ = self.loop.run_until_complete(get_text(url, auth, x_forwarded_for))
        self.assertEqual(status_1, 200)

        text_2, status_2, _ = self.loop.run_until_complete(get_text(url, auth, x_forwarded_for))
        self.assertEqual(status_2, 401)
        self.assertEqual(text_2, '{"details": "Incorrect authentication credentials."}')

    def test_nonces_cleared(self):
        ''' Makes duplicate requests, but with the code patched so the nonce expiry time
            is shorter then the allowed Hawk skew. The second request succeeding gives
            evidence that the cache of nonces was cleared.
        '''
        self.setup_manual()

        now = datetime.datetime.now()
        past = now + datetime.timedelta(seconds=-45)

        with patch('app.NONCE_EXPIRE', 30):
            asyncio.ensure_future(run_application(), loop=self.loop)
            is_http_accepted_eventually()

            url = 'http://127.0.0.1:8080/hawk/'
            x_forwarded_for = '1.2.3.4, 4.4.4.4'

            with freeze_time(past):
                auth = auth_header(
                    'incoming-some-id-1', 'incoming-some-secret-1', url, 'GET', '', '',
                )
                _, status_1, _ = self.loop.run_until_complete(
                    get_text(url, auth, x_forwarded_for))
            self.assertEqual(status_1, 200)

            with freeze_time(now):
                _, status_2, _ = self.loop.run_until_complete(
                    get_text(url, auth, x_forwarded_for))
            self.assertEqual(status_2, 200)

    def test_no_x_forwarded_for_401(self):
        self.setup_manual()

        asyncio.ensure_future(run_application(), loop=self.loop)
        is_http_accepted_eventually()

        url = 'http://127.0.0.1:8080/hawk/'
        auth = auth_header(
            'incoming-some-id-1', 'incoming-some-secret-1', url, 'GET', '', '',
        )
        text, status, _ = self.loop.run_until_complete(get_text_no_x_forwarded_for(url, auth))
        self.assertEqual(status, 401)
        self.assertEqual(text, '{"details": "Incorrect authentication credentials."}')

    def test_bad_x_forwarded_for_401_v1(self):
        self.setup_manual()

        asyncio.ensure_future(run_application(), loop=self.loop)
        is_http_accepted_eventually()

        url = 'http://127.0.0.1:8080/hawk/'
        auth = auth_header(
            'incoming-some-id-1', 'incoming-some-secret-1', url, 'GET', '', '',
        )
        x_forwarded_for = '1.2.3.4'
        text, status, _ = self.loop.run_until_complete(get_text(url, auth, x_forwarded_for))
        self.assertEqual(status, 401)
        self.assertEqual(text, '{"details": "Incorrect authentication credentials."}')

    def test_bad_x_forwarded_for_401_v2(self):
        self.setup_manual()

        asyncio.ensure_future(run_application(), loop=self.loop)
        is_http_accepted_eventually()

        url = 'http://127.0.0.1:8080/hawk/'
        auth = auth_header(
            'incoming-some-id-1', 'incoming-some-secret-1', url, 'GET', '', '',
        )
        x_forwarded_for = '3.4.5.6'
        text, status, _ = self.loop.run_until_complete(get_text(url, auth, x_forwarded_for))
        self.assertEqual(status, 401)
        self.assertEqual(text, '{"details": "Incorrect authentication credentials."}')

    def test_bad_x_forwarded_for_401_v3(self):
        self.setup_manual()

        asyncio.ensure_future(run_application(), loop=self.loop)
        is_http_accepted_eventually()

        url = 'http://127.0.0.1:8080/hawk/'
        auth = auth_header(
            'incoming-some-id-1', 'incoming-some-secret-1', url, 'GET', '', '',
        )
        x_forwarded_for = '3.4.5.6, 1.2.3.4'
        text, status, _ = self.loop.run_until_complete(get_text(url, auth, x_forwarded_for))
        self.assertEqual(status, 401)
        self.assertEqual(text, '{"details": "Incorrect authentication credentials."}')

    def test_bad_x_forwarded_for_401_v4(self):
        self.setup_manual()

        asyncio.ensure_future(run_application(), loop=self.loop)
        is_http_accepted_eventually()

        url = 'http://127.0.0.1:8080/hawk/'
        auth = auth_header(
            'incoming-some-id-1', 'incoming-some-secret-1', url, 'GET', '', '',
        )
        x_forwarded_for = '1.2.3.4, 3.4.5.6, 7.8.9.10'
        text, status, _ = self.loop.run_until_complete(get_text(url, auth, x_forwarded_for))
        self.assertEqual(status, 401)
        self.assertEqual(text, '{"details": "Incorrect authentication credentials."}')

    def test_bad_x_forwarded_for_401_v5(self):
        self.setup_manual()

        asyncio.ensure_future(run_application(), loop=self.loop)
        is_http_accepted_eventually()

        url = 'http://127.0.0.1:8080/hawk/'
        auth = auth_header(
            'incoming-some-id-1', 'incoming-some-secret-1', url, 'GET', '', '',
        )
        x_forwarded_for = '3.4.5.6, 1.2.3.4'
        text, status, _ = self.loop.run_until_complete(get_text(url, auth, x_forwarded_for))
        self.assertEqual(status, 401)
        self.assertEqual(text, '{"details": "Incorrect authentication credentials."}')

    def test_second_id_returns_object(self):
        self.setup_manual()

        asyncio.ensure_future(run_application(), loop=self.loop)
        is_http_accepted_eventually()

        url = 'http://127.0.0.1:8080/hawk/'
        auth = auth_header(
            'incoming-some-id-2', 'incoming-some-secret-2', url, 'GET', '', '',
        )
        x_forwarded_for = '1.2.3.4, 4.4.4.4'
        text, status, _ = self.loop.run_until_complete(get_text(url, auth, x_forwarded_for))
        self.assertEqual(status, 200)
        self.assertEqual(text, '{"secret": "to-be-hidden"}')

    def test_get_returns_object(self):
        self.setup_manual()

        asyncio.ensure_future(run_application(), loop=self.loop)
        is_http_accepted_eventually()

        url = 'http://127.0.0.1:8080/hawk/'
        auth = auth_header(
            'incoming-some-id-1', 'incoming-some-secret-1', url, 'GET', '', '',
        )
        x_forwarded_for = '1.2.3.4, 4.4.4.4'
        text, status, _ = self.loop.run_until_complete(get_text(url, auth, x_forwarded_for))
        self.assertEqual(status, 200)
        self.assertEqual(text, '{"secret": "to-be-hidden"}')


class TestProcess(unittest.TestCase):

    def setUp(self):
        self.server = Popen([sys.executable, '-m', 'app'], env={
            **mock_env(),
        })

    def tearDown(self):
        for task in asyncio.Task.all_tasks():
            task.cancel()
        self.server.kill()

    def test_server_accepts_http(self):
        self.assertTrue(is_http_accepted_eventually())


def is_http_accepted_eventually():
    loop = asyncio.get_event_loop()
    connected_future = asyncio.ensure_future(_is_http_accepted_eventually(), loop=loop)
    return loop.run_until_complete(connected_future)


async def _is_http_accepted_eventually():
    def is_connection_error(exception):
        return 'Cannot connect to host' in str(exception)

    attempts = 0
    while attempts < 20:
        try:
            async with aiohttp.ClientSession() as session:
                await session.get('http://127.0.0.1:8080', timeout=1)
            return True
        except aiohttp.client_exceptions.ClientConnectorError as exception:
            attempts += 1
            await asyncio.sleep(0.2)
            if not is_connection_error(exception):
                return True

    return False


def auth_header(key_id, secret_key, url, method, content, content_type):
    return mohawk.Sender({
        'id': key_id,
        'key': secret_key,
        'algorithm': 'sha256',
    }, url, method, content=content, content_type=content_type).request_header


async def get_text(url, auth, x_forwarded_for):
    async with aiohttp.ClientSession() as session:
        result = await session.get(url, headers={
            'Authorization': auth,
            'Content-Type': '',
            'X-Forwarded-For': x_forwarded_for,
            'X-Forwarded-Proto': 'http',
        }, timeout=1)
    return (await result.text(), result.status, result.headers)


async def get_text_no_auth(url, x_forwarded_for):
    async with aiohttp.ClientSession() as session:
        result = await session.get(url, headers={
            'Content-Type': '',
            'X-Forwarded-For': x_forwarded_for,
            'X-Forwarded-Proto': 'http',
        }, timeout=1)
    return (await result.text(), result.status, result.headers)


async def get_text_no_x_forwarded_for(url, auth):
    async with aiohttp.ClientSession() as session:
        headers = {
            'Authorization': auth,
            'Content-Type': '',
            'X-Forwarded-Proto': 'http',
        }
        result = await session.get(url, headers=headers, timeout=1)
    return (await result.text(), result.status, result.headers)


async def get_text_no_content_type(url, auth, x_forwarded_for):
    async with aiohttp.ClientSession() as session:
        result = await session.get(url, headers={
            'Authorization': auth,
            'X-Forwarded-For': x_forwarded_for,
            'X-Forwarded-Proto': 'http',
        }, timeout=1)

    return (await result.text(), result.status, result.headers)


def mock_env():
    return {
        'INCOMING_ACCESS_KEY_PAIRS_HAWK__1__KEY_ID': 'incoming-some-id-1',
        'INCOMING_ACCESS_KEY_PAIRS_HAWK__1__SECRET_KEY': 'incoming-some-secret-1',
        'INCOMING_ACCESS_KEY_PAIRS_HAWK__2__KEY_ID': 'incoming-some-id-2',
        'INCOMING_ACCESS_KEY_PAIRS_HAWK__2__SECRET_KEY': 'incoming-some-secret-2',
        'INCOMING_ACCESS_KEY_PAIRS_DIGEST__1__KEY_ID': 'incoming-some-id-1',
        'INCOMING_ACCESS_KEY_PAIRS_DIGEST__1__SECRET_KEY': 'incoming-some-secret-1',
        'INCOMING_IP_WHITELIST__1': '1.2.3.4',
        'INCOMING_IP_WHITELIST__2': '2.3.4.5',
        'PORT': '8080',
    }
