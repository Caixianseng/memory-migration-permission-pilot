"""Pure HTTP fixtures for routing/receipts; never starts Open WebUI or a model."""
import unittest
from unittest.mock import patch
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import uuid
from scripts import native_webui_projection_worker as m

class Cookies:

    def __init__(self):
        self.clears = 0

    def clear(self):
        self.clears += 1

class Response:

    def __init__(self, value=None, status=200, *, raw=None):
        self.content = raw if raw is not None else json.dumps(value).encode()
        self.status_code = status
        self.request = SimpleNamespace(headers={})

    def json(self):
        return json.loads(self.content)

class FakeClient:

    def __init__(self, responses=()):
        self.responses = list(responses)
        self.cookies = Cookies()
        self.calls = []

    def request(self, method, path, **kwargs):
        self.calls.append((method, path, deepcopy(kwargs)))
        response = self.responses.pop(0)
        response.request.headers = {k.lower(): v for k, v in kwargs.get('headers', {}).items()}
        return response

def recorder(tmp_path, responses=(), cap=200):
    client = FakeClient(responses)
    result = m.SafeHTTPRecorder(client, tmp_path / uuid.uuid4().hex, http_cap=cap)
    result.tokens = {a: 'fixture-token-value-for-' + a for a in m.ACTORS}
    for value in result.tokens.values():
        result.remember(value)
    return (result, client)

def worker(tmp_path, responses=()):
    w = m.WebUIProjectionWorker(state=Path(tempfile.gettempdir()) / ('webui_fake_' + uuid.uuid4().hex))
    w.ready = True
    w.stage = 'fake_http_fixtures_only'
    w.recorder, client = recorder(tmp_path, responses)
    w.identities = {a: {'id': 'fake-native-' + a, 'role': 'user'} for a in m.ACTORS}
    w.inference = SimpleNamespace(verify=lambda: None, events=[], close=lambda: None)
    w.datasets = {'readonly': {'id': 'fake-note-ro', 'name': 'controlled_readonly', 'owner': 'owner'}}
    w.facts = {'readonly': {'id': 'fake-file-ro', 'dataset': 'readonly', 'text_sha256': m.sha(b'SYNTHETIC_VALUE_A71')}}
    w.readers = {'readonly': set()}
    return (w, client)

class IdentityClient(FakeClient):
    """Models only auth response contracts, never a real security backend."""

    def __init__(self):
        super().__init__()
        self.users, self.tokens = ({}, {})

    def request(self, method, path, **kwargs):
        self.calls.append((method, path, deepcopy(kwargs)))
        if path in {'/api/v1/auths/add', '/api/v1/auths/signup'}:
            body = kwargs['json']
            actor = body['name'][len('controlled-'):]
            self.users[body['email']] = {'id': 'fake-id-' + actor, 'email': body['email'], 'role': body.get('role', 'admin')}
            response = Response({'ok': True})
        elif path == '/api/v1/auths/signin':
            user = dict(self.users[kwargs['json']['email']])
            token = 'fake-distinct-token-for-' + user['id']
            self.tokens[token] = user
            response = Response({**user, 'token': token})
        elif path == '/api/v1/auths/':
            token = kwargs['headers']['Authorization'].removeprefix('Bearer ')
            response = Response({**self.tokens[token], 'token': token})
        else:
            raise AssertionError('unexpected_fake_auth_route')
        response.request.headers = {k.lower(): v for k, v in kwargs.get('headers', {}).items()}
        return response

class NativeWebUIProjectionWorkerTests(unittest.TestCase):

    def setUp(self):
        self._temporary = tempfile.TemporaryDirectory(prefix='native_webui_fake_')
        self.tmp_path = Path(self._temporary.name).resolve()
        self.assertTrue(self.tmp_path.is_relative_to(Path(tempfile.gettempdir()).resolve()))
        self.addCleanup(self._temporary.cleanup)

    def test_raw_native_bytes_preserved_without_json_wrapping(self):
        w, client = worker(self.tmp_path, [Response(raw=b'SYNTHETIC_VALUE_A71')])
        result = w('read_raw', {'dataset': 'readonly', 'fact_key': 'readonly', 'actor': 'alice_reader'})
        trace = result['trace']
        self.assertTrue(client.calls[0][:2] == ('GET', '/api/v1/files/fake-file-ro/content'))
        self.assertTrue(trace['native_raw_body'] == 'SYNTHETIC_VALUE_A71')
        self.assertTrue(trace['byte_count'] == 19)
        self.assertTrue(Path(trace['native_response_file']).read_bytes() == b'SYNTHETIC_VALUE_A71')
        self.assertTrue(trace['native_body_sha256'] == hashlib.sha256(b'SYNTHETIC_VALUE_A71').hexdigest())

    def test_denial_is_actual_native_status_not_local_acl_filter(self):
        w, client = worker(self.tmp_path, [Response({'detail': 'Not found'}, 404)])
        result = w('read_raw', {'dataset': 'readonly', 'fact_key': 'readonly', 'actor': 'bob_worker'})
        self.assertTrue(result['status'] == 404)
        self.assertTrue(len(client.calls) == 1)
        self.assertTrue(result['trace']['response_checked'] is True)

    def test_list_calls_return_original_arrays_and_note_file_association(self):
        note = {'id': 'fake-note-ro', 'data': {'files': [{'type': 'file', 'id': 'fake-file-ro'}]}}
        w, client = worker(self.tmp_path, [Response([{'id': 'fake-note-ro'}]), Response(note)])
        listing = w('list_datasets', {'actor': 'alice_reader'})
        detail = w('list_data', {'dataset': 'readonly', 'actor': 'alice_reader'})
        self.assertTrue(json.loads(listing['trace']['native_raw_body']) == [{'id': 'fake-note-ro'}])
        self.assertTrue(json.loads(detail['trace']['native_raw_body']) == note)
        self.assertTrue(client.calls[0][1] == '/api/v1/notes/')
        self.assertTrue('params' not in client.calls[0][2])

    def test_only_read_actor_share_attempt_reaches_native_http(self):
        w, client = worker(self.tmp_path, [Response({'detail': 'Forbidden'}, 403)])
        w.readers['readonly'] = {'alice_reader'}
        result = w('grant', {'dataset': 'readonly', 'actor': 'alice_reader', 'recipient': 'bob_worker', 'permission': 'read'})
        self.assertTrue(result['status'] == 403)
        self.assertTrue(client.calls[0][:2] == ('POST', '/api/v1/notes/fake-note-ro/access/update'))
        self.assertTrue(w.readers['readonly'] == {'alice_reader'})

    def test_grant_and_revoke_preserve_other_recipients(self):
        bob = {'principal_type': 'user', 'principal_id': 'fake-native-bob_reader', 'permission': 'read'}
        alice = {'principal_type': 'user', 'principal_id': 'fake-native-alice_reader', 'permission': 'read'}
        w, client = worker(self.tmp_path, [Response({'access_grants': [alice, bob]}), Response({'access_grants': [bob]})])
        w.readers['readonly'] = {'bob_reader'}
        self.assertTrue(w('grant', {'dataset': 'readonly', 'actor': 'owner', 'recipient': 'alice_reader', 'permission': 'read'})['status'] == 200)
        self.assertTrue(w('revoke', {'dataset': 'readonly', 'actor': 'owner', 'recipient': 'alice_reader', 'permission': 'read'})['status'] == 200)
        self.assertTrue(w.readers['readonly'] == {'bob_reader'})
        self.assertTrue(client.calls[1][2]['json'] == {'access_grants': [bob]})

    def test_native_acl_postcondition_mismatch_is_not_reported_success(self):
        w, client = worker(self.tmp_path, [Response({'access_grants': []})])
        with self.assertRaisesRegex(m.ProjectionError, 'native_acl_response_not_exact_requested_set'):
            w('grant', {'dataset': 'readonly', 'actor': 'owner', 'recipient': 'alice_reader', 'permission': 'read'})
        self.assertTrue(w.readers['readonly'] == set())
        self.assertTrue(w.recorder.requests[0]['status'] == 200)

    def test_add_uses_formal_no_process_upload_then_note_attachment(self):
        upload = {'id': 'fake-file-managed', 'user_id': 'fake-native-owner'}
        attach = {'data': {'files': [{'type': 'file', 'id': 'fake-file-managed'}]}}
        w, client = worker(self.tmp_path, [Response(upload), Response(attach), Response(raw=b'SYNTHETIC_VALUE_B92')])
        w.datasets['managed'] = {'id': 'fake-note-managed', 'name': 'controlled_managed', 'owner': 'owner'}
        w.readers['managed'] = set()
        result = w('add_exact_fact', {'dataset': 'managed', 'fact_key': 'managed', 'actor': 'owner', 'text': 'SYNTHETIC_VALUE_B92'})
        self.assertTrue(result['id'] == 'fake-file-managed')
        self.assertTrue(client.calls[0][:2] == ('POST', '/api/v1/files/'))
        self.assertTrue(client.calls[0][2]['params'] == {'process': 'false', 'process_in_background': 'false'})
        self.assertTrue(client.calls[0][2]['files']['file'][1] == b'SYNTHETIC_VALUE_B92')
        self.assertTrue(client.calls[1][1] == '/api/v1/notes/fake-note-managed/update')
        self.assertTrue(w.facts['managed']['id'] == 'fake-file-managed')
        self.assertTrue(result['trace']['native_raw_body'] == 'SYNTHETIC_VALUE_B92')

    def test_summary_has_mapping_without_any_http_request(self):
        w, client = worker(self.tmp_path)
        summary = w('summary', {})
        self.assertTrue(client.calls == [])
        self.assertTrue(summary['datasets']['readonly']['id'] == 'fake-note-ro')
        self.assertTrue(summary['facts']['readonly']['id'] == 'fake-file-ro')
        self.assertTrue(summary['native_agent_authentication'] is False)
        self.assertTrue(summary['vector_or_semantic_search_measured'] is False)

    def test_create_dataset_has_cognee_compatible_id_and_native_note_mapping(self):
        body = {'id': 'fake-managed-note', 'user_id': 'fake-native-owner', 'access_grants': []}
        w, client = worker(self.tmp_path, [Response(body)])
        result = w('create_dataset', {'dataset': 'managed', 'actor': 'owner'})
        self.assertTrue(result['id'] == result['dataset']['id'] == 'fake-managed-note')
        self.assertTrue(result['logical_dataset'] == 'managed')
        self.assertTrue(result['trace']['native_raw_body'] == json.dumps(body))
        self.assertTrue(client.calls[0][:2] == ('POST', '/api/v1/notes/create'))
        self.assertTrue(client.calls[0][2]['json']['access_grants'] == [])
        self.assertTrue(client.calls[0][2]['json']['data']['files'] == [])

    def test_http_cap_is_checked_before_forwarding(self):
        r, client = recorder(self.tmp_path, [Response(raw=b'ok')], cap=1)
        r.request('GET', '/api/v1/notes/', actor='owner')
        with self.assertRaisesRegex(m.ProjectionError, 'native_http_cap_exhausted'):
            r.request('GET', '/api/v1/notes/', actor='owner')
        self.assertTrue(len(client.calls) == len(r.requests) == 1)

    def test_auth_request_and_response_never_persisted(self):
        r, client = recorder(self.tmp_path, [Response({'token': 'an-in-memory-auth-token'})])
        r.request('POST', '/api/v1/auths/signin', credential=True, json={'password': 'a-fake-password'})
        trace = r.requests[0]
        self.assertTrue(trace['credential_response_omitted'] is True)
        self.assertTrue(not any((k in trace for k in ('request_json', 'native_raw_body', 'native_body_sha256', 'native_response_file'))))
        self.assertTrue(list(r.directory.iterdir()) == [])

    def _assert_credential_field_blocked(self, body):
        r, _ = recorder(self.tmp_path, [Response(body)])
        with self.assertRaisesRegex(m.ProjectionError, 'credential_field_in_response'):
            r.request('GET', '/api/v1/notes/', actor='owner')
        self.assertTrue('native_raw_body' not in r.requests[0])
        self.assertTrue(list(r.directory.iterdir()) == [])

    def test_actual_token_value_in_plain_response_blocked(self):
        r, _ = recorder(self.tmp_path, [Response(raw=b'fixture-token-value-for-owner')])
        with self.assertRaisesRegex(m.ProjectionError, 'credential_value_in_response'):
            r.request('GET', '/api/v1/notes/', actor='owner')
        self.assertTrue('native_raw_body' not in r.requests[0])

    def test_unregistered_actor_or_extra_claim_does_not_reach_native(self):
        w, client = worker(self.tmp_path)
        with self.assertRaises(m.ProjectionError):
            w('read_raw', {'dataset': 'readonly', 'fact_key': 'readonly', 'actor': 'admin'})
        with self.assertRaises(m.ProjectionError):
            w('read_raw', {'dataset': 'readonly', 'fact_key': 'readonly', 'actor': 'alice_reader', 'is_admin': True})
        self.assertTrue(client.calls == [])

    def test_unsupported_vector_or_knowledge_commands_do_not_forward(self):
        w, client = worker(self.tmp_path)
        for command in ('query_vector', 'create_knowledge', 'llm'):
            with self.assertRaisesRegex(m.ProjectionError, 'unsupported_native_command'):
                w(command, {})
        self.assertTrue(client.calls == [])

    def test_inference_classifier_counts_attempt_not_success(self):
        self.assertTrue(m.InferenceBoundary.classify('open_webui.retrieval.utils', 'async_embedding_function') == 'embedding')
        self.assertTrue(m.InferenceBoundary.classify('open_webui.routers.knowledge', 'embed_knowledge_base_metadata') == 'embedding')
        self.assertTrue(m.InferenceBoundary.classify('openai.resources.chat.completions', 'create') == 'generation')
        self.assertTrue(m.InferenceBoundary.classify('open_webui.routers.retrieval', 'get_ef') is None)

    def test_state_must_be_new_ascii_system_temp(self):
        with self.assertRaisesRegex(m.ProjectionError, 'new_ascii_system_temp_state_required'):
            m.WebUIProjectionWorker(state=Path(tempfile.gettempdir()))
        with self.assertRaisesRegex(m.ProjectionError, 'new_ascii_system_temp_state_required'):
            m.WebUIProjectionWorker(state=Path(tempfile.gettempdir()) / '非ASCII-state')

    def test_declared_configuration_uses_no_local_embedding_model(self):
        state = self.tmp_path / 'state'
        state.mkdir()
        with patch.object(m, 'isolate_environment', lambda _state: None), patch.object(m.os, 'environ', {}):
            settings = m.configure(state)
            self.assertEqual(settings['RAG_EMBEDDING_ENGINE'], '')
            self.assertEqual(settings['RAG_EMBEDDING_MODEL'], '')
            self.assertEqual(settings['ENABLE_OLLAMA_API'], 'false')
            self.assertEqual(settings['ENABLE_OPENAI_API'], 'false')
            self.assertEqual(settings['OLLAMA_BASE_URL'], 'http://127.0.0.1:9')
            self.assertEqual(settings['WEBUI_AUTH'], 'true')
            self.assertNotIn('WEBUI_SECRET_KEY', settings)
            self.assertTrue(m.os.environ['WEBUI_SECRET_KEY'])

    def test_six_identity_bootstrap_contract_uses_independent_signin_and_whoami(self):
        client = IdentityClient()
        r = m.SafeHTTPRecorder(client, self.tmp_path / 'identity_responses', http_cap=200)
        identities = m.create_identities(r)
        self.assertTrue(set(identities) == {'bootstrap_admin', *m.ACTORS})
        self.assertTrue(len({v['id'] for v in identities.values()}) == 6)
        self.assertTrue(identities['bootstrap_admin']['role'] == 'admin')
        self.assertTrue(all((identities[a]['role'] == 'user' for a in m.ACTORS)))
        self.assertTrue(len(client.calls) == 17)
        self.assertTrue(all((q['credential_response_omitted'] for q in r.requests)))
        self.assertTrue(all(('native_raw_body' not in q for q in r.requests)))
        self.assertTrue(client.cookies.clears == 17)

    def test_credential_password_field_blocked_before_persistence(self):
        self._assert_credential_field_blocked({'password': 'not-a-real-password'})

    def test_credential_api_key_field_blocked_before_persistence(self):
        self._assert_credential_field_blocked({'api_key': 'not-a-real-key'})

    def test_credential_token_field_blocked_before_persistence(self):
        self._assert_credential_field_blocked({'token': 'not-a-real-token'})
if __name__ == '__main__':
    unittest.main()
