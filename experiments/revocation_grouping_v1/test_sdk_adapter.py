import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('group_sdk_adapter', Path(__file__).with_name('sdk_adapter.py'))
sdk = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sdk)


class AdapterContractTests(unittest.TestCase):
    def test_failed_dispatch_keeps_reservation_and_stops_new_jobs(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(sdk, '_restrict_private_dir'):
            client = sdk.FlashSDKClient(Path(temp).resolve(), 3, 3)
            with patch.object(client, '_exchange', side_effect=RuntimeError('native error must stay private')):
                with self.assertRaisesRegex(sdk.SDKAdapterError, '^sdk_runtime_failure$'):
                    client.generate([{'role': 'user', 'content': 'new source'}], 'failed', 256, 'source')
            self.assertGreater(client._totals()[1], 0)
            self.assertTrue((client.root / 'STOPPED.json').exists())
            with self.assertRaisesRegex(sdk.SDKAdapterError, 'unresolved_job'):
                client.generate([{'role': 'user', 'content': 'next'}], 'next', 256, 'source')
            self.assertFalse((client.root / 'job-next').exists())

    def test_duplicate_job_preserves_existing_receipt(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(sdk, '_restrict_private_dir'):
            client = sdk.FlashSDKClient(Path(temp).resolve(), 3, 3)
            job = client.root / 'job-old'
            job.mkdir()
            sdk.save(job / 'reservation.json', {'reservation_cny': '0.08'})
            sdk.save(job / 'receipt.json', {'status': 'ok', 'estimated_peak_cost_cny': '0.00036',
                'input_tokens': 100, 'output_tokens': 20, 'usage': {'inputTokens': 100, 'outputTokens': 20, 'totalTokens': 120}})
            before = (job / 'receipt.json').read_bytes()
            with self.assertRaisesRegex(sdk.SDKAdapterError, 'job_limit_or_duplicate_no_retry'):
                client.generate([{'role': 'user', 'content': 'new'}], 'old', 256, 'source')
            self.assertEqual((job / 'receipt.json').read_bytes(), before)
            self.assertFalse((client.root / 'STOPPED.json').exists())

    def test_usage_and_price_use_reported_tokens(self):
        summary = {'last_terminal_reason': {'kind': 'completed'}, 'final_assistant_interrupted': False,
                   'final_assistant_text': 'answer', 'final_assistant_source': {'provider': 'deepseek-account', 'model': 'deepseek-flash'},
                   'assistant_usage_events': [{'usage': {'inputTokens': 100, 'outputTokens': 20, 'totalTokens': 120}}]}
        self.assertEqual(sdk.extract_usage(summary, 64, 1024)[1:3], (100, 20))
        self.assertEqual(str(sdk.peak_cost(100, 20)), '0.00036')
        summary['assistant_usage_events'][0]['usage']['outputTokens'] = 65
        with self.assertRaises(sdk.SDKAdapterError):
            sdk.extract_usage(summary, 64, 1024)

    def test_native_cache_read_is_additional_input_not_part_of_miss(self):
        usage = {'inputTokens': 487, 'outputTokens': 91, 'cacheReadTokens': 9344, 'cacheWriteTokens': 0, 'totalTokens': 9922}
        tokens, peak, cache_peak = sdk.usage_costs(usage)
        self.assertEqual(tokens['input_total_tokens'], 9831)
        self.assertEqual(tokens['input_uncached_tokens'], 487)
        self.assertEqual(peak, sdk.Decimal('0.02039'))
        self.assertEqual(cache_peak, sdk.Decimal('0.00207576'))
        self.assertEqual(cache_peak / 2, sdk.Decimal('0.00103788'))

    def test_unknown_cache_write_price_has_no_cache_aware_cost(self):
        tokens, peak, cache_peak = sdk.usage_costs({'inputTokens': 10, 'outputTokens': 2,
            'cacheReadTokens': 0, 'cacheWriteTokens': 20, 'totalTokens': 32})
        self.assertEqual(tokens['input_total_tokens'], 30)
        self.assertEqual(peak, sdk.Decimal('0.000076'))
        self.assertIsNone(cache_peak)

    def test_native_usage_rejects_bad_totals_and_unverified_aliases(self):
        for usage in ({'inputTokens': 10, 'outputTokens': 2, 'cacheReadTokens': 20, 'totalTokens': 12},
                      {'inputTokens': True, 'outputTokens': 2, 'totalTokens': 3},
                      {'inputTokens': 10, 'outputTokens': 2, 'cacheReadTokens': -1, 'totalTokens': 11},
                      {'input_tokens': 10, 'output_tokens': 2, 'total_tokens': 12},
                      {'inputTokens': 10, 'outputTokens': 2}):
            with self.subTest(usage=usage), self.assertRaises(sdk.SDKAdapterError):
                sdk.normalize_usage(usage)

    def test_legacy_ledger_recomputes_total_input_without_overwriting(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(sdk, '_restrict_private_dir'):
            client = sdk.FlashSDKClient(Path(temp).resolve(), 3, 3)
            job = client.root / 'job-old'
            job.mkdir()
            sdk.save(job / 'reservation.json', {'reservation_cny': '0.08'})
            sdk.save(job / 'receipt.json', {'status': 'ok', 'estimated_peak_cost_cny': '0.001702',
                'input_tokens': 487, 'output_tokens': 91, 'usage': {'inputTokens': 487, 'outputTokens': 91,
                    'cacheReadTokens': 9344, 'cacheWriteTokens': 0, 'totalTokens': 9922}})
            before = (job / 'receipt.json').read_bytes()
            self.assertEqual(client._totals()[0], sdk.Decimal('0.02039'))
            self.assertEqual((job / 'receipt.json').read_bytes(), before)
            self.assertEqual(len(client.legacy_cost_corrections), 1)
            client.cap = sdk.Decimal('0.01')
            with self.assertRaisesRegex(sdk.SDKAdapterError, 'corrected_ledger_exceeds_budget_cap'):
                client._totals()

    def test_wrong_model_or_missing_usage_cannot_be_success(self):
        with self.assertRaises(sdk.SDKAdapterError):
            sdk.extract_usage({'last_terminal_reason': {'kind': 'completed'}, 'final_assistant_interrupted': False,
                               'final_assistant_text': 'answer', 'final_assistant_source': {'provider': 'other', 'model': sdk.MODEL}}, 64, 1024)

    def test_dispatch_preserves_exact_messages(self):
        messages = [{'role': 'system', 'content': '只读本次来源'}, {'role': 'user', 'content': '预算为18万元。'}]
        prompt = sdk.dispatch_text(messages)
        self.assertEqual(json.loads(prompt.split('\n', 1)[1])['messages'], messages)
        with self.assertRaises(sdk.SDKAdapterError):
            sdk.dispatch_text([{'role': 'assistant', 'content': 'old answer'}])

    def test_patch_disables_context_and_uses_account_barrier(self):
        root = Path(__file__).parent.absolute()
        patch = sdk.build_patch(root, root, root / 'dsh_group_guard.mjs', 'prompt', 1024)
        self.assertIn({'id': 'agent-instructions', 'disabled': True}, patch)
        self.assertIn({'id': 'llm-retry', 'disabled': True}, patch)
        self.assertIn({'id': 'llm-deepseek-account', 'config': {'retryPolicy': {'mode': 'normal', 'maxRetries': 0}}}, patch)
        inserted = patch[-1]['insert']
        self.assertEqual(inserted[-1]['config']['maxRequestBytes'], 32768)
        self.assertLess(sdk.peak_cost(sdk.request_bound('prompt') + 2048, 2048), sdk.Decimal('0.5'))

    def test_guard_checks_exact_business_input_and_duplicate_stream(self):
        guard = Path(__file__).with_name('dsh_group_guard.mjs').absolute().as_uri()
        script = f"""
import {{createGuard,runtimeContextText}} from {json.dumps(guard)};
import {{createHash}} from 'node:crypto';
const sha=s=>createHash('sha256').update(s).digest('hex');
const config={{maxRequests:1,maxTokens:1024,maxRequestBytes:256000,dispatchSha256:sha('prompt'),workspace:'D:\\fixture'}};
const g=createGuard(config,()=>{{}},()=>{{}});
await g.agentRequest({{}},async()=>({{maxTokens:1024,reasoningEffort:'off'}}));
const input={{provider:'deepseek-account',model:'deepseek-flash',maxTokens:1024,reasoningEffort:'off',tools:[],messages:[{{role:'user',content:[{{type:'text',text:'prompt'}}]}},{{role:'user',content:[{{type:'text',text:runtimeContextText(config.workspace)}}]}}]}};
g.llmStream(input,()=>1);
if(g.state.allowed_stream_count!==1)throw Error('not admitted');
let rejected=false;try{{g.llmStream(input,()=>1);}}catch{{rejected=true;}}
if(!rejected)throw Error('second stream admitted');
const b=createGuard(config,()=>{{}},()=>{{}});
await b.agentRequest({{}},async()=>({{maxTokens:1024,reasoningEffort:'off'}}));
input.messages[0].content[0].text='unregistered';
rejected=false;try{{b.llmStream(input,()=>1);}}catch{{rejected=true;}}
if(!rejected||b.state.reject_code!=='business_input_mismatch')throw Error('input not bound');
const c=createGuard(config,()=>{{}},()=>{{}});
await c.agentRequest({{}},async()=>({{maxTokens:1024,reasoningEffort:'off'}}));
input.messages[0].content[0].text='prompt';
input.messages.push({{role:'user',content:[{{type:'text',text:'extra business source'}}]}});
rejected=false;try{{c.llmStream(input,()=>1);}}catch{{rejected=true;}}
if(!rejected||c.state.reject_code!=='business_input_mismatch')throw Error('extra business context admitted');
console.log('guard contract passed');
"""
        result = subprocess.run(['D:/node/node.exe', '--input-type=module', '-e', script], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
