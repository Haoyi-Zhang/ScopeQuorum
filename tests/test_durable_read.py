"""Regression for the composed durable dependency-read path."""
from pathlib import Path
import asyncio
import os
import sys
import tempfile
import unittest
from unittest.mock import Mock,patch
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'src'))
from durable_read_study import run_case
from durable_witness_network import DurableWitnessProcessNetwork

@unittest.skipUnless(os.name == 'posix', 'requires POSIX directory fsync')
class DurableRootReadTests(unittest.TestCase):
    def test_failed_startup_closes_owned_child_and_pipes(self):
        with tempfile.TemporaryDirectory() as directory:
            network=DurableWitnessProcessNetwork(Path(directory))
            parent,child,process=Mock(),Mock(),Mock()
            parent.poll.return_value=False
            process.is_alive.side_effect=[True,False]
            network.context=SimpleNamespace(Pipe=Mock(return_value=(parent,child)),
                                            Process=Mock(return_value=process))
            with self.assertRaisesRegex(RuntimeError,'start timeout'):
                network._start('w0')
            process.terminate.assert_called_once()
            process.join.assert_called_once_with(timeout=5)
            parent.close.assert_called_once()
            child.close.assert_called_once()
            self.assertEqual(network.processes,{})

    def test_partial_network_entry_cleans_previously_started_witnesses(self):
        with tempfile.TemporaryDirectory() as directory:
            network=DurableWitnessProcessNetwork(Path(directory))
            process=Mock()
            process.is_alive.return_value=False
            def start(witness):
                if witness=='w1':raise RuntimeError('injected startup failure')
                network.processes[witness]=process
                network.pids[witness]=123
                network.ports[witness]=1234
            with patch.object(network,'_start',side_effect=start):
                with self.assertRaisesRegex(RuntimeError,'injected startup failure'):
                    asyncio.run(network.__aenter__())
            self.assertEqual(network.processes,{})
            self.assertEqual(network.pids,{})
            self.assertEqual(network.ports,{})

    def test_malformed_readiness_kills_child_that_survives_termination(self):
        with tempfile.TemporaryDirectory() as directory:
            network=DurableWitnessProcessNetwork(Path(directory))
            parent,child,process=Mock(),Mock(),Mock()
            parent.poll.return_value=True
            parent.recv.return_value={}
            process.is_alive.side_effect=[True,True]
            network.context=SimpleNamespace(Pipe=Mock(return_value=(parent,child)),
                                            Process=Mock(return_value=process))
            with self.assertRaisesRegex(RuntimeError,'bad witness ready'):
                network._start('w0')
            process.terminate.assert_called_once()
            process.kill.assert_called_once()
            self.assertEqual(process.join.call_count,2)
            self.assertEqual(network.processes,{})

    def test_dependency_invalidation_survives_required_signer_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            result=asyncio.run(run_case(Path(directory),'revoke','after-replace'))
        self.assertEqual(result['partial_signatures'],2)
        self.assertTrue(result['honest_process_replaced'])
        self.assertEqual(result['distinct_initial_processes'],4)
        self.assertEqual(result['epsilon'],2)
        self.assertEqual(result['recovered_frontier_before_retry'],result['effective_frontier'])
        self.assertEqual(result['stale_branch_signatures'],0)
        self.assertEqual(result['direct_stale_signer_rejections'],3)
        self.assertEqual(result['injected_exit_code'],73)
        self.assertEqual(len(result['observations']),6)

    def test_clock_configuration_is_exact_and_retained(self):
        async def scenario(root):
            async with DurableWitnessProcessNetwork(root) as network:
                with self.assertRaises(ValueError):
                    await network.configure('n1','n1',clock_epsilon=True)
                with self.assertRaises(ValueError):
                    await network.configure('bad/id','n1',clock_epsilon=2)
                self.assertEqual(network.cases,{})
                await network.configure('n1','n1',clock_epsilon=2)
                with self.assertRaises(ValueError):
                    await network.configure('alias','n1',clock_epsilon=2)
                alias=await network.rpc('w1',{'op':'configure','case':'alias','ns':'n1',
                    'faulty':False,'clock_epsilon':2})
                self.assertEqual(alias,{'error':'IDENTITY_ALREADY_CONFIGURED'})
                with self.assertRaises(ValueError):
                    await network.configure('n1','n1',clock_epsilon=0)
                await network.restart('w1')
                reply=await network.rpc('w1',{'op':'configure','case':'n1','ns':'n1',
                    'faulty':False,'clock_epsilon':0})
                self.assertEqual(reply,{'error':'CONFIG_MISMATCH'})
        with tempfile.TemporaryDirectory() as directory:
            asyncio.run(scenario(Path(directory)))

    def test_coordinator_reopen_cannot_reset_namespace_signer_state(self):
        from codec import commitment,manifest
        from fixtures import grant
        from model import Authority
        async def scenario(root):
            authority=Authority('n1')
            authority.append('grant',grant('n1'),10)
            authority.append('publish',manifest('n1','leaf',[]),10)
            body={'op':'checkpoint','ns':'n1','count':len(authority.log),
                  'tip':commitment(authority.log[-1]),'issued':14}
            async with DurableWitnessProcessNetwork(root) as first:
                await first.configure('original','n1',clock_epsilon=2)
                await first.advance('original',12)
                self.assertEqual(len(await first.signatures('original',body,authority.log)),4)
            async with DurableWitnessProcessNetwork(root) as reopened:
                with self.assertRaises(RuntimeError):
                    await reopened.configure('wrong-policy','n1',clock_epsilon=0)
                self.assertEqual(reopened.cases,{})
                await reopened.configure('renamed','n1',clock_epsilon=2)
                statuses=await reopened.status('renamed')
                self.assertTrue(all(r['summary']['count']==len(authority.log) for r in statuses.values()))
                self.assertTrue(reopened.state_path('w1','renamed').name.startswith('namespace-n1'))
        with tempfile.TemporaryDirectory() as directory:
            asyncio.run(scenario(Path(directory)))

    def test_legacy_namespace_prefix_and_mismatched_files_do_not_reset_state(self):
        import json
        from durable_witness import DurableWitness
        async def scenario(root):
            async with DurableWitnessProcessNetwork(root) as network:
                with self.assertRaises(RuntimeError):
                    await network.configure('new','n1',clock_epsilon=2)
                self.assertFalse((root/'w1'/'namespace-n1.json').exists())
                self.assertEqual(network.cases,{})
        for filename in ('namespace-legacy.json','namespace-n0.json'):
            with tempfile.TemporaryDirectory() as directory:
                root=Path(directory)
                for witness in ('w0','w1','w2','w3'):
                    owned=root/witness
                    owned.mkdir()
                    DurableWitness(owned/filename,'n1',witness,clock_epsilon=2)
                asyncio.run(scenario(root))

if __name__=='__main__':
    unittest.main()
