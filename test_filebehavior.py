import threading
import unittest

from filebehavior import FileBehavior


IDENTITY = (1200, 10.0)
ROW = dict(pid=IDENTITY[0], created=IDENTITY[1], name='editor', exe='/usr/bin/editor')


def burst(behavior, count, identity=IDENTITY, action=('modifica',), now=100, prefix='file'):
    for index in range(count):
        behavior.record(identity, f'{prefix}-{index}', action, f'/home/test/Documenti/{index}.txt', now=now)


class FileBehaviorTests(unittest.TestCase):
    def test_mass_modification_is_explained_but_alone_does_not_become_high(self):
        behavior = FileBehavior()
        burst(behavior, 150)
        finding, = behavior.poll([ROW], now=101)
        self.assertEqual(finding['severity'], 'media')
        self.assertEqual(finding['pid'], IDENTITY[0])
        self.assertEqual(finding['created'], IDENTITY[1])
        self.assertIn('150 file distinti in 15 s', finding['reasons'][0])
        self.assertIn('150 modificati, 0 rinominati, 0 eliminati', finding['reasons'][0])
        self.assertIn('/home/test/Documenti', finding['reasons'][0])

    def test_high_requires_twenty_distinct_renamed_or_deleted_files(self):
        behavior = FileBehavior()
        burst(behavior, 100)
        for index in range(19):
            behavior.record(IDENTITY, f'file-{index}', ('rinomina', 'eliminazione'), '/home/test/Documenti/x', now=101)
        self.assertEqual(behavior.poll([ROW], now=101)[0]['severity'], 'media')
        behavior.record(IDENTITY, 'file-19', ('eliminazione',), '/home/test/Documenti/x', now=102)
        self.assertEqual(behavior.poll([ROW], now=102)[0]['severity'], 'alta')

    def test_same_fid_is_counted_once_across_many_writes_and_renames(self):
        behavior = FileBehavior(medium=2)
        for index in range(100):
            behavior.record(IDENTITY, ('fsid', b'stable-handle'), ('modifica', 'rinomina'),
                            f'/home/test/Documenti/renamed-{index}', now=100)
        self.assertEqual(behavior.poll([ROW], now=101), [])
        self.assertEqual(len(behavior._files), 1)
        burst(behavior, 1)
        finding, = behavior.poll([ROW], now=101)
        self.assertIn('2 file distinti', finding['reasons'][0])

    def test_normal_work_on_a_few_files_does_not_alert(self):
        behavior = FileBehavior()
        burst(behavior, 12, action=('modifica', 'rinomina', 'eliminazione'))
        self.assertEqual(behavior.poll([ROW], now=101), [])

    def test_pid_reuse_does_not_transfer_an_old_process_activity(self):
        behavior = FileBehavior()
        burst(behavior, 40)
        replacement = dict(ROW, created=20.0)
        self.assertEqual(behavior.poll([replacement], now=101), [])
        self.assertEqual(len(behavior._files), 0)
        burst(behavior, 5, identity=(1200, 20.0), now=102)
        self.assertEqual(behavior.poll([replacement], now=103), [])

    def test_only_active_processes_have_findings(self):
        behavior = FileBehavior()
        burst(behavior, 40)
        self.assertEqual(behavior.poll([], now=101), [])
        self.assertEqual(behavior.poll([ROW], now=102), [])

    def test_ignored_name_and_executable_remove_activity(self):
        for ignored in ((ROW['name'],), (ROW['exe'],)):
            with self.subTest(ignored=ignored):
                behavior = FileBehavior()
                burst(behavior, 40)
                self.assertEqual(behavior.poll([ROW], ignored=ignored, now=101), [])
                self.assertEqual(len(behavior._files), 0)

    def test_file_records_expire_at_window_boundary(self):
        behavior = FileBehavior()
        burst(behavior, 30)
        self.assertEqual(len(behavior.poll([ROW], now=114.9)), 1)
        self.assertEqual(behavior.poll([ROW], now=115), [])
        self.assertEqual(len(behavior._files), 0)
        self.assertEqual(len(behavior._processes), 0)

    def test_each_action_expires_independently(self):
        behavior = FileBehavior()
        burst(behavior, 100, action=('rinomina',))
        burst(behavior, 100, now=114)
        self.assertEqual(behavior.poll([ROW], now=114)[0]['severity'], 'alta')
        finding, = behavior.poll([ROW], now=116)
        self.assertEqual(finding['severity'], 'media')
        self.assertIn('100 modificati, 0 rinominati, 0 eliminati', finding['reasons'][0])

    def test_file_capacity_is_global_and_does_not_accumulate_an_event_queue(self):
        behavior = FileBehavior(max_files=5, max_processes=4)
        for index in range(200):
            identity = (index % 3 + 1, 1.0)
            behavior.record(identity, index, ('modifica',), '/home/test/Documenti/x', now=100)
            self.assertLessEqual(len(behavior._files), 5)
            self.assertLessEqual(sum(len(files) for files in behavior._processes.values()), 5)
        self.assertTrue(behavior.overflow)
        self.assertEqual(behavior.dropped, 195)

    def test_process_capacity_evicts_oldest_process_and_its_files(self):
        behavior = FileBehavior(max_files=10, max_processes=2)
        burst(behavior, 2, identity=(1, 1.0))
        burst(behavior, 3, identity=(2, 1.0))
        burst(behavior, 1, identity=(3, 1.0))
        self.assertEqual(set(behavior._processes), {(2, 1.0), (3, 1.0)})
        self.assertEqual(len(behavior._files), 4)
        self.assertTrue(behavior.overflow)
        self.assertEqual(behavior.dropped, 2)

    def test_pruning_old_records_does_not_count_as_overflow(self):
        behavior = FileBehavior(max_files=5)
        burst(behavior, 5)
        burst(behavior, 5, now=116, prefix='fresh')
        self.assertEqual(len(behavior._files), 5)
        self.assertFalse(behavior.overflow)
        self.assertEqual(behavior.dropped, 0)

    def test_reason_contains_at_most_three_directories_and_no_filenames(self):
        behavior = FileBehavior()
        for index in range(40):
            behavior.record(IDENTITY, index, ('modifica',), f'/home/test/dir{index}/secret-file.txt', now=100)
        reason = behavior.poll([ROW], now=101)[0]['reasons'][0]
        self.assertEqual(reason.count('/home/test/dir'), 3)
        self.assertNotIn('secret-file', reason)

    def test_concurrent_producers_and_poll_keep_both_indices_consistent(self):
        behavior = FileBehavior(max_files=100, max_processes=4)
        rows = [dict(ROW, pid=index + 1) for index in range(4)]
        errors = []

        def producer(pid):
            try:
                for index in range(200):
                    behavior.record((pid, 10.0), index, ('modifica',), '/home/test/Documenti/x', now=100)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=producer, args=(row['pid'],)) for row in rows]
        for thread in threads:
            thread.start()
        for _ in range(20):
            behavior.poll(rows, now=101)
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertLessEqual(len(behavior._files), 100)
        self.assertEqual(len(behavior._files), sum(len(files) for files in behavior._processes.values()))
        self.assertEqual(set(behavior._files), {
            (identity, file_id) for identity, files in behavior._processes.items() for file_id in files
        })


if __name__ == '__main__':
    unittest.main()
