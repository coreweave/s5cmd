import unittest

from prepare_storage_wif import policy


class PolicyTests(unittest.TestCase):
    def test_exchange_and_storage_permissions_are_separate(self):
        proposal = policy('synthetic-observed-subject')
        exchange, storage = proposal['statements']
        self.assertEqual(exchange['resources'], ['*'])
        self.assertEqual(exchange['actions'], ['cwobject:CreateAccessKeyOIDC'])
        self.assertEqual(storage['resources'], ['s5cmd-acceptance-*', 's5cmd-acceptance-*/*'])
        self.assertNotIn('s3:*', storage['actions'])
        self.assertEqual(exchange['principals'], storage['principals'])

    def test_wildcard_or_multiline_subject_is_rejected(self):
        for subject in ('', 'repo:example/*', 'repo:example/?', 'repo:example/[ab]', 'synthetic\nsubject'):
            with self.subTest(subject=subject), self.assertRaises(ValueError):
                policy(subject)


if __name__ == '__main__':
    unittest.main()
