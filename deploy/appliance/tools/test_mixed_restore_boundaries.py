"""Inert mixed-restore proof projection, identity and invocation boundaries."""
import json
import unittest

import test_mixed_restore as fixture
import test_ssh


class Boundaries(unittest.TestCase):
    def proof(self):
        return dict(schema=1,config_sha256='a'*64,connections={'desktop-a':1,'desktop-b':2,'terminal-c':3},
            enrolled=True,identity_sha256='b'*64,census_sha256='c'*64,prepared_sha256='d'*64)

    def test_full_unchanged_identity_census_proof_accepts_only_expected_fields(self):
        self.assertEqual(fixture.validate_proof(self.proof()),self.proof())
        for change in [dict(private_key='SECRET'),dict(identity_sha256='SECRET'),dict(enrolled=False),
                       dict(connections={'desktop-a':True,'desktop-b':2,'terminal-c':3}),dict(schema=True)]:
            with self.assertRaises(RuntimeError):fixture.validate_proof(dict(self.proof(),**change))

    def test_totp_or_census_change_is_distinguishable_after_valid_projection(self):
        before=fixture.validate_proof(self.proof())
        for field in ('identity_sha256','census_sha256','prepared_sha256','config_sha256'):
            after=fixture.validate_proof(dict(self.proof(),**{field:'f'*64}))
            self.assertNotEqual(before,after)
            self.assertNotIn('SECRET',json.dumps(after))


    def test_same_image_default_preserves_existing_restore_path(self):
        image = 'sha256:' + 'a' * 64
        self.assertEqual(fixture.application_images(image),
                         {'producer': image, 'restored': image})
        self.assertEqual(fixture.application_images('a' * 64),
                         {'producer': image, 'restored': image})

    def test_explicit_old_producer_does_not_replace_restored_target(self):
        target = 'sha256:' + 'a' * 64
        source = 'sha256:' + 'b' * 64
        images = fixture.application_images(target, source)
        self.assertEqual(images, {'producer': source, 'restored': target})
        # Existing ownership checks must retain each role's actual image;
        # the target must never authorize cleanup of the old producer or vice versa.
        for role, image in images.items():
            info = {'Id': 'c' * 64, 'Image': image, 'Name': 'synthetic-' + role,
                    'Config': {'Labels': {test_ssh.LABEL: 'd' * 32}}}
            expected = dict(cid='c' * 64, image=image, token='d' * 32,
                            name='synthetic-' + role)
            self.assertTrue(test_ssh.owned(info, **expected))
            other = target if role == 'producer' else source
            self.assertFalse(test_ssh.owned(info, **dict(expected, image=other)))

    def test_source_image_requires_full_immutable_identity(self):
        target = 'sha256:' + 'a' * 64
        for source in ('', 'latest', 'b' * 12, 'sha256:' + 'b' * 63):
            with self.assertRaises(ValueError):
                fixture.application_images(target, source)
        with self.assertRaises(ValueError):
            fixture.application_images('latest', 'b' * 64)


if __name__=='__main__':unittest.main()
