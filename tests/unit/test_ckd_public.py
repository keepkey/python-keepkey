import unittest
import keepkeylib.ckd_public as ckd_public

class DeserializeTestCase(unittest.TestCase):

    def test_deserialize_xpub_from_bip32_spec(self):
        xpub = "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon"
        result = ckd_public.deserialize(xpub)
        self.assertEqual(result.depth, 3)
        self.assertEqual(result.fingerprint, 3635104055)
        self.assertEqual(result.child_num, 1)
        self.assertEqual(
                result.chain_code,
                b'\xf3f\xf4\x8f\x1e\xa9\xf2\xd1\xd3\xfe\x95\x8c\x95\xca\x84\xea\x18\xe4\xc4\xdd\xb96l3l\x92~\xb2F\xfb8\xcb')
        self.assertEqual(
                result.public_key,
                b'\x03\xa7\xd1\xd8V\xde\xb7LP\x8e\x05\x03\x1f\x98\x95\xda\xb5F&%\x1b8\x06\xe1kK\xd1.x\x1a}\xf5\xb9')

if __name__ == "__main__":
    unittest.main()
