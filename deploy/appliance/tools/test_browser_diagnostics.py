"""Browser failure metadata must not disclose runtime values or stack content."""
import unittest
import test_image


class BrowserDiagnosticsTest(unittest.TestCase):
    def test_exception_preserves_class_and_location_without_content(self):
        result = {'exceptionDetails': {
            'lineNumber': 0, 'columnNumber': 248,
            'text': 'synthetic private text',
            'exception': {'className': 'TypeError',
                          'description': 'synthetic private value and stack'},
            'stackTrace': {'description': 'synthetic private stack'}}}
        with self.assertRaises(AssertionError) as caught:
            test_image.browser_value(result)
        self.assertEqual(str(caught.exception),
                         'Browser expression failed: class=TypeError, lineNumber=0, columnNumber=248')

    def test_untrusted_exception_class_is_not_echoed(self):
        with self.assertRaisesRegex(AssertionError, 'class=Unknown$'):
            test_image.browser_value({'exceptionDetails': {
                'exception': {'className': 'private arbitrary text'},
                'lineNumber': 'private arbitrary text'}})


if __name__ == '__main__':
    unittest.main()
