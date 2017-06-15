import unittest2
from obj_finder import ObjFinder



class MyTestCase(unittest2.TestCase):
    def test_something(self):
        ObjFinder().sync_from_server()


if __name__ == '__main__':
    unittest2.main()
