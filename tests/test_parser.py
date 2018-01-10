from .context import abusech
import unittest


class ConnectTestSuite(unittest.TestCase):

    def test_zeus_ip(self):
        ip = abusech.AbuseCh.zeus_ip_list()
        self.assertGreater(len(ip), 10, 'Found a total of {0} ipaddresses'.format(len(ip)))

    def test_feodo_ip(self):
        ip = abusech.AbuseCh.feodo_ip_list()
        self.assertGreater(len(ip), 10, 'Found a total of {0} ipaddresses'.format(len(ip)))

    def test_ransomware_ip(self):
        ip = abusech.AbuseCh.ransomware_ip_list()
        self.assertGreater(len(ip), 10, 'Found a total of {0} ipaddresses'.format(len(ip)))


if __name__ == '__main__':
    unittest.main()
    # print(AbuseCh.ransomware_domain_list())
    # print(AbuseCh.get_all_ip_lists())print
