import requests
from ipaddress import IPv4Address, AddressValueError
import re


class AbuseCh:
    """
    AbuseCh website scraper
    """

    @staticmethod
    def validate(ipv4):
        try:
            ip = IPv4Address(ipv4)
        except AddressValueError:
            return False
        else:
            return True

    @staticmethod
    def _get_ip_list(url, reason):
        response = requests.get(url=url)
        if not response.status_code == requests.codes.ok:
            raise Exception('Unable to fetch AbuseCh list: {0}'.format(url))
        # --
        ip_list = []
        for ip in response.content.splitlines():
            ip = ip.decode('ascii')
            if ip.startswith('#'):
                continue
            if AbuseCh.validate(ipv4=ip):
                ip_list.append((ip, reason))
        return ip_list

    @staticmethod
    def _get_domain_list(url, reason):
        response = requests.get(url=url)
        if not response.status_code == requests.codes.ok:
            raise Exception('Unable to fetch AbuseCh list: {0}'.format(url))
        # --
        domain_list = []
        for domain in response.content.splitlines():
            domain = domain.decode('ascii').lower()
            if domain.startswith('#'):
                continue
            domain_list.append((domain, reason))
        return domain_list

    @classmethod
    def zeus_ip_list(cls):
        url = 'https://zeustracker.abuse.ch/blocklist.php?download=badips'
        return cls._get_ip_list(url=url, reason='zeus')

    @classmethod
    def feodo_ip_list(cls):
        urls = [
            'https://feodotracker.abuse.ch/blocklist/?download=ipblocklist',
            'https://feodotracker.abuse.ch/blocklist/?download=badips',
        ]
        ip_list = []
        for url in urls:
            ip_list += cls._get_ip_list(url=url, reason='feodo')
        return ip_list

    @staticmethod
    def ransomware_page(list_type):
        """
        Fetches urls of blocklists
        :param list_type: ip, domain, url
        :return:
        """
        base_url = 'https://ransomwaretracker.abuse.ch'
        url = '{0}/blocklist'.format(base_url)
        response = requests.get(url=url)
        if not response.status_code == requests.codes.ok:
            raise Exception('Unable to fetch AbuseCh list: {0}'.format(url))
        # --
        ransom_list = []
        for line in response.content.splitlines():
            line = line.decode('ascii')
            if '<td>{0} blocklist</td>'.format(list_type) in line.lower() and 'n/a' not in line:
                if list_type == 'ip':
                    match = re.match('\s*<tr>.*_IPBL</td><td>(.*?)</td>.*?<a href=\"(.*?)\"\s+target', line)
                elif list_type == 'domain':
                    match = re.match('\s*<tr>.*_DOMBL</td><td>(.*?)</td>.*?<a href=\"(.*?)\"\s+target', line)
                if not match or match.groups()[1].startswith('/downloads/RW_'):
                    continue
                ransom_list.append((match.groups()[0].lower(), '{0}{1}'.format(base_url, match.groups()[1])))
        return ransom_list

    @classmethod
    def ransomware_ip_list(cls):
        ip_list = []
        for list_type, url  in cls.ransomware_page('ip'):
            ip_list += cls._get_ip_list(url=url, reason=list_type)
        return ip_list

    @classmethod
    def ransomware_domain_list(cls):
        dom_list = []
        for list_type, url in cls.ransomware_page('domain'):
            dom_list += cls._get_domain_list(url=url, reason=list_type)
        return dom_list

    @classmethod
    def get_all_ip_lists(cls, ):
        return cls.zeus_ip_list() + cls.feodo_ip_list() + cls.ransomware_ip_list()

    @classmethod
    def get_all_ssl_certs(cls):
        # todo: Build this out...
        url = 'https://sslbl.abuse.ch/downloads/dyre_ssl_extended.csv'
        url = 'https://sslbl.abuse.ch/downloads/ssl_extended.csv'
        return None
