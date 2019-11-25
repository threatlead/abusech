from requests_html import HTMLSession
from ipaddress import IPv4Address, AddressValueError
from collections import namedtuple
from datetime import datetime
import re


class AbuseCh:
    """
    AbuseCh website scraper
    """
    date_format = '%Y-%m-%d %H:%M:%S'

    def __init__(self):
        self.session = HTMLSession()

    def get_url(self, url):
        response = self.session.get(url=url)
        if not response.status_code == 200:
            raise Exception('Unable to fetch AbuseCh list: {0}'.format(url))
        return response

    @staticmethod
    def parse_validate_csv(response, columns):
        # split lines and convert into ascii
        rows = [line.decode('ascii', errors='ignore') for line in response.content.splitlines()]
        # remove commented lines & split
        rows = [row.split(',') for row in rows if not row.startswith('#')]
        # validate column count & return
        return [row for row in rows if len(row) == columns]

    @classmethod
    def parse_ip_csv(cls, response):
        rows = cls.parse_validate_csv(response=response, columns=3)
        ip_csv_data = namedtuple('IPAddress', ['datetime', 'ipaddress', 'port'])
        # validate that second element is valid ipaddress
        rows = [row for row in rows if cls.validate(row[1])]
        rows = [(datetime.strptime(row[0], cls.date_format), row[1], int(row[2])) for row in rows]
        # build return data
        return [ip_csv_data(datetime=r[0], ipaddress=r[1], port=r[2]) for r in rows]

    @staticmethod
    def validate(ipv4):
        try:
            ip = IPv4Address(ipv4)
        except AddressValueError:
            return False
        else:
            return True

    @staticmethod
    def parse_description_table(table, header_list):
        data = {}
        for tr in table.find('tr'):
            data[tr.find('th', first=True).text.lower().replace(':', '')] = tr.find('td', first=True).text.lower()
        for match in header_list:
            if match[0] in data.keys():
                data[match[1]] = data[match[0]]
                del(data[match[0]])
        return data

    @staticmethod
    def parse_hash_table(table, td_count):
        data = []
        for tr in table.find('tr'):
            td = tr.find('td')
            if not len(td) == td_count:
                continue
            data.append(td)
        return data

    @staticmethod
    def parse_virustotal_data(td):
        if td.text == 'n/a':
            return None
        # dict with link, sha256 and results
        a = td.find('a', first=True)
        virustotal = {
            'link': a.attrs['href'],
            'results': a.text.split(' ')[0]
        }
        match = re.findall(r'/file/([a-f0-9]{64})/analysis', a.attrs['href'])
        virustotal['sha256'] = match[0]
        return virustotal
