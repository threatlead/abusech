from .abusech import AbuseCh
from collections import namedtuple
from datetime import datetime
import re


class SslBl(AbuseCh):
    base_url = 'https://sslbl.abuse.ch'

    @classmethod
    def parse_ssl_csv(cls, response):
        rows = cls.parse_validate_csv(response=response, columns=3)
        ssl_csv_data = namedtuple('SSL', ['datetime', 'sha1', 'reason'])
        # validate that second element is valid ssl hash
        rows = [row for row in rows if len(row[1]) == 40]
        rows = [(datetime.strptime(row[0], cls.date_format), row[1], row[2]) for row in rows]
        # build return data
        return [ssl_csv_data(datetime=r[0], sha1=r[1], reason=r[2]) for r in rows]

    @classmethod
    def parse_ja3_csv(cls, response):
        rows = cls.parse_validate_csv(response=response, columns=4)
        ja3_csv_data = namedtuple('JA3', ['first_seen', 'last_seen', 'md5', 'reason'])
        # validate that second element is valid ssl hash
        rows = [row for row in rows if len(row[0]) == 32]
        rows = [(datetime.strptime(row[1], cls.date_format), datetime.strptime(row[2], cls.date_format), row[0], row[3]) for row in rows]
        # build return data
        return [ja3_csv_data(first_seen=r[0], last_seen=r[1], md5=r[2], reason=r[3].lower()) for r in rows]


    def get_ip_blacklist(self, aggressive=False):
        if aggressive:
            response = self.get_url(url='{0}/blacklist/sslipblacklist_aggressive.csv'.format(self.base_url))
        else:
            response = self.get_url(url='{0}/blacklist/sslipblacklist.csv'.format(self.base_url))
        return self.parse_ip_csv(response=response)

    def get_ssl_blacklist(self):
        response = self.get_url(url='{0}/blacklist/sslblacklist.csv'.format(self.base_url))
        return self.parse_ssl_csv(response=response)

    def get_ja3_blacklist(self):
        response = self.get_url(url='{0}/blacklist/ja3_fingerprints.csv'.format(self.base_url))
        return self.parse_ja3_csv(response=response)

    def get_ja3_details(self, md5):
        response = self.get_url(url='{0}/ja3-fingerprints/{1}/'.format(self.base_url, md5))
        tables = response.html.find('table')
        # Details table
        details_list = [
            ('ja3 fingerprint', 'ja3'), ('first seen', 'first_seen'), ('last seen', 'last_seen'),
            ('status', 'status'), ('malware samples', 'sample_count'), ('destination ips', 'ipaddress_count'),
            ('malware', 'family'), ('listing date', 'listing_date')
        ]
        details = self.parse_description_table(table=tables[0], header_list=details_list)
        details['first_seen'] = datetime.strptime(details['first_seen'], '%Y-%m-%d %H:%M:%S utc')
        details['last_seen'] = datetime.strptime(details['last_seen'], '%Y-%m-%d %H:%M:%S utc')
        details['listing_date'] = datetime.strptime(details['listing_date'], self.date_format)
        details['sample_count'] = int(details['sample_count'].replace("'", ''))
        details['ipaddress_count'] = int(details['ipaddress_count'].replace("'", ''))
        # Hashes Table
        hash_table = self.parse_hash_table(table=tables[1], td_count=4)
        hashes = []
        for row in hash_table:
            hashdata = {}
            hashdata['timestamp'] = datetime.strptime(row[0].text, self.date_format)
            hashdata['md5'] = row[1].text
            hashdata['virustotal'] = self.parse_virustotal_data(row[2])
            botnet = row[3].text
            hashdata['ipaddress'], hashdata['port'] = botnet.split(':')
            hashes.append(hashdata)
        return {'details': details, 'hashes': hashes}

    def get_ssl_details(self, sha1):
        response = self.get_url(url='{0}/ssl-certificates/sha1/{1}/'.format(self.base_url, sha1))
        tables = response.html.find('table')
        # Details Table
        details_list = [
            ('sha1 fingerprint', 'ssl_sha1'), ('certificate common name (cn)', 'cn'),
            ('issuer distinguished name (dn)', 'dn'), ('tls version', 'tls_version'),
            ('first seen', 'first_seen'), ('last seen', 'last_seen'), ('status', 'status'),
            ('listing reason', 'reason'), ('listing date', 'listing_date'),
            ('malware samples', 'sample_count'), ('botnet c&cs', 'ipaddress_count')
        ]
        details = self.parse_description_table(table=tables[0], header_list=details_list)
        details['first_seen'] = datetime.strptime(details['first_seen'], '%Y-%m-%d %H:%M:%S utc')
        details['last_seen'] = datetime.strptime(details['last_seen'], '%Y-%m-%d %H:%M:%S utc') if not details['last_seen'] == 'never' else None
        details['listing_date'] = datetime.strptime(details['listing_date'], '%Y-%m-%d %H:%M:%S')
        details['sample_count'] = int(details['sample_count'].replace("'", ''))
        details['ipaddress_count'] = int(details['ipaddress_count'].replace("'", ''))
        # Hashes Table
        hash_table = self.parse_hash_table(table=tables[1], td_count=5)
        hashes = []
        for row in hash_table:
            hashdata = {}
            hashdata['timestamp'] = datetime.strptime(row[0].text, '%Y-%m-%d %H:%M:%S')
            hashdata['md5'] = row[1].text
            hashdata['virustotal'] = self.parse_virustotal_data(row[2])
            hashdata['family'] = row[3].find('a', first=True).find('span', first=True).text.lower()
            hashdata['ipaddress'], hashdata['port'] = row[4].text.split(':')
            hashes.append(hashdata)
        return {'details': details, 'hashes': hashes}
