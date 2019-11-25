from .abusech import AbuseCh
from collections import namedtuple
from datetime import datetime


class Feodo(AbuseCh):
    base_url = 'https://feodotracker.abuse.ch'
    ip = namedtuple('IPAddress', ['first_seen', 'ipaddress', 'port', 'last_seen', 'family'])
    malware = namedtuple('Malware', ['first_seen', 'md5', 'family'])

    def get_ip_blacklist(self):
        response = self.get_url(url='{0}/downloads/ipblocklist.csv'.format(self.base_url))
        iplist = self.parse_validate_csv(response=response, columns=5)
        data = []
        for row in iplist:
            data.append(self.ip(
                first_seen=datetime.strptime(row[0], self.date_format),
                ipaddress=row[1],
                port=int(row[2]),
                last_seen=datetime.strptime(row[3], '%Y-%m-%d') if len(row[3]) > 0 else None,
                family=row[4].lower()
            ))
        return data

    def get_ip_aggressive(self):
        response = self.get_url(url='{0}/downloads/ipblocklist_aggressive.csv'.format(self.base_url))
        iplist = self.parse_validate_csv(response=response, columns=4)
        data = []
        for row in iplist:
            data.append(self.ip(
                first_seen=datetime.strptime(row[0], self.date_format),
                ipaddress=row[1],
                port=int(row[2]),
                last_seen=None,
                family=row[3].lower()
            ))
        return data

    def get_malware_hashes(self):
        response = self.get_url(url='{0}/downloads/malware_hashes.csv'.format(self.base_url))
        dataset = self.parse_validate_csv(response=response, columns=3)
        data = []
        for row in dataset:
            data.append(self.malware(
                first_seen=datetime.strptime(row[0], self.date_format),
                md5=row[1] if len(row[1]) == 32 else None,
                family=row[2].lower()
            ))
        return data

    def get_ipaddress_details(self, ipaddress):
        response = self.get_url(url='{0}/browse/host/{1}/'.format(self.base_url, ipaddress))
        tables = response.html.find('table')
        # Details table
        details_list = [
            ('host', 'host'), ('hostname', 'host_name'), ('status', 'status'),
            ('spamhaus sbl', 'spamhaus_sbl'), ('malware', 'family'), ('as number', 'asn_id'),
            ('as name', 'asn_name'), ('country', 'country'), ('first seen', 'first_seen'),
            ('last seen', 'last_seen'), ('last online', 'last_online')
        ]
        details = self.parse_description_table(table=tables[0], header_list=details_list)
        details['first_seen'] = datetime.strptime(details['first_seen'], '%Y-%m-%d %H:%M:%S utc')
        details['last_seen'] = datetime.strptime(details['last_seen'], '%Y-%m-%d %H:%M:%S utc')
        details['last_online'] = datetime.strptime(details['last_online'], '%Y-%m-%d').date()
        details['host_name'] = None if details['host_name'] == 'n/a' else details['host_name']
        details['asn_id'] = int(details['asn_id'].lstrip('as')) if details['asn_id'].startswith('as') else None
        details['spamhaus_sbl'] = None if details['spamhaus_sbl'] == 'not listed' else details['spamhaus_sbl']
        # Hashes Table
        hash_table = self.parse_hash_table(table=tables[1], td_count=6)
        hashes = []
        for row in hash_table:
            hashdata = {}
            hashdata['timestamp'] = datetime.strptime(row[0].text, self.date_format)
            hashdata['md5'] = row[1].text
            hashdata['virustotal'] = self.parse_virustotal_data(row[2])
            hashdata['ipaddress'] = row[3].text
            hashdata['port'] = int(row[4].text)
            hashdata['family'] = row[5].text.lower()
            hashes.append(hashdata)
        return {'details': details, 'hashes': hashes, 'count': len(tables[1].find('tbody', first=True).find('tr'))}
