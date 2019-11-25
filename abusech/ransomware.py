from .abusech import AbuseCh
from collections import namedtuple
from datetime import datetime


class RansomwareBl(AbuseCh):
    base_url = 'https://ransomwaretracker.abuse.ch'

    def get_blocklists(self):
        response = self.get_url(url='{0}/blocklist'.format(self.base_url))
        # --
        blocklists = []
        tables = response.html.find('table')
        blocklist_details = namedtuple('Blocklist', ['name', 'malware', 'scope', 'type', 'false_positives', 'url'])
        for tr in tables[1].find('tr'):
            td = tr.find('td')
            if not len(td) == 6:
                continue
            urls = td[5].find('center', first=True).absolute_links
            download_url = next(iter(urls)) if len(urls) > 0 else None
            data = blocklist_details(
                name=td[0].text,
                malware=td[1].text.lower(),
                scope=td[2].text.lower(),
                type=td[3].text.lower().replace('blocklist', '').strip(),
                false_positives=td[4].text.lower(),
                url=download_url,
            )
            blocklists.append(data)
        return blocklists

    def get_ip_list(self, url):
        response = self.get_url(url=url)
        iplist = self.parse_validate_csv(response=response, columns=1)
        return list(set([item[0] for item in iplist if self.validate(item[0])]))

    def get_domain_list(self, url):
        response = self.get_url(url=url)
        domain_list = self.parse_validate_csv(response=response, columns=1)
        return list(set([item[0] for item in domain_list]))

    def get_url_list(self, url):
        response = self.get_url(url=url)
        url_list = self.parse_validate_csv(response=response, columns=1)
        return list(set([item[0] for item in url_list]))

    def get_blocklist(self, url):
        if url.endswith('_IPBL.txt'):
            return self.get_ip_list(url=url)
        elif url.endswith('_DOMBL.txt'):
            return self.get_domain_list(url=url)
        elif url.endswith('_URLBL.txt'):
            return self.get_url_list(url=url)
        else:
            return None

    def get_tracker(self):
        response = self.get_url(url='{0}/feeds/csv/'.format(self.base_url))
        rows = self.parse_validate_csv(response=response, columns=10)
        dataset = []
        tracker = namedtuple('Ransomware', ['timestamp', 'threat', 'malware', 'host', 'url', 'status', 'registrar', 'ipaddress', 'asn', 'country'])
        for row in rows:
            dataset.append(tracker(
                timestamp=datetime.strptime(row[0].strip('"'), self.date_format),
                threat=row[1].strip('"').lower(),
                malware=row[2].strip('"').lower(),
                host=row[3].strip('"'),
                url=row[4].strip('"'),
                status=row[5].strip('"'),
                registrar=row[6].strip('"') if len(row[6].strip('"')) > 0 else None,
                ipaddress=row[7].strip('"'),
                asn=int(row[8].strip('"')) if len(row[8].strip('"')) > 0 else None,
                country=row[9].strip('"').lower(),
            ))
        return dataset
