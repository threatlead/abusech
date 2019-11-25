from .abusech import AbuseCh
from collections import namedtuple
from datetime import datetime


class UrlHaus(AbuseCh):
    base_url = 'https://urlhaus.abuse.ch'
    urls = namedtuple('UrlHaus', ['id', 'date_added', 'url', 'url_status', 'threat', 'tags', 'urlhaus_link', 'reporter'])
    payloads = namedtuple('Payload', ['timestamp', 'url', 'type', 'md5', 'sha256', 'signature'])

    def parse_url_csv(self, urllist):
        data = []
        for row in urllist:
            data.append(self.urls(
                id=int(row[0].strip('"')),
                date_added=datetime.strptime(row[1].strip('"'), self.date_format),
                url=row[2].strip('"'),
                url_status=row[3].strip('"'),
                threat=row[4].strip('"'),
                tags=row[5].strip('"'),
                urlhaus_link=row[6].strip('"'),
                reporter=row[7].strip('"')
            ))
        return data

    def get_data_dump(self):
        response = self.get_url(url='{0}/downloads/csv/'.format(self.base_url))
        urllist = self.parse_validate_csv(response=response, columns=8)
        return self.parse_url_csv(urllist=urllist)

    def get_recent_urls(self):
        response = self.get_url(url='{0}/downloads/csv_recent/'.format(self.base_url))
        urllist = self.parse_validate_csv(response=response, columns=8)
        return self.parse_url_csv(urllist=urllist)

    def get_online_urls(self):
        response = self.get_url(url='{0}/downloads/csv_online/'.format(self.base_url))
        urllist = self.parse_validate_csv(response=response, columns=8)
        return self.parse_url_csv(urllist=urllist)

    def get_payloads(self):
        response = self.get_url(url='{0}/downloads/payloads/'.format(self.base_url))
        urllist = self.parse_validate_csv(response=response, columns=6)
        data = []
        for row in urllist:
            data.append(self.payloads(
                timestamp=datetime.strptime(row[0].strip('"'), self.date_format),
                url=row[1].strip('"'),
                type=row[2].strip('"').lower(),
                md5=row[3].strip('"') if len(row[3].strip('"')) == 32 else None,
                sha256=row[4].strip('"') if len(row[4].strip('"')) == 64 else None,
                signature=None if row[5].strip('"').lower() == "none" else row[5].strip('"').lower(),
            ))
        return data
