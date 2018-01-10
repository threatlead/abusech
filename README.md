# ![Block](https://s13.postimg.org/p4pe0emlz/firewall.png) Abuse.CH Blocklists

## Usage

### Zeus IpAddress BlockList

```python
>>> import abusech
>>> print(abusech.AbuseCh.zeus_ip_list()[:10])
```

```javascript
[
    ('101.200.81.187', 'zeus'),
    ('103.19.89.118', 'zeus'),
    ('103.230.84.239', 'zeus'),
    ('103.4.52.150', 'zeus'),
    ('103.7.59.135', 'zeus'),
    ('104.238.158.106', 'zeus'),
    ('107.161.186.90', 'zeus'),
    ('109.127.8.242', 'zeus'),
    ('109.229.210.250', 'zeus'),
    ('109.229.36.65', 'zeus')
]
```

## Supported lists

* zeus_ip_list
* feodo_ip_list
* ransomware_ip_list
* ransomware_domain_list


## Pending
* Other domain lists
* SSL list
