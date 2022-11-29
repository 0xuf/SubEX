# SubEX

## SubEX is a script to find subdomains of a domain using several methods

### built with
* [![Python][Python]][Python-URL]
* [![ShuffleDNS]][ShuffleDNS-URL]
* [![MassDNS]][MassDNS-URL]
* [![DnsGEN]][DnsGEN-URL]
* [![BeautifulSoup]][BeautifulSoup-URL]

## Installation
```bash
git clone https://github.com/0xuf/SubEX.git
cd SubEX
pip install -r requirements.txt
python main.py -h
```
## Usage
```
usage: main.py [-h] -d  [-t] [-r] [-w] [-o] [-s] [-sr] [-sf] [-shd] [-msd] [-dnsg]

options:
  -h, --help            show this help message and exit
  -d , --domain         Target Domain
  -r , --resolvers      list of resolvers to use (default = /home/x/SubEX/resolvers.txt)
  -w , --wordlist       list of words to dns bruteforce (default = /home/x/SubEX/wordlist.txt)
  -o , --output         file to save results
  -s, --silent          display only results in the output
  -sf , --subfinder     Path to the subfinder binary (default = /usr/bin/subfinder)
  -shd , --shuffle-dns 
                        Path to the shuffledns binary (default = /usr/bin/shuffledns)
  -dnsx                 Path to the dnsx binary (default = /usr/bin/dnsx)
  -msd , --mass-dns     Path to the massdns binary (default = /usr/bin/massdns)
  -dnsg , --dnsgen      Path to the dnsgen binary (default = /usr/bin/dnsgen)
              
```

# License
```
This project is licensed under MIT License.
```

# Author
Discord: NotAvailable#7600

[Instagram](https://instagram.com/n0t.4vailable)

[Python]: https://img.shields.io/badge/python-000000?style=for-the-badge&logo=python&logoColor=blue
[Python-URL]: https://python.org
[ShuffleDNS]: https://img.shields.io/badge/ShuffleDNS-20232A?style=for-the-badge
[ShuffleDNS-Url]: https://github.com/projectdiscovery/shuffledns
[Dnsx-Url]: https://github.com/projectdiscovery/dnsx
[MassDNS]: https://img.shields.io/badge/MassDNS-123124?style=for-the-badge
[MassDNS-URL]: https://github.com/blechschmidt/massdns
[DnsGEN]: https://img.shields.io/badge/DnsGEN-35495E?style=for-the-badge
[DnsGEN-URL]: https://github.com/ProjectAnte/dnsgen
[BeautifulSoup]: https://img.shields.io/badge/BeautifulSoup-0769AD?style=for-the-badge
[BeautifulSoup-URL]: https://beautiful-soup-4.readthedocs.io/en/latest/
