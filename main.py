import argparse
import sys
import random
import logging
import validators
from rich.logging import RichHandler
from rich.console import Console
from rich.progress import track

import dns.resolver as dns
import subprocess
import os
from requests import (
    Session, get
)
from concurrent.futures import (
    ThreadPoolExecutor, as_completed
)
from pathlib import Path
from re import (
    findall, IGNORECASE, escape
)
from typing import Union
from time import sleep

# Define rich as logging handler
FORMAT = "%(message)s"
logging.basicConfig(
    level="INFO", format=FORMAT, datefmt="[%X]", handlers=[RichHandler()]
)
log = logging.getLogger("rich")
console = Console()


class Printing:

    @staticmethod
    def cleanup():
        """
        This method will clean the command line
        """
        os.system("cls") if os.name == "nt" else os.system("clear")

    @staticmethod
    def ascii_art():
        """
        This method will print ASCII art of SubEX
        """
        clear = "\x1b[0m"
        colors = [36, 32, 34, 35, 31, 37]

        x = r"""
   _____       _     ________   __
  / ____|     | |   |  ____\ \ / /
 | (___  _   _| |__ | |__   \ V / 
  \___ \| | | | '_ \|  __|   > <  
  ____) | |_| | |_) | |____ / . \ 
 |_____/ \__,_|_.__/|______/_/ \_\  v1.0.1

       github.com/0xuf/subex                    

            """
        for N, line in enumerate(x.split("\n")):
            sys.stdout.write("\x1b[1;%dm%s%s\n" % (random.choice(colors), line, clear))
            sleep(0.05)


class SubEX:
    """
    SubEX Main class
    """
    output: list = []
    abuseipdb: str = "https://www.abuseipdb.com/"
    crtsh: str = "https://crt.sh/?q={}"
    session: Session = Session()
    base_dir: Path = Path(__file__).resolve().parent
    version: str = "1.0.1"
    headers: dict = {
        "Host": "www.abuseipdb.com",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:103.0) Gecko/20100101 Firefox/103.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Connection": "close",
    }

    def __init__(self, domain: str, thread: int = 5, resolvers: str = "resolvers.txt",
                 wordlist: str = "wordlist.txt", output: str = "/tmp/subex.txt", silent: bool = False,
                 show_result: bool = True, subfinder: str = "/usr/bin/subfinder",
                 shuffle_dns: str = "/usr/bin/shuffledns", mass_dns: str = "/usr/bin/massdns",
                 dnsgen: str = "/usr/bin/dnsgen", dnsx: str = "/usr/bin/dnsx") -> None:
        """
        __init__ magic method
        :param domain: receive domain as input to get subdomains
        :param thread: Number of concurrent threads
        :param resolvers: List of resolvers to use in DNS query
        :param wordlist: List of words to use in DNS bruteforce
        :param output: Output file to save results
        :param silent: display only results in the output if silent is True
        :param show_result: Display the subdomains found in the output if show_result is True
        :param subfinder: Path to the subfinder binary
        :param shuffle_dns: Path to the shuffledns binary
        :param mass_dns: Path to the massdns binary
        :param dnsgen: Path to the dnsgen binary
        :param dnsx: Path to the dnsx binary
        """

        log.info(f"Running SubEX v‌{self.version} on {domain}") if not silent else ...

        # Check resolvers file exists to read
        try:
            with open(resolvers, mode="r") as _resolvers:
                resolvers_list = _resolvers.read().splitlines()
                _resolvers.close()
        except FileNotFoundError:
            log.error(f"resolvers file({resolvers}) doesn't exists.")
            sys.exit()

        log.info(f"Loaded {resolvers} file") if not silent else ...

        # Check wordlist file exists or not
        if not os.path.exists(wordlist):
            log.error(f"wordlist file({wordlist}) file doesn't exists.")
            sys.exit()

        log.info(f"Loaded {wordlist} file") if not silent else ...

        self.domain: str = domain
        self.thread: int = int(thread)
        self.resolvers_list: list = resolvers_list
        self.resolvers: str = resolvers
        self.wordlist: str = wordlist
        self.output_file: str = output
        self.session.headers = self.headers
        self.resolver: dns.Resolver = dns.Resolver()
        self.resolver.nameservers = self.resolvers_list
        self.silent: bool = silent
        self.show_result: bool = show_result
        self._subfinder: str = subfinder
        self.shuffle_dns: str = shuffle_dns
        self.mass_dns: str = mass_dns
        self.dnsgen: str = dnsgen
        self.dnsx: str = dnsx

        Path(self.output_file).touch()
        log.info("Checking scripts ...")
        check_scripts = self.check_scripts()
        if check_scripts:
            for error in check_scripts:
                log.critical(error)
            sys.exit(True)

    @staticmethod
    def os_command(command: list) -> list:
        """
        This method will run the command and return it result in output
        :param command: list of commands
        """
        command = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        ).communicate()

        out, err = command[0].decode("UTF-8"), command[1].decode("UTF-8")

        return [out, err]

    def check_scripts(self) -> list:
        """
        This method will check binary of scripts are exists or not
        """
        errors: list = list()

        # Load script path's
        scripts = [
            self._subfinder, self.shuffle_dns,
            self.mass_dns, self.dnsgen, self.dnsx
        ]

        # Loop into scripts
        for script in track(scripts):
            try:
                _, err = self.os_command([script, "-silent"])
            except FileNotFoundError as error:
                errors.append(error)
                continue
        return errors

    def dns_query(self, domain: str) -> Union[str, int]:
        """
        This method will send dns query request
        :param domain: get domain for dns request
        :return: Nothing
        """
        out, err = self.os_command(
            ["sh", "-c", f"echo {domain} | {self.dnsx} -a -silent"]
        )

        return False if err != "" else domain

    def write(self, subdomains: list) -> None:
        """
        This method saves the found subdomains in the specified output
        :param subdomains: list of subdomains
        :return: Nothing
        """

        with open(self.output_file, mode="r") as subs:
            _subdomains: list = subs.read().splitlines()
            subs.close()

        with open(self.output_file, mode="a") as subs_:
            for subdomain in subdomains:
                subs_.write(f"{subdomain}\n") if subdomain not in _subdomains else ...
            subs_.close()

    def subfinder(self) -> list:
        """
        This method obtains the list of subdomains using subfinder
        :return: list of subdomains
        """
        # Get subdomains using subfinder
        subdomains, _ = self.os_command([self._subfinder, "-d", self.domain, "-silent"])

        results: list = []
        with ThreadPoolExecutor(max_workers=self.thread) as executor:
            for subdomain in subdomains:
                results.append(
                    executor.submit(self.dns_query, subdomain)
                ) if subdomain not in self.output else ...

            for result in as_completed(results):
                self.output.append(result.result()) if result.result() else ...

            executor.shutdown()

        self.write(self.output) if self.output_file is not None else ...

        return self.output

    def dns_brute(self) -> list:
        """
        This method obtains the list of subdomains using dns bruteforce
        :return: list of subdomains
        """
        # Get subdomains using shuffledns
        shuffle_dns: list = self.os_command([self.shuffle_dns, "-m", self.mass_dns, "-d", self.domain, "-r",
                                             self.resolvers, "-w", self.wordlist, "-silent"])[0].splitlines()

        # Append found subdomains in shuffledns
        [self.output.append(_subd) if _subd not in self.output and validators.domain(_subd) else ...
         for _subd in shuffle_dns]

        self.write(self.output) if self.output_file is not None else ...

        # Get subdomains using dnsgen
        dns_gen: list = self.os_command(["sh", "-c", f"cat {self.output_file} | {self.dnsgen} -"])[0].splitlines()

        results: list = []
        with ThreadPoolExecutor(max_workers=self.thread) as executor:
            for subdomain in dns_gen:
                results.append(
                    executor.submit(self.dns_query, subdomain)
                ) if subdomain not in self.output and validators.domain(subdomain) else ...

            for result in as_completed(results):
                self.output.append(result.result()) if result.result() else ...

            executor.shutdown()

        self.write(self.output) if self.output_file is not None else ...

        return self.output

    def crt_sh(self) -> list:
        """
        This method obtains the list of subdomains using crt.sh
        :return: list of subdomains
        """
        data: str = get(self.crtsh.format(self.domain)).content.decode("utf-8")
        finder = findall(
            f'<tr>(?:\s|\S)*?href="\?id=([0-9]+?)"(?:\s|\S)*?<td>([*_a-zA-Z0-9.-]+?\.{escape(self.domain)})</td>(?:\s|\S)*?</tr>',  # noqa
            data, IGNORECASE
        )
        results: list = []
        with ThreadPoolExecutor(max_workers=self.thread) as executor:
            for cert, domain in finder:
                subdomain = domain.split("@")[-1]
                if "*" not in subdomain:
                    results.append(
                        executor.submit(self.dns_query, subdomain)
                    ) if subdomain not in self.output else ...

            for result in as_completed(results):
                self.output.append(result.result()) if result.result() else ...

            executor.shutdown()

        self.write(self.output) if self.output_file is not None else ...

        return self.output

    def all(self) -> list:
        """
        This method executes all defined methods
        :return: list of subdomains
        """
        methods: list = [
            self.subfinder, self.dns_brute,
            self.crt_sh
        ]
        log.info(f"Loaded {len(methods)} methods") if not self.silent else ...
        if not self.silent:
            with console.status(f"[bold yellow][[bold red]~[bold yellow]] "
                                f"[bold blue]SubEX [bold white]v{self.version} [bold blue]working"):
                for method_number, method in enumerate(methods):
                    console.log(f"[bold green]Using [bold cyan]{method.__name__} [bold green]method")
                    method()
        else:
            for method in methods:
                method()

        if self.show_result:
            console.print("[bold cyan]---------------------------------------") if not self.silent else ...
            for output in self.output:
                console.print(f"[white]{output}")
            console.print("[bold cyan]---------------------------------------") if not self.silent else ...
        return self.output


if __name__ == "__main__":
    try:
        path: Path = Path(__file__).resolve().parent

        if "-s" not in sys.argv and "--silent" not in sys.argv:
            Printing.cleanup()
            Printing.ascii_art()

        argument_parser: argparse.ArgumentParser = argparse.ArgumentParser()
        argument_parser.add_argument(
            "-d", "--domain", metavar="", required=True, help="Target Domain"
        )
        argument_parser.add_argument(
            "-t", "--thread", metavar="", required=False, help="Number of concurrent threads (default = 5)"
        )
        argument_parser.add_argument(
            "-r", "--resolvers", metavar="", required=False,
            help=f"list of resolvers to use (default = {path}/resolvers.txt)"
        )
        argument_parser.add_argument(
            "-w", "--wordlist", metavar="", required=False,
            help=f"list of words to dns bruteforce (default = {path}/wordlist.txt)"
        )
        argument_parser.add_argument(
            "-o", "--output", metavar="", required=False,
            help=f"file to save results"
        )
        argument_parser.add_argument(
            "-s", "--silent", required=False, action="store_true",
            help="display only results in the output"
        )
        argument_parser.add_argument(
            "-sf", "--subfinder", required=False, metavar="",
            help="Path to the subfinder binary (default = /usr/bin/subfinder)"
        )
        argument_parser.add_argument(
            "-shd", "--shuffle-dns", required=False, metavar="",
            help="Path to the shuffledns binary (default = /usr/bin/shuffledns)"
        )
        argument_parser.add_argument(
            "-dnsx", required=False, metavar="",
            help="Path to the dnsx binary (default = /usr/bin/dnsx)"
        )
        argument_parser.add_argument(
            "-msd", "--mass-dns", required=False, metavar="",
            help="Path to the massdns binary (default = /usr/bin/massdns)"
        )
        argument_parser.add_argument(
            "-dnsg", "--dnsgen", required=False, metavar="",
            help="Path to the dnsgen binary (default = /usr/bin/dnsgen)"
        )

        args = argument_parser.parse_args()

        final_arguments: dict = {}

        for key, value in args.__dict__.items():
            if value is not None:
                final_arguments[key] = value

        _instance = SubEX(**final_arguments)
        _instance.all()

    except KeyboardInterrupt:
        if "-s" not in sys.argv and "--silent" not in sys.argv:
            Printing.cleanup()
            Printing.ascii_art()
            log.warning("KeyboardInterrupt Detected.")
        sys.exit()
