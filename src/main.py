import asyncio
import csv
import itertools
import json
import time
from collections import defaultdict
from datetime import datetime
from typing import Dict, List

import aiohttp

FIRST_YEAR = 2015
FIELDS = [
    "title",
    "cve",
    "ack",
    "date",
    "data_url",
    "display_url",
    "desc",
    "cvss",
    "exploited",
]


class Vulnerability:
    """class representing a vulnerability"""

    __slots__ = FIELDS
    # for saving memory

    def __init__(
        self,
        title: str,
        cve: str,
        ack: str,
        date: datetime,
        data_url: str = "",
        display_url: str = "",
        desc: str = "",
        cvss: float = 0,
        exploited: str = "",
    ):
        self.title = title
        self.cve = cve
        self.ack = ack
        self.date = date
        self.data_url = data_url
        self.display_url = display_url
        self.desc = desc
        self.cvss = cvss
        self.exploited = exploited

    def list_of_attrs(self):
        return [getattr(self, attr) for attr in self.__slots__]

    def __repr__(self):
        attrs = {attr: getattr(self, attr) for attr in self.__slots__}
        return "<{klass} @{id:x} {attrs}>".format(
            klass=self.__class__.__name__,
            id=id(self) & 0xFFFFFF,
            attrs=" ".join("{}={!r}".format(k, v) for k, v in attrs.items()),
        )


async def parse_year_xml(session: aiohttp.ClientSession, writer, year: int):
    url = f"https://portal.msrc.microsoft.com/api/security-guidance/en-us/acknowledgments/year/{year}"
    response = await session.get(url)
    result = await response.text()
    short_vulns = json.loads(result)
    for vuln in short_vulns["details"]:
        date = datetime.strptime(vuln["publishedDate"], "%Y-%m-%dT%H:%M:%SZ")
        cveNumber = vuln["cveNumber"]
        vuln_instance = Vulnerability(
            title=vuln["cveTitle"],
            cve=cveNumber,
            ack=" ".join(vuln["acknowledgments"]),
            date=date,
        )

        if cveNumber:
            vuln_instance.data_url = f"https://portal.msrc.microsoft.com/api/security-guidance/en-us/CVE/{cveNumber}"
            vuln_instance.display_url = f"https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/{cveNumber}"
            # visit URL
            more_info_response = await session.get(vuln_instance.data_url)
            result = await more_info_response.text()
            # parse HTML to get desc, last updated, max CVSS score, exploited
            detailed = json.loads(result)
            vuln_instance.desc = detailed["description"].split("\n")[0]
            vuln_instance.exploited = detailed["exploited"]
            if products := detailed["affectedProducts"]:
                # get max CVSS score
                try:
                    base_scores = [
                        float(product["baseScore"])
                        for product in products
                        if product["baseScore"]
                    ]
                    vuln_instance.cvss = max(base_scores)
                except ValueError:
                    pass

            writer.writerow(vuln_instance.list_of_attrs())


async def scan():
    with open("data.csv", "w",) as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(FIELDS)
        async with aiohttp.ClientSession() as session:
            tasks = [
                parse_year_xml(
                    session=session, writer=writer, year=FIRST_YEAR + year_inc
                )
                for year_inc in range(6)
            ]
            await asyncio.gather(*tasks)


if __name__ == "__main__":
    asyncio.run(scan())
