import asyncio
import csv
import json
import time
from collections import defaultdict
from datetime import datetime
from typing import Dict, List

import aiohttp

from src.utils import cleanhtml
from src.vulnerability import Vulnerability
from src.consts import FIELDS, FIRST_YEAR


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
            cve_id=cveNumber,
            ack=cleanhtml(" ".join(vuln["acknowledgments"])),
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
            vuln_instance.desc = cleanhtml(detailed["description"].split("\n")[0])
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
        writer.writerow([field.capitalize().replace("_", " ") for field in FIELDS])
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
