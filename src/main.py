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
from src.consts import FIELDS, FIRST_YEAR, FILE_NAME


def get_max_cvss(products: list, vuln_instance: Vulnerability):
    """get max CVSS score from products list"""
    try:
        base_scores = [
            float(product["baseScore"]) for product in products if product["baseScore"]
        ]
        vuln_instance.cvss = max(base_scores)
    except ValueError:  # no base scores
        return 0


async def get_detailed_vulnerability(
    session: aiohttp.ClientSession, vuln_instance: Vulnerability
):
    """send a request to a more detailed URL and insert to vulnerability object"""
    vuln_instance.data_url = f"https://portal.msrc.microsoft.com/api/security-guidance/en-us/CVE/{vuln_instance.cve_id}"
    vuln_instance.display_url = f"https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/{vuln_instance.cve_id}"
    # visit URL
    more_info_response = await session.get(vuln_instance.data_url)
    result = await more_info_response.text()
    # parse JSON to get desc, last updated, max CVSS score, exploited
    detailed = json.loads(result)
    vuln_instance.desc = cleanhtml(detailed["description"].split("\n")[0])
    vuln_instance.exploited = detailed["exploited"]
    if products := detailed["affectedProducts"]:
        get_max_cvss(products, vuln_instance)


async def parse_year_json(session: aiohttp.ClientSession, writer, year: int):
    """parse the main JSON of each year document that includes the basic information
    of all vulnerabilities"""
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
            await get_detailed_vulnerability(session, vuln_instance)
            writer.writerow(vuln_instance.list_of_attrs)


async def scan():
    """main function to gather asyncio tasks and run them concurrently"""
    with open(FILE_NAME, "w",) as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([field.capitalize().replace("_", " ") for field in FIELDS])
        async with aiohttp.ClientSession() as session:
            tasks = [
                parse_year_json(
                    session=session, writer=writer, year=FIRST_YEAR + year_inc
                )
                for year_inc in range(6)
            ]
            await asyncio.gather(*tasks)


if __name__ == "__main__":
    asyncio.run(scan())
