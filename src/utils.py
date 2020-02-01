import re


def cleanhtml(raw_html):
    """clean string of HTML tags"""
    cleanr = re.compile("<.*?>")
    cleantext = re.sub(cleanr, "", raw_html)
    return cleantext
