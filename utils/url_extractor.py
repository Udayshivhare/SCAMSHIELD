import re


def extract_urls(text):
    url_pattern = r"https?://[^\s]+"

    urls = re.findall(url_pattern, text)

    return urls