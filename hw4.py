import logging
import re
import sys
from bs4 import BeautifulSoup
from queue import Queue
from urllib import parse, request
from urllib.parse import urlparse

logging.basicConfig(level=logging.DEBUG, filename='output.log', filemode='w')
visitlog = logging.getLogger('visited')
extractlog = logging.getLogger('extracted')


def parse_links(root, html):
    soup = BeautifulSoup(html, 'html.parser')
    for link in soup.find_all('a'):
        href = link.get('href')
        if href:
            text = link.string
            if not text:
                text = ''
            text = re.sub('\s+', ' ', text).strip()
            yield (parse.urljoin(root, link.get('href')), text)

#sort by having the shorter ones first(I think shorter links tend to relate to more general pages, thus are more important)
#ex: home/details would be more important than "click to view this amazing video"
def parse_links_sorted(root, html):
    soup = BeautifulSoup(html, 'html.parser')
    result = []
    for link in soup.find_all('a'):
        href = link.get('href')
        if href:
            text = link.string
            if not text:
                text = ''
            text = re.sub('\s+', ' ', text).strip()
            score = len(text)
            result.append((score, parse.urljoin(root, link.get('href')), text))

    result.sort()
    return [(a,b) for _,a,b in result]

def get_links(url):
    res = request.urlopen(url)
    return list(parse_links(url, res.read()))


def get_nonlocal_links(url):
    '''Get a list of links on the page specificed by the url,
    but only keep non-local links and non self-references.
    Return a list of (link, title) pairs, just like get_links()'''

    # TODO: implement
    links = get_links(url)
    filtered = []

    ourUrl = urlparse(url)

    for l in links:
        #print(f"Original URL: {url}")
        #print(f"Checking link: {l[0]}")
        curUrl = urlparse(l[0])
        if curUrl.scheme not in ('http', 'https'):
            #print("not https")
            continue
        if ourUrl.netloc != curUrl.netloc:
            #print("not same")
            filtered.append(l)
        elif ourUrl.path != curUrl.path:
            #print("not same")
            filtered.append(l)
        #else:
            #print("same")
    return filtered


def crawl(root, wanted_content=[], within_domain=True):
    '''Crawl the url specified by `root`.
    `wanted_content` is a list of content types to crawl
    `within_domain` specifies whether the crawler should limit itself to the domain of `root`
    '''
    # TODO: implement

    queue = Queue()
    queue.put(root)

    visited = []
    extracted = []

    base = urlparse(root).netloc

    while not queue.empty():
        url = queue.get()

        #skip visited ones
        if url in visited:
            continue

        try:
            req = request.urlopen(url)

            #do the content type thing
            content_type = req.headers['Content-Type']

            if wanted_content and content_type not in wanted_content:
                continue



            html = req.read()

            visited.append(url)
            visitlog.debug(url)

            for ex in extract_information(url, html):
                extracted.append(ex)
                extractlog.debug(ex)

            for link, title in parse_links_sorted(url, html):
                p1 = urlparse(link)
                p2 = urlparse(url)

                #skip self reference
                if p1.path == p2.path and p1.netloc == p2.netloc:
                    continue
                if p1.netloc != base and within_domain:
                    continue

                queue.put(link)

        except Exception as e:
            print(e, url)

    return visited, extracted


def extract_information(address, html):
    '''Extract contact information from html, returning a list of (url, category, content) pairs,
    where category is one of PHONE, ADDRESS, EMAIL'''

    # TODO: implement
    results = []
    for match in re.findall('\d\d\d-\d\d\d-\d\d\d\d', str(html)):
        results.append((address, 'PHONE', match))
   
    for match in re.findall('[\w\.-]+@[\w\.-]+\.\w+', str(html)):
        results.append((address, 'EMAIL', match))

    for match in re.findall('[A-Z][a-zA-Z]*, [A-Z][a-zA-Z]* \d\d\d\d\d', str(html)):
        results.append((address, 'ADDRESS', match))

    return results


def writelines(filename, data):
    with open(filename, 'w') as fout:
        for d in data:
            print(d, file=fout)


def main():
    site = sys.argv[1]

    links = get_links(site)
    writelines('links.txt', links)

    nonlocal_links = get_nonlocal_links(site)
    writelines('nonlocal.txt', nonlocal_links)

    visited, extracted = crawl(site)
    writelines('visited.txt', visited)
    writelines('extracted.txt', extracted)


if __name__ == '__main__':
    main()