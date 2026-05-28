import asyncio, httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

async def debug():
    async with httpx.AsyncClient(timeout=8.0, verify=False, follow_redirects=True) as c:
        resp = await c.get('http://127.0.0.1:8080/')
        soup = BeautifulSoup(resp.text, 'html.parser')
        base_domain = urlparse('http://127.0.0.1:8080/').netloc
        print('Base domain:', base_domain)
        for tag in soup.find_all('a', href=True):
            href = tag['href']
            link = urljoin('http://127.0.0.1:8080/', href)
            pl = urlparse(link)
            match = (pl.netloc == base_domain or not pl.netloc)
            print(f'  href={href} -> link={link} -> netloc={pl.netloc!r} -> match={match}')

asyncio.run(debug())
