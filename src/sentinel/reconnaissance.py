"""Single-origin bounded reconnaissance; target HTML is retained only transiently."""
import re
from html import unescape
from sentinel.redaction import redact

def inspect(client, url):
    response=client.request(url)
    title=None
    if response.body:
        match=re.search(br"<title[^>]*>(.*?)</title\s*>",response.body,re.I|re.S)
        if match:
            title=redact(unescape(match.group(1).decode("utf-8","replace")).strip()[:160])
    return response,{"status":response.status,"url":response.url,"elapsed_ms":round(response.elapsed_ms,2),"headers":response.headers,"content_type":response.headers.get("content-type"),"title":title,"error":response.error}
