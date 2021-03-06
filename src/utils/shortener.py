import base64
import json
import os

SITE_URL = os.getenv('SITE_URL')

def create_short_url(presentation_request: dict):
    b64_presentation = base64.b64encode(
        bytes(json.dumps(presentation_request), "utf-8")
    ).decode("utf-8")
    # url = f"{settings.SITE_URL}?m={b64_presentation}"
    url = f"{SITE_URL}?m={b64_presentation}"
    return url, b64_presentation
