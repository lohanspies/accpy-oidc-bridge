import base64
import json
# TODO - import env variables


def create_short_url(presentation_request: dict):
    b64_presentation = base64.b64encode(
        bytes(json.dumps(presentation_request), "utf-8")
    ).decode("utf-8")
    #TODO - fix static variable for url
    # url = f"{settings.SITE_URL}?m={b64_presentation}"
    url = f"https://localhost:5000?m={b64_presentation}"
    return url, b64_presentation
