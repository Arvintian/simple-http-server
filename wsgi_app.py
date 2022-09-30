import json


def simple_app(environ, start_response):
    body = environ["wsgi.input"].read()
    params: dict = json.loads(body)
    # make response
    data = params.get("content")
    status = "200 OK"
    response_headers = [("Content-Type", "text/plain"), ("Content-Length", len(data))]
    start_response(status, response_headers)
    return [data]
