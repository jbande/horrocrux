import base64


def byte_type_from_network(data):
    return base64.b64decode(data.encode('utf-8'))


def byte_type_to_network(data):
    return base64.b64encode(data).decode("utf-8")
