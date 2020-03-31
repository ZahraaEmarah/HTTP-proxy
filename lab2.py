import sys
import os
import enum
import socket


class HttpRequestInfo(object):
    """
    Represents a HTTP request information

    Since you'll need to standardize all requests you get
    as specified by the document, after you parse the
    request from the TCP packet put the information you
    get in this object.

    To send the request to the remote server, call to_http_string
    on this object, convert that string to bytes then send it in
    the socket.

    client_address_info: address of the client;
    the client of the proxy, which sent the HTTP request.

    requested_host: the requested website, the remote website
    we want to visit.

    requested_port: port of the webserver we want to visit.

    requested_path: path of the requested resource, without
    including the website name.

    NOTE: you need to implement to_http_string() for this class.
    """

    def __init__(self, client_info, method: str, requested_host: str,
                 requested_port: int,
                 requested_path: str,
                 headers: list):
        self.method = method
        self.client_address_info = client_info
        self.requested_host = requested_host
        self.requested_port = requested_port
        self.requested_path = requested_path
        # Headers will be represented as a list of lists
        # for example ["Host", "www.google.com"]
        # if you get a header as:
        # "Host: www.google.com:80"
        # convert it to ["Host", "www.google.com"] note that the
        # port is removed (because it goes into the request_port variable)
        self.headers = headers

    def to_http_string(self):
        """
        Convert the HTTP request/response
        to a valid HTTP string.
        As the protocol specifies:

        [request_line]\r\n
        [header]\r\n
        [headers..]\r\n
        \r\n

        (just join the already existing fields by \r\n)

        You still need to convert this string
        to byte array before sending it to the socket,
        keeping it as a string in this stage is to ease
        debugging and testing.
        """
        http_string = self.method + " " + self.requested_path + " HTTP/1.0\r\n"
        for i in self.headers:
            header = i[0] + ": " + i[1]
            http_string = http_string + header + "\r\n"

        http_string = http_string + "\r\n"
        return http_string

    def to_byte_array(self, http_string):
        """
        Converts an HTTP string to a byte array.
        """
        return bytes(http_string, "UTF-8")

    def display(self):
        print(f"Client:", self.client_address_info)
        print(f"Method:", self.method)
        print(f"Host:", self.requested_host)
        print(f"Port:", self.requested_port)
        stringified = [": ".join([k, v]) for (k, v) in self.headers]
        print("Headers:\n", "\n".join(stringified))


class HttpErrorResponse(object):
    """
    Represents a proxy-error-response.
    """

    def __init__(self, code, message):
        self.code = code
        self.message = message

    def to_http_string(self):
        http_string = self.code + " " + self.message
        http_string = http_string + "\r\n"
        return http_string

    def to_byte_array(self, http_string):
        """
        Converts an HTTP string to a byte array.
        """
        return bytes(http_string, "UTF-8")

    def display(self):
        print(self.to_http_string())


class HttpRequestState(enum.Enum):
    """
    The values here have nothing to do with
    response values i.e. 400, 502, ..etc.

    Leave this as is, feel free to add yours.
    """
    INVALID_INPUT = 0
    NOT_SUPPORTED = 1
    GOOD = 2
    PLACEHOLDER = -1


def entry_point(proxy_port_number):
    """
    Entry point, start your code here.

    Please don't delete this function,
    but feel free to modify the code
    inside it.
    """
    setup_sockets(int(proxy_port_number))
    return None


def setup_sockets(proxy_port_number):
    """
    Socket logic MUST NOT be written in the any
    class. Classes know nothing about the sockets.

    But feel free to add your own classes/functions.

    Feel free to delete this function.
    """
    print("Starting HTTP proxy on port:", proxy_port_number)

    # when calling socket.listen() pass a number
    # that's larger than 10 to avoid rejecting
    # connections automatically.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('127.0.0.1', proxy_port_number))
    sock.listen()
    connection, address = sock.accept()
    cache = {}
    data = b""
    with connection:
        print('Connected on', address)
        while True:
            # Receive the incoming HTTP request
            request = receive_request(connection)
            if request:
                print("*" * 50)
                print("Received HTTP request: ")
                print(request)
                cached_data = "None"
                # Start the HTTP processing pipeline
                try:
                    processed = http_request_pipeline(address, request)
                except IndexError as e:
                    print(e)
                    processed = HttpErrorResponse("400", "Bad Request")

                if isinstance(processed, HttpErrorResponse):  # Is an error
                    print("Error!")
                    print(processed.to_http_string())
                    error_byte_array = processed.to_byte_array(processed.to_http_string())
                    # Sending the error message to client
                    connection.sendall(error_byte_array)
                    sock.close()
                else:
                    print("Sending http request...")
                    for x in cache:
                        if x == request:
                            cached_data = cache[request]
                    print("before req")
                    print(cached_data)

                    if cached_data == "None":
                        processed_string = processed.to_http_string()
                        http_request_bytes = processed.to_byte_array(processed_string)
                        # Open a new socket
                        socket_request = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        socket_request.connect((processed.requested_host, processed.requested_port))
                        # Send the request
                        print("Request bytes: ")
                        print(http_request_bytes)
                        socket_request.send(http_request_bytes)
                        print("Receiving data...")
                        while True:
                            received_data = socket_request.recv(4096)
                            if not received_data:
                                break
                            # Now sending data to client
                            connection.sendall(received_data)
                            data = data + received_data
                        socket_request.close()
                        cache[request] = data
                        print(cache)
                    else:
                        connection.sendall(cached_data)
                    sock.close()
                    print("after req")
                    print(cached_data)
                    print("Data sent!")


def receive_request(connection):
    # This method receives the http request on the established connection
    # and returns the received request as a string
    input_bytes = bytes()
    while True:
        data = connection.recv(1024)
        if data == b'\r\n' or not data:  # End of request condition
            break
        input_bytes = input_bytes + data

    return input_bytes.decode()


def http_request_pipeline(source_address, http_raw_data):
    """
    HTTP request processing pipeline.

    - Validates the given HTTP request and returns
      an error if an invalid request was given.
    - Parses it
    - Returns a sanitized HttpRequestInfo

    returns:
     HttpRequestInfo if the request was parsed correctly.
     HttpErrorResponse if the request was invalid.

    Please don't remove this function, but feel
    free to change its content
    """
    validity = check_http_request_validity(http_raw_data)
    if validity == HttpRequestState.INVALID_INPUT:
        error_response = HttpErrorResponse("400", "Bad Request")
        return error_response
    elif validity == HttpRequestState.NOT_SUPPORTED:
        error_response = HttpErrorResponse("501", "Not Implemented")
        return error_response
    elif validity == HttpRequestState.GOOD:
        error_response = HttpErrorResponse("200", "OK")  # Valid request
        print(error_response.to_http_string())

    # Return error if needed, then:
    parsed = parse_http_request(source_address, http_raw_data)
    if parsed.requested_host == "":
        parsed = sanitize_http_request(parsed)  # Sanitize the request in case of full url in path
    return parsed


def parse_http_request(source_address, http_raw_data):
    """
    This function parses a "valid" HTTP request into an HttpRequestInfo
    object.
    """

    print("*" * 50)
    requested_port = 80  # Default
    parsed_lines = http_raw_data.split("\r\n")  # Parse by new line first
    parsed_spaces = parsed_lines[0].split(" ")  # Parse by spaces
    method = parsed_spaces[0]  # GET / PUT / ...etc
    if parsed_lines[1] != '':  # Relative
        requested_path = parsed_spaces[1]  # The directory

        # Split the second line to get the requested host and port if present
        parsed_output_header = parsed_lines[1].split(" ")
        host_port = parsed_output_header[1].split(":")
        requested_host = host_port[0]
        if len(host_port) > 1:
            requested_port = int(host_port[1])

        # Format header
        parsed_lines.pop(0)
        parsed_lines.pop(0)
        headers = list([["Host", requested_host]])  # Initialize list of headers
        for i in parsed_lines:
            if i != '':
                header = i.split(": ")
                headers.append([header[0], header[1]])

        ret = HttpRequestInfo(source_address, method, requested_host, requested_port, requested_path, headers)
    else:
        # In case of absolute
        requested_path = parsed_spaces[1]
        ret = HttpRequestInfo(source_address, method, "", requested_port, requested_path, [])
    # ret.display()
    return ret


def check_http_request_validity(http_raw_data) -> HttpRequestState:
    """
    Checks if an HTTP request is valid

    returns:
    One of values in HttpRequestState
    """
    valid_methods = list(["GET", "PUT", "HEAD", "POST", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"])
    supported_methods = list(["GET"])
    http_request_info = parse_http_request("", http_raw_data)
    headers = http_request_info.headers
    path = http_request_info.requested_path
    method = http_request_info.method

    # Check for a full url in path in case of no header
    split_path = path.split("/")
    if len(split_path) <= 2 and headers == []:
        no_host = True
    elif not is_a_url_host(path) and headers == []:
        no_host = True
    else:
        no_host = False

    # Check format of request line
    valid_request = True
    lines_list = http_raw_data.split("\r\n")
    request_line_list = lines_list[0].split(" ")
    if request_line_list[2] == '':
        valid_request = False

    # Check for valid header
    header_valid = True
    if headers:
        lines_list.pop(0)
        for i in lines_list:
            if i != "":
                header_split = i.split(": ")
                if len(header_split) <= 1:
                    header_valid = False
                    break

    # Check error type
    if method not in valid_methods:
        return HttpRequestState.INVALID_INPUT
    elif no_host:
        return HttpRequestState.INVALID_INPUT
    elif not header_valid:
        return HttpRequestState.INVALID_INPUT
    elif not valid_request:
        return HttpRequestState.INVALID_INPUT
    elif method not in supported_methods:
        return HttpRequestState.NOT_SUPPORTED
    else:
        return HttpRequestState.GOOD


def is_a_url_host(string):
    parse = string.split(".")
    if len(parse) >= 2:
        return True
    else:
        return False


def sanitize_http_request(request_info: HttpRequestInfo):
    """
    Puts an HTTP request on the sanitized (standard) form
    by modifying the input request_info object.

    for example, expand a full URL to relative path + Host header.

    returns:
    nothing, but modifies the input object
    """
    requested_port = request_info.requested_port  # Default
    parse_by_slash = request_info.requested_path.split("/")
    requested_host = parse_by_slash[2]
    # Initialize header
    header = [("Host", requested_host)]
    # Pop the unneeded values in the parsed string
    parse_by_slash.pop(0)
    parse_by_slash.pop(0)
    parse_by_slash.pop(0)
    # To separate the port if given:
    if parse_by_slash:
        parse_by_colon = parse_by_slash[len(parse_by_slash) - 1].split(":")
        if len(parse_by_colon) > 1:
            parse_by_slash[len(parse_by_slash) - 1] = parse_by_colon[0]
            requested_port = int(parse_by_colon[1])
    else:
        parse_by_colon = request_info.requested_path.split(":")
        if len(parse_by_colon) > 2:
            requested_port = int(parse_by_colon[2])
            split_slashes = parse_by_colon[1].split("/")
            requested_host = split_slashes[2]

    requested_path = ""
    for i in parse_by_slash:
        if i != '':
            requested_path = requested_path + i + "/"
    if not requested_path.startswith('/'):
        requested_path = "/" + requested_path

    if requested_path.endswith("/") and len(requested_path) > 1:
        requested_path = requested_path[0:len(requested_path) - 1]
    ret = HttpRequestInfo(request_info.client_address_info, request_info.method, requested_host,
                          requested_port, requested_path, header)
    return ret


#######################################
# Leave the code below as is.
#######################################


def get_arg(param_index, default=None):
    """
        Gets a command line argument by index (note: index starts from 1)
        If the argument is not supplies, it tries to use a default value.

        If a default value isn't supplied, an error message is printed
        and terminates the program.
    """
    try:
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print(
                f"[FATAL] The comand-line argument #[{param_index}] is missing")
            exit(-1)  # Program execution failed.


def check_file_name():
    """
    Checks if this file has a valid name for *submission*

    leave this function and as and don't use it. it's just
    to notify you if you're submitting a file with a correct
    name.
    """
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_){,2}lab2\.py", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    else:
        print(f"[LOG] File name is correct.")


def main():
    """
    Please leave the code in this function as is.

    To add code that uses sockets, feel free to add functions
    above main and outside the classes.
    """
    print("\n\n")
    print("*" * 50)
    print(f"[LOG] Printing command line arguments [{', '.join(sys.argv)}]")
    check_file_name()
    print("*" * 50)

    # This argument is optional, defaults to 18888
    proxy_port_number = get_arg(1, 18888)
    entry_point(proxy_port_number)


if __name__ == "__main__":
    main()
