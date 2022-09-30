# coding:utf-8

import socket
from multiprocessing.dummy import Pool as ThreadPool
import io
import traceback
import logging
import os


class Server(object):

    SERVER_STRING = b"Server: SimpleHttpd/1.0.0\r\n"

    def __init__(self, host, port, worker_count=4):
        self._host = host
        self._port = port
        self._listen_fd = None
        self._worker_count = worker_count
        self._worker_pool = ThreadPool(worker_count)
        self._logger = logging.getLogger("simple.httpd")
        self._logger.setLevel(logging.DEBUG)
        self._logger.addHandler(logging.StreamHandler())

    def run(self):
        self._listen_fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listen_fd.bind((self._host, self._port))
        self._listen_fd.listen(self._worker_count)
        self._logger.info("server on: http://{}:{}".format(self._host, self._port))
        try:
            while True:
                conn, addr = self._listen_fd.accept()
                self._worker_pool.apply_async(self.accept_request, (conn, addr,))
        except Exception as e:
            traceback.print_exc()
        finally:
            self._logger.info("server shutdown")
            self._listen_fd.close()

    def accept_request(self, conn: socket.socket, addr):
        try:
            # request line
            first_line = self._get_line(conn)
            method, path, http_version = first_line.strip().split()
            # request header
            headers = self._get_headers(conn)
            # body
            content_length = int(headers.get("content-length", 0))
            body = b""
            if content_length > 0:
                body = self._get_body(conn, size=content_length)
            # dispatch request
            if method == "GET":
                code = self.try_file(conn, path)
            elif method == "POST":
                code = self.unimplemented(conn)
            else:
                code = self.unimplemented(conn)
            self._logger.info("{}:{} {} {} {} {}".format(addr[0], addr[1], http_version, method, path, code))
        except Exception as e:
            traceback.print_exc()
        finally:
            conn.close()

    def try_file(self, conn: socket.socket, path: str):
        here = os.path.abspath(os.path.dirname(__file__))
        target = os.path.join(here, "www", path.strip("/"))
        if not os.path.isfile(target):
            return self.not_found(conn)
        with open(target, "rb") as target_file:
            data = target_file.read()
            # status line
            conn.sendall(b"HTTP/1.0 200 OK\r\n")
            # headers
            conn.sendall(self.SERVER_STRING)
            if ".html" in path:
                conn.sendall(b"Content-Type: text/html\r\n")
            else:
                conn.sendall(b"Content-Type: application/octetstream\r\n")
            conn.sendall(bytes("Content-Length: {}\r\n".format(len(data)), "utf-8"))
            conn.sendall(b"Connection: close\r\n")
            conn.sendall(b"\r\n")
            # body
            conn.sendall(data)
            return 200

    def not_found(self, conn: socket.socket):
        html = "<html>"
        html += "<head><title>Not Found</title></head>"
        html += "<body>Not Found</body>"
        html += "</html>"
        html = bytes(html, "utf-8")
        conn.sendall(b"HTTP/1.0 404 Not Found\r\n")
        conn.sendall(self.SERVER_STRING)
        conn.sendall(b"Content-Type: text/html\r\n")
        conn.sendall(b"Content-Encoding: utf-8\r\n")
        conn.sendall(bytes("Content-Length: {}\r\n".format(len(html)), "utf-8"))
        conn.sendall(b"\r\n")
        conn.sendall(html)
        return 404

    def unimplemented(self, conn: socket.socket):
        html = "<html>"
        html += "<head><title>Method Not Implemented</title></head>"
        html += "<body>HTTP request method not supported</body>"
        html += "</html>"
        html = bytes(html, "utf-8")
        conn.sendall(b"HTTP/1.0 501 Method Not Implemented\r\n")
        conn.sendall(self.SERVER_STRING)
        conn.sendall(b"Content-Type: text/html\r\n")
        conn.sendall(b"Content-Encoding: utf-8\r\n")
        conn.sendall(bytes("Content-Length: {}\r\n".format(len(html)), "utf-8"))
        conn.sendall(b"\r\n")
        conn.sendall(html)
        return 501

    def _get_line(self, conn: socket.socket, length=1024) -> str:
        buf = io.BytesIO()
        i = 0
        while True and i <= length:
            data = conn.recv(1)
            buf.write(data)
            if data == b"\r":
                _next = conn.recv(1, socket.MSG_PEEK)
                if _next == b"\n":
                    buf.write(conn.recv(1))
                else:
                    buf.write(b"\n")
                break
            i += 1
        return buf.getvalue().decode("utf-8")

    def _get_headers(self, conn: socket.socket) -> dict:
        headers = {}
        header_line = self._get_line(conn).strip()
        while header_line:
            header = header_line.split(":")
            k, v = header[0], header[1]
            headers[k.strip().lower()] = v.strip().lower()
            header_line = self._get_line(conn).strip()
        return headers

    def _get_body(self, conn: socket.socket, size: int):
        buf = io.BytesIO()
        i = 0
        while i < size:
            data = conn.recv(size-i)
            buf.write(data)
            i += len(data)
        return buf.getvalue()


if __name__ == "__main__":
    server = Server("0.0.0.0", 3000)
    server.run()
