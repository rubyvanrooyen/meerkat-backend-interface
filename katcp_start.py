import json
import logging
import os
import signal
import socket
import tornado

from argparse import (ArgumentParser,
                      ArgumentDefaultsHelpFormatter)
from src.katcp_server import BLBackendInterface
# from src.effelsberg.config import get_nodes


@tornado.gen.coroutine
def on_shutdown(ioloop, server, log):
    log.info("Shutting down server")
    yield server.stop()
    ioloop.stop()


def cli():
    usage = "%(prog)s [options]"
    description = 'start BLUSE KATCP server'

    parser = ArgumentParser(usage=usage,
                            description=description,
                            formatter_class=ArgumentDefaultsHelpFormatter)
    parser.add_argument(
        '--ip',
        type=str,
        default="localhost",
        # default="10.8.76.31",  # BLH1 IP address
        help='fixed IP of localhost system')
    parser.add_argument(
        '-p', '--port',
        type=long,
        default=5000,  # default CAM port
        # default=8050,  # default port on BLH1
        help='port number to bind to')
    parser.add_argument(
        '--nodeset',
        type=str,
        default="effelsberg",
        help='name of the nodeset to use')

    # Options for development and testing
    title = "development and testing"
    description = "additional convenience settings"
    group = parser.add_argument_group(title=title,
                                      description=description)
    group.add_argument(
        '--debug',
        action='store_true',
        help='verbose logger output for debugging')

    main(parser.parse_args())


# Set up logging to console and file.
def set_logger(log_file='/tmp/BLUSE.katcpserver.log',
               log_level=logging.DEBUG):

    log = logging.getLogger("BLUSE.interface")
    FORMAT = "[ %(levelname)s - %(asctime)s - %(filename)s:%(lineno)s] %(message)s"
    logging.basicConfig(format=FORMAT)
    log.setLevel(log_level)

    # create and add logfile handler
    f_handler = logging.FileHandler(log_file)
    log_format = logging.Formatter(FORMAT)  # optional
    f_handler.setFormatter(log_format)
    log.addHandler(f_handler)

    # Depricated logging in newer versions of ubuntu does not work like this anymore
    # syslog_addr = '/dev/log' if os.path.exists('/dev/log') else '/var/run/syslog'
    # handler = logging.handlers.SysLogHandler(address=syslog_addr)
    # log.addHandler(handler)

    return log


def main(args):

    if args.debug:
        # note: debug logging will only go to logfile
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    log = set_logger(log_level=log_level)
    log.info("Starting BLBackendInterface instance")

    ioloop = tornado.ioloop.IOLoop.current()
    server = BLBackendInterface(args.ip, args.port)
    signal.signal(signal.SIGINT, lambda sig, frame: ioloop.add_callback_from_signal(
        on_shutdown, ioloop, server))
    def start():
        server.start()
        log.info("Listening at {0}, Ctrl-C to terminate server".format(server.bind_address))
        # nodes = get_nodes(args.nodeset)
        # for node in nodes:
        #     ip = socket.gethostbyname(node["host"])
        #     print node["host"],ip,node["port"]
        #     server._add_node(node["host"],ip,node["port"])
    ioloop.add_callback(start)
    ioloop.start()

if __name__ == "__main__":
    cli()

