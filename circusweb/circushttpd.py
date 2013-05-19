import argparse
import os
import sys
from time import time
from urlparse import urlparse

try:
    from beaker.middleware import SessionMiddleware
    from bottle import app, run, static_file, redirect, request
    from socketio import socketio_manage
except ImportError, e:
    reqs = os.path.join(os.path.abspath(os.path.dirname(__file__)),
                        'web-requirements.txt')
    raise ImportError('You need to install dependencies to run the webui. '
                      'You can do so by using "pip install -r '
                      '%s"\nInitial error: %s' % (reqs, str(e)))

from circusweb.namespace import StatsNamespace
from circusweb import __version__, logger
from circus.util import configure_logger, LOG_LEVELS, DEFAULT_ENDPOINT_MULTICAST
from circusweb.util import (run_command, render_template, set_message, route,
                            MEDIADIR)
from circusweb.session import connect_to_circus, disconnect_from_circus
from circusweb.server import SocketIOServer
import socket
import json
import threading


session_opts = {
    'session.type': 'file',
    'session.cookie_expires': 300,
    'session.data_dir': './data',
    'session.auto': True
}


app = SessionMiddleware(app(), session_opts)


DISCOVERED_ENDPOINTS = []


def autodiscovery_thread():
    any_addr = '0.0.0.0'

    multicast_addr, multicast_port = urlparse(DEFAULT_ENDPOINT_MULTICAST) \
        .netloc.split(':')
    multicast_port = int(multicast_port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                         socket.IPPROTO_UDP)
    sock.bind((any_addr, 0))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    sock.sendto(json.dumps(''),
                (multicast_addr, multicast_port))

    timer = time()
    while True:
        data, address = sock.recvfrom(1024)
        data = json.loads(data)
        endpoint = data.get('endpoint', "")
        if endpoint.startswith('tcp://'):
            # In case of multi interface binding i.e: tcp://0.0.0.0:5557
            endpoint = endpoint.replace('0.0.0.0', address[0])

        DISCOVERED_ENDPOINTS.append(endpoint)

        if time() - timer > 30 * 60:
            # Rediscover every 30 seconds
            del DISCOVERED_ENDPOINTS[:]
            timer = time()
            sock.sendto(json.dumps(''),
                        (multicast_addr, multicast_port))


discovery_thread = threading.Thread(target=autodiscovery_thread)
discovery_thread.start()


@route('/media/<filename:path>', ensure_client=False)
def get_media(filename):
    return static_file(filename, root=MEDIADIR)


@route('/', method='GET')
def index():
    return render_template('index.html')


@route('/watchers/<name>/process/kill/<pid>')
def kill_process(name, pid):
    return run_command(
        func='killproc', args=(name, pid),
        message='process {pid} killed sucessfully'.format(pid=pid),
        redirect_url='/watchers/%s' % name)


@route('/watchers/<name>/process/decr', method='GET')
def decr_proc(name):
    return run_command(
        func='decrproc', args=(name,),
        message='removed one process from the {watcher} pool'.format(
            watcher=name),
        redirect_url='/watchers/%s' % name)


@route('/watchers/<name>/process/incr', method='GET')
def incr_proc(name):

    return run_command(
        func='incrproc', args=(name,),
        message='added one process to the {watcher} pool'.format(watcher=name),
        redirect_url='/watchers/%s' % name)


@route('/watchers/<name>/switch_status', method='GET')
def switch(name):
    return run_command(func='switch_status', args=(name,),
                       message='status switched', redirect_url='/')


@route('/add_watcher', method='POST')
def add_watcher():
    return run_command('add_watcher',
                       kwargs=request.POST,
                       message='added a new watcher',
                       redirect_url='/watchers/%(name)s' % request.POST,
                       redirect_on_error='/')


@route('/watchers/<name>', method='GET')
def watcher(name):
    return render_template('watcher.html', name=name)


@route('/sockets', method='GET')
def sockets():
    return render_template('sockets.html')


# XXX we need to add the ssh server option in the form
@route('/connect', method=['POST', 'GET'], ensure_client=False)
def connect():
    """Connects to the stats client, using the endpoint that's passed in the
    POST body.
    """
    def _ask_connection():
        return render_template('connect.html', endpoints=DISCOVERED_ENDPOINTS)

    if request.method == 'GET':
        return _ask_connection()

    elif request.method == 'POST':
        # if we got an endpoint in the POST body, store it.
        if request.forms.endpoint is None:
            return _ask_connection()

        endpoint = request.forms.endpoint
        client = connect_to_circus(endpoint)
        if not client.connected:
            set_message('Impossible to connect')

        redirect('/')


@route('/disconnect')
def disconnect():
    if disconnect_from_circus():
        set_message('You are now disconnected')
    redirect('/')


@route('/socket.io/<someid>/websocket/<socket_id>', method='GET')
def socketio(someid, socket_id):
    return socketio_manage(request.environ, {'': StatsNamespace})


def main():
    parser = argparse.ArgumentParser(description='Run the Web Console')

    parser.add_argument('--fd', help='FD', default=None)
    parser.add_argument('--host', help='Host', default='0.0.0.0')
    parser.add_argument('--port', help='port', default=8080)
    parser.add_argument('--server', help='web server to use',
                        default=SocketIOServer)
    parser.add_argument('--endpoint', default=None,
                        help='Circus Endpoint. If not specified, Circus will '
                             'ask you which system you want to connect to')
    parser.add_argument('--version', action='store_true', default=False,
                        help='Displays Circus version and exits.')
    parser.add_argument('--log-level', dest='loglevel', default='info',
                        choices=LOG_LEVELS.keys() + [key.upper() for key in
                                                     LOG_LEVELS.keys()],
                        help="log level")
    parser.add_argument('--log-output', dest='logoutput', default='-',
                        help="log output")
    parser.add_argument('--ssh', default=None, help='SSH Server')

    args = parser.parse_args()

    if args.version:
        print(__version__)
        sys.exit(0)

    # configure the logger
    configure_logger(logger, args.loglevel, args.logoutput)

    if args.endpoint is not None:
        connect_to_circus(args.endpoint, args.ssh)

    run(app, host=args.host, port=args.port, server=args.server, fd=args.fd)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
