import sys
import socket
import re
from pathlib import Path

operations = {'ls': 'LIST', 'rm': 'DELE', 'rmdir': 'RMD', 'mkdir': 'MKD', 'cp': 'STOR', 'mv': 'RETR'}

TYPE = 'TYPE I\r\n'
MODE = 'MODE S\r\n'
STRU = 'STRU F\r\n'
PASV = 'PASV \r\n'
QUIT = 'QUIT\r\n'

CTRL_CHANNEL = None
BUFFER = 65565


def parse_url(url):
    if url.startswith('ftp://'):
        strp_ftp = url.replace('ftp://', '')
        if "@" in strp_ftp:
            username_password = strp_ftp.split('@')[0].split(':')
            if len(username_password) < 2:
                username = username_password[0]
                password = ''
            else:
                username = username_password[0]
                password = username_password[1]
            domain_port_path = strp_ftp.split('@')[1]
        else:
            username = 'anonymous'
            password = ''
            domain_port_path = strp_ftp

        path = '/'.join(domain_port_path.split('/')[1:])
        domain_port = domain_port_path.split('/')[0].split(':')
        if len(domain_port) < 2:
            domain = domain_port[0]
            port = 21
        else:
            domain = domain_port[0]
            port = int(domain_port[1])

        return username, password, path, domain, port


def create_connection(hostname, port=21):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((hostname, port))
        return sock
    except Exception as e:
        print(f'Problem occurred while creating socket connection.\nError: {e}')


def send_receive(ctrl_sock, msg, data_sock=None):
    try:
        print(f'Sending message: {msg}')
        ctrl_sock.sendall(msg.encode('utf-8'))
        if data_sock:
            data = data_sock.recv(BUFFER)
        else:
            data = ctrl_sock.recv(BUFFER)

        if data:
            print(f'Message received: \n{data.decode("utf-8")}')
            return data
        else:
            print(f'Noting received from server')
    except Exception as e:
        print(f'Error occurred while sending or receiving.\nError: {e}')


def parse_response(rsp):
    rsp = rsp.decode('utf-8')
    rsp_code = rsp.split(" ")[0]
    rsp_msg = ' '.join(rsp.split(" ")[1:])
    return rsp_code, rsp_msg


def process_ls(ctrl_ch, path):
    try:
        # setting PASV
        data = send_receive(ctrl_ch, PASV)
        rsp_code, rsp_msg = parse_response(data)
        if not rsp_code.startswith("2"):
            raise Exception(f'Unable to execute command: {PASV.strip()}')
        else:
            data_conn = re.search(r'\((.*)\)', rsp_msg).group(1)
            data_conn_ip = '.'.join(data_conn.split(',')[:4])
            data_conn_port = (int(data_conn.split(',')[4:][0]) << 8) + int(data_conn.split(',')[4:][1])

        # creating data_ch
        data_channel = create_connection(data_conn_ip, data_conn_port)
        if data_channel is None:
            raise socket.error('Socket not created')

        msg = f'LIST /{path}\r\n'
        send_receive(ctrl_ch, msg, data_channel)

    except Exception as e:
        print(f'Error while executing "{msg.strip()}" command.\nError: {e}')    # noqa
    finally:
        data_channel.close()    # noqa


def process_rm(ctrl_ch, path):
    try:
        msg = f'DELE /{path}\r\n'
        data = send_receive(ctrl_ch, msg)
        rsp_code, _ = parse_response(data)
        if not rsp_code.startswith("2"):
            raise Exception(f'{msg.strip()} returned non 2xx response')
    except Exception as e:
        print(f'Error while executing "{msg.strip()}" command.\nError: {e}')    # noqa


def process_cp(ctrl_ch, orig_path, dst_path, op, mv=False):
    try:
        # setting TYPE
        send_receive(ctrl_ch, TYPE)

        # setting MODE
        send_receive(ctrl_ch, MODE)

        # setting STRU
        send_receive(ctrl_ch, STRU)

        # setting PASV
        data = send_receive(ctrl_ch, PASV)
        rsp_code, rsp_msg = parse_response(data)
        if not rsp_code.startswith("2"):
            raise Exception(f'Unable to execute command: {PASV.strip()}')
        else:
            data_conn = re.search(r'\((.*)\)', rsp_msg).group(1)
            data_conn_ip = '.'.join(data_conn.split(',')[:4])
            data_conn_port = (int(data_conn.split(',')[4:][0]) << 8) + int(data_conn.split(',')[4:][1])

        # creating data_ch
        data_channel = create_connection(data_conn_ip, data_conn_port)
        if data_channel is None:
            raise socket.error('Socket not created')

        if op == 'RETR':
            fp = Path(dst_path).resolve()
            msg = f'{op} {orig_path}\r\n'

            with open(fp, 'wb+') as file:
                data = send_receive(ctrl_ch, msg)
                rsp_code, _ = parse_response(data)
                if rsp_code != "150":
                    raise Exception(f'RETR returned unexpected response')

                file_data = data_channel.recv(BUFFER)
                file.write(file_data)
                data_channel.close()

                data = ctrl_ch.recv(BUFFER)
                print(f"Message received:\n{data.decode('utf-8')}")

                rsp_code, _ = parse_response(data)
                if not rsp_code.startswith("2"):
                    raise Exception(f'{msg.strip()} returned non 2xx response')

                if mv:
                    process_rm(ctrl_ch, orig_path)

        elif op == 'STOR':
            fp = Path(orig_path).resolve()
            msg = f'{op} {dst_path}\r\n'

            with open(fp, 'rb') as f:
                data = send_receive(ctrl_ch, msg)
                rsp_code, _ = parse_response(data)

                if rsp_code != "150":
                    raise Exception(f'STOR returned unexpected response')

                data_channel.sendfile(file=f, offset=0)
                data_channel.close()

                data = ctrl_ch.recv(BUFFER)
                rsp_code, _ = parse_response(data)
                if not rsp_code.startswith("2"):
                    raise Exception(f'Unable to execute command: "{msg.strip()}"')

                print(f"Message received:\n{data.decode('utf-8')}")
                if mv:
                    fp.unlink()

    except Exception as e:
        print(f'Error while executing "{msg.strip()}" command.\nError: {e}\n')    # noqa


def exc_cmd(cmd, arg_1, arg_2=None):
    if arg_1.startswith('ftp://'):
        username, password, path, hostname, port = parse_url(arg_1)
    elif arg_2 and arg_2.startswith('ftp://'):
        username, password, path, hostname, port = parse_url(arg_2)
    else:
        raise ValueError(f'FTP url not present in arg_1 or arg_2. arg_1 = {arg_1}, arg_2 = {arg_2}')

    # creating control channel socket
    ctrl_channel = create_connection(hostname, port)
    if ctrl_channel is None:
        raise socket.error('Socket not created')

    global CTRL_CHANNEL
    CTRL_CHANNEL = ctrl_channel

    data = ctrl_channel.recv(BUFFER)
    print(data.decode('utf-8'))

    # sending username
    msg = f'USER {username}\r\n'
    send_receive(ctrl_channel, msg)

    if password:
        # sending password
        msg = f'PASS {password}\r\n'
        data = send_receive(ctrl_channel, msg)
        rsp_code, _ = parse_response(data)
        if not rsp_code.startswith("2"):
            raise PermissionError(f'Server refused to connect with the given username: {username} & password: '
                                  f'{password}')

    # executing cmd
    if cmd == 'rmdir' or cmd == 'mkdir':
        msg = f'{operations.get(cmd)} {path}\r\n'
        data = send_receive(ctrl_channel, msg)
        rsp_code, _ = parse_response(data)
        if not rsp_code.startswith("2"):
            raise Exception(f'Unable to execute command: "{msg.strip()}"')

    elif cmd == 'ls':
        process_ls(ctrl_ch=ctrl_channel, path=path)

    elif cmd == 'rm':
        process_rm(ctrl_ch=ctrl_channel, path=path)

    elif cmd == 'mv':
        orig_path, dst_path, op = (path, arg_2, 'RETR') if arg_1.startswith('ftp://') else (arg_1, path, 'STOR')
        process_cp(ctrl_ch=ctrl_channel, orig_path=orig_path, dst_path=dst_path, op=op, mv=True)

    elif cmd == 'cp':
        orig_path, dst_path, op = (path, arg_2, 'RETR') if arg_1.startswith('ftp://') else (arg_1, path, 'STOR')
        process_cp(ctrl_ch=ctrl_channel, orig_path=orig_path, dst_path=dst_path, op=op)

    # quiting from FTP server
    send_receive(ctrl_channel, QUIT)


def main():
    operation, param_1, param_2 = None, None, None
    args = sys.argv
    if len(args) < 3:
        raise ValueError('Invalid amount of arguments passed')
    elif args[1] not in operations:
        raise ValueError(f'Invalid operation "{args[1]}" passed as argument')
    elif len(args) == 3:
        operation = args[1]
        param_1 = args[2]
    elif len(args) == 4:
        operation = args[1]
        param_1 = args[2]
        param_2 = args[3]

    if (operation == 'cp' or operation == 'mv') and not param_2:
        raise ValueError(f'ARG2 is required "{operation}" operation')

    exc_cmd(cmd=operation, arg_1=param_1, arg_2=param_2)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'Error: {error}')
    finally:
        if CTRL_CHANNEL:
            CTRL_CHANNEL.close()    # noqa
