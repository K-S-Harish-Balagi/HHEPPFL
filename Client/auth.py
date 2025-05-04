import subprocess
import platform
import hashlib
import hmac

'''
import os

def generate_strong_passkey():
    passkey_bytes = os.urandom(256)  # 256 random bytes
    return passkey_bytes
'''
    
# 256 Byte Random Passkey
passkey = b'\xcaV\xd4Q\xbeR:\x01vT\x1c\xdc\x03\xbf]K\xd2[\x9b\xce\xfbm\xe8\xe5\xee\xcfY\xcd}\xf9\xfd\x92\xc0j\xab{8^\xe0\x7f\xd5#t\xa7A`.\xdb3\x87\x97\xf2\xba\xb7\xcf\xeaOeRN;\x7f\x0c\xc8\xc1I\nN\xea\xa3\xb4\xe6\xb6/+Q\xfc\x01\x82\x9f\x98\xbb#YVL1\xb1ZC$\xb4\xa7\x16+\xad\x05i\xb2\x98\x9c\xb8\xf9\x8b\xae\xd6D^\xdePE\x9d\xd3\xd5z\xc8\xdaI\x0fu\xc7h4S>\x97\xc3\xd6H4\xbc\xf0\xc4\xdc\xf5\x99\xacgW\x0b\xe7\xde\xda\x01\x13\xb6a\xb2\x16\x030\xf5\xcf \x82K\xba\x85T\x80\xd8\xb6\x89!4\xbb\x00B}\x8c\x8ak\x11\xfb.y\xfd\xf9\x9b&+\x95\xf06\xbc\xe2\xad\xf9\x10\xec\xd7\xf2\xad\xc7\xf5\xfe=\xecbi4\x15\x84Wu\x9e\xb7\xef\xd9\xb3\xf4\xd4PPh\t\x11\xda\xc8\x86OW\xc6@"\xb2\xd7\x19\xd4\x11Z\xaa\x93\xfd\xa7\x95\x9b:\xc8u\xd2:\xcc\x18\xf8\x14\xe9i\xb7\xe1\xfcZe\xb9\xfa\xd2'


def get_device_serial():
    try:
        system = platform.system()
        if system == "Windows":
            command = "wmic bios get serialnumber"
            output = subprocess.check_output(command, shell=True, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
            serial = output.decode().split("\n")[1].strip()
        elif system == "Linux":
            command = "cat /sys/class/dmi/id/board_serial"
            output = subprocess.check_output(command, shell=True, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
            serial = output.decode().strip()
        elif system == "Darwin":  # Mac
            command = "system_profiler SPHardwareDataType | awk '/Serial/ {print $4}'"
            output = subprocess.check_output(command, shell=True, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
            serial = output.decode().strip()
        else:
            serial = "UNKNOWN"
    except Exception:
        serial = "UNKNOWN"
    return serial

def get_hashed_serial():
    serial = get_device_serial()
    return hashlib.sha256(serial.encode()).hexdigest()

def generate_hmac_signature(serial, timestamp):
    message = f"{serial}{timestamp}".encode()
    signature = hmac.new(passkey, message, hashlib.sha256).hexdigest()
    return signature