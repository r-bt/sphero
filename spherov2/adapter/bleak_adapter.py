from bleak import BleakScanner, BleakClient
from bleak.backends.bluezdbus import defs, utils
from dbus_fast.message import Message
# import sys
import asyncio
# import pdb
import inspect
import functools
# import os
from spherov2.socketfromfd import fromfd
# import pyshark, 
import threading
# import queue
import multiprocessing
import logging
# import time
import subprocess

logpath = "sphero_log.log"
logger = logging.getLogger('log')
logger.setLevel(logging.INFO)
ch = logging.FileHandler(logpath)
ch.setFormatter(logging.Formatter('%(message)s'))
logger.addHandler(ch)

def get_bytearray_from_hex_string(hex_string: str) -> bytearray:
    # Split the string into individual hex values
    hex_values = hex_string.split(b":")

    # Convert hex values to integers
    int_values = [int(hex_value, 16) for hex_value in hex_values]

    # Create a bytearray from the integer values
    return bytearray(int_values)

class Sniffer:
    _sniffer_process = None
    _queue = None
    _capturing_event = None
    _listeners = {
        "hci0": {},
        "hci1": {},
        "hci2": {},
    }
    _handles_to_address = {}

    @staticmethod
    def init():
        if Sniffer._sniffer_process is not None:
            raise Exception("Sniffer already initialized!")

        Sniffer._queue = multiprocessing.Queue()

        Sniffer._capturing_event = multiprocessing.Event()

        Sniffer._sniffer_process = multiprocessing.Process(target=Sniffer.capture_live_packets)
        Sniffer._sniffer_process.start()

        Sniffer._capturing_event.wait()

    @staticmethod
    def capture_live_packets():
        # Create btmon processes
        btmon_process = subprocess.Popen(['btmon'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        Sniffer._capturing_event.set()
        print("Capturing!")

        i = 0
        mode = 0
        handle_to_add = None
        for stdout_line in iter(btmon_process.stdout.readline, ""):
            if i == 0:
                if b"ATT: Handle Value Notification" in stdout_line:
                    i = 2
                    mode = 1
                if b"LE Connection Complete" in stdout_line:
                    i = 2
                    mode = 2
            else:
                i -= 1
                if i == 0:
                    if mode == 1:
                        data = stdout_line.split(b"Data: ")[1].strip()
                        bt_bytes = bytearray.fromhex(data.decode('utf-8'))
                        Sniffer._queue.put(bt_bytes)
                        mode = 0
                    elif mode == 2:
                        handle_to_add = stdout_line.split(b"Handle: ")[1].strip()
                        mode = 3 
                        i = 3
                    elif mode == 3:
                        data = stdout_line.split(b"Peer address: ")[1].strip()
                        data = data.split(b" ")[0].strip()
                        Sniffer._handles_to_address[handle_to_add] = data
                        print(Sniffer._handles_to_address)
                        mode = 0
        # print("Capturing in {id}!".format(id=multiprocessing.current_process().pid))
        # logger.info("Started Capturing")
        # capture = pyshark.LiveCapture(interface="bluetooth0")
        # packet_generator = capture.sniff_continuously()
        # # pyshark needs to start before any ble connections are made
        # Sniffer._capturing_event.set()
        # logger.info("Set the event")
        # for raw_packet in packet_generator:
        #     if 'btatt' in raw_packet and raw_packet.btatt.get('opcode') == '0x0000001b':
        #         if raw_packet.btatt.get('service_uuid128') == '00:01:00:01:57:4f:4f:20:53:70:68:65:72:6f:21:21':
        #             if 'bthci_acl' in raw_packet:
        #                 if 'src_bd_addr' in raw_packet.bthci_acl.field_names:
        #                     if raw_packet.bthci_acl.src_bd_addr in ['d1:b2:09:68:f8:60', 'c6:e7:40:7b:1b:35']:
        #                         bt_bytes = get_bytearray_from_hex_string(raw_packet.btatt.get('value').encode('latin1'))
        #                         # print("added to queue")
        #                         with open('second_log.log', 'a') as file:
        #                             file.write("Packet captured at {time} with value = {value}\n".format(time=time.time(), value=','.join('{:02x}'.format(x) for x in bt_bytes)))
        #                         Sniffer._queue.put(bt_bytes)

class BleakAdapter(BleakClient):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._follow_file_task = None
        self.listen_to_packets_task = None

    @staticmethod
    async def scan_toys(timeout: float = 5.0, bleak_adapter=None):
        return await BleakScanner.discover(timeout, adapter=bleak_adapter)

    @staticmethod
    async def scan_toy(name: str, timeout: float = 5.0, bleak_adapter=None):
        return await BleakScanner.find_device_by_filter(
                lambda _, a: a.local_name == name, timeout, adapter=bleak_adapter)
    
    async def write(self, uuid, data):
        await self.write_gatt_char(uuid, bytearray(data), True)

    async def get_file_descriptor(self, uuid):
        char = self.services.get_characteristic(uuid)
        ## Acquire File Descriptor
        reply = await self._backend._bus.call(
            Message(
                destination=defs.BLUEZ_SERVICE,
                path=char.path, 
                interface=defs.GATT_CHARACTERISTIC_INTERFACE,
                member="AcquireNotify",
                signature="a{sv}",
                body=[{}],
            )
        )
        utils.assert_reply(reply)
        return reply.unix_fds[0]
    
    @staticmethod
    async def listen_to_socket(sock, cb):
        while True:
            try:
                line = sock.recv(1024)
                if line:
                    cb(bytearray(line))
                await asyncio.sleep(0)
            except BlockingIOError:
                await asyncio.sleep(0)
            except Exception as e:
                print(e)

    def handle_follow_file_task_done(self, task):
        print("Tasked ended!")
        # pdb.set_trace()
        # quit()

    # async def set_callback(self, uuid, callback):
    #     pass

    async def listen_for_packets(self, callback):
        print("Listening in thread {id}".format(id=threading.get_ident()))
        while True:
            await asyncio.sleep(0)
            try:
                packet = Sniffer._queue.get_nowait()
                # print(packet)
                callback(packet)
            except: 
                continue

    async def set_callback(self, uuid, callback):
        """
        Setups a callback which is run whenever new data

        Detects Linux to use AcquireNotify instead of StartNotify to reduce packet loss
        """

        if inspect.iscoroutinefunction(callback):
            def wrapped_callback(data):
                task = asyncio.create_task(callback(uuid, data))
                self._background_tasks.add(task)
                task.add_done_callback(self._background_tasks.discard)
        else:
            wrapped_callback = functools.partial(callback, uuid)

        self._listen_to_packets_task = asyncio.create_task(self.listen_for_packets(wrapped_callback))
        self._listen_to_packets_task.add_done_callback(self.handle_follow_file_task_done)

        await self.start_notify(uuid, lambda *args: None)

        # await self.start_notify(uuid, callback)
        # if sys.platform == "linux" or sys.platform == "linux2":
        #     if self._follow_file_task == None:

        #         

        #         try:
        #             descriptor = await self.get_file_descriptor(uuid)
        #             sock = fromfd(descriptor)
        #             sock.setblocking(False)
        #             self._follow_file_task = asyncio.create_task(self.listen_to_socket(sock, wrapped_callback))
        #             self._follow_file_task.add_done_callback(self.handle_follow_file_task_done)
        #         except Exception as e:
        #             print("Exception!")
        #             pdb.set_trace()
        #             await self.start_notify(uuid, callback)
        # else:
            
