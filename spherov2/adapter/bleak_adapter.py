from bleak import BleakScanner, BleakClient
from bleak.backends.bluezdbus import defs, utils
from dbus_fast.message import Message
import sys
import asyncio
import pdb
import inspect
import functools
import os
from spherov2.socketfromfd import fromfd
import pyshark, threading, pdb
import queue
import multiprocessing

class Sniffer:
    _sniffer_process = None
    _queue = None
    _capturing_event = None

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
        print("Capturing in {id}!".format(id=multiprocessing.current_process().pid))
        capture = pyshark.LiveCapture(interface="bluetooth0")
        packet_generator = capture.sniff_continuously()
        # pyshark needs to start before any ble connections are made
        Sniffer._capturing_event.set()
        for raw_packet in packet_generator:
            if 'bthci_acl' in raw_packet:
                if 'src_bd_addr' in raw_packet.bthci_acl.field_names:
                    if raw_packet.bthci_acl.src_bd_addr in ['d1:b2:09:68:f8:60', 'c6:e7:40:7b:1b:35']:
                        if 'btatt' in raw_packet and raw_packet.btatt.get('opcode') == '0x0000001b':
                            if raw_packet.btatt.get('service_uuid128') == '00:01:00:01:57:4f:4f:20:53:70:68:65:72:6f:21:21':
                                bt_bytes = bytearray(raw_packet.btatt.get('value').encode('latin1'))
                                # print("added to queue")
                                Sniffer._queue.put(bt_bytes)

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
        pdb.set_trace()
        # quit()

    # async def set_callback(self, uuid, callback):
    #     pass

    async def listen_for_packets(self, callback):
        print("Listening in thread {id}".format(id=threading.get_ident()))
        while True:
            await asyncio.sleep(0)
            try:
                # print("getting packet")
                packet = Sniffer._queue.get_nowait()
                print(packet)
            except: 
                # print("Exception!")
                continue

            # print(packet)
            # try:
            #     # packet = queue.get_nowait()
            #     # packet = test_queue.get_nowait()
            #     pass
            #     # packet = Sniffer._queue.get_nowait()
            #     # print(packet)
            #     # raise ValueError("Something")
            # except Exception as e:
            #     continue
            # print("There are {x} elements in queue".format(x=Sniffer._queue.qsize())) 
            # try:
            #     # packet = queue.get_nowait()
            #     packet = Sniffer._queue.get()
            #     print(packet)
            #     # raise ValueError("Something")
            # except Exception as e:
            #     continue
                
            # print("got a packet!")
                # pdb.set_trace()
                # print("Exception!")

            # await asyncio.sleep(0)
        #     try:
        #         packet = Sniffer.get_queue_item()
        #         # print("Got packet!")
        #         print(packet)
        #     except:
        #         # print("Error while getting packet")
        #         await asyncio.sleep(0)
        #         continue
            
        #     if packet is None:
        #         pass

        #     print("got packet from queue")

        #     callback(packet)

    # @staticmethod
    # def test_callback(uuid, data):
    #     print(data)

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

        await self.start_notify(uuid, lambda *args: None)

        self._listen_to_packets_task = asyncio.create_task(self.listen_for_packets(wrapped_callback))
        self._listen_to_packets_task.add_done_callback(self.handle_follow_file_task_done)

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
            
