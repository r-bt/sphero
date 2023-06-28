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

class BleakAdapter(BleakClient):
    _follow_file_task = None;

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
        quit()

    async def set_callback(self, uuid, callback):
        """
        Setups a callback which is run whenever new data

        Detects Linux to use AcquireNotify instead of StartNotify to reduce packet loss
        """
        if sys.platform == "linux" or sys.platform == "linux2":
            if self._follow_file_task == None:

                if inspect.iscoroutinefunction(callback):

                    def wrapped_callback(data):
                        task = asyncio.create_task(callback(uuid, data))
                        self._background_tasks.add(task)
                        task.add_done_callback(self._background_tasks.discard)

                else:
                    wrapped_callback = functools.partial(callback, uuid)

                try:
                    descriptor = await self.get_file_descriptor(uuid)
                    sock = fromfd(descriptor)
                    sock.setblocking(False)
                    self._follow_file_task = asyncio.create_task(self.listen_to_socket(sock, wrapped_callback))
                    self._follow_file_task.add_done_callback(self.handle_follow_file_task_done)
                except Exception:
                    print("Exception!")
                    await self.start_notify(uuid, callback)
        else:
            await self.start_notify(uuid, callback)
