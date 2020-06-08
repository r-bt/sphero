from enum import IntEnum
from functools import partial
from spherov2.helper import to_bytes
from spherov2.packet import Packet


class CollisionDetectionMethods(IntEnum):
    NO_COLLISION_DETECTION = 0
    ACCELEROMETER_BASED_DETECTION = 1
    ACCELEROMETER_BASED_WITH_EXTRA_FILTERING = 2
    HYBRID_ACCELEROMETER_AND_CONTROL_SYSTEM_DETECTION = 3


class Sensor:
    __encode = partial(Packet, device_id=24)
    sensor_streaming_data_notify = (24, 2, 0xff)

    @staticmethod
    def set_sensor_streaming_mask(interval, count, sensor_masks, target_id=None):
        return Sensor.__encode(
            command_id=0,
            data=[*to_bytes(interval, 2), count, *to_bytes(sensor_masks, 4)],
            target_id=target_id
        )

    @staticmethod
    def set_extended_sensor_streaming_mask(sensor_masks, target_id=None):
        return Sensor.__encode(command_id=12, data=to_bytes(sensor_masks, 4), target_id=target_id)

    @staticmethod
    def enable_gyro_max_notify(target_id=None):
        return Sensor.__encode(command_id=15, target_id=target_id)

    @staticmethod
    def configure_collision_detection(collision_detection_method: CollisionDetectionMethods,
                                      x_threshold, y_threshold, x_speed, y_speed, dead_time, target_id=None):
        return Sensor.__encode(command_id=17,
                               data=[collision_detection_method, x_threshold, y_threshold, x_speed, y_speed, dead_time],
                               target_id=target_id)

    @staticmethod
    def reset_locator_x_and_y(target_id=None):
        return Sensor.__encode(command_id=19, target_id=target_id)

    @staticmethod
    def set_locator_flags(locator_flags: bool, target_id=None):
        return Sensor.__encode(command_id=23, data=[int(locator_flags)], target_id=target_id)
