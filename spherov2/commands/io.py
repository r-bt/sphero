import struct
from enum import IntFlag, IntEnum

from spherov2.commands import Commands
from spherov2.helper import to_bytes, to_int


class AudioPlaybackModes(IntFlag):
    PLAY_IMMEDIATELY = 0x0  # 0b0
    PLAY_ONLY_IF_NOT_PLAYING = 0x1  # 0b1
    PLAY_AFTER_CURRENT_SOUND = 0x2  # 0b10


class UsbConnectionStatus(IntEnum):
    UNKNOWN = 0
    CONNECTED_BUT_NOT_READY = 1
    CONNECTED_AND_READY = 2
    DISCONNECTED = 3


class FadeOverrideOptions(IntEnum):
    NONE = 0
    NO_FADING = 1
    FADING_ANIMATIONS = 2


class SpecdrumsColorPaletteIndicies(IntEnum):
    DEFAULT = 0
    MIDI = 1


class FrameInfoTypes(IntEnum):
    COMPRESSED_FRAME_PLAYER_INFO_TYPE_8_BIT = 0
    COMPRESSED_FRAME_PLAYER_INFO_TYPE_16_BIT = 1
    COMPRESSED_FRAME_PLAYER_INFO_TYPE_32_BIT = 2
    COMPRESSED_FRAME_PLAYER_INFO_TYPE_64_BIT = 3


class FrameRotationOptions(IntEnum):
    NORMAL = 0
    ROTATE_90_DEGREES = 1
    ROTATE_180_DEGREES = 2
    ROTATE_270_DEGREES = 3


class TextScrollingReasonCodes(IntEnum):
    DONE = 0
    LOOPING = 1


class IO(Commands):
    _did = 26

    @staticmethod
    async def set_led(toy, s, s2, s3, s4, b, proc=None):  # Untested / Unknown Param Names
        await toy._execute(IO._encode(toy, 4, proc, [s, s2, s3, s4, b]))

    @staticmethod
    async def play_audio_file(toy, sound, playback_mode: AudioPlaybackModes, proc=None):
        await toy._execute(IO._encode(toy, 7, proc, [*to_bytes(sound, 2), playback_mode]))

    @staticmethod
    async def set_audio_volume(toy, volume, proc=None):
        await toy._execute(IO._encode(toy, 8, proc, [volume]))

    @staticmethod
    async def get_audio_volume(toy, proc=None):
        return await toy._execute(IO._encode(toy, 9, proc)).data[0]

    @staticmethod
    async def stop_all_audio(toy, proc=None):
        await toy._execute(IO._encode(toy, 10, proc))

    @staticmethod
    async def set_all_leds_with_16_bit_mask(toy, mask, values, proc=None):
        await toy._execute(IO._encode(toy, 14, proc, [*to_bytes(mask, 2), *values]))

    @staticmethod
    async def start_idle_led_animation(toy, proc=None):
        await toy._execute(IO._encode(toy, 25, proc))

    @staticmethod
    async def set_all_leds_with_32_bit_mask(toy, mask, values, proc=None):
        await toy._execute(IO._encode(toy, 26, proc, [*to_bytes(mask, 4), *values]))

    @staticmethod
    async def set_all_leds_with_8_bit_mask(toy, mask, values, proc=None):  # Untested / Unknown Param Names
        await toy._execute(IO._encode(toy, 28, proc, [*to_bytes(mask, 1), *values]))

    @staticmethod
    async def enable_color_tap_notify(toy, z, proc=None):  # Untested / Unknown Param Names
        await toy._execute(IO._encode(toy, 29, proc, [z]))

    color_tap_notify = (26, 30, 0xff), lambda listener, p: listener(p.data[0])  # Untested / Unknown Param Names

    @staticmethod
    async def set_compressed_frame_player_pixel(toy, x, y, r, g, b, proc=None):
        await toy._execute(IO._encode(toy, 45, proc, [x, y, r, g, b]))

    @staticmethod
    async def set_compressed_frame_player(toy, s_arr, proc=None):
        await toy._execute(IO._encode(toy, 46, proc, [*s_arr]))

    @staticmethod
    async def set_compressed_frame_player_one_color(toy, r, g, b, proc=None):
        await toy._execute(IO._encode(toy, 47, proc, [r, g, b]))

    @staticmethod
    async def save_compressed_frame_player64_bit_frame(toy, frame_index, compressed_frame, proc=None):
        await toy._execute(IO._encode(toy, 48, proc, [*to_bytes(frame_index, 2), *compressed_frame]))

    @staticmethod
    async def save_compressed_frame_player_animation(toy, animation_id, fps: int, fade_animation:bool, palette_colors, frames_indexes, proc=None):
        await toy._execute(IO._encode(
            toy, 49, proc, [animation_id, fps % 31, int(fade_animation), len(palette_colors) // 3, *palette_colors, *struct.pack('>%dH' % (len(frames_indexes) + 1), len(frames_indexes), *frames_indexes)]))

    @staticmethod
    async def play_compressed_frame_player_animation(toy, animation_id, proc=None):
        await toy._execute(IO._encode(toy, 50, proc, [animation_id]))

    @staticmethod
    async def play_compressed_frame_player_frame(toy, i, proc=None):  # unknown names
        await toy._execute(IO._encode(toy, 51, proc, to_bytes(i, 2)))

    @staticmethod
    async def get_compressed_frame_player_list_of_frames(toy, proc=None):
        data = await toy._execute(IO._encode(toy, 52, proc)).data
        return struct.unpack('>%dH' % (len(data) // 2), data)

    @staticmethod
    async def delete_all_compressed_frame_player_animations_and_frames(toy, proc=None):
        await toy._execute(IO._encode(toy, 53, proc))

    @staticmethod
    async def pause_compressed_frame_player_animation(toy, proc=None):
        await toy._execute(IO._encode(toy, 54, proc))

    @staticmethod
    async def resume_compressed_frame_player_animation(toy, proc=None):
        await toy._execute(IO._encode(toy, 55, proc))

    @staticmethod
    async def reset_compressed_frame_player_animation(toy, proc=None):
        await toy._execute(IO._encode(toy, 56, proc))

    @staticmethod
    async def override_compressed_frame_player_animation_global_settings(toy, fps:int, fade_options:FadeOverrideOptions, proc=None):  # Untested / Unknown Param Names
        await toy._execute(IO._encode(toy, 57, proc, [fps, fade_options]))

    @staticmethod
    async def set_compressed_frame_player_frame_rotation(toy, rotation: FrameRotationOptions, proc=None):
        await toy._execute(IO._encode(toy, 58, proc, [rotation.value]))

    @staticmethod
    async def set_compressed_frame_player_text_scrolling(toy, str_to_display: str, r, g, b, speed: int, repeat: bool, proc=None):
        await toy._execute(IO._encode(toy, 59, proc, [r, g, b, speed % 0x1f, int(repeat), *[ord(c) for c in str_to_display[:25]], 0x00]))

    set_compressed_frame_player_text_scrolling_notify = (26, 60, 0xff), lambda listener, p: listener(
        p.data[0])  # Untested / Unknown Param Names

    @staticmethod
    async def draw_compressed_frame_player_line(toy, x1, y1, x2, y2, r, g, b, proc=None):
        await toy._execute(IO._encode(toy, 61, proc, [x1, y1, x2, y2, r, g, b]))

    @staticmethod
    async def draw_compressed_frame_player_fill(toy, x1, y1, x2, y2, r, g, b, proc=None):
        await toy._execute(IO._encode(toy, 62, proc, [x1, y1, x2, y2, r, g, b]))

    compressed_frame_player_animation_complete_notify = (26, 63, 0xff), lambda listener, p: listener(p.data[0])

    @staticmethod
    async def assign_compressed_frame_player_frames_to_animation(toy, s, i, i_arr, proc=None):  # unknown names
        await toy._execute(IO._encode(toy, 64, proc, [s, *struct.pack('>%dH' % (len(i_arr) + 1), i, *i_arr)]))

    @staticmethod
    async def save_compressed_frame_player_animation_without_frames(toy, s, s2, z, s3, s_arr, i, proc=None):  # unknown names
        await toy._execute(IO._encode(toy, 65, proc, [s, s2, int(z), s3, *s_arr, *to_bytes(i, 2)]))

    @staticmethod
    async def set_compressed_frame_player_single_character(toy, r:int, g:int, b:int, character:str, proc=None):
        await toy._execute(IO._encode(toy, 66, proc, [r, g, b, ord(character)]))

    @staticmethod
    async def play_compressed_frame_player_animation_with_loop_option(toy, animation_id, loop, proc=None):
        await toy._execute(IO._encode(toy, 67, proc, [animation_id, int(loop)]))

    @staticmethod
    async def get_active_color_palette(toy, proc=None):
        return await toy._execute(IO._encode(toy, 68, proc)).data

    @staticmethod
    async def set_active_color_palette(toy, rgb_index_bytes, proc=None):
        await toy._execute(IO._encode(toy, 69, proc, rgb_index_bytes))

    @staticmethod
    async def get_color_identification_report(toy, red, green, blue, confidence_threshold, proc=None):
        return await toy._execute(IO._encode(toy, 70, proc, [red, green, blue, confidence_threshold])).data

    @staticmethod
    async def load_color_palette(toy, palette_index, proc=None):
        await toy._execute(IO._encode(toy, 71, proc, [palette_index]))

    @staticmethod
    async def save_color_palette(toy, palette_index, proc=None):
        await toy._execute(IO._encode(toy, 72, proc, [palette_index]))

    @staticmethod
    async def get_compressed_frame_player_frame_info_type(toy, proc=None):
        return FrameInfoTypes(await toy._execute(IO._encode(toy, 76, proc)).data[0])

    @staticmethod
    async def save_compressed_frame_player16_bit_frame(toy, i, i2, i3, i4, i5, proc=None):  # unknown names
        return to_int(await toy._execute(IO._encode(toy, 77, proc, struct.pack('>5H', i, i2, i3, i4, i5))).data)

    @staticmethod
    async def release_led_requests(toy, proc=None):
        await toy._execute(IO._encode(toy, 78, proc))
