# Sphero

![Read the Docs](https://img.shields.io/readthedocs/sphero?style=for-the-badge) ![GitHub last commit](https://img.shields.io/github/last-commit/r-bt/sphero?style=for-the-badge) [![All Contributors](https://img.shields.io/github/all-contributors/r-bt/sphero?color=ee8449&style=for-the-badge)](#contributors)

Sphero is a python library for controlling [Sphero](https://sphero.com/) toys. It implements the Sphero Version 2 [BLE API](https://sdk.sphero.com/docs/api_spec/general_api/) and utilizes python's new `asyncio` features to provide idiomatic ways of discovering, controlling and reading data from a variety of Sphero toys.

Sphero is a fork of the wonderful [spherov2 library](https://github.com/artificial-intelligence-class/spherov2.py). It implements an `async` API by centering bleak [bleak](https://github.com/hbldh/bleak) (a BLE library) to provide a performant, cross-platform, and multi-agent API

## Currently supported toys

| Name                    | Status |
|-------------------------|--------|
| Sphero 2.0 / SPRK       |✅      |
| Sphero Ollie            |✅      |
| Sphero BB-8             |✅      |
| Sphero BB-9E            |✅      |
| Sphero R2-D2 / R2-Q5    |✅      |
| Sphero BOLT             |✅      |
| Sphero SPRK+ / SPRK 2.0 |✅      |
| Sphero Mini             |✅      |
| Sphero RVR              |✅      |

## Usage

To install the library, run `pip install spherov2`. Python version `>= 3.7` are supported.

The library currently has two adapters, `BleakAdapter` and `TCPAdapter`. `BleakAdapter` is used by default when adapter is not specified, which connects to toys using the local Bluetooth adapter. For example:

```python
from spherov2 import scanner

with scanner.find_toy() as toy:
    ...
```

`TCPAdapter` allows the user to send and receive Bluetooth packets connected to another host via a server running on that host as a relay. To start the server, run `python -m spherov2.adapter.tcp_server [host] [port]`, with `host` and `port` by default being `0.0.0.0` and `50004`. To use the adapter, for example:

```python
from spherov2 import scanner
from spherov2.adapter.tcp_adapter import get_tcp_adapter

with scanner.find_toy(adapter=get_tcp_adapter('localhost')) as toy:
    ...
```

The TCP server is written in asynchronous fashion using `asyncio`, so that it supports `bleak` on all platforms.

On whichever device you decide to connect to the toys, you have to first install the BLE library by `pip install bleak`.

### Scanner

You can scan the toys around you using the scanner helper. To find all possible toys, simply call `scanner.find_toys()`. To find only a single toy, use `scanner.find_toy()`.

You can also find toys using specific filters. Please refer to the [document](https://spherov2.readthedocs.io/en/latest/scanner.html) for more information.

### APIs

There are two ways you can interact with the toys, one is to use the low-level APIs implemented for each toy with the commands they support. Low-level APIs can be found for each toy under `spherov2.toy.*`, and is not documented.

The other and recommended way is to use the high level API `spherov2.sphero_edu.SpheroEduAPI`, which is an implementation of the official [Sphero Edu APIs](https://sphero.docsapp.io/docs/get-started). Documentations can be found inside the source files with the docstrings, or [here](https://spherov2.readthedocs.io/en/latest/sphero_edu.html) as an HTML rendered version. For example:

```python
from spherov2 import scanner
from spherov2.sphero_edu import SpheroEduAPI

toy = scanner.find_toy()
with SpheroEduAPI(toy) as api:
    api.spin(360, 1)
```

## Comparison to other libraries

| Name     | 
|----------|
| [SpheroV2](https://github.com/artificial-intelligence-class/spherov2.py) |
| [SpheroNav](https://github.com/Tordensky/SpheroNav) |

## Acknowledgments

The logic is written based on reverse-engineering the official [Sphero Edu for Android](https://play.google.com/store/apps/details?id=com.sphero.sprk), with the help from available documentation and other unofficial community-based Sphero libraries like [igbopie/spherov2.js](https://github.com/igbopie/spherov2.js) and [EnotYoyo/pysphero](https://github.com/EnotYoyo/pysphero).

This project uses the [hbldh/bleak](https://github.com/hbldh/bleak) Bluetooth Low Energy library, which works across all platforms.

This library is made for educational purposes.  It is used by students in [CIS 521 - Artificial Intelligence](http://artificial-intelligence-class.org/) at the University of Pennsylvania, where we use Sphero robots to help teach the foundations of AI.

It is published as an open-source library under the [MIT License](LICENSE).

## Contributors

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->
