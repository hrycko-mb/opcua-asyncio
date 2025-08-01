# A copy of fork of the [asyncua](https://github.com/FreeOpcUa/opcua-asyncio) library

The fork is **publicly** available on Github [here](https://github.com/hrycko-mb/opcua-asyncio).

---

OPC UA / IEC 62541 Client and Server for Python >= 3.8 and pypy3 .
http://freeopcua.github.io/, https://github.com/FreeOpcUa/opcua-asyncio

# opcua-asyncio

opcua-asyncio is an asyncio-based asynchronous OPC UA client and server based on python-opcua, removing support of python < 3.8.
Asynchronous programming allows for simpler code (e.g. less need for locks) and can potentially provide performance improvements.
This library also provides a [synchronous wrapper](https://github.com/FreeOpcUa/opcua-asyncio/blob/master/asyncua/sync.py) over the async API, which can be used in synchronous code instead of python-opcua.

---

The OPC UA binary protocol implementation has undergone extensive testing with various OPC UA stacks. The API offers both a low level interface to send and receive all UA defined structures and high level classes allowing to write a server or a client in a few lines. It is easy to mix high level objects and low level UA calls in one application. Most low level code is autogenerated from xml specification.

The test coverage reported by coverage.py is over 95%, with the majority of the non-tested code being autogenerated code that is not currently in use.

# Warnings

opcua-asyncio is open-source and comes with absolutely no warranty. We try to keep it as bug-free as possible, and try to keep the API stable, but bugs and API changes will happen! In particular, API changes are expected to take place prior to any 1.0 release.

Some renaming of methods from get_xx to read_xx and set_xx to write_xxx have been made to better follow OPC UA naming conventions

Version 0.9.9 introduces some argument renaming due to more automatic code generation. Especially the arguments to NodeId, BrowseName, LocalizedText and DataValue, which are now CamelCase instead of lower case, following the OPC UA conventions used in all other structures in this library

# Installation

With uv/pip

    uv pip install asyncua

# Usage

We assume that you already have some experience with Python, the asyncio module, the async / await syntax and the concept of asyncio Tasks.

## Client class

The `Client` class provides a high level API for connecting to OPC UA servers, session management and access to basic
address space services.
The client can be used as a context manager. The client will then automatically connect and disconnect withing the `with`syntax.

```python
from asyncua import Client

async with Client(url='opc.tcp://localhost:4840/freeopcua/server/') as client:
    while True:
        # Do something with client
        node = client.get_node('i=85')
        value = await node.read_value()
```

Of course, you can also call the `connect`, `disconnect` methods yourself if you do not want to use the context manager.

See the example folder and the code for more information on the client API.

## Node class

The `Node` class provides a high level API for management of nodes as well as data access services.

## Subscription class

The `Subscription` class provides a high level API for management of monitored items.

## Server class

The `Server` class provides a high level API for creation of OPC UA server instances.

# Documentation

The documentation is available here [ReadTheDocs](http://opcua-asyncio.readthedocs.org/en/latest/).

The API remains mostly unchanged with regards to [python-opcua](http://opcua-asyncio.rtfd.io/).
The main difference is that most methods are now asynchronous.
Please have a look at [the examples](https://github.com/FreeOpcUa/opcua-asyncio/blob/master/examples) and/or the code.

A simple GUI client is available at: https://github.com/FreeOpcUa/opcua-client-gui

Browse the examples: https://github.com/FreeOpcUa/opcua-asyncio/tree/master/examples

The minimal examples are a good starting point.
Minimal client example: https://github.com/FreeOpcUa/opcua-asyncio/blob/master/examples/client-minimal.py
Minimal server example: https://github.com/FreeOpcUa/opcua-asyncio/blob/master/examples/server-minimal.py

A set of command line tools also available: https://github.com/FreeOpcUa/opcua-asyncio/tree/master/tools

- `uadiscover `(find_servers, get_endpoints and find_servers_on_network calls)
- `uals `(list children of a node)
- `uahistoryread`
- `uaread `(read attribute of a node)
- `uawrite `(write attribute of a node)
- `uacall `(call method of a node)
- `uasubscribe `(subscribe to a node and print datachange events)
- `uaclient `(connect to server and start python shell)
- `uaserver `(starts a demo OPC UA server)
  `tools/uaserver --populate --certificate cert.pem --private_key pk.pem`

How to generate certificate: https://github.com/FreeOpcUa/opcua-asyncio/tree/master/examples/generate_certificate.sh

## Client support

What works:

- connection to server, opening channel, session
- browsing and reading attributes value
- getting nodes by path and nodeids
- creating subscriptions
- subscribing to items for data change
- subscribing to events
- adding nodes
- method call
- user and password
- history read
- login with certificate
- communication encryption
- removing nodes

Tested servers: freeopcua C++, freeopcua Python, prosys, kepware, beckhoff, winCC, B&R, …

Not implemented yet:

- localized text feature
- XML protocol
- UDP (PubSub stuff)
- WebSocket
- maybe automatic reconnection...

## Server support

What works:

- creating channel and sessions
- read/set attributes and browse
- getting nodes by path and nodeids
- autogenerate address space from spec
- adding nodes to address space
- datachange events
- events
- methods
- basic user implementation (one existing user called admin, which can be disabled, all others are read only)
- encryption
- certificate handling
- removing nodes
- history support for data change and events
- more high level solution to create custom structures

Tested clients: freeopcua C++, freeopcua Python, uaexpert, prosys, quickopc

Not yet implemented:

- UDP (PubSub stuff)
- WebSocket
- session restore
- alarms
- XML protocol
- views
- localized text features
- better security model with users and password

### Running a server on a Raspberry Pi

Setting up the standard address-space from XML is the most time-consuming step of the startup process which may lead to
long startup times on less powerful devices like a Raspberry Pi. By passing a path to a cache-file to the server constructor,
a shelve holding the address space will be created during the first startup. All following startups will make use of the
cache-file which leads to significantly better startup performance (~3.5 vs 125 seconds on a Raspberry Pi Model B).

# Development

Code follows PEP8 apart for line lengths which should be max 160 characters and OPC UA structures that keep camel case
from XML definition.

All protocol code is under opcua directory

- `asyncua/ua` contains all UA structures from specification, most are autogenerated
- `asyncua/common` contains high level objects and methods used both in server and client
- `asyncua/client` contains client specific code
- `asyncua/server` contains server specific code
- `asyncua/utils` contains some utilities function and classes
- `asyncua/tools` contains code for command lines tools
- `schemas` contains the XML and text files from specification and the python scripts used to autogenerate code
- `tests` contains tests
- `docs` contains files to auto generate documentation from doc strings
- `examples` contains many example files
- `examples/sync` contains many example files using sync API
- `tools` contains python scripts that can be used to run command line tools from repository without installing

## Running a command for testing:

```
uv run uals -u opc.tcp://localhost:4840/myserver
```

## Running tests:

```
uv run pytest -v -s tests
```

## Coverage

```
uv run pytest -v -s --cov asyncua --cov-report=html
```

## Linting

To apply linting checks (including ruff, and mypy) at each commit run,

```bash
uv sync --group lint
uv run pre-commit install
```

You can also run all linters on all files with,

```bash
uv run pre-commit run -a
```
