# gdbsrv

This is a simple GDB server that can be executed on a PS4 or
PS5 that has been jailbroken and is running an ELF loader. The server
accepts connections on port 2159, and has been tested with gdb-15.

This project is based on [John Törnblom](https://github.com/john-tornblom)'s
[gdbsrv project][upstream]. It builds with the unified [payload SDK][sdk].

## Building for the PS4

Assuming you have the [payload SDK][sdk] installed on a POSIX machine, the GDB
server can be compiled using the following commands:

```console
export PS4_PAYLOAD_SDK=/opt/ps-payload-sdk/ps4
make PLATFORM=ps4
```

The payload is written to `build/ps4/gdbsrv-ps4.elf`.

## Building for the PS5

Assuming you have the [payload SDK][sdk] installed on a POSIX machine, the GDB
server can be compiled using the following commands:

```console
export PS5_PAYLOAD_SDK=/opt/ps-payload-sdk/ps5
make PLATFORM=ps5
```

The payload is written to `build/ps5/gdbsrv-ps5.elf`.

## Building for GNU/Linux systems

Assuming you have a compiler toolchain installed on your GNU/Linux system, the
GDB server can be compiled using the following command:

```console
make PLATFORM=linux
```

Object files are placed under `build/<platform>/objects/`. Clean with
`make PLATFORM=ps5 clean` and format the sources with
`make PLATFORM=ps5 format`. One GitHub Actions workflow builds both consoles
with the [payload SDK][sdk] and uploads separate `gdbsrv-ps4` and
`gdbsrv-ps5` artifacts.

## Usage

Start an ELF loader on your console, then send the matching ELF to its host and
port (9021 by default). For PS5:

```console
PS5_HOST=ps5
PS5_PORT=9021
nc -q0 "$PS5_HOST" "$PS5_PORT" < build/ps5/gdbsrv-ps5.elf
```

For PS4, use `build/ps4/gdbsrv-ps4.elf`. Once the server is running, connect gdb
to port 2159:

```console
(gdb) target extended-remote ps5:2159
```

The payload accepts these options:

- `-p PORT` binds the socket server to PORT instead of 2159.
- `-q` skips the on-screen notification when the server starts.

## Known issues

- Symbols from dynamic Sony libraries are not loaded correctly at the moment.
- A couple of arguments passed to the ELF are allocated on the heap, so gdb may
  report errors when trying to resolve the arguments to `_start()`.

## Reporting Bugs

If you encounter problems with gdbsrv, please [file a github issue][issues].
If you plan on sending pull requests which affect more than a few lines of
code, please file an issue before you start to work on your changes. This will
allow us to discuss the solution properly before you commit time and effort.

## License

gdbsrv is licensed under the GPLv3+.

[sdk]: https://github.com/ps-payload-dev/sdk
[issues]: https://github.com/ps-payload-dev/gdbsrv/issues/new
[upstream]: https://github.com/ps5-payload-dev/gdbsrv
