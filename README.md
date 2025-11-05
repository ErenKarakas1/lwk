# lwk

Simple wrapper around `lsof`/`ss` + `kill` to find and kill lingering processes.

## Usage

```bash
$ lwk --help  
Kill processes by port number or predefined names
Usage: lwk [NAME] [OPTIONS]

Options:
    -h, --help           Show this help message
    --ss                 Use 'ss' to find processes (default)
    --lsof               Use 'lsof' to find processes
    -p, --port <PORT>    Kill processes using the specified port
```

Modify the `PORT_MAP` hashmap in `lwk.cpp` to add your own predefined names.

`lwk $KEY` is equivalent to `lwk --port PORT_MAP[$KEY]`.

## Installation

```bash
make all      # Compile the program
make install  # Install the binary to ~/.local/bin
```