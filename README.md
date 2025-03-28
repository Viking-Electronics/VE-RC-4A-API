# RC-4A Library
Libraries for interacting with and controlling RC-4A Network relays.

## Getting Started
The RC-4A Library includes both C and Python example libraries to help you interact with your RC-4A network relay devices.

### C Usage
The C example can be found in `relay_test.c`. You can build the example by running `make` from the `c` directory. Headers in `c\include` contain prototypes of relevant functions used in interacting with RC-4A's. Library links against OpenSSL and OpenSSL Crypto, and can be installed with `apt-get install libssl-dev` on Ubuntu. Library can be linked against for use in your own program, and is located in `c/lib` directory after build. Makefile is formatted in a way that allows for easy integration into build systems, and use with cross-compile environments by providing CC, AR, and CFLAGS when calling make. 

### Python Usage
The Python example is available in `test_commands.py`. Use the following commands to interact with RC-4A devices from the `python` directory:

- **Discover RC-4A devices on the network:**
  ```bash
  python test_commands.py --discover
  ```

- **Set relay 1 on the device with IP `192.168.x.x`:**
  ```bash
  python test_commands.py -ip 192.168.x.x -c set -i 1 -u admin -p viking
  ```

- **Reset relay 1 on the device with IP `192.168.x.x`:**
  ```bash
  python test_commands.py -ip 192.168.x.x -c reset -i 1 -u admin -p viking
  ```

- **Activate relay 2 on the device with IP `192.168.x.x` for 5 seconds:**
  ```bash
  python test_commands.py -ip 192.168.x.x -c timed -i 2 -d 5 -u admin -p viking
  ```

- **Toggle relay 1 on the device with IP `192.168.x.x`:**
  ```bash
  python test_commands.py -ip 192.168.x.x -c toggle -i 1 -u admin -p viking
  ```

- **Query the inputs on the device with IP `192.168.x.x`:**
  ```bash
  python test_commands.py -ip 192.168.x.x -c inputs -u admin -p viking
  ```

## Support
For issues or questions, please use the issue tracker associated with this project.

## License
This project is licensed under the Apache License 2.0 License. Feel free to use and modify the libraries as needed for your own projects.
