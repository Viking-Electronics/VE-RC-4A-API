import lib.VikingRC4A as Viking
import argparse

parser = argparse.ArgumentParser(description="Test the Viking Network Relay Control commands")
parser.add_argument("--discover", action="store_true", help="Discover devices on the network")
parser.add_argument("-ip", dest="ip", type=str, help="The IP address of the relay controller")
parser.add_argument("-c", dest="command", type=str, help="The command to test, ex set, reset, timed, toggle")
parser.add_argument("-i", dest="index", type=int, help="The relay index to send a test command to")
parser.add_argument("-d", dest="duration", type=int, help="The duration used for a timed command")
parser.add_argument("-u", dest="username", type=str, help="The username for the relay controller (default is admin)")
parser.add_argument("-p", dest="password", type=str, help="The password for the relay controller (default is viking)")

#How to use this testing script:

#Discover RC-4A devices on the network
#python test_commands.py --discover

#Set relay 1 on device with IP 192.168.x.x
#python test_commands.py -ip 192.168.x.x -c set -i 1 -u admin -p viking

#Reset relay 1 on device with IP 192.168.x.x
#python test_commands.py -ip 192.168.x.x -c reset -i 1 -u admin -p viking

#Timed activation on relay 2 on device with IP 192.168.x.x for 5 seconds
#python test_commands.py -ip 192.168.x.x -c timed -i 2 -d 5 -u admin -p viking

#Toggle relay 1 on device with IP 192.168.x.x
#python test_commands.py -ip 192.168.x.x -c toggle -i 1 -u admin -p viking

#Query the inputs on the device with IP 192.168.x.x
#python test_commands.py -ip 192.168.x.x -c inputs -u admin -p viking

args = parser.parse_args()

devices = Viking.RelayControl.discover()

if args.discover is True:
    if devices is None:
        print("Failed to discover devices on network")
        exit(-1)

    for device in devices:
        print(device)

    exit(0)

if args.ip is None and args.mac is None:
    print("No device address specified, please use ip or mac")
    exit(-1)

if args.username is None:
    args.username = "admin"

if args.password is None:
    args.password = "viking"

if args.command is None:
    print("No command specified")
    exit(-1)

if args.index is None and args.command != "inputs":
    print("No index specified")
    exit(-1)

if args.command == "timed" and args.duration is None:
    print("Timed command specified without duration")
    exit(-1)

target_device = None
for device in devices:
    if args.ip is not None and device.ip == args.ip:
        target_device = device
        break
    elif args.mac is not None and device.mac == args.mac:
        target_device = device
        break

if target_device is None:
    print("Failed to find device with specified address")
    if devices is not None:
        print("Discovered devices:")
        for device in devices:
            print(device)
    exit(-1)

print("Using device:")
print(target_device)

target_device.set_credentials(args.username, args.password)
resp = None

if args.command == "set":
    print("Setting relay %d" % args.index)
    resp = target_device.command(args.index, Viking.Commands.RELAY_SET)
elif args.command == "reset":
    print("Resetting relay %d" % args.index)
    resp = target_device.command(args.index, Viking.Commands.RELAY_RESET)
elif args.command == "timed":
    print("Setting relay %d for %d seconds" % (args.index, args.duration))
    resp = target_device.command(args.index, Viking.Commands.RELAY_TIMED, duration=args.duration)
elif args.command == "toggle":
    print("Toggling relay %d" % args.index)
    resp = target_device.command(args.index, Viking.Commands.RELAY_TOGGLE)
elif args.command == "inputs":
    print("Querying inputs")
    resp = target_device.get_inputs()
else:
    print("Unknown command")
    exit(-1)

if resp is not None:
    print("Response:")
    print(resp)