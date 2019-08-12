# cpp-socketwrapper

A C++ single-file header-only cross platform socket wrapper, with a modern interface.

This is based on a stripped down version of https://github.com/yhirose/cpp-httplib - check that out if you want a lightweight HTTP/HTTPS library!

### Example Usage

```cpp
#include <iostream>

#include "SocketWrapper.h"

int main()
{
    sockwrapper::SocketWrapper socket("127.0.0.1", 3333);

    /* Setup the function that gets called on every message */
    socket.onMessage([](const std::string message){
        std::cout << "Recieved message from socket: " << message << std::endl;
    });

    /* Open the socket and start listening for messages */
    const bool success = socket.start();

    if (!success)
    {
        std::cout << "Failed to open socket!" << std::endl;
        return;
    }

    /* Send a message to the socket. Returns a bool indicating success. */
    socket.sendMessage("Hello, World!\n");

    /* Send a message, and return the next message received */
    std::optional<std::string> res = sendMessageAndGetResponse("ping\n");

    if (res)
    {
        std::cout << *res << std::endl;
    }
}
```

### SSL Usage

The SSL socket works just the same as the normal socket.
You must define `SOCKETWRAPPER_OPENSSL_SUPPORT` to enable SSL socket support.

You will also need to link against OpenSSL.

```cpp
#include <iostream>

#define SOCKETWRAPPER_OPENSSL_SUPPORT

#include "SocketWrapper.h"

int main()
{
    sockwrapper::SSLSocketWrapper socket("127.0.0.1", 8443);

    socket.start();

    socket.sendMessage("Hello, World!\n");
}
```

### API Reference


#### Constructor

```cpp
SocketWrapper(
    const char *host,
    const int port,
    const char messageDelimiter = '\n',
    const time_t timeout_sec = 10);
```

`host` - The host you want to open the socket on

`port` - The remote port to open the socket on

`messageDelimiter` - How to determine when one message ends and another begins. Due to the nature of sockets, there is no way to tell when a message is done transmitting, so the protocol must define this. By default, we split messages on newlines.

This may need some work for use cases with more complicated protocols. Pull Requests welcome.

`timeout_sec` - How long to wait before cancelling the connection in `start()`, or cancel waiting for a response in `sendMessageAndGetResponse`

#### `start()`

Opens the socket, and starts a thread to listen for incoming messages. Returns a boolean indicating success.

#### `stop()`

Closes down the socket, and stops the thread that has been listening for incoming messages.

You do not need to call this manually - once the object goes out of scope, it will automatically clean up. 
You may wish to manually call this anyway to close the socket once you are done with it, of course.

#### `sendMessage(const std::string &message)`

Sends a string down the socket. No message alterations are done, so if your protocol needs a newline on the end, for example, make sure you include that.

Returns false if the socket is invalid. Note that a return value of `true` does not necessarily indicate the other party received the message. They may have closed the socket without informing us, for example.

#### `sendMessage(const std::vector<uint8_t> &message)`

Functions identically to `sendMessage(const std::string &message)` but takes a vector for convenience.

#### `sendMessageAndGetResponse(const std::string &message, const bool timeout = true)`

Sends a string down the socket, and waits for the next reply from the socket, which is then returned. The same caveats as `sendMessage` apply.

Note that the string returned is not neccessarily the same one that was a response to what you sent.
For example, if you send two messages very rapidly, and wait for the second response, it is likely you will in fact get the first response, as no data has arrived at the socket by the time the second message was sent.

There is no way to solve this on the library end, as we have no insight into how the protocol you are using functions.

Note that the `onMessage` callback will still be fired for the message you awaited for.

The timeout argument configures whether we should wait forever for a message, or return `std::nullopt` after the timeout specified in the constructor elapses.

#### `sendMessageAndGetResponse(const std::vector<uint8_t> &message, const bool timeout = true)`

Functions identically to `sendMessageAndGetResponse(const std::string &message)` but takes a vector for convenience.

#### `onMessage(const std::function<void(const std::string message) callback)`

Assigns a function to be called each time a message is received on the socket.

#### `onSocketClosed(const std::function<void(void) callback)`

Assigns a function to be called when the socket has been shutdown.
