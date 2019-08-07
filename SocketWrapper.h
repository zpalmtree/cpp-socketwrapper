//  Copyright (c) 2017-2019 Yuji Hirose. All rights reserved.
//  Copyright (c) 2019 Zpalmtree. All rights reserved.
//
//  MIT License
//
//  Adapted from https://github.com/yhirose/cpp-httplib

#pragma once

#ifdef _WIN32
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif //_CRT_SECURE_NO_WARNINGS

#ifndef _CRT_NONSTDC_NO_DEPRECATE
#define _CRT_NONSTDC_NO_DEPRECATE
#endif //_CRT_NONSTDC_NO_DEPRECATE

#ifndef NOMINMAX
#define NOMINMAX
#endif // NOMINMAX

#include <io.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

typedef SOCKET socket_t;
#else
#include <arpa/inet.h>
#include <cstring>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

typedef int socket_t;
#define INVALID_SOCKET (-1)
#endif //_WIN32

#include <cassert>
#include <fcntl.h>
#include <future>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#ifdef SOCKETWRAPPER_OPENSSL_SUPPORT
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#include <openssl/crypto.h>
inline const unsigned char *ASN1_STRING_get0_data(const ASN1_STRING *asn1)
{
    return M_ASN1_STRING_data(asn1);
}
#endif
#endif

/*
 * Configuration
 */
#define SOCKETWRAPPER_READ_TIMEOUT_SECOND 5
#define SOCKETWRAPPER_READ_TIMEOUT_USECOND 0

namespace sockwrapper
{
    class Stream
    {
      public:
        virtual ~Stream() {}
        virtual int read(char *ptr, size_t size) = 0;
        virtual int write(const char *ptr, size_t size1) = 0;
        virtual int write(const char *ptr) = 0;
        virtual int write(const std::string &s) = 0;
    };

    class SocketStream : public Stream
    {
      public:
        SocketStream() {};
        SocketStream(socket_t sock);
        virtual ~SocketStream();

        virtual int read(char *ptr, size_t size);
        virtual int write(const char *ptr, size_t size);
        virtual int write(const char *ptr);
        virtual int write(const std::string &s);

      private:
        socket_t sock_;
    };

    class BufferStream : public Stream
    {
      public:
        BufferStream() {}
        virtual ~BufferStream() {}

        virtual int read(char *ptr, size_t size);
        virtual int write(const char *ptr, size_t size);
        virtual int write(const char *ptr);
        virtual int write(const std::string &s);

        const std::string &get_buffer() const;

      private:
        std::string buffer;
    };

    class SocketWrapper
    {
      public:
        /* CONSTRUCTOR AND DESTRUCTOR */

        SocketWrapper(
            const char *host,
            const int port = 80,
            const char messageDelimiter = '\n',
            const time_t timeout_sec = 10);

        virtual ~SocketWrapper();

        /* PUBLIC MEMBER FUNCTIONS */

        virtual bool is_valid() const;

        /* Initialize the socket connection and start listening for messages */
        bool start();

        /* Close the socket connection and stop listening for messages */
        void stop();

        /* Send a message down the socket */
        bool sendMessage(const std::string &message);

        /* Send a message down the socket and wait for the next response (Can time out) */
        std::optional<std::string> sendMessageAndGetResponse(const std::string &message);

        /* Register a function to be called when a message is received */
        void onMessage(const std::function<void(const std::string &message)> callback);

      protected:
        /* PRIVATE MEMBER FUNCTIONS */

        /* The function which grabs and processes messages from the socket */
        void waitForMessages();

        /* PRIVATE MEMBER VARIABLES */

        /* The host to connect to */
        const std::string m_host;

        /* The port to connect to */
        const int m_port;

        /* What character to split incoming messages on */
        const char m_messageDelimiter;

        /* How long to wait for socket to connect in init() */
        time_t timeout_sec_;

        /* The socket instance we are wrapping */
        socket_t m_socket = INVALID_SOCKET;

        /* The socket reader/writer */
        SocketStream m_socketStream;

        /* The function to call upon message receieval */
        std::function<void(const std::string &message)> m_messageCallback;

        /* The thread that listens for messages */
        std::thread m_listenThread;

        /* This will be set to the next message to arrive when sendMessageAndGetResponse
           is set */
        std::promise<std::string> m_nextMessagePromise;

        /* Should we pass the next message to sendMessageAndGetResponse */
        std::atomic<bool> m_giveMeTheNextMessagePlease;

        /* Should we stop the listen thread */
        std::atomic<bool> m_shouldStop;

        /* Has the listen thread been started */
        std::atomic<bool> m_started = false;

        /* Used to synchronize writes */
        std::mutex m_sendMutex;
    };

#ifdef SOCKETWRAPPER_OPENSSL_SUPPORT
    class SSLSocketStream : public Stream
    {
      public:
        SSLSocketStream() {};
        SSLSocketStream(socket_t sock, SSL *ssl);
        virtual ~SSLSocketStream();

        virtual int read(char *ptr, size_t size);
        virtual int write(const char *ptr, size_t size);
        virtual int write(const char *ptr);
        virtual int write(const std::string &s);

      private:
        socket_t sock_;
        SSL *ssl_;
    };

    class SSLSocketWrapper : public SocketWrapper
    {
      public:
        SSLSocketWrapper(
            const char *host,
            int port = 443,
            const char messageDelimiter = '\n',
            time_t timeout_sec = 10,
            const char *client_cert_path = nullptr,
            const char *client_key_path = nullptr);

        virtual ~SSLSocketWrapper();

        virtual bool is_valid() const;

        void set_ca_cert_path(const char *ca_ceert_file_path, const char *ca_cert_dir_path = nullptr);
        void enable_server_certificate_verification(bool enabled);

        long get_openssl_verify_result() const;

      private:
        bool verify_host(X509 *server_cert) const;
        bool verify_host_with_subject_alt_name(X509 *server_cert) const;
        bool verify_host_with_common_name(X509 *server_cert) const;
        bool check_host_name(const char *pattern, size_t pattern_len) const;

        SSL_CTX *ctx_;
        std::mutex ctx_mutex_;
        std::vector<std::string> host_components_;
        std::string ca_cert_file_path_;
        std::string ca_cert_dir_path_;
        bool server_certificate_verification_ = false;
        long verify_result_ = 0;
    };
#endif

    /*
     * Implementation
     */
    namespace detail
    {
        template<class Fn> void split(const char *b, const char *e, char d, Fn fn)
        {
            int i = 0;
            int beg = 0;

            while (e ? (b + i != e) : (b[i] != '\0'))
            {
                if (b[i] == d)
                {
                    fn(&b[beg], &b[i]);
                    beg = i + 1;
                }
                i++;
            }

            if (i)
            {
                fn(&b[beg], &b[i]);
            }
        }

        // NOTE: until the read size reaches `fixed_buffer_size`, use `fixed_buffer`
        // to store data. The call can set memory on stack for performance.
        class stream_line_reader
        {
          public:
            stream_line_reader(Stream &strm, char *fixed_buffer, size_t fixed_buffer_size):
                strm_(strm),
                fixed_buffer_(fixed_buffer),
                fixed_buffer_size_(fixed_buffer_size)
            {
            }

            const char *ptr() const
            {
                if (glowable_buffer_.empty())
                {
                    return fixed_buffer_;
                }
                else
                {
                    return glowable_buffer_.data();
                }
            }

            size_t size() const
            {
                if (glowable_buffer_.empty())
                {
                    return fixed_buffer_used_size_;
                }
                else
                {
                    return glowable_buffer_.size();
                }
            }

            std::string getline(const char delimiter, const std::atomic<bool> &shouldStop)
            {
                fixed_buffer_used_size_ = 0;
                glowable_buffer_.clear();

                while (!shouldStop)
                {
                    char byte;

                    /* Read a byte */
                    auto n = strm_.read(&byte, 1);

                    /* Socket possibly closed / timeout */
                    if (n < 0)
                    {
                        continue;
                    }

                    /* Append the byte to the buffer */
                    append(byte);

                    /* Message complete */
                    if (byte == delimiter)
                    {
                        return std::string(ptr(), size());
                    }
                }

                return std::string();
            }

            bool getline()
            {
                fixed_buffer_used_size_ = 0;
                glowable_buffer_.clear();

                for (size_t i = 0;; i++)
                {
                    char byte;
                    auto n = strm_.read(&byte, 1);

                    if (n < 0)
                    {
                        return false;
                    }
                    else if (n == 0)
                    {
                        if (i == 0)
                        {
                            return false;
                        }
                        else
                        {
                            break;
                        }
                    }

                    append(byte);

                    if (byte == '\n')
                    {
                        break;
                    }
                }

                return true;
            }

          private:
            void append(char c)
            {
                if (fixed_buffer_used_size_ < fixed_buffer_size_ - 1)
                {
                    fixed_buffer_[fixed_buffer_used_size_++] = c;
                    fixed_buffer_[fixed_buffer_used_size_] = '\0';
                }
                else
                {
                    if (glowable_buffer_.empty())
                    {
                        assert(fixed_buffer_[fixed_buffer_used_size_] == '\0');
                        glowable_buffer_.assign(fixed_buffer_, fixed_buffer_used_size_);
                    }
                    glowable_buffer_ += c;
                }
            }

            Stream &strm_;
            char *fixed_buffer_;
            const size_t fixed_buffer_size_;
            size_t fixed_buffer_used_size_;
            std::string glowable_buffer_;
        };

        inline int close_socket(socket_t sock)
        {
#ifdef _WIN32
            return closesocket(sock);
#else
            return close(sock);
#endif
        }

        inline int select_read(socket_t sock, time_t sec, time_t usec)
        {
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(sock, &fds);

            timeval tv;
            tv.tv_sec = static_cast<long>(sec);
            tv.tv_usec = static_cast<long>(usec);

            return select(static_cast<int>(sock + 1), &fds, nullptr, nullptr, &tv);
        }

        inline bool wait_until_socket_is_ready(socket_t sock, time_t sec, time_t usec)
        {
            fd_set fdsr;
            FD_ZERO(&fdsr);
            FD_SET(sock, &fdsr);

            auto fdsw = fdsr;
            auto fdse = fdsr;

            timeval tv;
            tv.tv_sec = static_cast<long>(sec);
            tv.tv_usec = static_cast<long>(usec);

            if (select(static_cast<int>(sock + 1), &fdsr, &fdsw, &fdse, &tv) < 0)
            {
                return false;
            }
            else if (FD_ISSET(sock, &fdsr) || FD_ISSET(sock, &fdsw))
            {
                int error = 0;
                socklen_t len = sizeof(error);
                if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&error, &len) < 0 || error)
                {
                    return false;
                }
            }
            else
            {
                return false;
            }

            return true;
        }

        inline int shutdown_socket(socket_t sock)
        {
#ifdef _WIN32
            return shutdown(sock, SD_BOTH);
#else
            return shutdown(sock, SHUT_RDWR);
#endif
        }

        template<typename Fn> socket_t create_socket(const char *host, int port, Fn fn, int socket_flags = 0)
        {
#ifdef _WIN32
#define SO_SYNCHRONOUS_NONALERT 0x20
#define SO_OPENTYPE 0x7008

            int opt = SO_SYNCHRONOUS_NONALERT;
            setsockopt(INVALID_SOCKET, SOL_SOCKET, SO_OPENTYPE, (char *)&opt, sizeof(opt));
#endif

            // Get address info
            struct addrinfo hints;
            struct addrinfo *result;

            memset(&hints, 0, sizeof(struct addrinfo));
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_flags = socket_flags;
            hints.ai_protocol = 0;

            auto service = std::to_string(port);

            if (getaddrinfo(host, service.c_str(), &hints, &result))
            {
                return INVALID_SOCKET;
            }

            for (auto rp = result; rp; rp = rp->ai_next)
            {
                // Create a socket
#ifdef _WIN32
                auto sock =
                    WSASocketW(rp->ai_family, rp->ai_socktype, rp->ai_protocol, nullptr, 0, WSA_FLAG_NO_HANDLE_INHERIT);
#else
                auto sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
#endif
                if (sock == INVALID_SOCKET)
                {
                    continue;
                }

#ifndef _WIN32
                if (fcntl(sock, F_SETFD, FD_CLOEXEC) == -1)
                {
                    continue;
                }
#endif

                // Make 'reuse address' option available
                int yes = 1;
                setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, sizeof(yes));
#ifdef SO_REUSEPORT
                setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (char *)&yes, sizeof(yes));
#endif

                // bind or connect
                if (fn(sock, *rp))
                {
                    freeaddrinfo(result);
                    return sock;
                }

                close_socket(sock);
            }

            freeaddrinfo(result);
            return INVALID_SOCKET;
        }

        inline void set_nonblocking(socket_t sock, bool nonblocking)
        {
#ifdef _WIN32
            auto flags = nonblocking ? 1UL : 0UL;
            ioctlsocket(sock, FIONBIO, &flags);
#else
            auto flags = fcntl(sock, F_GETFL, 0);
            fcntl(sock, F_SETFL, nonblocking ? (flags | O_NONBLOCK) : (flags & (~O_NONBLOCK)));
#endif
        }

        inline bool is_connection_error()
        {
#ifdef _WIN32
            return WSAGetLastError() != WSAEWOULDBLOCK;
#else
            return errno != EINPROGRESS;
#endif
        }

#ifdef _WIN32
        class WSInit
        {
          public:
            WSInit()
            {
                WSADATA wsaData;
                WSAStartup(0x0002, &wsaData);
            }

            ~WSInit()
            {
                WSACleanup();
            }
        };

        static WSInit wsinit_;
#endif

    } // namespace detail

    // Socket stream implementation
    inline SocketStream::SocketStream(socket_t sock): sock_(sock) {}

    inline SocketStream::~SocketStream() {}

    inline int SocketStream::read(char *ptr, size_t size)
    {
        if (detail::select_read(sock_, SOCKETWRAPPER_READ_TIMEOUT_SECOND, SOCKETWRAPPER_READ_TIMEOUT_USECOND) > 0)
        {
            return recv(sock_, ptr, static_cast<int>(size), 0);
        }
        return -1;
    }

    inline int SocketStream::write(const char *ptr, size_t size)
    {
        return send(sock_, ptr, static_cast<int>(size), 0);
    }

    inline int SocketStream::write(const char *ptr)
    {
        return write(ptr, strlen(ptr));
    }

    inline int SocketStream::write(const std::string &s)
    {
        return write(s.data(), s.size());
    }

    // Buffer stream implementation
    inline int BufferStream::read(char *ptr, size_t size)
    {
#if defined(_MSC_VER) && _MSC_VER < 1900
        return static_cast<int>(buffer._Copy_s(ptr, size, size));
#else
        return static_cast<int>(buffer.copy(ptr, size));
#endif
    }

    inline int BufferStream::write(const char *ptr, size_t size)
    {
        buffer.append(ptr, size);
        return static_cast<int>(size);
    }

    inline int BufferStream::write(const char *ptr)
    {
        return write(ptr, strlen(ptr));
    }

    inline int BufferStream::write(const std::string &s)
    {
        return write(s.data(), s.size());
    }

    inline const std::string &BufferStream::get_buffer() const
    {
        return buffer;
    }

    // HTTP client implementation
    inline SocketWrapper::SocketWrapper(
        const char *host,
        const int port,
        const char messageDelimiter,
        const time_t timeout_sec):
        m_host(host),
        m_port(port),
        m_messageDelimiter(messageDelimiter),
        timeout_sec_(timeout_sec)
    {
    }

    inline SocketWrapper::~SocketWrapper()
    {
        stop();
    }

    inline bool SocketWrapper::is_valid() const
    {
        return true;
    }

    inline bool SocketWrapper::start()
    {
        /* Already started */
        if (m_started)
        {
            return true;
        }

        /* Create the socket */
        m_socket = detail::create_socket(m_host.c_str(), m_port, [=](socket_t sock, struct addrinfo &ai) {
            detail::set_nonblocking(sock, true);

            auto ret = connect(sock, ai.ai_addr, static_cast<int>(ai.ai_addrlen));
            if (ret < 0)
            {
                if (detail::is_connection_error() || !detail::wait_until_socket_is_ready(sock, timeout_sec_, 0))
                {
                    detail::close_socket(sock);
                    return false;
                }
            }

            detail::set_nonblocking(sock, false);
            return true;
        });

        if (m_socket == INVALID_SOCKET)
        {
            return false;
        }

        m_socketStream = SocketStream(m_socket);
        m_shouldStop = false;
        m_started = true;

        /* Start listening for messages */
        m_listenThread = std::thread(&SocketWrapper::waitForMessages, this);

        return true;
    }

    inline void SocketWrapper::stop()
    {
        m_shouldStop = true;

        if (m_socket != INVALID_SOCKET)
        {
            detail::shutdown_socket(m_socket);
        }

        if (m_listenThread.joinable())
        {
            m_listenThread.join();
        }

        m_started = false;
    }

    inline bool SocketWrapper::sendMessage(const std::string &message)
    {
        if (m_socket == INVALID_SOCKET)
        {
            return false;
        }

        std::scoped_lock<std::mutex> lock(m_sendMutex);

        m_socketStream.write(message);

        return true;
    }

    inline std::optional<std::string> SocketWrapper::sendMessageAndGetResponse(const std::string &message)
    {
        const bool success = sendMessage(message);

        if (!success)
        {
            return std::nullopt;
        }

        m_nextMessagePromise = std::promise<std::string>();

        std::future<std::string> futureMessage = m_nextMessagePromise.get_future();

        m_giveMeTheNextMessagePlease = true;

        const std::string result = futureMessage.get();

        return result;
    }

    inline void SocketWrapper::onMessage(const std::function<void(const std::string &message)> callback)
    {
        m_messageCallback = callback;
    }

    inline void SocketWrapper::waitForMessages()
    {
        const auto bufsiz = 4096;
        char buf[bufsiz];

        while (!m_shouldStop)
        {
            detail::stream_line_reader reader(m_socketStream, buf, bufsiz);

            const std::string message = reader.getline(m_messageDelimiter, m_shouldStop);

            if (m_shouldStop)
            {
                break;
            }

            if (m_giveMeTheNextMessagePlease)
            {
                m_nextMessagePromise.set_value(message);
                m_giveMeTheNextMessagePlease = false;
            }

            if (m_messageCallback)
            {
                m_messageCallback(message);
            }
        }
    }

/*
 * SSL Implementation
 */
#ifdef SOCKETWRAPPER_OPENSSL_SUPPORT
    namespace detail
    {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        static std::shared_ptr<std::vector<std::mutex>> openSSL_locks_;

        class SSLThreadLocks
        {
          public:
            SSLThreadLocks()
            {
                openSSL_locks_ = std::make_shared<std::vector<std::mutex>>(CRYPTO_num_locks());
                CRYPTO_set_locking_callback(locking_callback);
            }

            ~SSLThreadLocks()
            {
                CRYPTO_set_locking_callback(nullptr);
            }

          private:
            static void locking_callback(int mode, int type, const char * /*file*/, int /*line*/)
            {
                auto &locks = *openSSL_locks_;
                if (mode & CRYPTO_LOCK)
                {
                    locks[type].lock();
                }
                else
                {
                    locks[type].unlock();
                }
            }
        };

#endif

        class SSLInit
        {
          public:
            SSLInit()
            {
                SSL_load_error_strings();
                SSL_library_init();
            }

            ~SSLInit()
            {
                ERR_free_strings();
            }

          private:
#if OPENSSL_VERSION_NUMBER < 0x10100000L
            SSLThreadLocks thread_init_;
#endif
        };

        static SSLInit sslinit_;

    } // namespace detail

    // SSL socket stream implementation
    inline SSLSocketStream::SSLSocketStream(socket_t sock, SSL *ssl): sock_(sock), ssl_(ssl) {}

    inline SSLSocketStream::~SSLSocketStream() {}

    inline int SSLSocketStream::read(char *ptr, size_t size)
    {
        if (SSL_pending(ssl_) > 0
            || detail::select_read(sock_, SOCKETWRAPPER_READ_TIMEOUT_SECOND, SOCKETWRAPPER_READ_TIMEOUT_USECOND) > 0)
        {
            return SSL_read(ssl_, ptr, size);
        }
        return -1;
    }

    inline int SSLSocketStream::write(const char *ptr, size_t size)
    {
        return SSL_write(ssl_, ptr, size);
    }

    inline int SSLSocketStream::write(const char *ptr)
    {
        return write(ptr, strlen(ptr));
    }

    inline int SSLSocketStream::write(const std::string &s)
    {
        return write(s.data(), s.size());
    }

    // SSL HTTP client implementation
    inline SSLSocketWrapper::SSLSocketWrapper(
        const char *host,
        int port,
        const char messageDelimiter,
        time_t timeout_sec,
        const char *client_cert_path,
        const char *client_key_path):
        SocketWrapper(host, port, messageDelimiter, timeout_sec)
    {
        ctx_ = SSL_CTX_new(SSLv23_client_method());

        detail::split(&m_host[0], &m_host[m_host.size()], '.', [&](const char *b, const char *e) {
            host_components_.emplace_back(std::string(b, e));
        });
        if (client_cert_path && client_key_path)
        {
            if (SSL_CTX_use_certificate_file(ctx_, client_cert_path, SSL_FILETYPE_PEM) != 1
                || SSL_CTX_use_PrivateKey_file(ctx_, client_key_path, SSL_FILETYPE_PEM) != 1)
            {
                SSL_CTX_free(ctx_);
                ctx_ = nullptr;
            }
        }
    }

    inline SSLSocketWrapper::~SSLSocketWrapper()
    {
        if (ctx_)
        {
            SSL_CTX_free(ctx_);
        }
    }

    inline bool SSLSocketWrapper::is_valid() const
    {
        return ctx_;
    }

    inline void SSLSocketWrapper::set_ca_cert_path(const char *ca_cert_file_path, const char *ca_cert_dir_path)
    {
        if (ca_cert_file_path)
        {
            ca_cert_file_path_ = ca_cert_file_path;
        }
        if (ca_cert_dir_path)
        {
            ca_cert_dir_path_ = ca_cert_dir_path;
        }
    }

    inline void SSLSocketWrapper::enable_server_certificate_verification(bool enabled)
    {
        server_certificate_verification_ = enabled;
    }

    inline long SSLSocketWrapper::get_openssl_verify_result() const
    {
        return verify_result_;
    }

    inline bool SSLSocketWrapper::verify_host(X509 *server_cert) const
    {
        /* Quote from RFC2818 section 3.1 "Server Identity"

           If a subjectAltName extension of type dNSName is present, that MUST
           be used as the identity. Otherwise, the (most specific) Common Name
           field in the Subject field of the certificate MUST be used. Although
           the use of the Common Name is existing practice, it is deprecated and
           Certification Authorities are encouraged to use the dNSName instead.

           Matching is performed using the matching rules specified by
           [RFC2459].  If more than one identity of a given type is present in
           the certificate (e.g., more than one dNSName name, a match in any one
           of the set is considered acceptable.) Names may contain the wildcard
           character * which is considered to match any single domain name
           component or component fragment. E.g., *.a.com matches foo.a.com but
           not bar.foo.a.com. f*.com matches foo.com but not bar.com.

           In some cases, the URI is specified as an IP address rather than a
           hostname. In this case, the iPAddress subjectAltName must be present
           in the certificate and must exactly match the IP in the URI.

        */
        return verify_host_with_subject_alt_name(server_cert) || verify_host_with_common_name(server_cert);
    }

    inline bool SSLSocketWrapper::verify_host_with_subject_alt_name(X509 *server_cert) const
    {
        auto ret = false;

        auto type = GEN_DNS;

        struct in6_addr addr6;
        struct in_addr addr;
        size_t addr_len = 0;

        if (inet_pton(AF_INET6, m_host.c_str(), &addr6))
        {
            type = GEN_IPADD;
            addr_len = sizeof(struct in6_addr);
        }
        else if (inet_pton(AF_INET, m_host.c_str(), &addr))
        {
            type = GEN_IPADD;
            addr_len = sizeof(struct in_addr);
        }

        auto alt_names = static_cast<const struct stack_st_GENERAL_NAME *>(
            X509_get_ext_d2i(server_cert, NID_subject_alt_name, nullptr, nullptr));

        if (alt_names)
        {
            auto dsn_matched = false;
            auto ip_mached = false;

            auto count = sk_GENERAL_NAME_num(alt_names);

            for (auto i = 0; i < count && !dsn_matched; i++)
            {
                auto val = sk_GENERAL_NAME_value(alt_names, i);
                if (val->type == type)
                {
                    auto name = (const char *)ASN1_STRING_get0_data(val->d.ia5);
                    auto name_len = (size_t)ASN1_STRING_length(val->d.ia5);

                    if (strlen(name) == name_len)
                    {
                        switch (type)
                        {
                            case GEN_DNS:
                                dsn_matched = check_host_name(name, name_len);
                                break;

                            case GEN_IPADD:
                                if (!memcmp(&addr6, name, addr_len) || !memcmp(&addr, name, addr_len))
                                {
                                    ip_mached = true;
                                }
                                break;
                        }
                    }
                }
            }

            if (dsn_matched || ip_mached)
            {
                ret = true;
            }
        }

        GENERAL_NAMES_free((STACK_OF(GENERAL_NAME) *)alt_names);

        return ret;
    }

    inline bool SSLSocketWrapper::verify_host_with_common_name(X509 *server_cert) const
    {
        const auto subject_name = X509_get_subject_name(server_cert);

        if (subject_name != nullptr)
        {
            char name[BUFSIZ];
            auto name_len = X509_NAME_get_text_by_NID(subject_name, NID_commonName, name, sizeof(name));

            if (name_len != -1)
            {
                return check_host_name(name, name_len);
            }
        }

        return false;
    }

    inline bool SSLSocketWrapper::check_host_name(const char *pattern, size_t pattern_len) const
    {
        if (m_host.size() == pattern_len && m_host == pattern)
        {
            return true;
        }

        // Wildcard match
        // https://bugs.launchpad.net/ubuntu/+source/firefox-3.0/+bug/376484
        std::vector<std::string> pattern_components;
        detail::split(&pattern[0], &pattern[pattern_len], '.', [&](const char *b, const char *e) {
            pattern_components.emplace_back(std::string(b, e));
        });

        if (host_components_.size() != pattern_components.size())
        {
            return false;
        }

        auto itr = pattern_components.begin();
        for (const auto &h : host_components_)
        {
            auto &p = *itr;
            if (p != h && p != "*")
            {
                auto partial_match = (p.size() > 0 && p[p.size() - 1] == '*' && !p.compare(0, p.size() - 1, h));
                if (!partial_match)
                {
                    return false;
                }
            }
            ++itr;
        }

        return true;
    }
#endif

} // namespace sockwrapper
