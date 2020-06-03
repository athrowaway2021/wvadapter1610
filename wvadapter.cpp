#include "wvadapter.h"
#include <iostream>
#include <stdio.h>  
#include <stdlib.h>  

const uint8_t init_data[50] = {
    0x00, 0x00, 0x00, 0x32, 0x70, 0x73, 0x73, 0x68, 0x00, 0x00, 0x00, 0x00,
    0xed, 0xef, 0x8b, 0xa9, 0x79, 0xd6, 0x4a, 0xce, 0xa3, 0xc8, 0x27, 0xdc,
    0xd5, 0x1d, 0x21, 0xed, 0x00, 0x00, 0x00, 0x12, 0x12, 0x10, 0x2c, 0x56,
    0x12, 0x69, 0x3a, 0xc9, 0x49, 0x5b, 0xa5, 0x04, 0xab, 0xac, 0xa2, 0xd4,
    0x5b, 0x3c
};

uint8_t* _block;
bool first_except;
HANDLE wv_handle;

LONG NTAPI crypt_injection(PEXCEPTION_POINTERS except_info)
{
    if (first_except)
    {
        first_except = false;

        byte* code = new byte[19]{ 0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x94, 0x24, 0x68, 0x24, 0x00, 0x00, 0x90 };
        memcpy(&code[2], &_block, 8);

        intptr_t inject_address = (intptr_t)wv_handle + 0x32f0de;

        DWORD old_protect;
        VirtualProtect((void*)inject_address, 19, PAGE_EXECUTE_READWRITE, &old_protect);
        memcpy((void*)inject_address, code, 19);
        VirtualProtect((void*)inject_address, 19, old_protect, &old_protect);
    }
    else
    {
        except_info->ContextRecord->Dr1 = 0x0;
        except_info->ContextRecord->Dr6 = 0x0;
        except_info->ContextRecord->Dr7 = 0x0;
        except_info->ContextRecord->EFlags = 0x0001;
    }

    return EXCEPTION_CONTINUE_EXECUTION;
}

Adapter::Adapter()
{

}

Adapter::~Adapter()
{
    if (!session_id.empty())
    {
        wv_adapter->CloseSession(++promise_id, session_id.data(), session_id.size());
        wv_adapter->RemoveSession(++promise_id, session_id.data(), session_id.size());
    }
    wv_adapter->~CdmAdapter();
}

void Adapter::OnCDMMessage(const char* session, uint32_t session_size, CDMADPMSG msg, const uint8_t* data, size_t data_size, uint32_t status)
{
    if (msg == CDMADPMSG::kSessionMessage)
    {
        challenge_len = data_size;
        challenge = new uint8_t[challenge_len];
        memcpy(challenge, data, challenge_len);

        session_id = session;
    }
}

void Adapter::CDMLog(const char* msg)
{
    return;
}

bool Adapter::rsa_crypt(uint8_t* in, uint8_t* out, char* cdm_path)
{
    _block = in;
    std::string basepath = cdm_path;
    basepath = basepath.substr(0, basepath.size() - 15);

    wv_adapter = std::shared_ptr<media::CdmAdapter>(new media::CdmAdapter(
        "com.widevine.alpha",
        cdm_path,
        basepath,
        media::CdmConfig(false, false),
        (dynamic_cast<media::CdmAdapterClient*>(this))));

    if (!wv_adapter->valid())
    {
        wv_adapter = nullptr;
        return NULL;
    }

    wv_handle = GetModuleHandle("widevinecdm.dll");

    intptr_t breakpoint_address = (intptr_t)wv_handle + 0x6addcb;

    current_thread = GetCurrentThread();
    GetThreadContext(current_thread, &current_context);

    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    ctx.Dr0 = breakpoint_address;
    ctx.Dr1 = 0x00000000;
    ctx.Dr2 = 0x00000000;
    ctx.Dr3 = 0x00000000;
    ctx.Dr6 = 0xFFFF0FF1;
    ctx.Dr7 = 0x00000401;

    SetThreadContext(current_thread, &ctx);
    if (except_handler = AddVectoredExceptionHandler(0, crypt_injection))
    {
        first_except = true;
        wv_adapter->CreateSessionAndGenerateRequest(++promise_id, cdm::SessionType::kTemporary, cdm::InitDataType::kCenc, init_data, 50);
        RemoveVectoredExceptionHandler(except_handler);
    }

    int retries = 0;
    while (session_id.empty() && ++retries < 10)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));

    if (session_id.empty() || !challenge_len)
    {
        return false;
    }

    memcpy(out, &challenge[challenge_len - 256], 256);

    return true;
}

extern "C"
{
    EXPORT_API void rsa_crypt(uint8_t* in, uint8_t* out, char* cdm_path)
    {
        Adapter* a = new Adapter();
        a->rsa_crypt(in, out, cdm_path);
    }
}

#pragma region cli

int char_to_int(char input)
{
    if (input >= '0' && input <= '9')
        return input - '0';
    if (input >= 'A' && input <= 'F')
        return input - 'A' + 10;
    if (input >= 'a' && input <= 'f')
        return input - 'a' + 10;
    return 0;
}

void hex_to_bytes(const char* hex, uint8_t* bytes)
{
    while (*hex && hex[1])
    {
        *(bytes++) = char_to_int(*hex) * 16 + char_to_int(hex[1]);
        hex += 2;
    }
}

std::string bytes_to_hex(uint8_t* bytes, int len)
{
    std::stringstream ss;
    ss << std::hex;

    for (int i(0); i < len; ++i)
        ss << std::setw(2) << std::setfill('0') << (int)bytes[i];

    return ss.str();
}

int main(int argc, char* argv[])
{
    if (argc != 3)
    {
        std::cout << "Wrong arg count\nUsage: wvadapter [data (hex)] [cdm_path]" << std::endl;
        return 0;
    }

    char* in_hex = argv[1];
    char* cdm_path = argv[2];

    uint8_t* in = new uint8_t[256];
    uint8_t* out = new uint8_t[256];
    hex_to_bytes(in_hex, in);

    Adapter* a = new Adapter();
    a->rsa_crypt(in, out, cdm_path);

    std::cout << bytes_to_hex(out, 256) << std::endl;
}

#pragma endregion