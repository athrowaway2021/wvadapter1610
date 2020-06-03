#pragma once
#include "cdm/media/cdm/cdm_adapter.h"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>

class Adapter : public media::CdmAdapterClient
{
private:
    std::shared_ptr<media::CdmAdapter> wv_adapter;
    std::string session_id;
    uint8_t* challenge;
    int challenge_len = 0;
    int promise_id = 1;

    PVOID except_handler;
    HANDLE current_thread;
    CONTEXT current_context;
    
public:
    Adapter();
    ~Adapter();

    virtual void OnCDMMessage(const char* session, uint32_t session_size, CDMADPMSG msg, const uint8_t* data, size_t data_size, uint32_t status);
    virtual void CDMLog(const char* msg);

    bool rsa_crypt(uint8_t* in, uint8_t* out, char* cdm_path);
};

#define EXPORT_API __declspec(dllexport)
