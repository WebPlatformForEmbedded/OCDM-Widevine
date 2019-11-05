/*
 * Copyright 2016-2017 TATA ELXSI
 * Copyright 2016-2017 Metrological
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "MediaSession.h"
#include "HostImplementation.h"

#include <assert.h>
#include <iostream>
#include <sstream>
#include <sys/utsname.h>

namespace CDMi {

using std::placeholders::_1;

class WideVine : public IMediaKeys, public widevine::Cdm::IEventListener
{
private:
    WideVine (const WideVine&) = delete;
    WideVine& operator= (const WideVine&) = delete;

    typedef std::map<std::string, MediaKeySession*> SessionMap;

public:
    WideVine()
        : _adminLock()
        , _pendingLock()
        , _cdm(nullptr)
        , _host()
        , _sessions()
        , _isServerCertificateSet(false)
        , _pendingSessions() {

        widevine::Cdm::ClientInfo client_info;

        // Set client info that denotes this as the test suite:
        client_info.product_name = "WPEFramework";
        client_info.company_name = "www.metrological.com";
        client_info.model_name = "www";

    #if defined(__linux__)
        client_info.device_name = "Linux";
        {
            struct utsname name;
            if (!uname(&name)) {
                client_info.arch_name = name.machine;
            }
        }
#else
        client_info.device_name = "unknown";
#endif
        client_info.build_info = __DATE__;

        if (widevine::Cdm::kSuccess == widevine::Cdm::initialize(
                widevine::Cdm::kNoSecureOutput, client_info, &_host, &_host, &_host, static_cast<widevine::Cdm::LogLevel>(0))) {
#ifdef ENABLE_SERVICE_CERTIFICATE
            _cdm = widevine::Cdm::create(this, &_host, true);
#else
            _cdm = widevine::Cdm::create(this, &_host, false);
            _isServerCertificateSet = true;
#endif
        }
    }
    virtual ~WideVine() {
        _adminLock.Lock();

        SessionMap::iterator index (_sessions.begin());

        while  (index != _sessions.end()) {
            delete index->second;
            index++;
        }

        _sessions.clear();

        _adminLock.Unlock();

        if (_cdm != nullptr) {
            delete _cdm;
        }
    }

    virtual CDMi_RESULT CreateMediaKeySession(
        const string& /* keySystem */,
        int32_t licenseType,
        const char *f_pwszInitDataType,
        const uint8_t *f_pbInitData,
        uint32_t f_cbInitData,
        const uint8_t *f_pbCDMData,
        uint32_t f_cbCDMData,
        IMediaKeySession **f_ppiMediaKeySession) {

        CDMi_RESULT dr = CDMi_S_FALSE;
        *f_ppiMediaKeySession = nullptr;

        MediaKeySession* mediaKeySession = new MediaKeySession(_cdm,
                licenseType,
                std::bind(&SessionCallback, reinterpret_cast<void*>(this), _1));

        dr = mediaKeySession->Init(licenseType,
            f_pwszInitDataType,
            f_pbInitData,
            f_cbInitData,
            f_pbCDMData,
            f_cbCDMData);


        if (dr != CDMi_SUCCESS) {
            delete mediaKeySession;
        }
        else {
            *f_ppiMediaKeySession = mediaKeySession;
        }

        return dr;
    }

    static void SessionCallback(void* mediaKeysArg, void* mediaKeySessionArg)
    {
        WideVine* mediaKeys = reinterpret_cast<WideVine*>(mediaKeysArg);
        MediaKeySession* mediaKeySession =
                reinterpret_cast<MediaKeySession*>(mediaKeySessionArg);
        mediaKeys->SessionCallbacki(mediaKeySession);
    }

    void SessionCallbacki(MediaKeySession* mediaKeySession)
    {
        if (mediaKeySession == nullptr) {
            _pendingLock.Lock();
            _isServerCertificateSet = true;
            _pendingLock.Unlock();

            for (auto iter = _pendingSessions.begin();
                    iter != _pendingSessions.end(); ++iter) {
                mediaKeySession = *iter;
                createSession(mediaKeySession);
            }
            _pendingSessions.clear();

        } else {
            bool isFirstRequest = false;
            bool isPendingSession = false;

            _pendingLock.Lock();
            if (_isServerCertificateSet == false) {
                isPendingSession = true;
                isFirstRequest = _pendingSessions.empty();
                _pendingSessions.push_back(mediaKeySession);
            }
            _pendingLock.Unlock();

            if (isPendingSession == true) {
                if (isFirstRequest == true) {
                    CDMi_RESULT ret =
                            mediaKeySession->sendServerCertificateRequest();
                    ASSERT(ret == CDMi_SUCCESS);
                    (void)ret; // To supress warning
                }
            } else {
                createSession(mediaKeySession);
            }
        }
    }

    void createSession(MediaKeySession* mediaKeySession)
    {
        CDMi_RESULT ret = mediaKeySession->createSession();
        ASSERT(ret == CDMi_SUCCESS);

        if (ret == CDMi_SUCCESS) {

            _adminLock.Lock();
            std::string sessionId(mediaKeySession->GetSessionIdInternal());
            _sessions.insert(
                    std::pair<std::string, MediaKeySession*>(sessionId,
                            mediaKeySession));
            _adminLock.Unlock();

            ret = mediaKeySession->generateRequest();
            ASSERT(ret == CDMi_SUCCESS);
        }
    }

    virtual CDMi_RESULT SetServerCertificate(
        const uint8_t *f_pbServerCertificate,
        uint32_t f_cbServerCertificate) {

        CDMi_RESULT dr = CDMi_S_FALSE;

        std::string serverCertificate(reinterpret_cast<const char*>(f_pbServerCertificate), f_cbServerCertificate);
        if (widevine::Cdm::kSuccess == _cdm->setServiceCertificate(serverCertificate)) {
            dr = CDMi_SUCCESS;
        }
        return dr;
    }

    virtual CDMi_RESULT DestroyMediaKeySession(
        IMediaKeySession *f_piMediaKeySession) {

        std::string sessionId (f_piMediaKeySession->GetSessionId());

        _adminLock.Lock();

        SessionMap::iterator index (_sessions.find(sessionId));

        if (index != _sessions.end()) {
            _sessions.erase(index);
        }

        _adminLock.Unlock();

        delete f_piMediaKeySession;

        return CDMi_SUCCESS;
    }

    virtual void onMessage(const std::string& session_id,
        widevine::Cdm::MessageType f_messageType,
        const std::string& f_message) {

        _adminLock.Lock();

        SessionMap::iterator index (_sessions.find(session_id));

        if (index != _sessions.end()) index->second->onMessage(f_messageType, f_message);

        _adminLock.Unlock();
    }

    virtual void onKeyStatusesChange(const std::string& session_id) {

        _adminLock.Lock();

        SessionMap::iterator index (_sessions.find(session_id));

        if (index != _sessions.end()) index->second->onKeyStatusChange();

        _adminLock.Unlock();
    }

    virtual void onRemoveComplete(const std::string& session_id) {

        _adminLock.Lock();

        SessionMap::iterator index (_sessions.find(session_id));

        if (index != _sessions.end()) index->second->onRemoveComplete();

        _adminLock.Unlock();
    }

    // Called when a deferred action has completed.
    virtual void onDeferredComplete(const std::string& session_id, widevine::Cdm::Status result) {

        _adminLock.Lock();

        SessionMap::iterator index (_sessions.find(session_id));

        if (index != _sessions.end()) index->second->onDeferredComplete(result);

        _adminLock.Unlock();
    }

    // Called when the CDM requires a new device certificate
    virtual void onDirectIndividualizationRequest(const std::string& session_id, const std::string& request) {

        _adminLock.Lock();

        SessionMap::iterator index (_sessions.find(session_id));

        if (index != _sessions.end()) index->second->onDirectIndividualizationRequest(request);

        _adminLock.Unlock();
    }

private:
    WPEFramework::Core::CriticalSection _adminLock;
    WPEFramework::Core::CriticalSection _pendingLock;
    widevine::Cdm* _cdm;
    HostImplementation _host;
    SessionMap _sessions;
    bool _isServerCertificateSet;
    std::vector<MediaKeySession*> _pendingSessions;
};

static SystemFactoryType<WideVine> g_instance({"video/webm", "video/mp4", "audio/webm", "audio/mp4"});

}  // namespace CDMi

CDMi::ISystemFactory* GetSystemFactory() {

    return (&CDMi::g_instance); 
}
