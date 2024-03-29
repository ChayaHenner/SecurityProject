from enum import Enum
class ResponsePayloadCodes(Enum):
    RegistrationSuccess = 1600
    RegistrationFailed = 1601
    SendingSymmetricKey = 1603


SERVER_VERSION = 24

class Response:
    def __init__(self, code):
        self.version = SERVER_VERSION
        self.code = code
        self.payload_size = 0
        #according to code

    # def update_payload(self, payload_size):
    #     self.payload_size = payload_size


class ResponseRegistrationSuccess(Response):
    def __init__(self, client_id):
        super().__init__(ResponsePayloadCodes.RegistrationSuccess.value)
        self.client_id = client_id
        
class ResponseRegistrationFailed(Response):
    def __init__(self):
        super().__init__(ResponsePayloadCodes.RegistrationFailed.value)

class ResponseSendingSymmetricKey(Response):
    def __init__(self):
        super().__init__(ResponsePayloadCodes.SendingSymmetricKey.value)
