import logging
import sys
import codecs
import psutil
import pprint
from etw import ETW, ProviderInfo
from etw.GUID import GUID
from etw import evntrace as et


## Interesting iteams
#  .get("EventDescriptor").get("Id")
#  ID 501 = Store cookie
#  ID 1057 = Personally Identifiable Info
#  ID 104 = Creation or descstrugtion of internet handles
#  ID 210 = Request HEader
#  ID 211 = HTTP Seader
#  ID 104 = handle request
#  ID 203 = HTTP response or get

logger = logging.getLogger("event_trace_data")
logger.setLevel(logging.DEBUG)
print_replacement = logging.StreamHandler(stream=sys.stdout)
print_replacement.setFormatter(logging.Formatter("%(message)s"))
print_replacement.setLevel(logging.INFO)
file_log = logging.FileHandler("./event_traced.log")
file_format = "%(asctime)s:%(levelname)s:%(message)s" 
file_log.setFormatter(logging.Formatter(file_format))
file_log.delay = True
file_log.setLevel(logging.DEBUG)
#logger.addHandler(print_replacement)
logger.addHandler(file_log)


def get_process_name_from_pid(pid):
    try:
        process = psutil.Process(pid)
        return process.name()
    except psutil.NoSuchProcess:
        return None
    
ALL_PROVIDER_KEYWORDS = ['WININET_KEYWORD_HANDLES', 'WININET_KEYWORD_HTTP', 'WININET_KEYWORD_CONNECTION', 'WININET_KEYWORD_AUTH', 'WININET_KEYWORD_HTTPS', 'WININET_KEYWORD_AUTOPROXY', 'WININET_KEYWORD_COOKIES', 'WININET_KEYWORD_IE', 'WININET_KEYWORD_AOAC', 'WININET_KEYWORD_HTTPDIAG', 'WININET_KEYWORD_SEND', 'WININET_KEYWORD_RECEIVE', 'WININET_KEYWORD_MOBILE', 'WININET_KEYWORD_PII_PRESENT', 'WININET_KEYWORD_PACKET', 'win:ResponseTime', 'Microsoft-Windows-WinINet/Analytic', 'Microsoft-Windows-WinINet/UsageLog', 'Microsoft-Windows-WinINet/WebSocket']

TARGET_KEYWORDS = ['WININET_KEYWORD_AUTH', 'WININET_KEYWORD_HTTPS','WININET_KEYWORD_COOKIES', 'WININET_KEYWORD_SEND', 'WININET_KEYWORD_RECEIVE', 'WININET_KEYWORD_PII_PRESENT', 'WININET_KEYWORD_PACKET']

INTERESTING_EVENTS = [501,1057,104,210,211,104,203]


class INETETW(ETW):

    def __init__(
            self,
            ring_buf_size=4096,
            max_str_len=4096,
            min_buffers=0,
            max_buffers=0,
            level=et.TRACE_LEVEL_RESERVED9,
            any_keywords=None,
            all_keywords=None,
            filters=None):

        self.event_callback = self.on_event

        providers = [ProviderInfo('Microsoft-Windows-WinINet',
                                  GUID("{43D1A55C-76D6-4F7E-995C-64C711E5CAFE}"),
                                  level,
                                  0xFFFFFFFF,
                                  all_keywords)]

        super().__init__(
            ring_buf_size=ring_buf_size,
            max_str_len=max_str_len,
            min_buffers=min_buffers,
            max_buffers=max_buffers,
            event_callback=self.event_callback,
            task_name_filters=filters,
            providers=providers)

    def on_event(self, event_tufo):
        event_id, event = event_tufo
        id = event.get("EventHeader",{"ProcessId":0}).get("ProcessId","Unknown")
        process_name = get_process_name_from_pid(id)

        # if "dns" in str(event.items()).lower():
        #     pprint.pprint(event.items())

        EventId = event.get("EventHeader",{}).get("EventDescriptor",{}).get("Id")
        if EventId in INTERESTING_EVENTS:
            as_string = pprint.pformat(event)
            logger.info(f"{process_name} ({event_id})- \n {as_string}")




def main():
    # Create an INETETW instance with the parameters provided.
    with INETETW():
        # call common run function to handle command line inout / output
        input("press enter to stop")

if __name__ == '__main__':
    string_variants = []
    if len(sys.argv) > 1:
            string_variants = [
                sys.argv[1],
                codecs.encode(sys.argv[1], "utf-16le").decode("latin-1"),
                codecs.encode(sys.argv[1], "utf-16be").decode("latin-1")
            ]
    else:
        for each_word in ["response", "set-cookie","post", "password","username"]:
            string_variants = [
                each_word
            ]
    main()
