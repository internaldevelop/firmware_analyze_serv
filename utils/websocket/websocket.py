import websocket
from websocket import create_connection
import utils.sys.config


class MyWebsocket:
    def __init__(self):

        def on_message(ws, message):
            print(ws)
            print(message)

        def on_error(ws, error):
            print(ws)
            print(error)

        def on_close(ws):
            print(ws)
            print("### closed ###")

        # websocket.enableTrace(True)
        # wsurl = utils.sys.config.g_ws_url
        # ws = websocket.WebSocketApp(wsurl,
        #                             on_message=on_message,
        #                             on_error=on_error,
        #                             on_close=on_close)
        # print(type(ws))
        # self.ws = ws
        #
        # ws.run_forever()  长连接
        # ws.send("test")


    def sendmsg(self, msg):
        # print(msg)
        # self.ws.send(msg)

        wsurl = utils.sys.config.g_ws_url
        ws = create_connection(wsurl)
        print("Sending 'Hello, World'...")
        ws.send(msg)
        print("Sent")
        print("Receiving...")
        result = ws.recv()
        print("Received '%s'" % result)
        ws.close()


