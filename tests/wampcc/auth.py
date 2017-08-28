#
# Copyright (c) 2017 Darren Smith
#
# wampcc is free software; you can redistribute it and/or modify
# it under the terms of the MIT license. See LICENSE for details.
#

    def onWampChallenge(self, msg):

        # TODO: only support 'wampcra'; should check for it

        # TODO: need to respond to the challenge
        serverchallenge=msg.extra[u'challenge'].encode('utf8');
        print serverchallenge
        print ("got challenge: {0} {1}".format(msg.method,serverchallenge ) );
        secret="secret2"
        digest = hmac.new(secret,msg=serverchallenge , digestmod=hashlib.sha256).digest()

        signature = base64.b64encode(digest)             # note, in p3k mode, need to use the .decode() method
        pp.pprint(signature)

        signature=unicode( signature, 'utf8' );
        pp.pprint(signature)

        try:
            reply = message.Authenticate( signature );
            serialmsg, serialmsgIsBinary = self._serializer.serialize( reply )

            print ("reply: {0}".format( reply ))
            print "encode->";

            self.sendMessage( serialmsg )
        except Exception as e:
            traceback.print_exc()
            print("->Error: {}".format(e))

